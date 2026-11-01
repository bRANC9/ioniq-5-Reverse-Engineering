#!/usr/bin/env python3
"""Decompile every vendor application binary in a tree, in a resumable queue.

The recovered userland holds 2,767 ELF files and about 1.4 GB, most of it
third-party (Qt, ICU, Mesa). This tool targets the vendor application layer
(`app/` and `navi/`) and keeps its own state, so a run can be stopped and resumed:

    python3 tools/uk_fw/decompile_all.py --jobs 4

Each worker claims one binary at a time with an exclusive lock file, decompiles it
through `decompile.py`, and records the outcome in `work/decompiled/all-state.json`.
Binaries are ordered small first so the queue delivers results early.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
DEFAULT_TREE = PROJECT / "work/vm/vendor-userspace-260128/rootfs-tree"
DEFAULT_STATE = PROJECT / "work/decompiled/all-state.json"
DEFAULT_OUT = PROJECT / "work/decompiled"
DEFAULT_ROOTS = ("app", "navi")
# Third-party runtimes are not the research target and dominate the byte count.
SKIP_PREFIXES = ("app/lib/libQt", "app/lib/libicu", "navi/Lib/libQt", "navi/Lib/libicu")


def elf_files(tree: Path, roots: tuple[str, ...]) -> list[dict]:
    found = []
    for root in roots:
        base = tree / root
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            try:
                # Devices and FIFOs in a recovered rootfs block on open(); only a
                # regular file can carry an ELF header.
                info = os.stat(path, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    continue
                with path.open("rb") as handle:
                    if handle.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue
            relative = str(path.relative_to(tree))
            if relative.startswith(SKIP_PREFIXES):
                continue
            found.append({"path": relative, "size": path.stat().st_size})
    found.sort(key=lambda item: item["size"])
    return found


def load_state(path: Path) -> dict:
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return {"schema": 1, "done": {}, "failed": {}, "claimed": {}}


def save_state(path: Path, state: dict) -> None:
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(path)


def claim(state_path: Path, relative: str, max_age: float = 120.0) -> bool:
    """Exclusive claim with stale takeover, so workers share one queue.

    A lock left by a killed worker would otherwise stall the queue forever: the
    pending binary can never be claimed and the loop spins.
    """
    lock = state_path.parent / "claims" / (relative.replace("/", "__") + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    for attempt in (0, 1):
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                too_old = time.time() - lock.stat().st_mtime > max_age
            except OSError:
                too_old = True
            if attempt == 0 and too_old:
                try:
                    lock.unlink()
                except OSError:
                    pass
                continue
            return False
        os.close(descriptor)
        return True
    return False


def release(state_path: Path, relative: str) -> None:
    lock = state_path.parent / "claims" / (relative.replace("/", "__") + ".lock")
    try:
        lock.unlink()
    except OSError:
        pass


def clear_stale_claims(state_path: Path, max_age: float = 3600.0) -> int:
    """Drop claim locks left behind by a killed worker.

    A claim whose binary is neither done nor failed and whose lock is older than the
    age limit cannot belong to a live worker, so leaving it would stall the queue.
    """
    claims = state_path.parent / "claims"
    if not claims.is_dir():
        return 0
    state = load_state(state_path)
    removed = 0
    for lock in claims.glob("*.lock"):
        relative = lock.name[: -len(".lock")].replace("__", "/")
        if relative in state["done"] or relative in state["failed"]:
            stale = True
        else:
            try:
                stale = time.time() - lock.stat().st_mtime > max_age
            except OSError:
                stale = True
        if stale:
            try:
                lock.unlink()
                removed += 1
            except OSError:
                pass
    return removed


def worker(tree: Path, state_path: Path, out_root: Path, timeout: int,
           share: tuple[int, int] = (0, 1)) -> dict:
    """Work through one slice of the queue.

    Slices are static (every n-th pending item) so parallel workers never contend for
    the same binary; the claim file stays as a safety net for an overlapping run.
    """
    processed = []
    index, count = share
    while True:
        state = load_state(state_path)
        pending = [item for item in state["queue"]
                   if item["path"] not in state["done"] and item["path"] not in state["failed"]]
        if not pending:
            break
        mine = [item for position, item in enumerate(pending) if position % count == index]
        if not mine:
            break
        target = mine[0]
        if not claim(state_path, target["path"]):
            time.sleep(3)
            continue
        try:
            binary = tree / target["path"]
            out = out_root / Path(target["path"]).name
            command = [sys.executable, str(HERE / "decompile.py"),
                       "--binary", str(binary), "--select", "ALL",
                       # One project directory per worker: two overlapping runs used to
                       # collide on the same path and abort with a lock exception.
                       "--project", str(PROJECT / f"work/ghidra-all-{index}"
                                      / Path(target["path"]).name),
                       "--out", str(out), "--limit", "0",
                       "--analysis-timeout", "1800", "--function-timeout", "60",
                       "--discard"]
            started = time.time()
            try:
                finished = subprocess.run(command, capture_output=True, text=True,
                                          timeout=timeout, check=False)
                returncode = finished.returncode
                output = (finished.stdout or "") + (finished.stderr or "")
            except subprocess.TimeoutExpired as expired:
                # A single slow binary must not take the queue down with it.
                returncode = -1
                output = (f"timed out after {timeout}s: "
                          f"{(expired.stdout or b'')[-300:]!r}")
            state = load_state(state_path)
            record = {"path": target["path"], "size": target["size"],
                      "returncode": returncode,
                      "seconds": round(time.time() - started, 1)}
            artifacts = (len(list(out.glob("*.c"))) + len(list(out.glob("*.asm")))
                         if out.is_dir() else 0)
            record["artifacts"] = artifacts
            if artifacts:
                # The artifacts are the deliverable: a binary that produced them is done
                # even when the headless launcher still exits non-zero for its own
                # reasons, and a binary that failed once then succeeded belongs to one
                # set only.
                state["done"][target["path"]] = record
                state["failed"].pop(target["path"], None)
                processed.append(record)
            else:
                record["log_tail"] = output[-500:]
                state["failed"][target["path"]] = record
                state["done"].pop(target["path"], None)
            save_state(state_path, state)
        finally:
            release(state_path, target["path"])
    return {"processed": processed}


def count_queue(state: dict) -> dict:
    """Counts that cannot double-count a binary present in both sets.

    A path used to land in `done` and stay in `failed` after a later success, which made
    `queue - done - failed` subtract it twice and under-report the work left.
    """
    done = set(state["done"])
    failed = set(state["failed"])
    pending = [item["path"] for item in state["queue"]
               if item["path"] not in done and item["path"] not in failed]
    return {"queue": len(state["queue"]), "done": len(done - failed),
            "failed": len(failed - done), "pending": len(pending),
            "overlap": len(done & failed)}


def repair_state(state_path: Path, out_root: Path) -> int:
    """Resolve entries that sit in both `done` and `failed`.

    The artifact on disk decides: a directory with C or listing output means the binary
    decompiled, so the failure record is dropped (and the other way round).
    """
    state = load_state(state_path)
    overlap = set(state["done"]) & set(state["failed"])
    fixed = 0
    for relative in overlap:
        out = out_root / Path(relative).name
        has_artifacts = out.is_dir() and any(
            out.glob("*.c")) or out.is_dir() and any(out.glob("*.asm"))
        if has_artifacts:
            state["failed"].pop(relative, None)
            state["done"][relative].setdefault("note", "repaired: artifacts on disk")
        else:
            state["done"].pop(relative, None)
        fixed += 1
    if fixed:
        save_state(state_path, state)
    return fixed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", type=Path, default=DEFAULT_TREE)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--roots", nargs="*", default=list(DEFAULT_ROOTS))
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=7200)
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--share", default="",
                        help="i/n: process only every n-th pending binary")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the queue and exit")
    args = parser.parse_args(argv)

    state_path = args.state.resolve()
    if args.reset and state_path.is_file():
        state_path.unlink()
    state = load_state(state_path)
    if "queue" not in state:
        state["queue"] = elf_files(args.tree, tuple(args.roots))
        save_state(state_path, state)
    repaired = repair_state(state_path, args.out.resolve())
    if repaired:
        print(json.dumps({"repaired_overlap": repaired}))
        state = load_state(state_path)
    counts = count_queue(state)
    print(json.dumps(counts, indent=2))
    removed = clear_stale_claims(state_path)
    if removed:
        print(json.dumps({"cleared_stale_claims": removed}))
    if args.dry_run:
        return 0

    if args.jobs > 1 and not args.share:
        # Independent worker processes over static slices: no claim contention, and a
        # killed worker only loses its own slice, which the next run picks up.
        import subprocess as sp

        children = []
        for index in range(args.jobs):
            command = [sys.executable, str(Path(__file__)), "--tree", str(args.tree),
                       "--state", str(state_path), "--out", str(args.out),
                       "--timeout", str(args.timeout),
                       "--share", f"{index}/{args.jobs}"]
            children.append(sp.Popen(command, stdout=sp.DEVNULL, stderr=sp.STDOUT))
        for child in children:
            child.wait()
    else:
        index, count = (0, 1)
        if args.share:
            left, right = args.share.split("/")
            index, count = int(left), max(1, int(right))
        worker(args.tree, state_path, args.out, args.timeout, (index, count))

    state = load_state(state_path)
    print(json.dumps({"done": len(state["done"]), "failed": len(state["failed"]),
                      "queue": total}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
