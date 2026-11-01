# IONIQ 5 reverse-engineering research

Research notes, source tools and validation tests for a 2021 UK-origin
Hyundai IONIQ 5 Standard Gen5W infotainment system. The documented methods
and compatibility assessments distinguish official package evidence,
owner-supplied observations and community reports.

This public repository was initialized from a sanitized snapshot with fresh
Git history. Raw diagnostic exports, device dumps and private working
records are not included. See [PUBLIC-RELEASE.md](PUBLIC-RELEASE.md) for the
publication boundary and [tests/README.md](tests/README.md) for validation.

The research documents software and subsystem behavior. It does not include
a tested vehicle modification, update procedure or claim that a community
method works on the owner's installed build.

## VM research

The [current technical handover](HANDOVER.md) records a VM-adapted boot of the
European Gen5W Linux kernel, the recovered vendor userspace and launcher stack, the
AppNavi observation contract, and the unresolved Home-to-Navigation transition. Authored guest
helpers and experiment scripts are in [vm/repro](vm/repro), with bounded
evidence and inspected screenshots in [vm/evidence](vm/evidence). See
[vm/README.md](vm/README.md) for the source mapping and local artifact
requirements.

### Where the VM work stands

| Area | State | Notes |
| --- | --- | --- |
| Vendor kernel boot | Working | Gen5W kernel boots under QEMU with a documented ABL boot-parameter adaptation; anti-tamper satisfied inside the VM |
| Recovered rootfs / userspace | Working | EU `260128` image decrypted offline; mounted read-only |
| Launcher standby → profile confirm | Working | Authentic driver-selection and safety-notice screen |
| Authentic Home screen | Working | Real `AppHomeScreen` tile grid |
| AppNavi (navigation) | Partial | Full chain reaches engine success and creates surfaces 3000/4903; genuine map pixels are verified separately in the widget surface |
| Home ↔ Navigation compositing | Blocked | Full chain reports `notifyNaviLaunched[5] window[0]`; manager remains at 35/11 instead of transitioning to Navigation |
| Audio, persistence, restart/suspend | Not started | Need evidence-derived service contracts |
| CAN / MICOM | Partial | Local D-Bus simulation exists; real contract still being reconstructed |
| Input (touch/keys) | Partial | Wayland input harness exists; not wired end to end |

The table records the retained full-chain evidence. What this repository can rebuild
from the public package today is narrower and separately tested: the kernel shell
(`tests/test_vm_e2e.py`) and the recovered vendor userspace with the launcher stack
(`tests/test_vm_vendor_e2e.py`). The Home/Navigation frames above come from the
private workspace described in [HANDOVER.md](HANDOVER.md); reproducing them here needs
a renderer the vendor Qt build accepts, which is still open.

Runs use QEMU with TCG acceleration, `-cpu max,vendor=GenuineIntel`, 1536 MiB RAM,
disk `snapshot=on`, and **no NIC**. Snapshot mode is mandatory: a run must never
mutate the base image or reach the network.

### Inspected screenshots

All frames are Wayland framebuffer captures at the head unit's real 1920×720
geometry, taken from the running VM.

**Authentic profile / confirm screen** — produced by the genuine launcher, not a
mock-up.

![Authentic driver-selection and safety notice screen](vm/evidence/screenshots/profile-confirm.png)

**Authentic `AppHomeScreen`** — the real tile grid and top bar.

![Authentic AppHomeScreen tile grid](vm/evidence/screenshots/authentic-home.png)

**Attempted navigation, still showing Home** — the honest failure case. This
frame was captured during the navigation window; only the page-indicator dots
changed.

![Navigation attempt still displaying Home screen](vm/evidence/screenshots/navigation-attempt.png)

**Genuine AppNavi map pixels** — real road network, river and position arrow,
rendered by the authentic binary into its own surface.

![Authentic AppNavi map surface](vm/evidence/screenshots/appnavi-map-widget.png)

### Why Navigation does not appear yet

The latest full-chain result and evidence boundaries are tracked in
[HANDOVER.md](HANDOVER.md) and [docs/navigation-status.md](docs/navigation-status.md).
This is no longer a surface-creation or map-rendering blocker: AppNavi reaches engine
initialization and creates parent `3000` plus widget `4903`; genuine map pixels are
verified in the widget surface. The full launcher chain still does not complete the
Home-to-Navigation transition.

The remaining blocker is the manager contract:

- AppNavi emits `SendNaviBootFail(5)` on `/navigation_map`; `5` is a hard-coded
  literal, but its enum meaning and selection path are unresolved.
- The manager observes `notifyNaviLaunched[5] window[0]` and stays at current/drawing
  AppID `35/11` (`APP_NAVI_LOADING` / Home) instead of reaching `APP_NAVI` (`30`).
- The observed AppNavi lifecycle delivers foreground information; the separate
  background notification that latches the manager's window byte has not been
  observed. A Camera/Standby run proves the BG path can occur after a positive-size
  to `0×0` transition, but that AppNavi lifecycle has not been demonstrated.

Do not patch status `5`, force the window byte, or synthesize a success callback.
The latest run restores visible Home on return; stable Navigation composition remains
unproven.

## Tooling for the next phase

- `tools/uk_fw/setup_eu260128.py` verifies the official package, decrypts the TE2
  inputs and prepares a minimal kernel/serial-shell workspace in one offline command.
- `tools/uk_fw/vendor_rootfs.py` assembles and boots the recovered vendor userspace,
  binds the software GL stack on request, and refreshes the image in seconds.
- `tools/uk_fw/decompile.py` drives Ghidra headless (JDK 21, no root) to turn a
  retained listing address into C, one function at a time.

See [tests/README.md](tests/README.md) for what passes today and the measured test
coverage.
