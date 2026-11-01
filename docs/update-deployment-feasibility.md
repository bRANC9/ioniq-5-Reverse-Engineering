# Could a corrected updater reach the hardware? Gate-by-gate

Status: static analysis of the EU `260128` package plus one measured capability
(byte-exact envelope re-encryption). No unit was contacted, nothing was flashed, and
no OEM key material exists in this repository. This document maps **what a corrected
package would have to satisfy**, and separates "we can produce this bit-for-bit" from
"this needs the OEM private key".

Scope note: the repository's research scope stops at acceptance analysis on a bench
unit. Nothing here is an instruction to flash a vehicle, and a failed update can leave
a head unit unusable.

## Two independent chains, two different roots of trust

| # | Gate | What it validates | Can this project satisfy it? | Evidence |
| --- | --- | --- | --- | --- |
| A1 | `ipk.` boot container header | magic, sizes, duplicate length fields, kernel command line | yes, format is fully parsed | `evidence/eu-boot-container-signature.md` |
| A2 | Boot container signature | **RSA-2048, PKCS#1 v1.5, SHA-256** over `[0, hdr+total+4)`; OEM modulus ships inside each `iasImage*_sub` | **no** — needs the OEM private key | same, plus `evidence/eu-keystore-manifest-root-of-trust.md` |
| A3 | Boot-time trust root | `manifest_keyring` created from the `oemkm=<size>@<phys>` region the boot loader supplies; the parameter is not in any packaged command line | not reachable from a package | `evidence/eu-keystore-manifest-root-of-trust.md` |
| B1 | `.ver` manifest record | `path|name|record-id|signed-crc32|size|flag`; CRC-32 and size are recomputable | yes — `tools/uk_fw/ver_manifest.py verify` | `tools/uk_fw/ver_manifest.py` |
| B2 | Updater CRC comparison | the updater logs `crc front value [0x%x]` and RedBend's `Source signature 0x%08x and CRC 0x%08x mismatch` — a 32-bit value pair, not public-key crypto | likely yes; the "signature" is the CRC-32 carried by the manifest | `work/updater/AppUpgrade.elf` strings (`RedBend:`), `[VELIX] : _CheckCKSOfFile` |
| B3 | Per-image digest lists | `HU/images/*/md5sum.txt`, `Vr_fixed md5sum checking` | yes, plain MD5 | package tree, updater strings |
| B4 | Version gate / anti-rollback | `E_UPDATE_VERSION_DOWN/SAME/UP`, UNECE version comparison, map-version skip logic | yes, the comparison is a userland version string | updater strings; `evidence/child-notes/10-antirollback-and-downgrade.md` |
| B5 | TE2 envelope | AES-128-CBC, IV `sha256(basename + signed_int32(body_size))[:16]`, trailer integrity `sha256(iv + metadata[36:])` | **yes, byte-exact** — see below | `tools/uk_fw/gen5w_encrypt.py` |
| B6 | TE2 trailer stores | 8,176-byte signature store and 8,192-byte key store, high entropy, purpose unestablished | produced byte-identically when a template envelope is reused; **whether the updater validates them is unknown** | `gen5w_decrypt._analyze` report |
| B7 | Encrypted-file detection | `CheckEncryptFile`, `this file is not encrypted` | yes, the scheme is implemented | updater strings |
| C1 | Delivery path | engineering mode (SOP check + PIN), USB media, update-acceptance UI, MICOM handshake | not demonstrated on this build; community reports only | `evidence/attack-surface-prioritisation.md`, `evidence/community-entry-methods.md` |

Reading the table: the **kernel/boot container** is protected by an OEM signature whose
private key is not in any analysed artifact, so a corrected kernel cannot be made
acceptable by re-packing alone. The **application/userland** side is different: its
gates are CRCs, MD5 lists, a version string and an AES envelope with a known key — all
reproducible here.

## Measured capability: envelopes are reproducible, not just readable

`tools/uk_fw/gen5w_encrypt.py` is the inverse of the decryptor and was proven against
the real package: decrypting `HU/firmware/update.tar.gz` and re-encrypting it with the
vendor file as template reproduces the **original file byte for byte** (SHA-256 equal),
including the ciphertext tail stored in the metadata padding field. The test that pins
this is `tests/test_gen5w_encrypt.py::VendorEnvelopeReproductionTests`.

The same scheme wraps the updater itself: `AppUpgrade` is a TE2 envelope whose body
decrypts to an ELF64 binary (`work/updater/AppUpgrade.elf`), which is how the gate
table above could be read from the updater's own strings instead of inferred.

## What this does not establish

- Whether the unit checks the TE2 signature/key stores (B6). If it does, and they cover
  the payload, then a modified payload inside an otherwise valid envelope is rejected
  even though the envelope is well formed.
- Whether the `.ver` CRC repair path is enough in practice: `Ioniq5-VULNERABILITIES.md`
  records field reports of rejection **despite** a repaired CRC, which is consistent
  with an additional check somewhere on the unit.
- Anything about the vehicle-side delivery path (C1). Engineering mode is a documented
  surface, not a proven bypass.

## Cheapest next experiments, in order

1. **Static, no hardware:** locate the updater's verification call graph. `AppUpgrade`
   is decrypted and disassemblable; the open question is whether any code path opens
   the TE2 trailer stores (B6) or only the CRCs (B2). Grep for the store offsets
   (`0x34`, `0x2024`) and for `verify`/`check` symbols, then decompile the containing
   function with `tools/uk_fw/decompile.py`. This decides whether the application chain
   is a CRC gate or a keyed gate — the single most valuable unknown.
2. **Static:** establish which component verifies the boot container (A2/A3). The
   kernel only *consumes* `manifest_keyring`; the verifier is outside it, so look in
   the recovery/updater partitions for an RSA verify call and its key source.
3. **Bench only:** the `.ver` CRC repair experiment on a bench unit with a reversible
   medium, observing the acceptance log — never on the owner's vehicle.
4. Only if 1–3 show an unkeyed path: a minimal corrected application package, still
   rejecting any change to the kernel container.

## What this repository will not do

- No OEM private key recovery, no signature forgery, no anti-rollback counter bypass.
- No firmware flashing procedure for a vehicle; no instructions that assume a bricked
  unit is acceptable.
- No claim that any of this works on the owner's installed build.
