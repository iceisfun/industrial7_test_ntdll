# Validation on Windows 10

VERIFIED: the full corpus (164 areas) was run on genuine Windows 10 22H2 x64 (build 19045, ntdll 10.0.19041.2788) in a local QEMU/KVM guest (throwaway overlay of a pinned base image), once as a real standard user (medium integrity) and once elevated, at corpus commit `54217a7` (test sources; later commits touch tooling and documentation only).

| Mode | areas | tests | failed | skipped | checks passed | checks failed |
|---|---|---|---|---|---|---|
| standard user | 164 | 3718 | 0 | 23 | 116273 | 0 |
| administrator | 164 | 3718 | 0 | 6 | 116571 | 0 |

Per-area SUMMARY lines for both modes are in [COVERAGE.md](COVERAGE.md); the raw per-area logs of this run are local under `results/win10/{adm,std}/` (ignored by Git).

Skips are privilege or environment gated and each prints a concrete reason (for example `SeBackupPrivilege absent from the token (standard user)`).

Review and correction history for this pass:

- Every new area was written by one pass and then re-checked by an independent reviewer pass that re-ran it on the guest. Reviewers removed always-true checks, tightened over-wide accepted-status sets and added missing error paths (see each area's `EVIDENCE.md`).
- Standard-user mode was first mis-run (the launcher tried to create a user itself and failed), so no standard-user result existed for the new areas until the full run above. That run found real standard-user differences, fixed to match Windows 10: `NtSetDebugFilterState` returns STATUS_ACCESS_DENIED (not STATUS_PRIVILEGE_NOT_HELD) for a non-elevated token; `PssNtQuerySnapshot` class 9 returns success for a non-elevated token and STATUS_NOT_FOUND elevated; named sections and symbolic links cannot be created in the global `\BaseNamedObjects` by a standard user (the session directory is used instead); `dbg_print_family` no longer depends on test order.
- `nt_vm` timed out once as standard user while another guest was running at the same time (host load); alone and in the final run it passes.

Limits: only build 19045 was available as a baseline, other Windows 10 builds and locales are UNVERIFIED; each mode was run in full once after the last fixes (individual areas were run repeatedly during development, no flakiness was recorded). Wine was not used as an authority.

Earlier record (before this expansion, 28 areas): 2188 tests, standard 0 failed / 2 skipped, administrator 0 failed / 1 skipped.

## nt_cancel_io (separate oracle record, bb #1228)

The `nt_cancel_io` area was also run on a Windows 10 22H2 guest by another lane at commits a6fc062 (15 tests) and 0cc9da9 (16 tests): standard user x2 and administrator x2, all green and byte-identical, no expectation changed. Notes: native `NtCancelIoFileEx` returns 0x00000000 with `IoStatusBlock.Status` 0x00000000; the cancelled request's completion-port packet arrives as a failed-I/O packet for that request only (`iosb.Status` 0xC0000120, 0 bytes). The full-corpus run above includes this area (16 tests, both modes).
