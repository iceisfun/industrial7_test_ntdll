# App container, token namespace, boot-status and persisted-state getters

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788); decompilation (corpus explorer) for the branch structure,
guest run for names and statuses. Session numbers are taken from `ProcessIdToSessionId`, never hard-coded.

| Export (RVA) | Contract asserted | Source |
| --- | --- | --- |
| RtlGetAppContainerSidType (0x446c0) | S-1-15-2 with 8 sub-authorities: type 2 (parent), 12: type 1 (child), status 0; other counts: type 3 and 0xC000A200; wrong authority, revision or first sub-authority, or non package SIDs: type 0 and 0xC000A200 | decomp, observed |
| RtlGetAppContainerParent (0x43e50) | output cleared first; child (12 sub-authorities) returns a heap SID made of the first 8 sub-authorities (freed with RtlFreeSid); a parent or non package SID: 0xC000000D | decomp, observed |
| RtlGetAppContainerNamedObjectPath (0x43f20) | with a package SID: absolute `\Sessions\<n>\AppContainerNamedObjects\<sid>`, relative `AppContainerNamedObjects\<sid>`; non package SID: 0xC000A200 | decomp, observed |
| RtlGetTokenNamedObjectPath (0x45900) | process token: `\Sessions\<n>\BaseNamedObjects`; relative form `Global\Session\<n>`; pseudo token handle accepted; bad handle 0xC0000008 | decomp, observed |
| RtlGetSetBootStatusData (0xedf20) | only error paths (no boot data is read or written): write of item 0xf is rejected with 0xC000000D before any I/O; reads through a handle that does not exist or NULL return 0xC0000008 | decomp |
| RtlGetSystemBootStatusEx (0xee080) | size at or over 1 GiB with a non-NULL length pointer: 0xC0000095 without reaching the kernel | decomp |
| RtlGetSystemBootStatus (0x8b910) | class 0 returns 4 bytes when permitted; a failure must be access denied or privilege not held (administrator and standard modes both noted) | decomp, observed |
| RtlGetPersistedStateLocation (0x57dc0) | with no policy key for the source the default location is returned with the byte length including NUL; type 2: 0xC00000F1; small buffer: 0x80000005 with the required size and untouched buffer; skipped if a policy key exists | decomp, observed |

Skips: RtlGetPersistedStateLocation when a policy key is present.
