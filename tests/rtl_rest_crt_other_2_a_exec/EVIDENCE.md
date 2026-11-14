# Exception, context, work item and process-parameter helpers: Windows 10 contracts

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). Decompilations from the Corpus Explorer
(`http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp`), confirmed on the guest.

| Export | Source | Checked |
| --- | --- | --- |
| RtlKnownExceptionFilter | decomp 0x100860: `(code != 0xC0000194) - 1`: STATUS_POSSIBLE_DEADLOCK gives -1 (continue execution), anything else 0 | Several codes |
| RtlLocateLegacyContext | decomp 0x81160: header words {All.Offset, All.Length, Legacy.Offset, Legacy.Length}; accepted when the legacy chunk lies inside the All range, output length only on success | In-range, exactly-filling, one-over, before-range, NULL length |
| RtlLocateExtendedFeature, RtlLocateExtendedFeature2 | decomp 0xf5cc0 / 0x715a0 (the first passes the shared-user-data XState configuration, 0x7ffe03d8): ids below 2 and from 64 up give NULL; length output optional | AVX (id 2): pointer and length equal LocateXStateFeature on an InitializeContext XSTATE context, length 256; configuration with no features enabled gives NULL; skips when AVX state is not enabled |
| RtlLookupFunctionTable | decomp 0x9c520: fills image base and exception-directory size for a code address; outputs untouched for non-image addresses | ntdll, kernel32, this exe (sizes from the PE exception directory), unmapped and stack addresses |
| RtlRestoreContext | decomp 0x6ddb0: resumes a captured context | Control returns to the capture point exactly once more, with and without an exception record |
| RtlRaiseStatus, RtlRaiseNoncontinuableException | decomp 0x1025c0 / 0xa1950: build a noncontinuable record and raise it; the record's address comes from the supplied context | A first-chance vectored handler observes code, flags (EXCEPTION_NONCONTINUABLE), parameters and address, then resumes at a captured context |
| RtlQueueWorkItem | decomp 0xb780: posts a threadpool task | Callback runs once per item on another thread with the exact context, flags 0 / 0x10 / 0x20, 20 queued items |
| RtlQueueApcWow64Thread | decomp 0xdc150: forwards to the APC queueing syscall | The routine is a WOW64 thunk target so it is never run: queued to a suspended thread that is terminated; result equals NtQueueApcThread for a dead thread; invalid / NULL handle 0xC0000008 |
| RtlNormalizeProcessParams | decomp 0x88d10: when the NORMALIZED flag (bit 0 at +8) is clear, nine offset fields (+0x40 +0x58 +0x68 +0x78 +0xb8 +0xc8 +0xd8 +0xe8 +0x418) that are non-zero get the block address added, and the flag is set; NULL returns NULL | Synthetic block, second call is idempotent, zero fields stay zero, live PEB block returned untouched |
| RtlOsDeploymentState | decomp 0x101fb0: returns 1 (standard) unless a registry flag selects 2 (compact) | Value in {1, 2}, stable across calls (SKU dependent, so no single value is asserted) |
| RtlRetrieveNtUserPfn | decomp 0x8c230: after user32 initialised the three user-callback table pointers inside ntdll | After loading user32: status 0, three non-NULL pointers inside ntdll's image, repeatable |

Not tested (see the report): RtlRaiseExceptionForReturnAddressHijack. The routine unbalances the stack
(`sub rsp,0xd0 ... add rsp,0xc8; ret`) and the exception it raises (0x80000033) faults inside ntdll's dispatcher
when raised from user code, so it can only be driven by the kernel's return-address hijack detection.
