# nt_other_2_b_obj evidence

Oracle: Windows 10 22H2 (ntdll 10.0.19041), x64, run as administrator and as a standard user (identical results).
Every Zw name is called directly; the Nt/Zw alias relationship (identical address) is asserted in `alias_pairs`.
The Corpus Explorer decompilation of all these exports is a bare system-call stub, so argument-validation
orders and status codes come from public documentation plus observation on the Windows 10 guest.

| Test | Expected values and source |
|---|---|
| atoms | Atom values >= 0xC000, reference counted (add twice, delete twice), case-insensitive find (documented RtlAtom behaviour; observed). Deleted atom: find -> STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034, delete -> STATUS_INVALID_HANDLE 0xC0000008 (observed). Zero length -> STATUS_OBJECT_NAME_INVALID 0xC0000033, NULL name -> STATUS_INVALID_PARAMETER (observed). |
| atom_ex | Flags 0 behaves as ZwAddAtom; flags 0x80000000 -> STATUS_INVALID_PARAMETER (observed). |
| luid_uuid | LUIDs strictly increase and are non-zero (documented). ZwAllocateUuids: non-zero time and range, seed constant between calls (observed). NULL pointers -> STATUS_ACCESS_VIOLATION from the probe. |
| virtual_memory(_ex) | Size rounded to pages (0x1800 -> 0x2000), fresh commit is zero, zero size / bad protection (0x3 -> STATUS_INVALID_PAGE_PROTECTION 0xC0000045) / zero allocation type / ZeroBits 63 -> STATUS_INVALID_PARAMETER, bad process handle -> STATUS_INVALID_HANDLE. Ex with ExtendedParameterCount 3 and a NULL array -> STATUS_INVALID_PARAMETER. All observed. |
| close_dup_compare | Duplicate shares the object; DUPLICATE_CLOSE_SOURCE closes the source; reduced access (SYNCHRONIZE) denies SetEvent (ERROR_ACCESS_DENIED). ZwCompareObjects: same object -> 0, different -> STATUS_NOT_SAME_OBJECT 0xC00001AC, bad handle -> STATUS_INVALID_HANDLE. Closing twice / NULL / junk -> STATUS_INVALID_HANDLE (no debugger attached). |
| clear_event | Clears a signalled notification event; a semaphore -> STATUS_OBJECT_TYPE_MISMATCH; a handle without EVENT_MODIFY_STATE -> STATUS_ACCESS_DENIED. |
| cancel_timer | The BOOLEAN output is the timer's **signalled** state, not "was pending": 0 for a freshly set pending timer, 1 after expiry (observed; contrary to the common reading of the header). Optional pointer may be NULL; event handle -> type mismatch; bad output pointer -> access violation. |
| cancel_timer2 | NtCreateTimer2 timer: cancel with zeroed parameters and with NULL -> 0; NULL handle -> STATUS_INVALID_HANDLE (observed). |
| delay_execution | Relative 50 ms waits >= 40 ms; zero interval returns 0 or STATUS_YIELD_EXECUTION 0x40000024 (observed both; success-class statuses); absolute time in the past returns promptly; an alertable delay with a queued user APC returns STATUS_USER_APC 0xC0 and runs the APC; NULL interval -> access violation. |
| alert_thread | A thread in an alertable delay returns STATUS_ALERTED 0x101; NULL -> invalid handle, event -> type mismatch. |
| alert_resume_thread | Previous suspend count 1 for a CREATE_SUSPENDED thread, 0 for a running one; the second call alerts the thread's wait. The alert issued while the thread was still suspended is NOT retained (observed: the thread only returned after the second alert). |
| alert_by_thread_id | Timeout 0x102 without an alert; alert on the own thread id then wait -> STATUS_ALERTED, and the alert is consumed; bogus id -> STATUS_INVALID_CID 0xC000000B (observed). |
| reserve_object | Types 0 and 1 give a closable handle, type 2 -> STATUS_INVALID_PARAMETER, NULL output -> access violation (observed). |
| mapped_files_same | Same image / two addresses inside one image -> 0; different images -> STATUS_NOT_SAME_DEVICE 0xC00000D4; private memory vs image -> STATUS_CONFLICTING_ADDRESSES 0xC0000018 (observed). |

Skips: only for missing exports (REQUIRE). No privilege-dependent behaviour is exercised.
