# Worker factory objects

Reference: Windows 10 22H2 ntdll 10.0.19041.2788; system-call stubs (Nt/Zw share an RVA). The thread pool code in ntdll
calls NtSetInformationWorkerFactory with the same classes (decompilation of TpSetPoolMinThreads, TpSetPoolMaxThreads,
TpSetPoolStackInformation, TpSetPoolThreadBasePriority, TpSetPoolWorkerThreadIdleTimeout, TpSetPoolThreadCpuSets,
TpTrimPools), which fixes the class numbering. Statuses were observed on the Windows 10 guest (admin and standard user).

| Check | Source |
| --- | --- |
| Create on a private I/O completion port with ThreadMaximum 4, start routine and parameter; BasicInformation (class 7, 120 bytes) returns exactly those, ThreadMinimum 0, Shutdown 0, TotalWorkerCount 0, BindingCount 0, ProcessId = this process | observed |
| Create: NULL out handle 0xC0000005; NULL port or NULL process 0xC0000008; event as port or process 0xC0000024; max threads 0, NULL start routine, commit > reserve and a second factory on the same port are accepted | observed |
| Query: only class 7 is supported (all other classes 0xC0000003); short buffer 0xC0000004 with return length 120; NULL buffer 0xC0000005; NULL return length accepted | observed |
| Set: ULONG classes 3,4,5,8,11,12,13,14 accept exactly 4 bytes (other lengths 0xC0000004); class 2 idle timeout takes an 8-byte negative value (positive -> 0xC000000D, length 4 -> 0xC0000004) and is reflected in BasicInformation; class 10 stack information takes 16 bytes and is reflected; class 6 (paused) 0xC0000002 for every length; classes 0,1,7,16+ 0xC0000003; min/max reflected in BasicInformation; NULL buffer 0xC0000005 | observed |
| NtWorkerFactoryWorkerReady: bad handle 0xC0000008, wrong type 0xC0000024, no worker registered 0xC0000001 | observed |
| NtReleaseWorkerFactoryWorker on a factory with a start routine creates a worker: the start routine runs with the start parameter | observed |
| Shutdown: bad handle / wrong type errors; after a successful shutdown BasicInformation.Shutdown is 1; a second shutdown returns 0 | observed |
| NtWaitForWorkViaWorkerFactory with NULL arguments returns 0xC000000D (only argument validation is reachable from a non-worker thread; success path not tested; observed 0xC000000D for NULL handle and wrong type, logged only, not asserted) | observed (not asserted) |

The pending-count output of NtShutdownWorkerFactory, ReleaseWorkerFactoryWorker after shutdown (0x80) and the class 15 (CPU sets)
and class 9 values are not asserted: they depend on internal worker state or hardware.
