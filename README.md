# ntdll.dll conformance tests (Windows 10 x64)

A corpus of black-box C tests for the user-mode behaviour of `ntdll.dll` on 64-bit Windows 10. The expectations come from public documentation and from behaviour observed on Windows 10 22H2 (build 19045, ntdll 10.0.19041.2788). Windows is the reference: a test that fails on a genuine Windows 10 installation is a bug in the test.

Every function under test is resolved at run time with `GetModuleHandle`/`LoadLibrary` and `GetProcAddress` and called through a typed pointer, so the executables do not import ntdll directly. `U(Name)` searches ntdll only; `UIN("module.dll", Name)` pins a module; `UN(Name)` is used for exports that are not declared in the SDK headers (a local typedef is supplied through `UDECL`). Ordinary CRT and kernel32 calls build fixtures and implement the harness.

## Layout

- `tests/<area>/*.c` - one executable per area, built to `build/<area>.exe`. Areas cover Rtl string, path, conversion, numeric, bitmap, table, heap, memory, security, sync, time, threadpool and context helpers, Nt file, registry, process, thread, token, sync and virtual-memory calls, the loader, the C runtime exports, and the export table itself.
- `common/` - the small test harness (`t.c`, `t.h`, `modules.h`).
- `Makefile` - cross build with mingw-w64. `run_all.bat` - runs every built area on Windows.
- `COVERAGE.md` - which exports each area refers to.
- `VALIDATION.md` - results of the corpus on Windows 10 22H2.

## Build

With GNU make and `x86_64-w64-mingw32-gcc` (a Linux cross compiler, or MinGW-w64 under MSYS2 on Windows):

    make -j8                    # build/<area>.exe for every area
    make build/rtl_strings.exe  # a single area

MSVC is not supported: the harness uses GNU C extensions (`__typeof__`, `__attribute__((constructor))`).

## Run on Windows 10

Copy `build\` and `run_all.bat` to a Windows 10 x64 machine (use a disposable VM or a snapshot; some tests create and delete files, registry keys and kernel objects under temporary names) and run:

    run_all.bat              rem all areas, results in results\<area>.txt
    build\rtl_strings.exe    rem one area
    build\rtl_strings.exe utf8   rem only tests whose name contains "utf8"

Run once as a standard user and once elevated; a few tests skip when a privilege is missing.

## Result format

Each executable prints `RUN  <name>` before each test and `OK   <name>`, `FAIL <name>` or `SKIP <name>` after it. Details are indented lines between the two: `  FAIL <file>:<line>: <expression> (<observed values>)`, `  SKIP <reason>` and `  NOTE <information>`. The last line is

    SUMMARY tests=N failed=N skipped=N checks_pass=N checks_fail=N

The exit code is 1 if any test failed and 0 otherwise; a missing `SUMMARY` line means the process crashed or hung. A `SKIP` means a prerequisite was not available (for example a privilege or a writable namespace). `NOTE` lines record values that vary between Windows versions and are informational only.

## Reading a failure

Check the failing line first: tests check documented status codes, output sizes and buffer contents, and print both the expected and observed values. A difference on a Windows 10 build other than 22H2, a different locale, or an unusual security configuration is a candidate environment difference rather than a defect; behaviour that differs from documentation on 22H2 is worth reporting with the output of the failing test.
