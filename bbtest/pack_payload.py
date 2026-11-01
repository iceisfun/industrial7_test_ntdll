#!/usr/bin/env python3
"""Pack the ntdll corpus build for the queue and for win10vm.sh.

  pack_payload.py artifact --build-dir build [--out DIR]
      Deterministic ntdll-build.tar (build/<area>.exe, sorted, mtime 0, owner
      0) plus build-manifest.txt (sha256, size, name) in DIR
      (default $BBTEST_OUT_DIR). Fails unless every expected area has an exe.

  pack_payload.py payload --build build|ntdll-build.tar --mode std|admin --out DIR
      Stage DIR for `win10vm.sh run --payload DIR --shutdown`: build/*.exe,
      runner.ps1, run.cmd (CRLF unless --eol lf), payload.manifest. win10vm.sh
      mounts DIR as \\i7run\\ and runs run.cmd at logon; run.cmd drives
      runner.ps1, which prints the `I7RES` framing on COM1.

Stdlib only.
"""
import argparse
import hashlib
import io
import os
import shutil
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))

RUN_CMD = (
    "@echo off\n"
    "mode COM1:115200,n,8,1 >nul\n"
    "mkdir C:\\i7 2>nul\n"
    'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass '
    '-File "%~dp0runner.ps1" -Mode {mode} >COM1 2>&1\n'
    "exit /b 0\n"
)


def expected_areas():
    with open(os.path.join(HERE, "areas.txt")) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def collect_exes(build_dir, areas):
    exes = {}
    for n in sorted(os.listdir(build_dir)):
        if n.endswith(".exe"):
            with open(os.path.join(build_dir, n), "rb") as f:
                exes[n] = f.read()
    want = {a + ".exe" for a in areas}
    missing = sorted(want - set(exes))
    extra = sorted(set(exes) - want)
    if missing:
        raise SystemExit("missing exes: " + ", ".join(missing))
    if extra:
        raise SystemExit("unexpected exes (update areas.txt): " + ", ".join(extra))
    return exes


def make_tar(exes):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        for n in sorted(exes):
            ti = tarfile.TarInfo("build/" + n)
            ti.size = len(exes[n])
            ti.mtime = 0
            ti.mode = 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            t.addfile(ti, io.BytesIO(exes[n]))
    return buf.getvalue()


def manifest(exes):
    return "".join("%s  %d  %s\n" % (sha256(exes[n]), len(exes[n]), n) for n in sorted(exes))


def exes_from(src, areas):
    if os.path.isdir(src):
        return collect_exes(src, areas)
    exes = {}
    with tarfile.open(src) as t:
        for m in t.getmembers():
            if m.isfile() and m.name.startswith("build/") and m.name.endswith(".exe"):
                name = m.name[len("build/"):]
                if "/" in name or name.startswith("."):
                    raise SystemExit("bad member " + m.name)
                exes[name] = t.extractfile(m).read()
    want = {a + ".exe" for a in areas}
    if set(exes) != want:
        raise SystemExit("tar exes differ from areas.txt: missing=%s extra=%s" %
                         (sorted(want - set(exes)), sorted(set(exes) - want)))
    return exes


def cmd_artifact(a):
    exes = collect_exes(a.build_dir, expected_areas())
    out = a.out or os.environ.get("BBTEST_OUT_DIR")
    if not out:
        raise SystemExit("--out or BBTEST_OUT_DIR required")
    os.makedirs(out, exist_ok=True)
    data = make_tar(exes)
    with open(os.path.join(out, "ntdll-build.tar"), "wb") as f:
        f.write(data)
    with open(os.path.join(out, "build-manifest.txt"), "w") as f:
        f.write(manifest(exes))
    print("ntdll-build.tar sha256=%s exes=%d" % (sha256(data), len(exes)))
    return 0


def cmd_payload(a):
    exes = exes_from(a.build, expected_areas())
    mode = {"std": "std", "adm": "admin", "admin": "admin"}[a.mode]
    if os.path.exists(a.out) and os.listdir(a.out):
        raise SystemExit("--out must be empty or absent: " + a.out)
    os.makedirs(os.path.join(a.out, "build"), exist_ok=True)
    for n, b in exes.items():
        with open(os.path.join(a.out, "build", n), "wb") as f:
            f.write(b)
    shutil.copyfile(a.runner or os.path.join(HERE, "runner.ps1"), os.path.join(a.out, "runner.ps1"))
    cmd = RUN_CMD.format(mode=mode)
    if a.eol == "crlf":
        cmd = cmd.replace("\n", "\r\n")
    with open(os.path.join(a.out, "run.cmd"), "wb") as f:
        f.write(cmd.encode("ascii"))
    with open(os.path.join(a.out, "runner.ps1"), "rb") as f:
        rsha = sha256(f.read())
    with open(os.path.join(a.out, "payload.manifest"), "w") as f:
        f.write("# mode=%s eol=%s runner.ps1=%s\n" % (mode, a.eol, rsha))
        f.write(manifest(exes))
    print("payload %s mode=%s exes=%d runner.ps1 sha256=%s" % (a.out, mode, len(exes), rsha))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    s = p.add_subparsers(dest="cmd", required=True)
    x = s.add_parser("artifact")
    x.add_argument("--build-dir", default="build")
    x.add_argument("--out")
    x.set_defaults(fn=cmd_artifact)
    y = s.add_parser("payload")
    y.add_argument("--build", required=True, help="build dir or ntdll-build.tar")
    y.add_argument("--mode", required=True, choices=["std", "adm", "admin"])
    y.add_argument("--out", required=True)
    y.add_argument("--runner", help="runner.ps1 (default: the one next to this script)")
    y.add_argument("--eol", choices=["crlf", "lf"], default="crlf")
    y.set_defaults(fn=cmd_payload)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
