#!/usr/bin/env python3
"""Tests scripts/verify-image-arch.py against a stub `docker` (no daemon needed)."""
import os, stat, subprocess, sys, tempfile, textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "verify-image-arch.py")
fails = 0

def elf(machine):
    return b"\x7fELF\x02\x01\x01" + b"\0" * 11 + machine.to_bytes(2, "little") + b"\0" * 40

def run(cfg_arch, file_arch, expect_rc, label, psutil_so=True):
    global fails
    with tempfile.TemporaryDirectory() as td:
        stub = os.path.join(td, "docker")
        with open(stub, "w") as f:
            f.write(textwrap.dedent(f"""\
                #!/usr/bin/env python3
                import sys, os
                a = sys.argv[1:]
                E = {elf(file_arch)!r}
                if a[0] == "image": print("{cfg_arch}")
                elif a[0] == "create": print("cid1")
                elif a[0] == "cp":
                    src, dst = a[-2], a[-1]
                    if src.endswith("/psutil"):
                        os.makedirs(dst)
                        if {psutil_so!r}: open(os.path.join(dst, "_psutil_linux.cpython-312.so"), "wb").write(E)
                    else: open(dst, "wb").write(E)
                """))
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR)
        r = subprocess.run([sys.executable, "-I", SCRIPT, "ref@sha256:x", "arm64"],
                           env={"DOCKER": stub, "PATH": os.environ["PATH"]}, capture_output=True, text=True)
        ok = r.returncode == expect_rc
        print(("ok  " if ok else "FAIL"), label, "rc=", r.returncode)
        if not ok:
            fails += 1; print(r.stdout, r.stderr)

run("arm64", 183, 0, "genuine arm64 passes")
run("arm64", 62, 1, "arm64-labelled x86-64 binaries (the 2026-11-19 bug) fail")
run("amd64", 183, 1, "wrong config architecture fails")
run("arm64", 183, 1, "missing compiled extension fails closed", psutil_so=False)
sys.exit(1 if fails else 0)
