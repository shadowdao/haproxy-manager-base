#!/usr/bin/env python3
"""Verify that a per-platform image really contains binaries for that platform.

CI only (not copied into images' runtime use). Usage:

    verify-image-arch.py <image-ref> <amd64|arm64>

Pulls <image-ref> (normally <repo>@sha256:<digest> of ONE platform, pushed by
digest and not yet tagged) with --platform linux/<arch>, never runs it, and
checks:
  * the image config's architecture equals <arch>;
  * the ELF e_machine of haproxy, bash, the python interpreter and every
    compiled extension of the python stack (psutil *.so) equals <arch>.

Why: 2026-11-19, haproxy-manager-base:latest carried an "arm64" entry whose
binaries were all x86-64 (the in-house python:3.12-slim base was a flattened
amd64-only manifest, so the arm64 build silently ran on an amd64 base).
Manifest/config metadata said arm64; only the ELF headers told the truth.

Exit 0 = every checked file matches; non-zero = mismatch or could not check
(fail closed). Env DOCKER overrides the docker command (tests use a stub).
"""
import os
import shlex
import struct
import subprocess
import sys
import tempfile

EM = {"amd64": 62, "arm64": 183}          # EM_X86_64, EM_AARCH64
EM_NAME = {62: "x86-64", 183: "aarch64", 40: "arm", 3: "i386"}
FILES = ["/usr/sbin/haproxy", "/bin/bash", "/usr/local/bin/python3.12"]
EXT_DIR = "/usr/local/lib/python3.12/site-packages/psutil"   # compiled (_psutil_linux*.so)


def elf_machine(path):
    """e_machine of an ELF file, or None if it is not a little-endian ELF."""
    with open(path, "rb") as f:
        h = f.read(20)
    if len(h) < 20 or h[:4] != b"\x7fELF":
        return None
    endian = "<" if h[5] == 1 else ">"
    return struct.unpack(endian + "H", h[18:20])[0]


def docker(*args, check=True):
    cmd = shlex.split(os.environ.get("DOCKER", "docker")) + list(args)
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def main(argv):
    if len(argv) != 3 or argv[2] not in EM:
        print("usage: verify-image-arch.py <image-ref> <amd64|arm64>", file=sys.stderr)
        return 2
    ref, arch = argv[1], argv[2]
    want = EM[arch]
    bad = []
    docker("pull", "--quiet", "--platform", f"linux/{arch}", ref)
    cfg = docker("image", "inspect", ref, "--format", "{{.Architecture}}").stdout.strip()
    print(f"{ref}: image config architecture={cfg} (expected {arch})")
    if cfg != arch:
        bad.append(f"config architecture {cfg!r}")
    cid = docker("create", "--platform", f"linux/{arch}", ref).stdout.strip()
    try:
        with tempfile.TemporaryDirectory() as td:
            for f in FILES:
                dst = os.path.join(td, os.path.basename(f))
                docker("cp", "-L", f"{cid}:{f}", dst)
                m = elf_machine(dst)
                print(f"  {f}: {EM_NAME.get(m, m)}")
                if m != want:
                    bad.append(f"{f} is {EM_NAME.get(m, m)}")
            extdir = os.path.join(td, "psutil")
            docker("cp", f"{cid}:{EXT_DIR}", extdir)
            sos = sorted(os.path.join(extdir, n) for n in os.listdir(extdir) if n.endswith(".so"))
            if not sos:
                bad.append(f"no compiled extension found in {EXT_DIR}")
            for so in sos:
                m = elf_machine(so)
                print(f"  psutil/{os.path.basename(so)}: {EM_NAME.get(m, m)}")
                if m != want:
                    bad.append(f"psutil/{os.path.basename(so)} is {EM_NAME.get(m, m)}")
    finally:
        docker("rm", cid, check=False)
    if bad:
        print(f"::error::{ref} is labelled linux/{arch} but: " + "; ".join(bad), file=sys.stderr)
        return 1
    print(f"OK: {ref} is genuinely {arch}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
