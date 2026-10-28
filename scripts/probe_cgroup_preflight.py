#!/usr/bin/env python3
"""Read-only BPF capability probe plus a disposable delegated child cgroup.

This never attaches a program or starts a helper. Run only as an unprivileged
host user; namespace root must not map to host root.
"""
import ctypes
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile
import uuid


def load_probe():
    if platform.machine() != "x86_64":
        return {"attempted": False, "reason": "syscall number only defined for x86_64"}
    insns = ctypes.create_string_buffer(bytes.fromhex("b7000000010000009500000000000000"))
    license_ = ctypes.create_string_buffer(b"GPL")
    attr = ctypes.create_string_buffer(144)
    struct.pack_into("IIQQ", attr, 0, 15, 2, ctypes.addressof(insns), ctypes.addressof(license_))
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(321, 5, ctypes.byref(attr), len(attr))
    if result < 0:
        error = ctypes.get_errno()
        return {"attempted": True, "loaded": False, "errno": error, "error": os.strerror(error)}
    os.close(result)
    return {"attempted": True, "loaded": True}


def child():
    mappings = [tuple(map(int, line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
    if os.geteuid() != 0 or not mappings or any(outer == 0 for _, outer, _ in mappings):
        raise RuntimeError("refusing to run outside a user namespace without host root")
    result = {"uid_map": mappings, "bpf_load": load_probe(), "policy_tested": False}
    with tempfile.TemporaryDirectory(prefix="waydroid-cgroup-preflight-") as tmp:
        mount = subprocess.run(["mount", "-t", "cgroup2", "none", tmp], capture_output=True, text=True)
        result["mount"] = {"returncode": mount.returncode, "stderr": mount.stderr.strip()}
        if mount.returncode == 0:
            target = Path(tmp) / ("waydroid-probe-" + uuid.uuid4().hex)
            try:
                try:
                    target.mkdir()
                    result["child_created"] = True
                    query = subprocess.run(["bpftool", "cgroup", "show", str(target)], capture_output=True, text=True)
                    result["query"] = {"returncode": query.returncode, "stderr": query.stderr.strip()}
                finally:
                    if target.exists():
                        target.rmdir()
            finally:
                subprocess.run(["umount", tmp], check=True, capture_output=True)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if sys.argv[1:] == ["--child"]:
        child()
    elif len(sys.argv) == 1 and os.geteuid() != 0:
        print(json.dumps({"host_user_bpf_load": load_probe(), "policy_tested": False}), flush=True)
        subprocess.run(["unshare", "--user", "--map-root-user", "--mount", "--cgroup",
                        sys.executable, "-B", str(Path(__file__).resolve()), "--child"], check=True)
    else:
        raise SystemExit("run without arguments as an unprivileged host user")
