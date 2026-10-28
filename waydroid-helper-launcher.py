#!/usr/bin/env python3
"""Internal one-shot gate; the manager must install BPF before releasing it."""
import os
import re
import sys


def main():
    if os.geteuid() != 0 or len(sys.argv) not in (6, 7) or (len(sys.argv) == 7 and sys.argv[6] != "--persistent"):
        raise PermissionError("internal root-only launcher")
    gate, binder, uid, gid = (int(value) for value in sys.argv[1:5])
    sandbox = sys.argv[5]
    if (min(gate, binder, uid, gid) <= 0 or
            not re.fullmatch(r"/run/waydroid-multi/sandbox-[0-9a-f]{32}-[0-9a-f]{32}", sandbox)):
        raise ValueError("invalid internal launcher arguments")
    if os.read(gate, 1) != b"G":
        raise PermissionError("supervisor did not release helper")
    os.close(gate)
    os.set_inheritable(binder, True)
    os.execv("/usr/bin/python3", ["/usr/bin/python3", "-B", "-I",
                                  "/usr/lib/waydroid-multi/waydroid-binder-helper.py",
                                  str(binder), str(uid), str(gid), sandbox] + sys.argv[6:])


if __name__ == "__main__":
    main()
