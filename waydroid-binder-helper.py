#!/usr/bin/env python3
"""Isolated Binder probe; persistent mode is experimental and not exposed by D-Bus."""
import ctypes
import fcntl
import json
import os
from pathlib import Path
import stat
import sys

import gbinder

NAMES = ("binder", "hwbinder", "vndbinder")
CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWNET = 0x40000000
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_NOSUID = 2
MS_NOEXEC = 8
PR_SET_DUMPABLE = 4
PR_SET_KEEPCAPS = 8
PR_SET_NO_NEW_PRIVS = 38
PR_GET_DUMPABLE = 3
PR_GET_NO_NEW_PRIVS = 39


class CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]


def call(function, *args):
    libc = ctypes.CDLL(None, use_errno=True)
    if getattr(libc, function)(*args) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def mount(source, target, filesystem, flags, data=None):
    encode = lambda value: None if value is None else os.fsencode(value)
    call("mount", encode(source), encode(target), encode(filesystem), ctypes.c_ulong(flags), encode(data))


def serve(report, commands):
    """Tiny internal protocol; EOF terminates instead of adopting an orphan."""
    while True:
        command = commands.readline(16)
        if command == b"ping\n":
            report()
        elif command in (b"stop\n", b""):
            return
        else:
            raise ValueError("invalid helper command")


def main():
    if os.geteuid() != 0 or len(sys.argv) not in (5, 6) or (len(sys.argv) == 6 and sys.argv[5] != "--persistent"):
        raise PermissionError("root and valid internal arguments are required")
    persistent = len(sys.argv) == 6
    binder_fd, uid, gid = (int(value) for value in sys.argv[1:4])
    sandbox = sys.argv[4]
    if min(uid, gid) <= 0 or not os.path.isabs(sandbox) or not stat.S_ISDIR(os.fstat(binder_fd).st_mode):
        raise ValueError("invalid helper arguments")
    source_root = os.readlink(f"/proc/self/fd/{binder_fd}")
    if not source_root.startswith("/") or source_root.endswith(" (deleted)"):
        raise ValueError("invalid Binder directory")
    call("unshare", CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET)
    mount(None, "/", None, MS_REC | MS_PRIVATE)
    held, visible = os.fstat(binder_fd), os.stat(source_root, follow_symlinks=False)
    if (held.st_dev, held.st_ino) != (visible.st_dev, visible.st_ino):
        raise ValueError("Binder directory changed")
    mount("tmpfs", sandbox, "tmpfs", MS_NOSUID | MS_NOEXEC, "size=4m,mode=0755")
    dev = Path(sandbox) / "dev"
    dev.mkdir(mode=0o755)
    for name in NAMES:
        target = dev / name
        target.touch(mode=0o600)
        mount(str(Path(source_root) / name), str(target), None, MS_BIND)
    os.close(binder_fd)
    # subprocess closes inherited FDs except binder_fd; also close any FDs
    # opened by library imports before dropping privileges and chrooting.
    for entry in os.listdir("/proc/self/fd"):
        if entry.isdigit() and int(entry) > 2:
            try:
                os.close(int(entry))
            except OSError:
                pass
    os.chdir(sandbox)
    os.chroot(".")
    os.chdir("/")
    call("prctl", PR_SET_KEEPCAPS, 0, 0, 0, 0)
    call("prctl", PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    call("prctl", PR_SET_DUMPABLE, 0, 0, 0, 0)
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid) or os.getgroups():
        raise PermissionError("credentials did not drop completely")
    libc = ctypes.CDLL(None, use_errno=True)
    header, capabilities = CapHeader(0x20080522, 0), (CapData * 2)()
    if libc.capget(ctypes.byref(header), ctypes.byref(capabilities)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    privileges_dropped = (all(not (item.effective or item.permitted or item.inheritable) for item in capabilities) and
                          libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 and
                          libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0)
    if not privileges_dropped:
        raise PermissionError("helper still has privileges or is dumpable")
    service = gbinder.ServiceManager("/dev/binder")
    def report():
        devices = {}
        for name in NAMES:
            fd = os.open("/dev/" + name, os.O_RDWR | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                if not stat.S_ISCHR(info.st_mode):
                    raise ValueError("not a character device")
                protocol = bytearray(4)
                fcntl.ioctl(fd, 0xC0046209, protocol, True)
                devices[name] = {"major": os.major(info.st_rdev), "minor": os.minor(info.st_rdev),
                                 "protocol": int.from_bytes(protocol, sys.byteorder, signed=True)}
            finally:
                os.close(fd)
        print(json.dumps({"uid": uid, "gid": gid, "devices": devices, "gbinder": bool(service),
                          "privileges_dropped": privileges_dropped,
                          "control_visible": os.path.exists("/dev/binder-control"),
                          "host_etc_visible": os.path.exists("/etc/passwd")}), flush=True)
    report()
    if persistent:
        serve(report, sys.stdin.buffer)
    return service


if __name__ == "__main__":
    main()
