"""Minimal Binder allocation primitive for a separately mounted binderfs.

This is not wired to the runtime. The caller must mount, verify ownership and
filesystem type, authorize access, and dispose of its own mount on failure.
"""
import fcntl
import ctypes
import os
from pathlib import Path
import stat
import struct

# _IOWR('b', 1, struct binderfs_device), fixed-size Linux UAPI structure.
BINDER_CTL_ADD = (3 << 30) | (264 << 16) | (ord("b") << 8) | 1
BINDER_NAMES = ("binder", "hwbinder", "vndbinder")
BINDERFS_MAGIC = 0x6c6f6f70


def allocate_nodes(mountpoint):
    """Allocate three new nodes. An existing name is an error, never reused."""
    control = Path(mountpoint) / "binder-control"
    fd = os.open(control, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if not stat.S_ISCHR(os.fstat(fd).st_mode):
            raise ValueError("binder-control must be a character device")
        for name in BINDER_NAMES:
            fcntl.ioctl(fd, BINDER_CTL_ADD, struct.pack("256sII", name.encode("ascii"), 0, 0))
    finally:
        os.close(fd)
    return tuple(Path(mountpoint) / name for name in BINDER_NAMES)


def initialize_fresh_nodes(mountpoint):
    """Use kernel-created defaults or allocate them on a verified fresh mount.

    Some kernels populate binderfs from CONFIG_ANDROID_BINDER_DEVICES. The
    caller must have created and verified this mount; this function cannot
    establish ownership or trust of an arbitrary existing mount.
    """
    paths = tuple(Path(mountpoint) / name for name in BINDER_NAMES)
    present = [os.path.lexists(path) for path in paths]
    if any(present) and not all(present):
        raise ValueError("partially populated binderfs")
    if not any(present):
        allocate_nodes(mountpoint)
    devices = []
    for path in paths:
        info = os.lstat(path)
        if not stat.S_ISCHR(info.st_mode):
            raise ValueError(f"not a Binder character device: {path}")
        devices.append(info.st_rdev)
    if len(set(devices)) != len(paths):
        raise ValueError("Binder device numbers are not distinct")
    return paths


def configure_private_access(mountpoint, group_id):
    """Configure a root-created, verified private mount for one dedicated group.

    The caller must allocate a group exclusively to the instance, verify the
    mount's recorded identity, and keep the host ancestor root-only. Not wired
    to the service until group provisioning and helper isolation exist.
    """
    if os.geteuid() != 0:
        raise PermissionError("root is required")
    if type(group_id) is not int or group_id <= 0 or group_id >= 2**32 - 1:
        raise ValueError("a dedicated non-root group is required")
    fd = os.open(mountpoint, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        buf = ctypes.create_string_buffer(256)
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.fstatfs(fd, ctypes.byref(buf)) != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        if ctypes.c_ulong.from_buffer(buf).value != BINDERFS_MAGIC:
            raise ValueError("not binderfs")
        info = os.fstat(fd)
        if info.st_uid != 0:
            raise ValueError("binderfs must be owned by root")
        nodes = [os.stat(name, dir_fd=fd, follow_symlinks=False) for name in BINDER_NAMES]
        if not all(stat.S_ISCHR(node.st_mode) and node.st_uid == 0 for node in nodes):
            raise ValueError("Binder nodes must be root-owned character devices")
        if len({node.st_rdev for node in nodes}) != len(nodes):
            raise ValueError("Binder device numbers are not distinct")
        control = os.stat("binder-control", dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISCHR(control.st_mode) or control.st_uid != 0:
            raise ValueError("binder-control must be a root-owned character device")
        for name in BINDER_NAMES:
            os.chown(name, 0, 0, dir_fd=fd, follow_symlinks=False)
            os.chmod(name, 0o666, dir_fd=fd, follow_symlinks=False)
        os.chown("binder-control", 0, 0, dir_fd=fd, follow_symlinks=False)
        os.chmod("binder-control", 0o600, dir_fd=fd, follow_symlinks=False)
        os.fchown(fd, 0, group_id)
        os.fchmod(fd, 0o710)
    finally:
        os.close(fd)
