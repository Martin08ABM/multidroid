"""Explicit administrator-reserved helper identities; never derived from clients."""
from dataclasses import dataclass


@dataclass(frozen=True)
class IdentityPool:
    uid_start: int
    gid_start: int
    count: int

    def __post_init__(self):
        if any(type(v) is not int for v in (self.uid_start, self.gid_start, self.count)):
            raise ValueError("identity pool values must be integers")
        if not 1 <= self.count <= 64 or min(self.uid_start, self.gid_start) <= 0:
            raise ValueError("invalid identity pool")
        if max(self.uid_start, self.gid_start) + self.count >= 2**32 - 1:
            raise ValueError("identity pool overflows")

    def at(self, index):
        if type(index) is not int or not 0 <= index < self.count:
            raise ValueError("invalid identity index")
        return self.uid_start + index, self.gid_start + index

    def index(self, uid, gid):
        if type(uid) is not int or type(gid) is not int:
            raise ValueError("identity values must be integers")
        index = uid - self.uid_start
        if not 0 <= index < self.count or gid != self.gid_start + index:
            raise ValueError("identity is outside configured pool")
        return index


def binder_device_rules(nodes):
    """Create an isolated cgroup v2 allowlist for just three Binder devices.

    This is a fragment for a future container, not a complete Android device
    policy. Do not use until the remaining required devices are enumerated.
    """
    import os
    import stat
    values = []
    for node in nodes:
        info = os.stat(node, follow_symlinks=False)
        if not stat.S_ISCHR(info.st_mode):
            raise ValueError("not a character device")
        values.append((os.major(info.st_rdev), os.minor(info.st_rdev)))
    if len(values) != 3 or len(set(values)) != 3:
        raise ValueError("expected three distinct Binder devices")
    return ["lxc.cgroup2.devices.deny = a"] + [
        f"lxc.cgroup2.devices.allow = c {major}:{minor} rw" for major, minor in values
    ]
