"""Strict prospective systemd cgroup anchor and supervisor lease.

These primitives do not launch helpers, validate BPF or authorize cleanup.
The production service does not yet use them.
"""
import fcntl
import os
import subprocess

from multiinstance.privileged import (_CGROUP2_MAGIC, _TMPFS_MAGIC, _FILE_FLAGS, SecurityError,
                                      _check, _filesystem_type, _open_fixed_anchor, _path_from_fd)

SERVICE_CGROUP = "/system.slice/waydroid-multi-container.service"


def open_system_service_cgroup():
    """Open only the manager's fixed systemd service cgroup, not a client path."""
    if os.geteuid() != 0:
        raise PermissionError("system cgroup anchor requires root")
    fd = _open_fixed_anchor("/sys/fs/cgroup" + SERVICE_CGROUP)
    try:
        if _filesystem_type(fd) != _CGROUP2_MAGIC:
            raise SecurityError("service anchor is not cgroup v2")
        with open("/proc/self/cgroup", encoding="ascii") as file:
            paths = [line.rstrip("\n")[3:] for line in file if line.startswith("0::")]
        if paths != [SERVICE_CGROUP]:
            raise SecurityError("manager is not in its expected service cgroup")
        result = subprocess.run(["/usr/bin/systemctl", "--system", "show", "waydroid-multi-container.service",
                                 "--property=Delegate", "--value"], capture_output=True, text=True,
                                timeout=5, check=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        if result.stdout.strip() != "yes":
            raise SecurityError("systemd did not delegate the manager cgroup")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _lease_at(runtime_fd, uid, gid):
    """Internal helper: caller must first verify its fixed runtime anchor."""
    _check(runtime_fd, uid, gid, 0o700)
    fd = os.open("supervisor.lock", os.O_RDWR | os.O_CREAT | _FILE_FLAGS, 0o600, dir_fd=runtime_fd)
    try:
        _check(fd, uid, gid, 0o600, directory=False)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        opened = os.fstat(fd)
        entry = os.stat("supervisor.lock", dir_fd=runtime_fd, follow_symlinks=False)
        if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
            raise SecurityError("supervisor lease path changed")
        return fd
    except BaseException:
        os.close(fd)
        raise


def acquire_system_supervisor_lease():
    """Lock a root-only fixed runtime; hold FD for the entire supervisor life."""
    if os.geteuid() != 0:
        raise PermissionError("system supervisor lease requires root")
    runtime = _open_fixed_anchor("/run/waydroid-multi")
    try:
        if _path_from_fd(runtime) != "/run/waydroid-multi":
            raise SecurityError("runtime anchor changed")
        run = _open_fixed_anchor("/run")
        try:
            if (_filesystem_type(runtime) != _TMPFS_MAGIC or
                    os.fstat(runtime).st_dev != os.fstat(run).st_dev):
                raise SecurityError("runtime is not on the expected tmpfs")
        finally:
            os.close(run)
        return _lease_at(runtime, 0, 0)
    finally:
        os.close(runtime)


class SupervisorSession:
    """Pin the cooperative lease and systemd anchor for one manager process."""
    def __init__(self):
        self.pid = os.getpid()
        self.lease = acquire_system_supervisor_lease()
        try:
            self.cgroup = open_system_service_cgroup()
        except BaseException:
            os.close(self.lease)
            raise

    def verify(self):
        if os.getpid() != self.pid or self.lease is None or self.cgroup is None:
            raise SecurityError("supervisor lease is not owned by this process")
        runtime = _open_fixed_anchor("/run/waydroid-multi")
        try:
            _check(runtime, 0, 0, 0o700)
            _check(self.lease, 0, 0, 0o600, directory=False)
            run = _open_fixed_anchor("/run")
            try:
                if (_path_from_fd(runtime) != "/run/waydroid-multi" or
                        _filesystem_type(runtime) != _TMPFS_MAGIC or
                        os.fstat(runtime).st_dev != os.fstat(run).st_dev):
                    raise SecurityError("supervisor runtime anchor changed")
            finally:
                os.close(run)
            lease = os.fstat(self.lease)
            entry = os.stat("supervisor.lock", dir_fd=runtime, follow_symlinks=False)
            if (entry.st_dev, entry.st_ino) != (lease.st_dev, lease.st_ino):
                raise SecurityError("supervisor lease was replaced")
            fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(runtime)
        current = open_system_service_cgroup()
        try:
            pinned, observed = os.fstat(self.cgroup), os.fstat(current)
            if (pinned.st_dev, pinned.st_ino) != (observed.st_dev, observed.st_ino):
                raise SecurityError("delegated cgroup anchor changed")
        finally:
            os.close(current)

    def close(self):
        if os.getpid() != self.pid:
            raise SecurityError("forked child cannot manage supervisor session")
        for name in ("cgroup", "lease"):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)
