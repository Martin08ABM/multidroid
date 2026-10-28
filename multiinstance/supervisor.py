"""Review candidate for a privileged one-shot helper supervisor.

Not wired to D-Bus or the service. Incomplete or stopped resources remain
blocked until policy and sandbox recovery have been independently verified.
"""
import os
from pathlib import Path
import subprocess
import threading

from multiinstance.binder import configure_private_access
from multiinstance.bpf_policy import install_policy
from multiinstance.cgroup_anchor import SupervisorSession
from multiinstance.privileged import ProtectedStore, SecurityError, _DIR_FLAGS, _open_fixed_anchor, _path_from_fd


class SupervisorCandidate:
    """Synchronous internal launcher; do not enable as a production backend."""
    def __init__(self, store):
        if not isinstance(store, ProtectedStore):
            raise TypeError("protected system store is required")
        store._require_system_recovery_store()
        self.store = store
        self.session = SupervisorSession()
        self.lock = threading.Lock()

    def start(self, identifier, caller_uid, *, persistent=False):
        """Return a one-shot process; journal all resources before releasing it.

        On any failure, close the gate and retain the journals. No resource is
        signalled, unmounted or removed by the error path.
        """
        with self.lock:
            self.session.verify()
            intent = self.store.prepare_helper(identifier, caller_uid)
            cg = binder = sandbox_fd = program = gate_r = gate_w = None
            proc = None
            try:
                os.mkdir(intent["cgroup_name"], dir_fd=self.session.cgroup)
                cg = os.open(intent["cgroup_name"], _DIR_FLAGS, dir_fd=self.session.cgroup)
                self.store.remember_helper_cgroup(identifier, caller_uid, self.session.cgroup, cg)
                target = str(Path(_path_from_fd(self.store.binder_fd)) / identifier)
                configure_private_access(target, intent["gid"])
                binder = os.open(identifier, _DIR_FLAGS, dir_fd=self.store.binder_fd)
                devices = []
                for name in ("binder", "hwbinder", "vndbinder"):
                    info = os.stat(name, dir_fd=binder, follow_symlinks=False)
                    devices.append((os.major(info.st_rdev), os.minor(info.st_rdev)))
                runtime = _open_fixed_anchor("/run/waydroid-multi")
                try:
                    sandbox_name = "sandbox-" + identifier + "-" + intent["generation"]
                    os.mkdir(sandbox_name, 0o700, dir_fd=runtime)
                    sandbox_fd = os.open(sandbox_name, _DIR_FLAGS, dir_fd=runtime)
                finally:
                    os.close(runtime)
                self.store.record_helper_sandbox(identifier, caller_uid, self.session, sandbox_fd)
                program, _ = install_policy(cg, devices)
                self.store.record_helper_policy(identifier, caller_uid, self.session, cg, program)
                gate_r, gate_w = os.pipe2(os.O_CLOEXEC)
                sandbox = "/run/waydroid-multi/" + sandbox_name
                proc = subprocess.Popen(["/usr/bin/python3", "-B", "-I",
                                         "/usr/lib/waydroid-multi/waydroid-helper-launcher.py",
                                         str(gate_r), str(binder), str(intent["uid"]), str(intent["gid"]), sandbox] +
                                        (["--persistent"] if persistent else []),
                                        stdin=subprocess.PIPE if persistent else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        close_fds=True, pass_fds=(gate_r, binder), cwd="/",
                                        env={"PATH": "/usr/bin:/bin", "LANG": "C"})
                os.close(gate_r); gate_r = None
                fd = os.open("cgroup.procs", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=cg)
                try:
                    data = str(proc.pid).encode()
                    if os.write(fd, data) != len(data):
                        raise SecurityError("short write moving helper")
                finally:
                    os.close(fd)
                self.store.remember_helper_process(identifier, caller_uid, self.session.cgroup, cg, proc.pid)
                self.store.verify_helper_policy(identifier, caller_uid, self.session, cg, program)
                self.store.verify_helper_sandbox(identifier, caller_uid, self.session, sandbox_fd)
                pidfd = self.store.observe_helper_pidfd(identifier, caller_uid)
                try:
                    members_fd = os.open("cgroup.procs", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=cg)
                    try:
                        members = os.read(members_fd, 1024 * 1024 + 1)
                    finally:
                        os.close(members_fd)
                    if (len(members) > 1024 * 1024 or str(proc.pid).encode() not in members.splitlines() or
                            proc.poll() is not None):
                        raise SecurityError("helper left its verified cgroup or exited")
                finally:
                    os.close(pidfd)
                self.session.verify()
                if os.write(gate_w, b"G") != 1:
                    raise SecurityError("helper gate failed")
                os.close(gate_w); gate_w = None
                return proc
            except BaseException:
                if gate_w is not None:
                    os.close(gate_w); gate_w = None
                if proc is not None:
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass  # Ambiguous process and journals are retained.
                raise
            finally:
                for fd in (gate_r, gate_w, program, sandbox_fd, binder, cg):
                    if fd is not None:
                        os.close(fd)

    def close(self):
        self.session.close()
