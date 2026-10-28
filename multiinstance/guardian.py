"""Guardian: Independent per-instance resource owner and helper supervisor.

This module implements a guardian that runs independently per instance, manages its
own lifecycle, and safely recovers resources during the same boot. It is designed
to work with the existing SupervisorSession and ProtectedStore infrastructure.

Security model:
- Never signals any process (PID reuse risk)
- Never removes a cgroup unless its recorded inode and ownership match exactly
- Never removes journals unless all recorded state matches
- Publishes an immutable cleanup journal before any removal for crash resumability
- Validates boot ID, mount namespace, cgroup namespace, PID namespace on every operation

Author: MultiDroid Team
Date: 2026-10-28
"""

import os
import logging
import subprocess
import threading
from pathlib import Path
from typing import Tuple, Optional

from multiinstance.privileged import (
    ProtectedStore, SecurityError, _DIR_FLAGS, _FILE_FLAGS, _unlink_checked
)
from multiinstance.cgroup_anchor import SupervisorSession
from multiinstance.binder import configure_private_access, initialize_fresh_nodes
from multiinstance.bpf_policy import install_policy


# Launcher path (should be installed by package at /usr/lib/waydroid-multi/)
LAUNCHER_PATH = "/usr/lib/waydroid-multi/waydroid-helper-launcher.py"


class Guardian:
    """Independent per-instance resource owner and helper supervisor."""

    def __init__(self, store: ProtectedStore, identifier: str, caller_uid: int):
        self.store = store
        self.identifier = identifier
        self.caller_uid = caller_uid
        self.session: Optional[SupervisorSession] = None
        self.cgroup_fd: Optional[int] = None
        self.sandbox_fd: Optional[int] = None
        self.program_fd: Optional[int] = None
        self.helper_proc: Optional[subprocess.Popen] = None
        self.intent: Optional[dict] = None
        self.generation: Optional[str] = None
        self.helper_pid: Optional[int] = None
        self.helper_active: bool = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitor: threading.Event = threading.Event()

    def _require_session(self) -> None:
        """Create and verify a SupervisorSession."""
        if self.session is None:
            self.session = SupervisorSession()
            self.session.verify()

    def _prepare_helper(self) -> dict:
        """Prepare helper intent and record journals."""
        self._require_session()

        instance = self.store._instance(self.identifier)
        try:
            with self.store._lock(instance):
                self.store._record(instance, self.identifier, self.caller_uid)
                self.intent = self.store.prepare_helper(self.identifier, self.caller_uid)
                self.generation = self.intent["generation"]
        finally:
            os.close(instance)

        return self.intent

    def _create_cgroup(self, parent_fd: int) -> int:
        """Create cgroup child under parent and return its fd."""
        cg_name = f"wm-{self.identifier}-{self.generation}"
        os.mkdir(cg_name, 0o700, dir_fd=parent_fd)
        cg_fd = os.open(cg_name, _DIR_FLAGS, dir_fd=parent_fd)
        return cg_fd

    def _install_bpf_policy(self, cg_fd: int,
                            devices: Tuple[Tuple[int, int], ...]) -> Tuple[int, dict]:
        """Install BPF policy and return program fd and inspection result."""
        return install_policy(cg_fd, devices)

    def _create_sandbox(self) -> int:
        """Create sandbox directory and return fd."""
        runtime = os.open("/run/waydroid-multi", _DIR_FLAGS)
        try:
            sandbox_name = f"sandbox-{self.identifier}-{self.generation}"
            os.mkdir(sandbox_name, 0o700, dir_fd=runtime)
            sandbox_fd = os.open(sandbox_name, _DIR_FLAGS, dir_fd=runtime)
            return sandbox_fd
        finally:
            os.close(runtime)

    def _move_proc_to_cgroup(self, proc_pid: int, cgroup_fd: int) -> None:
        """Move a process into the specified cgroup. Raises on failure."""
        fd = os.open("cgroup.procs", os.O_WRONLY | os.O_CLOEXEC, dir_fd=cgroup_fd)
        try:
            data = str(proc_pid).encode()
            if os.write(fd, data) != len(data):
                raise SecurityError("short write moving helper to cgroup")
        finally:
            os.close(fd)

    def start(self) -> dict:
        """Start the guardian: prepare intent, create cgroup, install BPF,
        create sandbox, spawn helper via launcher, verify, release gate.

        The lifecycle follows the same safe sequence as SupervisorCandidate:
        1. Prepare helper intent (journal published atomically)
        2. Open instance binder directory
        3. Create cgroup under delegated service cgroup
        4. Install and verify BPF policy
        5. Create sandbox directory
        6. Spawn helper via launcher with gate pipe
        7. Move helper to cgroup (before releasing gate)
        8. Record all journals (cgroup, sandbox, policy, process)
        9. Verify everything via ProtectedStore
        10. Release gate (write 'G') — only after all verification passes
        11. Start monitoring thread

        On any failure before step 10, gate is never written, helper stays blocked.
        On failure after step 10, helper runs but journals retain recovery blockade.
        """
        self._require_session()

        # 1. Prepare helper intent
        intent = self._prepare_helper()
        self.generation = intent["generation"]

        # 2. Open instance binder directory (contains binder, hwbinder, vndbinder)
        binder_dir_fd = os.open(self.identifier, _DIR_FLAGS,
                                dir_fd=self.store.binder_fd)

        # 3. Configure private access on the instance binder mount
        target = f"/run/waydroid-multi/binderfs/{self.identifier}"
        configure_private_access(target, intent["gid"])

        # 4. Get device numbers from instance binder
        devices = []
        for name in ("binder", "hwbinder", "vndbinder"):
            info = os.stat(Path(target) / name)
            devices.append((os.major(info.st_rdev), os.minor(info.st_rdev)))

        # 5. Create cgroup under delegated service cgroup
        cg_fd = self._create_cgroup(self.session.cgroup)
        self.cgroup_fd = cg_fd

        # 6. Install BPF policy
        program_fd, policy_info = self._install_bpf_policy(cg_fd, tuple(devices))
        self.program_fd = program_fd

        # 7. Create sandbox directory
        sandbox_fd = self._create_sandbox()
        self.sandbox_fd = sandbox_fd
        sandbox = f"/run/waydroid-multi/sandbox-{self.identifier}-{self.generation}"

        # 8. Open binder fd for passing to launcher/helper
        binder_fd = os.open(target, _DIR_FLAGS, dir_fd=binder_dir_fd)

        # 9. Create gate pipe for launcher synchronization
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)

        # 10. Spawn helper via launcher
        try:
            proc = subprocess.Popen(
                ["/usr/bin/python3", "-B", "-I", LAUNCHER_PATH,
                 str(gate_read), str(binder_fd),
                 str(intent["uid"]), str(intent["gid"]), sandbox,
                 "--persistent"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=(gate_read, binder_fd),
                cwd="/",
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}
            )
        except BaseException:
            os.close(gate_read)
            os.close(gate_write)
            os.close(binder_fd)
            os.close(binder_dir_fd)
            raise

        # Parent: close gate_read and binder_fd (child retains via pass_fds)
        os.close(gate_read)
        os.close(binder_fd)
        os.close(binder_dir_fd)

        # 11. Move helper to cgroup BEFORE releasing gate
        try:
            self._move_proc_to_cgroup(proc.pid, cg_fd)
        except BaseException:
            # Gate never written, helper stays blocked waiting for 'G'
            os.close(gate_write)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            raise

        # 12. Record all journals
        self.store.remember_helper_cgroup(self.identifier, self.caller_uid,
                                          self.session.cgroup, cg_fd)
        self.store.record_helper_sandbox(self.identifier, self.caller_uid,
                                         self.session, sandbox_fd)
        self.store.record_helper_policy(self.identifier, self.caller_uid,
                                        self.session, cg_fd, program_fd)
        self.store.remember_helper_process(self.identifier, self.caller_uid,
                                           self.session.cgroup, cg_fd,
                                           proc.pid)

        # 13. Verify everything via ProtectedStore
        self.store.verify_helper_policy(self.identifier, self.caller_uid,
                                        self.session, cg_fd, program_fd)
        self.store.verify_helper_sandbox(self.identifier, self.caller_uid,
                                         self.session, sandbox_fd)
        self.store.verify_helper_cgroup(self.identifier, self.caller_uid,
                                        self.session.cgroup, cg_fd)

        # 14. Release gate — write 'G' to unblock launcher/helper
        try:
            if os.write(gate_write, b"G") != 1:
                raise SecurityError("helper gate write failed")
        finally:
            os.close(gate_write)

        # 15. Store references
        self.helper_proc = proc
        self.helper_pid = proc.pid
        self.helper_active = True

        # 16. Start monitoring thread
        self._monitor_thread = threading.Thread(
            target=self._monitor_helper,
            name=f"guardian-{self.identifier}-monitor",
            daemon=True
        )
        self._monitor_thread.start()

        return {
            "identifier": self.identifier,
            "generation": self.generation,
            "helper_pid": proc.pid,
            "cgroup_fd": cg_fd,
            "sandbox_fd": sandbox_fd,
            "program_fd": program_fd,
            "helper_active": True,
            "status": "started"
        }

    def _monitor_helper(self) -> None:
        """Monitor helper process: detect EOF, errors, or exit."""
        import select
        import errno

        proc = self.helper_proc
        if proc is None:
            return
        stdout_fd = proc.stdout.fileno() if proc and proc.stdout else None

        while not self._stop_monitor.is_set():
            # Check if process has exited
            poll_result = proc.poll() if proc else -1
            if poll_result is not None:
                self.helper_active = False
                break

            # Check for EOF on stdout (helper closed its stdout = exited)
            if stdout_fd is not None:
                rlist, _, _ = select.select([stdout_fd], [], [], 1.0)
                if stdout_fd in rlist:
                    try:
                        data = os.read(stdout_fd, 4096)
                        if not data:
                            # EOF — helper exited
                            self.helper_active = False
                            break
                    except OSError as exc:
                        if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                            self.helper_active = False
                            break

            # Check if helper process has died
            poll_result = proc.poll() if proc else -1
            if poll_result is not None:
                self.helper_active = False
                break

        self._stop_monitor.set()

    def stop(self, graceful: bool = True) -> dict:
        """Stop the helper and clean up all owned resources.

        Safe cleanup sequence:
        1. Send 'stop\n' to helper stdin (graceful protocol)
        2. Wait for helper exit
        3. Call recover_helper_same_boot_empty to atomically remove journals
           and the empty cgroup (with full identity verification)
        4. Close all FDs

        Never signals any process. Fails closed if identity cannot be
        demonstrated — in that case journals remain and the instance
        stays blocked for manual review.
        """
        if not self.helper_active:
            return {"status": "already stopped"}

        proc = self.helper_proc

        # 1. Send stop command via helper stdin
        if graceful and proc and proc.stdin:
            try:
                proc.stdin.write(b"stop\n")
                proc.stdin.flush()
                proc.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass

        # 2. Wait for helper to exit
        if proc:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logging.warning("Helper did not exit gracefully, terminating")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        self.helper_active = False

        # 3. Use the verified recovery path to remove journals and cgroup.
        # This re-validates boot, namespaces, cgroup inode, and that the
        # recorded PID is gone before removing anything. If verification
        # fails, nothing is removed and the instance stays blocked.
        if self.session is not None:
            try:
                self.store.recover_helper_same_boot_empty(
                    self.identifier, self.caller_uid, self.session
                )
            except (SecurityError, OSError) as exc:
                logging.warning("could not recover helper for %s: %s",
                                self.identifier, exc)

        # 4. Close remaining resources
        for fd in (self.sandbox_fd, self.program_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

        self.cgroup_fd = None
        self.sandbox_fd = None
        self.program_fd = None
        self.helper_proc = None

        return {
            "identifier": self.identifier,
            "status": "stopped",
            "helper_active": False,
            "helper_pid": self.helper_pid
        }

    def restart(self) -> dict:
        """Graceful stop + same-boot recovery + new start.

        Equivalent to stop(graceful=True) + recover_same_boot() + start().
        Fails closed if recovery rejects the state.
        """
        result_stop = self.stop(graceful=True)
        try:
            self.recover_same_boot()
        except SecurityError as exc:
            # If same-boot recovery fails, the instance is blocked by
            # an ambiguous resource. We must fail closed.
            logging.error("Guardian restart blocked by recovery: %s", exc)
            return {"status": "blocked", "reason": str(exc),
                    "previous_stop": result_stop}
        return self.start()

    def recover_same_boot(self) -> dict:
        """Recover from same-boot interruption using ProtectedStore.

        Delegates to store.recover_helper_same_boot_empty which:
        - Requires valid SupervisorSession
        - Refuses if recorded PID exists (even if reused)
        - Refuses if cgroup substituted (inode mismatch)
        - Refuses if incomplete or ambiguous state
        - Publishes immutable cleanup journal before any removal
        - Never signals any process
        """
        if self.session is None:
            self._require_session()

        return self.store.recover_helper_same_boot_empty(
            self.identifier, self.caller_uid, self.session
        )

    def status(self) -> dict:
        """Return current guardian status."""
        return {
            "identifier": self.identifier,
            "generation": self.generation,
            "helper_pid": self.helper_pid,
            "helper_active": self.helper_active,
            "cgroup_fd": self.cgroup_fd,
            "sandbox_fd": self.sandbox_fd,
            "program_fd": self.program_fd,
            "status": "running" if self.helper_active else "stopped"
        }

    def close(self) -> None:
        """Clean up all resources. Stops helper gracefully."""
        self._stop_monitor.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=1.0)

        self.stop(graceful=True)
        if self.session:
            self.session.close()