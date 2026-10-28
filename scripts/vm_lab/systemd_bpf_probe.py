"""VM-only integration of delegated cgroups, journals, BPF and real gbinder."""
import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import sys
import time

sys.path.insert(0, "/lab/project")
from multiinstance.binder import configure_private_access
from multiinstance.bpf_policy import inspect_policy, install_policy, open_program
from multiinstance.cgroup_anchor import SupervisorSession
from multiinstance.identities import IdentityPool
from multiinstance import privileged
from multiinstance.privileged import ProtectedStore, SecurityError, _DIR_FLAGS
from systemd_probe import durable

def start(store, session, ident, paths, keep, blocked=False, fail_attach=False):
    session.verify()
    intent = store.prepare_helper(ident, 0)
    os.mkdir(intent["cgroup_name"], dir_fd=session.cgroup)
    cg = os.open(intent["cgroup_name"], _DIR_FLAGS, dir_fd=session.cgroup)
    store.remember_helper_cgroup(ident, 0, session.cgroup, cg)
    target = "/run/waydroid-multi/binderfs/" + ident
    configure_private_access(target, intent["gid"])
    numbers = [os.stat(target + "/" + name).st_rdev for name in ("binder", "hwbinder", "vndbinder")]
    devices = [(os.major(value), os.minor(value)) for value in numbers]
    try:
        prog, verified = install_policy(-1 if fail_attach else cg, devices)
    except BaseException:
        os.close(cg)
        raise
    progid = verified["program_id"]
    if keep:
        store.record_helper_policy(ident, 0, session, cg, prog)
        print("SYSTEMD_BPF_POLICY_JOURNAL=PASS", flush=True)
    gate = os.pipe2(os.O_CLOEXEC)
    control = os.pipe2(os.O_CLOEXEC)
    output = os.pipe2(os.O_CLOEXEC)
    binder = os.open(target, _DIR_FLAGS)
    sandbox = ("/run/waydroid-multi/sandbox-" + ident + "-" + intent["generation"] if keep else
               "/run/waydroid-multi/lab-helper-" + intent["generation"])
    os.mkdir(sandbox, 0o700)
    if keep:
        sandboxfd = os.open(sandbox, _DIR_FLAGS)
        try:
            store.record_helper_sandbox(ident, 0, session, sandboxfd)
        finally:
            os.close(sandboxfd)
        print("SYSTEMD_SANDBOX_JOURNAL=PASS", flush=True)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(gate[1]); os.close(control[1]); os.close(output[0])
            os.dup2(control[0], 0); os.dup2(output[1], 1)
            os.set_inheritable(binder, True)
            for entry in os.listdir("/proc/self/fd"):
                if entry.isdigit() and int(entry) > 2 and int(entry) not in (binder, gate[0]):
                    try:
                        os.close(int(entry))
                    except OSError:
                        pass
            if os.read(gate[0], 1) != b"G":
                os._exit(21)
            os.close(gate[0])
            env = {"PATH": "/usr/bin:/bin", "LANG": "C", "WAYDROID_VM_BINDER_A": paths[0],
                   "WAYDROID_VM_BINDER_B": paths[1], "WAYDROID_VM_KEEP_AFTER_EOF": "1" if keep else "0"}
            os.execve("/usr/bin/python3", ["/usr/bin/python3", "-B", "-I", "/lab/hold_helper.py",
                                         str(binder), str(intent["uid"]), str(intent["gid"]), sandbox], env)
        except BaseException:
            os._exit(22)
    os.close(gate[0]); os.close(control[0]); os.close(output[1]); os.close(binder)
    try:
        fd = os.open("cgroup.procs", os.O_WRONLY | os.O_CLOEXEC, dir_fd=cg)
        try:
            os.write(fd, str(pid).encode())
        finally:
            os.close(fd)
        inspect_policy(cg, prog, devices)
        store.remember_helper_process(ident, 0, session.cgroup, cg, pid)
        session.verify()
        inspect_policy(cg, prog, devices)
        result = {"id": ident, "pid": pid, "cgname": intent["cgroup_name"], "policy": progid,
                  "sandbox": sandbox}
        if blocked:
            # Caller records test phase durably before crashing the manager.
            return result, gate[1], control[1], output[0]
        os.write(gate[1], b"G")
        os.close(gate[1])
        stream = os.fdopen(output[0], "r")
        first, second = stream.readline(), stream.readline()
        if "REAL_HELPER_ACCESS=PASS" not in first:
            raise RuntimeError("cross-device access failed: " + first + second)
        answer = json.loads(second)
        if not answer.get("gbinder") or not answer.get("privileges_dropped"):
            raise RuntimeError("gbinder helper did not drop privileges")
        result["control"] = control[1]
        result["output"] = stream
        return result
    except BaseException:
        # No automatic cleanup; journals retain the recovery blockade.
        try:
            os.close(gate[1])
        except OSError:
            pass
        os.close(control[1]); os.close(output[0])
        raise
    finally:
        os.close(prog); os.close(cg)


def pid_gone(pid):
    for _ in range(100):
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError:
            return True
        else:
            os.close(fd)
            time.sleep(0.05)
    return False


def check_b(store, session, b):
    fd = store.observe_helper_pidfd(b["id"], 0)
    os.close(fd)
    sandbox = os.open(b["sandbox"], _DIR_FLAGS)
    try:
        store.verify_helper_sandbox(b["id"], 0, session, sandbox)
    finally:
        os.close(sandbox)
    cg = os.open(b["cgname"], _DIR_FLAGS, dir_fd=session.cgroup)
    try:
        store.verify_helper_cgroup(b["id"], 0, session.cgroup, cg)
        fd = open_program(b["policy"])
        try:
            target = "/run/waydroid-multi/binderfs/" + b["id"]
            devs = [os.stat(target + "/" + name).st_rdev for name in ("binder", "hwbinder", "vndbinder")]
            inspect_policy(cg, fd, [(os.major(v), os.minor(v)) for v in devs])
            store.verify_helper_policy(b["id"], 0, session, cg, fd)
        finally:
            os.close(fd)
        members = os.open("cgroup.procs", os.O_RDONLY | os.O_CLOEXEC, dir_fd=cg)
        try:
            if str(b["pid"]).encode() not in os.read(members, 1024 * 1024).splitlines():
                raise RuntimeError("B helper is no longer in its protected cgroup")
        finally:
            os.close(members)
    finally:
        os.close(cg)
    time.sleep(0.25)
    fd = store.observe_helper_pidfd(b["id"], 0)
    os.close(fd)


def main():
    if os.geteuid() != 0 or "waydroid_systemd_bpf_lab=1" not in Path("/proc/cmdline").read_text().split():
        raise RuntimeError("requires disposable systemd BPF laboratory")
    state = Path("/state/bpf-phase.json")
    phase = json.loads(state.read_text()) if state.exists() else {"step": 0}
    store = ProtectedStore.system(create=True)
    session = SupervisorSession()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    try:
        if phase["step"] == 0:
            a, b = store.create(0, 0, "helper-a"), store.create(0, 0, "helper-b")
            failed = store.create(0, 0, "helper-failed")
            for ident in (a, b, failed):
                store.reserve_identity(ident, 0, IdentityPool(5000, 6000, 3))
                store.binder_start(ident, 0)
            paths = ["/run/waydroid-multi/binderfs/" + ident for ident in (a, b)]
            b_worker = start(store, session, b, paths, True)
            b_info = {k: v for k, v in b_worker.items() if k not in ("control", "output")}
            try:
                start(store, session, failed, paths, False, fail_attach=True)
            except OSError:
                pass
            else:
                raise RuntimeError("injected BPF attach unexpectedly succeeded")
            failed_dir = Path("/var/lib/waydroid-multi/instances") / failed
            if (failed_dir / "helper-process.json").exists():
                raise RuntimeError("failed BPF setup launched a helper")
            try:
                store.binder_stop(failed, 0)
            except SecurityError:
                pass
            else:
                raise RuntimeError("failed BPF setup did not retain blockade")
            check_b(store, session, b_info)
            print("SYSTEMD_BPF_ATTACH_FAILURE_BLOCKED=PASS", flush=True)
            a_info, gate, control, output = start(store, session, a, paths, False, blocked=True)
            durable(state, {"step": 1, "boot": boot, "a": a_info, "b": b_info, "paths": paths, "failed": failed})
            print("SYSTEMD_BPF_BLOCKED_CRASH", flush=True)
            os.kill(os.getpid(), signal.SIGKILL)
        if phase["step"] == 1:
            if phase["boot"] != boot:
                raise RuntimeError("unexpected reboot")
            check_b(store, session, phase["b"])
            if not pid_gone(phase["a"]["pid"]):
                raise RuntimeError("blocked helper survived closed gate")
            journal = Path("/var/lib/waydroid-multi/instances") / phase["a"]["id"] / "helper-process.json"
            original_record = json.loads(journal.read_text())
            journal.write_text(json.dumps({**original_record, "pid": phase["b"]["pid"]}))
            try:
                try:
                    store.recover_helper_same_boot_empty(phase["a"]["id"], 0, session)
                except SecurityError:
                    pass
                else:
                    raise RuntimeError("foreign PID was not refused")
                check_b(store, session, phase["b"])
                print("SYSTEMD_BPF_FOREIGN_PID_PRESERVED=PASS", flush=True)
            finally:
                journal.write_text(json.dumps(original_record))
            os.mkdir(phase["a"]["cgname"], dir_fd=session.cgroup)
            try:
                try:
                    store.recover_helper_same_boot_empty(phase["a"]["id"], 0, session)
                except SecurityError:
                    pass
                else:
                    raise RuntimeError("replacement cgroup was not refused")
                os.stat(phase["a"]["cgname"], dir_fd=session.cgroup, follow_symlinks=False)
                check_b(store, session, phase["b"])
                print("SYSTEMD_BPF_FOREIGN_CGROUP_PRESERVED=PASS", flush=True)
            finally:
                # This fixture created the replacement and owns the whole VM.
                os.rmdir(phase["a"]["cgname"], dir_fd=session.cgroup)
            durable(state, {**phase, "step": 11})
            original_unlink = privileged._unlink_checked
            def interrupted(fd, name, uid, gid):
                original_unlink(fd, name, uid, gid)
                if name == "helper-process.json":
                    print("SYSTEMD_BPF_CLEANUP_CRASH", flush=True)
                    os.kill(os.getpid(), signal.SIGKILL)
            privileged._unlink_checked = interrupted
            store.recover_helper_same_boot_empty(phase["a"]["id"], 0, session)
            raise RuntimeError("cleanup interruption did not occur")
        if phase["step"] == 11:
            check_b(store, session, phase["b"])
            store.recover_helper_same_boot_empty(phase["a"]["id"], 0, session)
            check_b(store, session, phase["b"])
            print("SYSTEMD_BPF_BLOCKED_RECOVERED=PASS", flush=True)
            a_worker = start(store, session, phase["a"]["id"], phase["paths"], False)
            os.write(a_worker["control"], b"quit\n")
            os.close(a_worker["control"])
            a_worker["output"].close()
            _, status = os.waitpid(a_worker["pid"], 0)
            if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                raise RuntimeError("A did not stop cleanly")
            store.recover_helper_same_boot_empty(phase["a"]["id"], 0, session)
            check_b(store, session, phase["b"])
            print("SYSTEMD_BPF_EMPTY_CGROUP_RECOVERED=PASS", flush=True)
            a_worker = start(store, session, phase["a"]["id"], phase["paths"], False)
            a_info = {k: v for k, v in a_worker.items() if k not in ("control", "output")}
            durable(state, {**phase, "step": 2, "a": a_info})
            print("SYSTEMD_BPF_RUNNING_CRASH", flush=True)
            os.kill(os.getpid(), signal.SIGKILL)
        if phase["step"] == 2:
            check_b(store, session, phase["b"])
            if not pid_gone(phase["a"]["pid"]):
                raise RuntimeError("A did not exit after manager crash")
            durable(state, {**phase, "step": 3})
            print("SYSTEMD_BPF_SAMEBOOT_PASS", flush=True)
            original_unlink = privileged._unlink_checked
            def reboot_during_cleanup(fd, name, uid, gid):
                original_unlink(fd, name, uid, gid)
                if name == "helper-intent.json":
                    print("SYSTEMD_BPF_REBOOT_DURING_CLEANUP", flush=True)
                    os.sync()
                    ctypes.CDLL(None).reboot(0x4321FEDC)
                    raise RuntimeError("poweroff failed")
            privileged._unlink_checked = reboot_during_cleanup
            store.recover_helper_same_boot_empty(phase["a"]["id"], 0, session)
            raise RuntimeError("cleanup did not trigger reboot")
        if phase["step"] == 3:
            if phase["boot"] == boot:
                raise RuntimeError("boot ID did not change")
            try:
                store.recover(phase["failed"], 0)
            except SecurityError:
                pass
            else:
                raise RuntimeError("incomplete BPF failure lost its blockade")
            print("SYSTEMD_BPF_INCOMPLETE_STILL_BLOCKED=PASS", flush=True)
            session.close()
            store.recover_helper_after_reboot(phase["a"]["id"], 0)
            print("SYSTEMD_BPF_CLEANUP_REBOOT_RECOVERED=PASS", flush=True)
            store.recover_helper_after_reboot(phase["b"]["id"], 0)
            store.recover(phase["b"]["id"], 0)
            store.binder_start(phase["b"]["id"], 0)
            print("SYSTEMD_BPF_REBOOT_PASS", flush=True)
            durable(state, {**phase, "step": 4})
            os.sync()
            ctypes.CDLL(None).reboot(0x4321FEDC)
            raise RuntimeError("poweroff failed")
        raise RuntimeError("unexpected phase")
    finally:
        if session.lease is not None:
            session.close()
        store.close()


if __name__ == "__main__":
    main()
