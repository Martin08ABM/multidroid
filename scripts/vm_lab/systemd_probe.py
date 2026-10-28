"""Real systemd/cgroup/persistence test, exclusively in a disposable VM."""
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0, "/lab/project")
from multiinstance.cgroup_anchor import open_system_service_cgroup
from multiinstance.identities import IdentityPool
from multiinstance import privileged
from multiinstance.privileged import ProtectedStore, SecurityError, _DIR_FLAGS


def durable(path, value):
    tmp = path.with_suffix(".new")
    with open(tmp, "w") as file:
        json.dump(value, file)
        file.flush()
        os.fsync(file.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, _DIR_FLAGS)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    if os.geteuid() != 0 or "waydroid_systemd_lab=1" not in Path("/proc/cmdline").read_text().split():
        raise RuntimeError("not a disposable systemd lab")
    state = Path("/state")
    phasefile = state / "phase.json"
    phase = json.loads(phasefile.read_text()) if phasefile.exists() else {"step": 0}
    instances = Path("/var/lib/waydroid-multi/instances")
    store = ProtectedStore.system(create=True)
    cgroup = open_system_service_cgroup()
    try:
        control_path = Path("/run/multidroid-control.pid")
        for _ in range(100):
            if control_path.exists():
                break
            time.sleep(0.05)
        pid_b = int(control_path.read_text())
        os.kill(pid_b, 0)
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if phase["step"] == 0:
            a, b = store.create(0, 0, "a"), store.create(0, 0, "b")
            incomplete = store.create(0, 0, "incomplete")
            store.reserve_identity(a, 0, IdentityPool(500000, 600000, 2))
            store.reserve_identity(incomplete, 0, IdentityPool(500000, 600000, 2))
            store.binder_start(a, 0)
            nodes_b = store.binder_start(b, 0)["nodes"]
            store.binder_start(incomplete, 0)
            incomplete_intent = store.prepare_helper(incomplete, 0)
            # Simulates interruption after mkdir and before cgroup identity publication.
            os.mkdir(incomplete_intent["cgroup_name"], dir_fd=cgroup)
            intent = store.prepare_helper(a, 0)
            os.mkdir(intent["cgroup_name"], dir_fd=cgroup)
            childfd = os.open(intent["cgroup_name"], _DIR_FLAGS, dir_fd=cgroup)
            try:
                store.remember_helper_cgroup(a, 0, cgroup, childfd)
                process = subprocess.Popen(["/usr/bin/sleep", "600"])
                with open("cgroup.procs", "w", opener=lambda path, flags: os.open(path, flags, dir_fd=childfd)) as file:
                    file.write(str(process.pid))
                store.remember_helper_process(a, 0, cgroup, childfd, process.pid)
            finally:
                os.close(childfd)
            durable(phasefile, {"step": 1, "a": a, "b": b, "boot": boot, "control": pid_b,
                                "nodes_b": nodes_b, "cgroup": intent["cgroup_name"],
                                "incomplete": incomplete, "incomplete_cgroup": incomplete_intent["cgroup_name"]})
            print("SYSTEMD_MANAGER_SIGKILL_REQUESTED", flush=True)
            os.kill(os.getpid(), signal.SIGKILL)
        if phase["step"] == 1:
            if phase["boot"] != boot or phase["control"] != pid_b:
                raise RuntimeError("control unit did not survive manager restart")
            if not all(Path(n).is_char_device() for n in phase["nodes_b"]):
                raise RuntimeError("B Binder did not survive manager restart")
            try:
                store.recover(phase["a"], 0)
            except SecurityError:
                pass
            else:
                raise RuntimeError("partial helper journal did not block recovery")
            try:
                store.recover(phase["incomplete"], 0)
            except SecurityError:
                pass
            else:
                raise RuntimeError("incomplete cgroup journal did not block recovery")
            try:
                os.stat(phase["incomplete_cgroup"], dir_fd=cgroup, follow_symlinks=False)
            except FileNotFoundError:
                print("SYSTEMD_INCOMPLETE_CGROUP_ABSENT_AFTER_UNIT_RESTART", flush=True)
            else:
                print("SYSTEMD_INCOMPLETE_CGROUP_PRESERVED=PASS", flush=True)
            durable(phasefile, {**phase, "step": 2})
            print("SYSTEMD_MANAGER_RESTART_ISOLATED=PASS", flush=True)
            os.sync()
            ctypes.CDLL(None, use_errno=True).reboot(0x4321FEDC)
            raise RuntimeError("poweroff failed")
        if phase["step"] == 2:
            if phase["boot"] == boot:
                raise RuntimeError("boot ID did not change")
            try:
                store.recover(phase["a"], 0)
            except SecurityError:
                pass
            else:
                raise RuntimeError("stale helper journal was cleared after reboot")
            old = instances / phase["a"] / "helper-intent.json"
            if not old.is_file():
                raise RuntimeError("persistent journal missing after reboot")
            guard = Path("/run/multidroid-boot2-b.json")
            if guard.exists():
                live_b = json.loads(guard.read_text())
                if live_b["control"] != pid_b:
                    raise RuntimeError("control B changed during recovery interruption")
                nodes_b = live_b["nodes"]
            else:
                store.recover(phase["b"], 0)
                nodes_b = store.binder_start(phase["b"], 0)["nodes"]
                durable(guard, {"control": pid_b, "nodes": nodes_b})
            if not phase.get("cleanup_interrupted"):
                os.mkdir(phase["cgroup"], dir_fd=cgroup)
                try:
                    try:
                        store.recover_helper_after_reboot(phase["a"], 0)
                    except SecurityError:
                        pass
                    else:
                        raise RuntimeError("replacement cgroup was not refused")
                    os.stat(phase["cgroup"], dir_fd=cgroup, follow_symlinks=False)
                    print("SYSTEMD_REPLACEMENT_PRESERVED=PASS", flush=True)
                finally:
                    # This fixture created this empty cgroup in its isolated VM.
                    os.rmdir(phase["cgroup"], dir_fd=cgroup)
                durable(phasefile, {**phase, "cleanup_interrupted": True})
                original = privileged._unlink_checked
                def interrupted(fd, name, uid, gid):
                    original(fd, name, uid, gid)
                    if name == "helper-process.json":
                        print("SYSTEMD_RECOVERY_SIGKILL_REQUESTED", flush=True)
                        os.kill(os.getpid(), signal.SIGKILL)
                privileged._unlink_checked = interrupted
                store.recover_helper_after_reboot(phase["a"], 0)
                raise RuntimeError("recovery interruption did not occur")
            if not all(Path(n).is_char_device() for n in nodes_b):
                raise RuntimeError("B Binder changed during recovery interruption")
            print("SYSTEMD_RECOVERY_RESTART_ISOLATED=PASS", flush=True)
            result = store.recover_helper_after_reboot(phase["a"], 0)
            if not result["stale_journals_removed"] or old.exists():
                raise RuntimeError("stale journals were not removed")
            if not all(Path(n).is_char_device() for n in nodes_b):
                raise RuntimeError("B Binder affected by A recovery")
            incomplete_result = store.recover_helper_after_reboot(phase["incomplete"], 0)
            if not incomplete_result["stale_journals_removed"]:
                raise RuntimeError("incomplete stale journal was not removed")
            print("SYSTEMD_INCOMPLETE_AFTER_REBOOT=PASS", flush=True)
            print("SYSTEMD_STALE_JOURNALS_RECOVERED=PASS", flush=True)
            durable(phasefile, {**phase, "step": 3, "second_boot": boot})
            print("SYSTEMD_PERSISTENT_REBOOT=PASS", flush=True)
            os.sync()
            ctypes.CDLL(None, use_errno=True).reboot(0x4321FEDC)
            raise RuntimeError("poweroff failed")
        raise RuntimeError("unexpected phase")
    finally:
        os.close(cgroup)
        store.close()


if __name__ == "__main__":
    main()
