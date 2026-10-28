#!/usr/bin/env python3
"""Real manager/Binder probe in a disposable user and mount namespace."""
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from multiinstance import privileged
from multiinstance.privileged import ProtectedStore, SecurityError, _DIR_FLAGS
from multiinstance.identities import IdentityPool


def child(root, parent_namespace=None, *, vm=False):
    if vm:
        if (os.geteuid() != 0 or os.getppid() != 1 or root != "/vmprobe" or
                "waydroid_vm_store_lab=1" not in Path("/proc/cmdline").read_text().split()):
            raise RuntimeError("this mode requires the disposable laboratory VM")
    elif os.geteuid() != 0 or os.stat("/proc/self/ns/mnt").st_ino == int(parent_namespace):
        raise RuntimeError("a private mount namespace with namespace root is required")
    base = Path(root)
    instances, binders = base / "instances", base / "binders"
    instances.mkdir(mode=0o711)
    binders.mkdir(mode=0o700)
    store = ProtectedStore(os.open(instances, _DIR_FLAGS), os.open(binders, _DIR_FLAGS))
    try:
        a, b = store.create(0, 0, "probe-a"), store.create(0, 0, "probe-b")
        nodes_a = store.binder_start(a, 0)["nodes"]
        nodes_b = store.binder_start(b, 0)["nodes"]
        store.reserve_identity(a, 0, IdentityPool(500000, 600000, 2))
        pid = os.fork()
        if pid == 0:
            original = privileged._write_new
            def interrupt_intent(parent, name, value, uid, gid):
                original(parent, name, value, uid, gid)
                if name == "helper-intent.json":
                    os.kill(os.getpid(), signal.SIGKILL)
            privileged._write_new = interrupt_intent
            store.prepare_helper(a, 0)
            os._exit(3)
        _, status = os.waitpid(pid, 0)
        helper_killed = os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        helper_intent = json.loads((instances / a / "helper-intent.json").read_text())
        try:
            store.binder_stop(a, 0)
        except SecurityError:
            helper_blocked = True
        else:
            helper_blocked = False
        cgroot = base / "cgroup"
        cgroot.mkdir()
        subprocess.run(["/usr/bin/mount", "-t", "cgroup2", "none", str(cgroot)], check=True, capture_output=True)
        try:
            (cgroot / helper_intent["cgroup_name"]).mkdir()
            parent_fd = os.open(cgroot, _DIR_FLAGS)
            child_fd = os.open(cgroot / helper_intent["cgroup_name"], _DIR_FLAGS)
            try:
                def crash_after_publication(name, action):
                    writer = os.fork()
                    if writer == 0:
                        original = privileged._write_new
                        def interrupt(parent, filename, value, uid, gid):
                            original(parent, filename, value, uid, gid)
                            if filename == name:
                                os.kill(os.getpid(), signal.SIGKILL)
                        privileged._write_new = interrupt
                        action()
                        os._exit(3)
                    _, writer_status = os.waitpid(writer, 0)
                    return os.WIFSIGNALED(writer_status) and os.WTERMSIG(writer_status) == signal.SIGKILL
                cg_killed = crash_after_publication("helper-cgroup.json",
                    lambda: store.remember_helper_cgroup(a, 0, parent_fd, child_fd))
                evidence = json.loads((instances / a / "helper-cgroup.json").read_text())
                evidence_real = evidence["ino"] == os.fstat(child_fd).st_ino
                process = subprocess.Popen(["/usr/bin/sleep", "30"])
                try:
                    (cgroot / helper_intent["cgroup_name"] / "cgroup.procs").write_text(str(process.pid))
                    process_killed = crash_after_publication("helper-process.json",
                        lambda: store.remember_helper_process(a, 0, parent_fd, child_fd, process.pid))
                    process_record = json.loads((instances / a / "helper-process.json").read_text())
                    process_real = process_record["pid"] == process.pid and process_record["start_ticks"] > 0
                    pinned = store.observe_helper_pidfd(a, 0)
                    process_pinned = os.fstat(pinned).st_ino > 0
                    os.close(pinned)
                    journal = instances / a / "helper-process.json"
                    journal.write_text(json.dumps({**process_record, "start_ticks": process_record["start_ticks"] + 1}))
                    try:
                        store.observe_helper_pidfd(a, 0)
                    except SecurityError:
                        reused_refused = True
                    else:
                        reused_refused = False
                    journal.write_text(json.dumps(process_record))
                    try:
                        store.recover(a, 0)
                    except SecurityError:
                        process_preserved = process.poll() is None
                    else:
                        process_preserved = False
                finally:
                    process.terminate()
                    process.wait(timeout=5)
            finally:
                os.close(parent_fd); os.close(child_fd)
            # This test knows it alone created the empty cgroup and never spawned a helper.
            (cgroot / helper_intent["cgroup_name"]).rmdir()
        finally:
            subprocess.run(["/usr/bin/umount", str(cgroot)], check=True, capture_output=True)
        helper_b_survives = all(Path(node).is_char_device() for node in nodes_b)
        # Explicit laboratory teardown only; the manager has no automatic helper cleanup yet.
        (instances / a / "helper-cgroup.json").unlink()
        (instances / a / "helper-process.json").unlink()
        (instances / a / "helper-intent.json").unlink()
        node_modes = {Path(node).name: oct(stat.S_IMODE(os.stat(node).st_mode)) for node in nodes_a}
        mount_mode = oct(stat.S_IMODE(os.stat(binders / a).st_mode))
        devices = [os.stat(node).st_rdev for node in nodes_a + nodes_b]
        distinct = len(set(devices)) == 6
        crash_known = store.create(0, 0, "crash-known")
        pid = os.fork()
        if pid == 0:
            original = privileged._unlink_checked
            def interrupt(parent, name, uid, gid):
                if name == "binder-intent.json":
                    os.kill(os.getpid(), signal.SIGKILL)
                return original(parent, name, uid, gid)
            privileged._unlink_checked = interrupt
            store.binder_start(crash_known, 0)
            os._exit(3)
        _, status = os.waitpid(pid, 0)
        known_killed = os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        known_recovered = store.recover(crash_known, 0)["cleaned"] and not (binders / crash_known).exists()
        crash_unknown = store.create(0, 0, "crash-unknown")
        pid = os.fork()
        if pid == 0:
            privileged.initialize_fresh_nodes = lambda _path: os.kill(os.getpid(), signal.SIGKILL)
            store.binder_start(crash_unknown, 0)
            os._exit(3)
        _, status = os.waitpid(pid, 0)
        unknown_killed = os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        unknown_recovered = store.recover(crash_unknown, 0)["cleaned"] and not (binders / crash_unknown).exists()
        crash_after_mount = store.create(0, 0, "crash-after-mount")
        pid = os.fork()
        if pid == 0:
            original_run = privileged.subprocess.run
            def interrupt_after_mount(command, **kwargs):
                result = original_run(command, **kwargs)
                if command[0] == "/usr/bin/mount":
                    os.kill(os.getpid(), signal.SIGKILL)
                return result
            privileged.subprocess.run = interrupt_after_mount
            store.binder_start(crash_after_mount, 0)
            os._exit(3)
        _, status = os.waitpid(pid, 0)
        after_mount_killed = os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        after_mount_recovered = store.recover(crash_after_mount, 0)["cleaned"] and not (binders / crash_after_mount).exists()
        crash_before_mount = store.create(0, 0, "crash-before-mount")
        pid = os.fork()
        if pid == 0:
            privileged.subprocess.run = lambda *_args, **_kwargs: os.kill(os.getpid(), signal.SIGKILL)
            store.binder_start(crash_before_mount, 0)
            os._exit(3)
        _, status = os.waitpid(pid, 0)
        before_mount_killed = os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        before_mount_recovered = store.recover(crash_before_mount, 0)["cleaned"] and not (binders / crash_before_mount).exists()
        foreign = store.create(0, 0, "foreign-mount")
        pid = os.fork()
        if pid == 0:
            privileged.initialize_fresh_nodes = lambda _path: os.kill(os.getpid(), signal.SIGKILL)
            store.binder_start(foreign, 0)
            os._exit(3)
        os.waitpid(pid, 0)
        subprocess.run(["/usr/bin/umount", str(binders / foreign)], check=True, capture_output=True)
        subprocess.run(["/usr/bin/mount", "-t", "binder", "-o", "max=4", "foreign-source", str(binders / foreign)], check=True, capture_output=True)
        try:
            store.recover(foreign, 0)
        except SecurityError:
            unknown_refused = True
        else:
            unknown_refused = False
        # This probe owns the disposable namespace and knows it created the mount.
        subprocess.run(["/usr/bin/umount", str(binders / foreign)], check=True, capture_output=True)
        unknown_cleaned = store.recover(foreign, 0)["cleaned"]
        store.binder_stop(a, 0)
        b_alive = all(Path(node).is_char_device() for node in nodes_b)
        a_cleaned = not (binders / a).exists() and not (instances / a / "binder.json").exists()
        store.binder_stop(b, 0)
        b_cleaned = not (binders / b).exists() and not (instances / b / "binder.json").exists()
        result = {"two_records": a != b, "six_distinct_devices": distinct,
                  "helper_intent_survives_sigkill": helper_killed,
                  "binder_blocked_by_helper_journal": helper_blocked,
                  "real_cgroup_evidence_recorded": evidence_real,
                  "real_process_evidence_recorded": process_real,
                  "real_process_pinned_for_diagnostics": process_pinned,
                  "mismatched_start_time_refused": reused_refused,
                  "cgroup_journal_survives_sigkill": cg_killed,
                  "process_journal_survives_sigkill": process_killed,
                  "live_process_preserved_on_refusal": process_preserved,
                  "b_survives_helper_journal": helper_b_survives,
                  "known_mount_after_sigkill_recovered": known_killed and known_recovered,
                  "mount_before_id_sigkill_recovered": unknown_killed and unknown_recovered,
                  "immediately_after_mount_sigkill_recovered": after_mount_killed and after_mount_recovered,
                  "before_mount_sigkill_recovered": before_mount_killed and before_mount_recovered,
                  "foreign_mount_refused": unknown_refused,
                  "foreign_mount_cleaned_after_manual_unmount": unknown_cleaned,
                  "b_survives_a_stop": b_alive, "a_cleaned": a_cleaned,
                  "b_cleaned": b_cleaned, "records_preserved":
                  store.inspect(a, 0)["id"] == a and store.inspect(b, 0)["id"] == b}
        if not all(result.values()):
            raise RuntimeError("manager probe failed: " + json.dumps(result))
        print(json.dumps({**result, "binder_node_modes": node_modes, "binder_mount_mode": mount_mode}))
    finally:
        store.close()


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--vm-child":
        child(sys.argv[2], vm=True)
        return
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        child(sys.argv[2], sys.argv[3])
        return
    with tempfile.TemporaryDirectory(prefix="waydroid-multi-manager-", dir="/var/tmp") as tmp:
        command = ["unshare", "--user", "--map-root-user", "--mount", "--cgroup", "--propagation", "private",
                   sys.executable, str(Path(__file__).resolve()), "--child", tmp,
                   str(os.stat("/proc/self/ns/mnt").st_ino)]
        result = subprocess.run(command, text=True, capture_output=True)
        if result.returncode:
            print(result.stderr, file=sys.stderr)
            sys.exit(result.returncode)
        print(json.dumps(json.loads(result.stdout), indent=2))


if __name__ == "__main__":
    main()
