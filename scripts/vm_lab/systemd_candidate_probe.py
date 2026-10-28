"""Exercise the installed candidate in a disposable VM; not a production service."""
import ctypes
import json
import os
from pathlib import Path
import signal
import select
import stat
import sys

sys.path.insert(0, "/usr/lib/waydroid-multi")
from multiinstance.identities import IdentityPool
from multiinstance.bpf_policy import PolicyError, open_program
from multiinstance.privileged import ProtectedStore, SecurityError
from multiinstance.privileged import _DIR_FLAGS
from multiinstance.supervisor import SupervisorCandidate
from multiinstance import supervisor as supervisor_module
from unittest import mock
from systemd_probe import durable


def main():
    if os.geteuid() != 0 or "waydroid_candidate_lab=1" not in Path("/proc/cmdline").read_text().split():
        raise RuntimeError("requires disposable candidate VM")
    installed = Path("/usr/lib/waydroid-multi")
    for entry in [installed, *installed.rglob("*")]:
        info = entry.lstat()
        expected = 0o755 if stat.S_ISDIR(info.st_mode) else 0o644
        if (info.st_uid != 0 or info.st_gid != 0 or stat.S_ISLNK(info.st_mode) or
                stat.S_IMODE(info.st_mode) != expected):
            raise RuntimeError("installed candidate has unsafe ownership or permissions")
    phasefile = Path("/state/candidate-phase.json")
    phase = json.loads(phasefile.read_text()) if phasefile.exists() else {"step": 0}
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    store = ProtectedStore.system(create=True)
    try:
        if phase["step"] == 0:
            a, b = store.create(0, 0, "candidate-a"), store.create(0, 0, "candidate-b")
            failed = store.create(0, 0, "candidate-failed")
            interrupted = store.create(0, 0, "candidate-interrupted")
            for identifier in (a, b, failed, interrupted):
                store.reserve_identity(identifier, 0, IdentityPool(5000, 6000, 4))
                store.binder_start(identifier, 0)
            supervisor = SupervisorCandidate(store)
            try:
                first = supervisor.start(a, 0, persistent=True)
                second = supervisor.start(b, 0, persistent=True)
                def response(child):
                    if not select.select([child.stdout], [], [], 15)[0]:
                        raise RuntimeError("helper response timed out")
                    data = json.loads(child.stdout.readline())
                    if not data.get("gbinder") or not data.get("privileges_dropped") or data.get("control_visible"):
                        raise RuntimeError("invalid helper response")
                    return data
                for child in (first, second):
                    response(child)
                if first.poll() is not None or second.poll() is not None:
                    raise RuntimeError("persistent helpers did not overlap")
                first.stdin.write(b"stop\n"); first.stdin.flush()
                if first.wait(timeout=15) != 0:
                    raise RuntimeError("first helper did not stop cleanly")
                second.stdin.write(b"ping\n"); second.stdin.flush()
                response(second)
                try:
                    supervisor.start(a, 0, persistent=True)
                except SecurityError:
                    pass
                else:
                    raise RuntimeError("restart bypassed unrecovered journals")
                print("CANDIDATE_PERSISTENT_B_SURVIVES_A_STOP=PASS", flush=True)
                for identifier in (a, b):
                    folder = Path("/var/lib/waydroid-multi/instances") / identifier
                    if not (folder / "helper-policy.json").is_file() or not (folder / "helper-sandbox.json").is_file():
                        raise RuntimeError("candidate did not record policy and sandbox")
                    try:
                        store.binder_stop(identifier, 0)
                    except SecurityError:
                        pass
                    else:
                        raise RuntimeError("candidate journal did not block cleanup")
                bfolder = Path("/var/lib/waydroid-multi/instances") / b
                afolder = Path("/var/lib/waydroid-multi/instances") / a
                b_intent = json.loads((bfolder / "helper-intent.json").read_text())
                a_policy = json.loads((afolder / "helper-policy.json").read_text())
                b_policy = json.loads((bfolder / "helper-policy.json").read_text())
                cg = os.open(b_intent["cgroup_name"], _DIR_FLAGS, dir_fd=supervisor.session.cgroup)
                good = open_program(b_policy["program_id"])
                foreign = open_program(a_policy["program_id"])
                try:
                    store.verify_helper_policy(b, 0, supervisor.session, cg, good)
                    try:
                        store.verify_helper_policy(b, 0, supervisor.session, cg, foreign)
                    except (SecurityError, PolicyError):
                        pass
                    else:
                        raise RuntimeError("foreign policy was not rejected")
                    print("CANDIDATE_FOREIGN_POLICY_REFUSED=PASS", flush=True)
                finally:
                    os.close(good); os.close(foreign); os.close(cg)
                sandbox = "/run/waydroid-multi/sandbox-" + b + "-" + b_intent["generation"]
                saved = sandbox + "-fixture"
                os.rename(sandbox, saved)
                os.mkdir(sandbox, 0o700)
                replacement = os.open(sandbox, _DIR_FLAGS)
                try:
                    try:
                        store.verify_helper_sandbox(b, 0, supervisor.session, replacement)
                    except SecurityError:
                        pass
                    else:
                        raise RuntimeError("replacement sandbox was not rejected")
                    if not Path(sandbox).is_dir():
                        raise RuntimeError("replacement sandbox was removed")
                    print("CANDIDATE_FOREIGN_SANDBOX_PRESERVED=PASS", flush=True)
                finally:
                    os.close(replacement)
                    # Fixture restores only directories it created in this VM.
                    os.rmdir(sandbox); os.rename(saved, sandbox)
                second.stdin.write(b"ping\n"); second.stdin.flush()
                response(second)
                second.stdin.write(b"stop\n"); second.stdin.flush()
                if second.wait(timeout=15) != 0:
                    raise RuntimeError("second helper did not stop cleanly")
                real_install = supervisor_module.install_policy
                with mock.patch.object(supervisor_module, "install_policy", side_effect=lambda _cg, devs: real_install(-1, devs)):
                    try:
                        supervisor.start(failed, 0)
                    except OSError:
                        pass
                    else:
                        raise RuntimeError("injected BPF attach succeeded")
                failed_dir = Path("/var/lib/waydroid-multi/instances") / failed
                if (failed_dir / "helper-process.json").exists():
                    raise RuntimeError("helper launched despite failed BPF")
                try:
                    store.recover(failed, 0)
                except SecurityError:
                    pass
                else:
                    raise RuntimeError("incomplete candidate state was not blocked")
                print("CANDIDATE_BPF_FAILURE_BLOCKED=PASS", flush=True)
                durable(phasefile, {"step": 10, "boot": boot, "a": a, "b": b, "failed": failed, "interrupted": interrupted})
                print("CANDIDATE_INSTALLED_PROBES=PASS", flush=True)
                real_write = os.write
                def kill_before_release(fd, data):
                    if data == b"G":
                        print("CANDIDATE_GATE_SIGKILL_REQUESTED", flush=True)
                        os.kill(os.getpid(), signal.SIGKILL)
                    return real_write(fd, data)
                with mock.patch.object(supervisor_module.os, "write", side_effect=kill_before_release):
                    supervisor.start(interrupted, 0)
                raise RuntimeError("gate interruption was not reached")
            finally:
                supervisor.close()
        if phase["step"] == 10:
            if phase["boot"] != boot:
                raise RuntimeError("unexpected reboot at gate")
            folder = Path("/var/lib/waydroid-multi/instances") / phase["interrupted"]
            if not all((folder / name).is_file() for name in ("helper-process.json", "helper-policy.json", "helper-sandbox.json")):
                raise RuntimeError("missing interrupted state")
            try:
                store.recover(phase["interrupted"], 0)
            except SecurityError:
                pass
            else:
                raise RuntimeError("interrupted gate did not remain blocked")
            print("CANDIDATE_GATE_SIGKILL_BLOCKED=PASS", flush=True)
            durable(phasefile, {**phase, "step": 1})
            os.kill(os.getpid(), signal.SIGKILL)
        if phase["step"] == 1:
            if phase["boot"] != boot:
                raise RuntimeError("unexpected reboot")
            for identifier in (phase["a"], phase["b"], phase["failed"], phase["interrupted"]):
                try:
                    store.recover(identifier, 0)
                except SecurityError:
                    pass
                else:
                    raise RuntimeError("same-boot recovery incorrectly removed candidate resources")
            print("CANDIDATE_SAMEBOOT_BLOCKED=PASS", flush=True)
            durable(phasefile, {**phase, "step": 2})
            os.sync()
            ctypes.CDLL(None).reboot(0x4321FEDC)
            raise RuntimeError("poweroff failed")
        if phase["step"] == 2:
            if phase["boot"] == boot:
                raise RuntimeError("boot did not change")
            for identifier in (phase["a"], phase["b"], phase["failed"], phase["interrupted"]):
                store.recover_helper_after_reboot(identifier, 0)
                store.recover(identifier, 0)
            store.binder_start(phase["b"], 0)
            print("CANDIDATE_REBOOT_RECOVERED=PASS", flush=True)
            durable(phasefile, {**phase, "step": 3})
            os.sync()
            ctypes.CDLL(None).reboot(0x4321FEDC)
            raise RuntimeError("poweroff failed")
        raise RuntimeError("unexpected phase")
    finally:
        store.close()


if __name__ == "__main__":
    main()
