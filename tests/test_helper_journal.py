import json
import os
import errno
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from multiinstance import privileged
from multiinstance.identities import IdentityPool
from multiinstance.bpf_policy import expected_instructions
from multiinstance.privileged import ProtectedStore, SecurityError, _DIR_FLAGS


class HelperJournalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / "instances").mkdir(mode=0o711)
        (self.base / "binders").mkdir(mode=0o700)
        self.store = ProtectedStore(os.open(self.base / "instances", _DIR_FLAGS),
                                    os.open(self.base / "binders", _DIR_FLAGS), os.getuid(), os.getgid())
        self.addCleanup(self.store.close)
        self.a = self.store.create(os.getuid(), os.getgid(), "a")
        self.b = self.store.create(os.getuid(), os.getgid(), "b")
        self.store.reserve_identity(self.a, os.getuid(), IdentityPool(500000, 600000, 2))
        self.source = "waydroid-multi-" + "a" * 32
        self.current = privileged._mount_identity()
        state = {"version": 3, "id": self.a, "mount_id": 123, "source": self.source, **self.current}
        path = self.base / "instances" / self.a / "binder.json"
        path.write_text(json.dumps(state))
        path.chmod(0o600)
        self.mounts = mock.patch.object(privileged, "_mounts_at", return_value=[(123, "binder")])
        self.sources = mock.patch.object(privileged, "_mount_source", return_value=self.source)
        self.mounts.start(); self.sources.start()
        self.addCleanup(self.mounts.stop); self.addCleanup(self.sources.stop)

    def test_intent_is_unique_authorized_and_blocks_binder_cleanup(self):
        with self.assertRaises(PermissionError):
            self.store.prepare_helper(self.a, os.getuid() + 1)
        intent = self.store.prepare_helper(self.a, os.getuid())
        self.assertEqual(intent["id"], self.a)
        self.assertEqual(intent["cgroup_name"], "wm-" + self.a + "-" + intent["generation"])
        with self.assertRaisesRegex(SecurityError, "helper state"):
            self.store.binder_stop(self.a, os.getuid())
        with self.assertRaisesRegex(SecurityError, "helper state"):
            self.store.prepare_helper(self.a, os.getuid())
        # A different instance is not blocked by A's journal.
        with mock.patch.object(privileged, "_mounts_at", return_value=[]):
            self.assertFalse(self.store.recover(self.b, os.getuid())["cleaned"])

    def test_intent_refuses_foreign_mount_and_pending_binder(self):
        with mock.patch.object(privileged, "_mount_source", return_value="foreign"):
            with self.assertRaisesRegex(SecurityError, "verified Binder"):
                self.store.prepare_helper(self.a, os.getuid())
        path = self.base / "instances" / self.a / "binder-intent.json"
        path.write_text("{}")
        path.chmod(0o600)
        with self.assertRaisesRegex(SecurityError, "incomplete"):
            self.store.prepare_helper(self.a, os.getuid())

    def test_cgroup_evidence_checks_identity_and_refuses_substitution(self):
        intent = self.store.prepare_helper(self.a, os.getuid())
        parent = self.base / "cg"
        parent.mkdir(mode=0o700)
        (parent / intent["cgroup_name"]).mkdir(mode=0o700)
        other = parent / "other"
        other.mkdir(mode=0o700)
        pfd = os.open(parent, _DIR_FLAGS)
        child = os.open(parent / intent["cgroup_name"], _DIR_FLAGS)
        foreign = os.open(other, _DIR_FLAGS)
        self.addCleanup(os.close, pfd); self.addCleanup(os.close, child); self.addCleanup(os.close, foreign)
        # Filesystem magic is simulated; inode/path/authorization checks are real.
        with mock.patch.object(privileged, "_filesystem_type", return_value=privileged._CGROUP2_MAGIC):
            with self.assertRaisesRegex(SecurityError, "differs"):
                self.store.remember_helper_cgroup(self.a, os.getuid(), pfd, foreign)
            evidence = self.store.remember_helper_cgroup(self.a, os.getuid(), pfd, child)
            self.assertEqual(evidence["ino"], os.fstat(child).st_ino)
            with self.assertRaises(FileExistsError):
                self.store.remember_helper_cgroup(self.a, os.getuid(), pfd, child)
            process = subprocess.Popen(["sleep", "30"])
            try:
                members = parent / intent["cgroup_name"] / "cgroup.procs"
                members.write_text("999999\n")
                with self.assertRaisesRegex(SecurityError, "not in recorded"):
                    self.store.remember_helper_process(self.a, os.getuid(), pfd, child, process.pid)
                with mock.patch.object(privileged, "_mount_source", return_value="foreign"):
                    with self.assertRaisesRegex(SecurityError, "mount changed"):
                        self.store.remember_helper_process(self.a, os.getuid(), pfd, child, process.pid)
                members.write_text(str(process.pid) + "\n")
                record = self.store.remember_helper_process(self.a, os.getuid(), pfd, child, process.pid)
                self.assertEqual(record["pid"], process.pid)
                self.assertGreater(record["start_ticks"], 0)
                observed = self.store.observe_helper_pidfd(self.a, os.getuid())
                os.close(observed)
                journal = self.base / "instances" / self.a / "helper-process.json"
                altered = {**record, "start_ticks": record["start_ticks"] + 1}
                journal.write_text(json.dumps(altered))
                with self.assertRaisesRegex(SecurityError, "identity changed"):
                    self.store.observe_helper_pidfd(self.a, os.getuid())
                journal.write_text(json.dumps(record))
                with mock.patch.object(privileged, "_mount_identity", return_value={**self.current, "boot": "different"}):
                    with self.assertRaisesRegex(SecurityError, "another boot"):
                        self.store.observe_helper_pidfd(self.a, os.getuid())
                journal.write_text(json.dumps({**record, "pid_namespace": "pid:[999999]"}))
                with self.assertRaisesRegex(SecurityError, "identity changed"):
                    self.store.observe_helper_pidfd(self.a, os.getuid())
                journal.write_text(json.dumps(record))
                with self.assertRaises(PermissionError):
                    self.store.observe_helper_pidfd(self.a, os.getuid() + 1)
            finally:
                process.terminate()
                process.wait(timeout=5)
            with self.assertRaises((ProcessLookupError, SecurityError)):
                self.store.observe_helper_pidfd(self.a, os.getuid())
            self.assertFalse(self.store.verify_helper_cgroup(self.a, os.getuid(), pfd, child)["cleanup_authorized"])
            with mock.patch.object(privileged, "_mount_identity", return_value={**self.current, "boot": "different"}):
                with self.assertRaisesRegex(SecurityError, "another boot"):
                    self.store.verify_helper_cgroup(self.a, os.getuid(), pfd, child)
            original = parent / intent["cgroup_name"]
            original.rename(parent / "displaced")
            original.mkdir(mode=0o700)
            replacement = os.open(original, _DIR_FLAGS)
            try:
                with self.assertRaisesRegex(SecurityError, "evidence differs"):
                    self.store.verify_helper_cgroup(self.a, os.getuid(), pfd, replacement)
                with self.assertRaisesRegex(SecurityError, "entry changed"):
                    self.store.verify_helper_cgroup(self.a, os.getuid(), pfd, child)
                self.assertTrue(original.is_dir())
            finally:
                os.close(replacement)
        with self.assertRaisesRegex(SecurityError, "helper state"):
            self.store.recover(self.a, os.getuid())

    def test_any_malformed_or_symlink_journal_fails_closed(self):
        marker = self.base / "instances" / self.a / "helper-intent.json"
        marker.symlink_to("/does-not-exist")
        with self.assertRaisesRegex(SecurityError, "helper state"):
            self.store.binder_stop(self.a, os.getuid())

    def test_null_binder_journal_is_not_treated_as_absent(self):
        path = self.base / "instances" / self.b / "binder.json"
        path.write_text("null"); path.chmod(0o600)
        with self.assertRaisesRegex(SecurityError, "null journal"):
            self.store.recover(self.b, os.getuid())

    def test_post_boot_recovery_refuses_present_resources_and_resumes_after_interruption(self):
        from multiinstance import cgroup_anchor
        intent = self.store.prepare_helper(self.a, os.getuid())
        folder = self.base / "instances" / self.a
        cgroot = self.base / "cg"
        cgroot.mkdir(mode=0o700)
        parent = os.open(cgroot, _DIR_FLAGS)
        self.addCleanup(os.close, parent)
        def lease():
            return os.open("/dev/null", os.O_RDONLY)
        def anchor():
            return os.dup(parent)
        with mock.patch.object(self.store, "_require_system_recovery_store"), \
             mock.patch.object(cgroup_anchor, "acquire_system_supervisor_lease", side_effect=lease), \
             mock.patch.object(cgroup_anchor, "open_system_service_cgroup", side_effect=anchor), \
             mock.patch.object(privileged, "_open_fixed_anchor", side_effect=lambda _path: os.dup(parent)):
            with self.assertRaisesRegex(SecurityError, "current boot"):
                self.store.recover_helper_after_reboot(self.a, os.getuid())
            intent["boot"] = "00000000-0000-0000-0000-000000000001"
            (folder / "helper-intent.json").write_text(json.dumps(intent))
            (cgroot / intent["cgroup_name"]).mkdir()
            with self.assertRaisesRegex(SecurityError, "cgroup name exists"):
                self.store.recover_helper_after_reboot(self.a, os.getuid())
            self.assertTrue((cgroot / intent["cgroup_name"]).is_dir())
            (cgroot / intent["cgroup_name"]).rmdir()
            with self.assertRaisesRegex(SecurityError, "Binder mount exists"):
                self.store.recover_helper_after_reboot(self.a, os.getuid())
            with mock.patch.object(privileged, "_mounts_at", return_value=[]):
                target = self.base / "binders" / self.a
                target.symlink_to("/does-not-exist")
                with self.assertRaisesRegex(SecurityError, "Binder target exists"):
                    self.store.recover_helper_after_reboot(self.a, os.getuid())
                target.unlink()
                sandbox = cgroot / ("sandbox-" + self.a + "-" + intent["generation"])
                sandbox.mkdir()
                with self.assertRaisesRegex(SecurityError, "sandbox target exists"):
                    self.store.recover_helper_after_reboot(self.a, os.getuid())
                self.assertTrue(sandbox.is_dir())
                sandbox.rmdir()
            fake = {"version": 1, "id": self.a, "generation": intent["generation"],
                    "parent_dev": 1, "parent_ino": 2, "dev": 1, "ino": 3}
            record_path = folder / "helper-cgroup.json"
            record_path.write_text(json.dumps({**fake, "generation": "f" * 32}))
            record_path.chmod(0o600)
            with mock.patch.object(privileged, "_mounts_at", return_value=[]), mock.patch("os.kill") as kill:
                with self.assertRaisesRegex(SecurityError, "inconsistent helper journal"):
                    self.store.recover_helper_after_reboot(self.a, os.getuid())
                kill.assert_not_called()
            self.assertTrue((folder / "helper-intent.json").exists())
            record_path.write_text(json.dumps(fake))
            original = privileged._unlink_checked
            def interrupted(fd, name, uid, gid):
                original(fd, name, uid, gid)
                if name == "helper-cgroup.json":
                    raise RuntimeError("simulated crash after unlink")
            with mock.patch.object(privileged, "_mounts_at", return_value=[]), \
                 mock.patch.object(privileged, "_unlink_checked", side_effect=interrupted):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.store.recover_helper_after_reboot(self.a, os.getuid())
            self.assertTrue((folder / "helper-intent.json").exists())
            with mock.patch.object(privileged, "_mounts_at", return_value=[]):
                self.assertTrue(self.store.recover_helper_after_reboot(self.a, os.getuid())["stale_journals_removed"])
            self.assertFalse((folder / "helper-intent.json").exists())

    def test_post_boot_recovery_refuses_injected_non_system_store(self):
        with self.assertRaisesRegex(SecurityError, "fixed system store"):
            self.store.recover_helper_after_reboot(self.a, os.getuid())

    def test_policy_and_sandbox_journal_validation_rejects_tampering(self):
        intent = self.store.prepare_helper(self.a, os.getuid())
        devices = [(242, 1), (242, 2), (242, 3)]
        policy = {"version": 1, "id": self.a, "generation": intent["generation"], "boot": intent["boot"],
                  "program_id": 12, "tag": "a" * 16, "devices": [list(p) for p in devices],
                  "bytecode_sha256": hashlib.sha256(expected_instructions(devices)).hexdigest()}
        privileged._validate_policy_journal(policy, intent, self.a)
        with self.assertRaisesRegex(SecurityError, "digest"):
            privileged._validate_policy_journal({**policy, "bytecode_sha256": "0" * 64}, intent, self.a)
        sandbox = {"version": 1, "id": self.a, "generation": intent["generation"], "boot": intent["boot"],
                   "mount_namespace": intent["mount_namespace"],
                   "name": "sandbox-" + self.a + "-" + intent["generation"],
                   "parent_dev": 1, "parent_ino": 2, "dev": 1, "ino": 3}
        privileged._validate_sandbox_journal(sandbox, intent, self.a)
        with self.assertRaisesRegex(SecurityError, "sandbox"):
            privileged._validate_sandbox_journal({**sandbox, "name": "../../waydroid"}, intent, self.a)

    def test_same_boot_recovery_requires_dead_pid_and_resumes_after_interruption(self):
        from multiinstance.cgroup_anchor import SupervisorSession
        intent = self.store.prepare_helper(self.a, os.getuid())
        parent = self.base / "cg-same-boot"
        parent.mkdir(mode=0o700)
        group = parent / intent["cgroup_name"]
        group.mkdir(mode=0o700)
        (group / "cgroup.procs").write_text("")
        pfd = os.open(parent, _DIR_FLAGS)
        cfd = os.open(group, _DIR_FLAGS)
        self.addCleanup(os.close, pfd); self.addCleanup(os.close, cfd)
        session = object.__new__(SupervisorSession)
        session.cgroup = pfd
        session.verify = mock.Mock()
        with mock.patch.object(privileged, "_filesystem_type", return_value=privileged._CGROUP2_MAGIC):
            self.store.remember_helper_cgroup(self.a, os.getuid(), pfd, cfd)
        folder = self.base / "instances" / self.a
        process = {"version": 1, "id": self.a, "generation": intent["generation"], "boot": intent["boot"],
                   "pid": 424242, "start_ticks": 123, "pid_namespace": os.readlink("/proc/self/ns/pid")}
        path = folder / "helper-process.json"
        path.write_text(json.dumps(process)); path.chmod(0o600)
        group.rename(parent / "displaced")
        group.mkdir(mode=0o700)
        with mock.patch.object(self.store, "_require_system_recovery_store"), \
             mock.patch.object(privileged, "_filesystem_type", return_value=privileged._CGROUP2_MAGIC), \
             mock.patch.object(privileged.os, "pidfd_open", side_effect=OSError(errno.ESRCH, "gone")), \
             mock.patch.object(privileged.os, "kill") as kill:
            with self.assertRaisesRegex(SecurityError, "substituted"):
                self.store.recover_helper_same_boot_empty(self.a, os.getuid(), session)
            kill.assert_not_called()
        self.assertTrue(group.is_dir())
        self.assertFalse((folder / "helper-cleanup.json").exists())
        group.rmdir()
        (parent / "displaced").rename(group)
        with mock.patch.object(self.store, "_require_system_recovery_store"), \
             mock.patch.object(privileged, "_filesystem_type", return_value=privileged._CGROUP2_MAGIC), \
             mock.patch.object(privileged.os, "pidfd_open", return_value=os.open("/dev/null", os.O_RDONLY)):
            with self.assertRaisesRegex(SecurityError, "exists or was reused"):
                self.store.recover_helper_same_boot_empty(self.a, os.getuid(), session)
        self.assertTrue(group.is_dir())
        original_rmdir = os.rmdir
        def remove_fake_group(name, *, dir_fd):
            os.unlink("cgroup.procs", dir_fd=cfd)
            return original_rmdir(name, dir_fd=dir_fd)
        original_unlink = privileged._unlink_checked
        def interrupted(fd, name, uid, gid):
            original_unlink(fd, name, uid, gid)
            if name == "helper-process.json":
                raise RuntimeError("simulated interruption")
        with mock.patch.object(self.store, "_require_system_recovery_store"), \
             mock.patch.object(privileged, "_filesystem_type", return_value=privileged._CGROUP2_MAGIC), \
             mock.patch.object(privileged.os, "pidfd_open", side_effect=OSError(errno.ESRCH, "gone")), \
             mock.patch.object(privileged.os, "rmdir", side_effect=remove_fake_group), \
             mock.patch.object(privileged, "_unlink_checked", side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                self.store.recover_helper_same_boot_empty(self.a, os.getuid(), session)
        self.assertFalse(group.exists())
        self.assertTrue((folder / "helper-cleanup.json").exists())
        with mock.patch.object(self.store, "_require_system_recovery_store"), \
             mock.patch.object(privileged.os, "pidfd_open", side_effect=OSError(errno.ESRCH, "gone")):
            self.assertTrue(self.store.recover_helper_same_boot_empty(self.a, os.getuid(), session)["same_boot"])
        self.assertFalse((folder / "helper-intent.json").exists())
        self.assertFalse((folder / "helper-cleanup.json").exists())

    def test_same_boot_incomplete_state_refuses_cleanup(self):
        from multiinstance.cgroup_anchor import SupervisorSession
        intent = self.store.prepare_helper(self.a, os.getuid())
        parent = self.base / "cg-incomplete"
        parent.mkdir(mode=0o700)
        group = parent / intent["cgroup_name"]
        group.mkdir(mode=0o700)
        pfd = os.open(parent, _DIR_FLAGS)
        self.addCleanup(os.close, pfd)
        session = object.__new__(SupervisorSession)
        session.cgroup = pfd
        session.verify = mock.Mock()
        with mock.patch.object(self.store, "_require_system_recovery_store"), \
             mock.patch.object(privileged.os, "rmdir") as remove, mock.patch.object(privileged.os, "kill") as kill:
            with self.assertRaisesRegex(SecurityError, "incomplete helper evidence"):
                self.store.recover_helper_same_boot_empty(self.a, os.getuid(), session)
            remove.assert_not_called(); kill.assert_not_called()
        self.assertTrue(group.is_dir())

    def test_same_boot_missing_group_clears_journals_without_signals_or_rmdir(self):
        from multiinstance.cgroup_anchor import SupervisorSession
        intent = self.store.prepare_helper(self.a, os.getuid())
        parent = self.base / "cg-absent"
        parent.mkdir(mode=0o700)
        group = parent / intent["cgroup_name"]
        group.mkdir(mode=0o700)
        pfd, cfd = os.open(parent, _DIR_FLAGS), os.open(group, _DIR_FLAGS)
        self.addCleanup(os.close, pfd); self.addCleanup(os.close, cfd)
        session = object.__new__(SupervisorSession)
        session.cgroup = pfd
        session.verify = mock.Mock()
        with mock.patch.object(privileged, "_filesystem_type", return_value=privileged._CGROUP2_MAGIC):
            self.store.remember_helper_cgroup(self.a, os.getuid(), pfd, cfd)
        record = {"version": 1, "id": self.a, "generation": intent["generation"], "boot": intent["boot"],
                  "pid": 424242, "start_ticks": 123, "pid_namespace": os.readlink("/proc/self/ns/pid")}
        path = self.base / "instances" / self.a / "helper-process.json"
        path.write_text(json.dumps(record)); path.chmod(0o600)
        group.rmdir()
        with mock.patch.object(self.store, "_require_system_recovery_store"), \
             mock.patch.object(privileged.os, "pidfd_open", side_effect=OSError(errno.ESRCH, "gone")), \
             mock.patch.object(privileged.os, "rmdir") as remove, mock.patch.object(privileged.os, "kill") as kill:
            result = self.store.recover_helper_same_boot_empty(self.a, os.getuid(), session)
            self.assertTrue(result["same_boot"])
            remove.assert_not_called(); kill.assert_not_called()

    def test_reboot_can_finish_cleanup_when_original_journals_are_already_gone(self):
        from multiinstance import cgroup_anchor
        intent = self.store.prepare_helper(self.a, os.getuid())
        intent["boot"] = "00000000-0000-0000-0000-000000000001"
        cg = {"version": 1, "id": self.a, "generation": intent["generation"],
              "parent_dev": 1, "parent_ino": 2, "dev": 1, "ino": 3}
        process = {"version": 1, "id": self.a, "generation": intent["generation"], "boot": intent["boot"],
                   "pid": 424242, "start_ticks": 123, "pid_namespace": os.readlink("/proc/self/ns/pid")}
        folder = self.base / "instances" / self.a
        (folder / "helper-intent.json").unlink()
        marker = folder / "helper-cleanup.json"
        marker.write_text(json.dumps({"version": 1, "id": self.a, "intent": intent, "cgroup": cg, "process": process}))
        marker.chmod(0o600)
        parent = self.base / "cg-after-reboot"
        parent.mkdir(mode=0o700)
        pfd = os.open(parent, _DIR_FLAGS)
        self.addCleanup(os.close, pfd)
        with mock.patch.object(self.store, "_require_system_recovery_store"), \
             mock.patch.object(cgroup_anchor, "acquire_system_supervisor_lease", side_effect=lambda: os.open("/dev/null", os.O_RDONLY)), \
             mock.patch.object(cgroup_anchor, "open_system_service_cgroup", side_effect=lambda: os.dup(pfd)), \
             mock.patch.object(privileged, "_open_fixed_anchor", side_effect=lambda _path: os.dup(pfd)), \
             mock.patch.object(privileged, "_mounts_at", return_value=[]):
            self.assertTrue(self.store.recover_helper_after_reboot(self.a, os.getuid())["stale_journals_removed"])
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
