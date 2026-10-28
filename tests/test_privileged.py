import json
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from multiinstance import privileged
from multiinstance.privileged import ProtectedStore, SecurityError


class ProtectedStoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.instances, self.binders = root / "instances", root / "binders"
        self.instances.mkdir(mode=0o711)
        self.binders.mkdir(mode=0o700)
        self.store = ProtectedStore(os.open(self.instances, privileged._DIR_FLAGS),
                                    os.open(self.binders, privileged._DIR_FLAGS), os.getuid(), os.getgid())
        self.addCleanup(self.store.close)
        self.uid, self.gid = os.getuid(), os.getgid()

    def create(self):
        import uuid
        return self.store.create(self.uid, self.gid, "test-" + uuid.uuid4().hex[:10])

    def test_create_inspect_authorize_and_separate_data(self):
        first, second = self.create(), self.create()
        self.assertNotEqual(first, second)
        self.assertEqual(self.store.inspect(first, self.uid)["id"], first)
        with self.assertRaises(PermissionError):
            self.store.inspect(first, self.uid + 12345)
        (self.instances / first / "data" / "marker").write_text("a")
        self.assertFalse((self.instances / second / "data" / "marker").exists())
        self.assertEqual(len(self.store.list(self.uid)), 2)
        self.assertEqual(self.store.list(self.uid + 12345), [])

    def test_invalid_and_duplicate_names_are_rejected(self):
        for name in ("../escape", "bad/name", "Upper", ""):
            with self.assertRaises(ValueError):
                self.store.create(self.uid, self.gid, name)
        self.store.create(self.uid, self.gid, "valid-name")
        with self.assertRaises(FileExistsError):
            self.store.create(self.uid, self.gid, "valid-name")

    def test_concurrent_create_of_same_name_is_serialized(self):
        def create():
            try:
                return self.store.create(self.uid, self.gid, "same-name")
            except FileExistsError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: create(), range(2)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(len(self.store.list(self.uid)), 1)

    def test_metadata_hardlink_and_data_mode_are_rejected(self):
        identifier = self.create()
        root = self.instances / identifier
        os.link(root / "instance.json", root / "hardlink")
        with self.assertRaises(SecurityError):
            self.store.inspect(identifier, self.uid)
        (root / "hardlink").unlink()
        os.chmod(root / "data", 0o755)
        with self.assertRaises(SecurityError):
            self.store.inspect(identifier, self.uid)

    def test_untrusted_caller_cannot_start_binder_or_change_owner(self):
        identifier = self.create()
        with mock.patch.object(privileged.subprocess, "run") as run:
            with self.assertRaises(PermissionError):
                self.store.binder_start(identifier, self.uid + 12345)
            run.assert_not_called()
        self.assertEqual(list(self.binders.iterdir()), [])
        meta = self.instances / identifier / "instance.json"
        record = json.loads(meta.read_text())
        record["uid"] = self.uid + 12345
        meta.write_text(json.dumps(record))
        with self.assertRaises(SecurityError):
            self.store.inspect(identifier, 0)

    def test_path_escape_symlink_and_unsafe_permissions_rejected(self):
        identifier = self.create()
        for bad in ("../waydroid", identifier + "/data", "A" * 32, ""):
            with self.assertRaises(SecurityError):
                self.store.inspect(bad, self.uid)
        target = self.instances / ("b" * 32)
        target.symlink_to(self.instances / identifier, target_is_directory=True)
        with self.assertRaises(OSError):
            self.store.inspect("b" * 32, self.uid)
        os.chmod(self.instances / identifier / "work", 0o777)
        with self.assertRaises(SecurityError):
            self.store.inspect(identifier, self.uid)

    def test_metadata_corruption_and_symlink_rejected(self):
        identifier = self.create()
        meta = self.instances / identifier / "instance.json"
        meta.write_text(json.dumps({"version": 1, "id": "c" * 32, "name": "test", "uid": self.uid, "gid": self.gid}))
        with self.assertRaises(SecurityError):
            self.store.inspect(identifier, self.uid)
        meta.unlink()
        meta.symlink_to("/etc/passwd")
        with self.assertRaises(OSError):
            self.store.inspect(identifier, self.uid)

    def test_binder_lifecycle_and_failure_cleanup_are_isolated(self):
        a, b = self.create(), self.create()
        mounts = {}
        counter = iter(range(100, 200))
        def simulate(command, **kwargs):
            target = command[-1]
            if command[0] == "/usr/bin/mount":
                mounts[target] = [(next(counter), "binder")]
                sources[target] = command[-2]
            else:
                mounts.pop(target)
            return mock.Mock(returncode=0)
        sources = {}
        with mock.patch.object(privileged, "_mounts_at", side_effect=lambda path: mounts.get(path, [])), \
             mock.patch.object(privileged, "_mount_source", side_effect=lambda path, _id: sources.get(path)), \
             mock.patch.object(privileged.subprocess, "run", side_effect=simulate) as run, \
             mock.patch.object(privileged, "initialize_fresh_nodes"):
            self.store.binder_start(a, self.uid)
            self.store.binder_start(b, self.uid)
            self.store.binder_stop(a, self.uid)
            self.assertIn(str(self.binders / b), mounts)
            self.assertTrue((self.instances / b / "binder.json").is_file())
            state = json.loads((self.instances / b / "binder.json").read_text())
            mounts[str(self.binders / b)] = [(state["mount_id"] + 1, "binder")]
            before = run.call_count
            with self.assertRaises(SecurityError):
                self.store.binder_stop(b, self.uid)
            self.assertEqual(run.call_count, before)

    def test_binder_failed_setup_cleans_only_own_mount(self):
        identifier = self.create()
        mounts = {}
        sources = {}
        def simulate(command, **kwargs):
            if command[0] == "/usr/bin/mount":
                mounts[command[-1]] = [(222, "binder")]
                sources[command[-1]] = command[-2]
            else:
                mounts.pop(command[-1])
            return mock.Mock(returncode=0)
        with mock.patch.object(privileged, "_mounts_at", side_effect=lambda path: mounts.get(path, [])), \
             mock.patch.object(privileged, "_mount_source", side_effect=lambda path, _id: sources.get(path)), \
             mock.patch.object(privileged.subprocess, "run", side_effect=simulate), \
             mock.patch.object(privileged, "initialize_fresh_nodes", side_effect=OSError("failed")):
            with self.assertRaises(OSError):
                self.store.binder_start(identifier, self.uid)
        self.assertFalse(mounts)
        self.assertFalse((self.binders / identifier).exists())
        self.assertFalse((self.instances / identifier / "binder.json").exists())
        self.assertEqual(self.store.inspect(identifier, self.uid)["id"], identifier)

    def test_interrupted_creation_completes_without_removing_data(self):
        with mock.patch.object(self.store, "_complete_creation", side_effect=RuntimeError("power loss")):
            with self.assertRaises(RuntimeError):
                self.store.create(self.uid, self.gid, "unfinished")
        entry = self.store.list(self.uid)[0]
        self.assertEqual(entry["state"], "creating")
        with self.assertRaises(PermissionError):
            self.store.recover(entry["id"], self.uid + 9876)
        self.store.recover(entry["id"], self.uid)
        self.assertEqual(self.store.inspect(entry["id"], self.uid)["name"], "unfinished")
        self.assertFalse((self.instances / entry["id"] / "creation.json").exists())

    def test_recover_stale_state_preserves_other_instance(self):
        first, second = self.create(), self.create()
        instance = self.instances / first
        state = {"version": 2, "id": first, "mount_id": 345, **privileged._mount_identity()}
        fd = os.open(instance, privileged._DIR_FLAGS)
        try:
            privileged._write_new(fd, "binder.json", state, self.uid, self.gid)
        finally:
            os.close(fd)
        (self.binders / first).mkdir(mode=0o700)
        (self.instances / second / "data" / "marker").write_text("keep")
        with mock.patch.object(privileged, "_mounts_at", return_value=[]):
            self.assertTrue(self.store.recover(first, self.uid)["cleaned"])
            self.assertFalse(self.store.recover(first, self.uid)["cleaned"])
        self.assertEqual((self.instances / second / "data" / "marker").read_text(), "keep")

    def test_recovery_refuses_unproven_or_changed_mount(self):
        identifier = self.create()
        instance = self.instances / identifier
        fd = os.open(instance, privileged._DIR_FLAGS)
        try:
            privileged._write_new(fd, "binder-intent.json", {"version": 1, "id": identifier, **privileged._mount_identity()}, self.uid, self.gid)
        finally:
            os.close(fd)
        (self.binders / identifier).mkdir(mode=0o700)
        with mock.patch.object(privileged, "_mounts_at", return_value=[(123, "binder")]), \
             mock.patch.object(privileged.subprocess, "run") as run:
            with self.assertRaises(SecurityError):
                self.store.recover(identifier, self.uid)
            run.assert_not_called()
        self.assertTrue((instance / "binder-intent.json").exists())

    def test_recovery_requires_matching_random_mount_source(self):
        identifier = self.create()
        instance = self.instances / identifier
        fd = os.open(instance, privileged._DIR_FLAGS)
        try:
            privileged._write_new(fd, "binder-intent.json", {"version": 2, "id": identifier,
                                  "source": "waydroid-multi-" + "f" * 32,
                                  **privileged._mount_identity()}, self.uid, self.gid)
        finally:
            os.close(fd)
        (self.binders / identifier).mkdir(mode=0o700)
        with mock.patch.object(privileged, "_mounts_at", return_value=[(123, "binder")]), \
             mock.patch.object(privileged, "_mount_source", return_value="foreign"), \
             mock.patch.object(privileged.subprocess, "run") as run:
            with self.assertRaises(SecurityError):
                self.store.recover(identifier, self.uid)
            run.assert_not_called()
        self.assertTrue((instance / "binder-intent.json").exists())

    def test_root_recovers_empty_unowned_partial_but_keeps_unknown_content(self):
        identifier = "e" * 32
        path = self.instances / identifier
        path.mkdir(mode=0o711)
        with self.assertRaises(PermissionError):
            self.store.recover(identifier, self.uid if self.uid != 0 else 12345)
        self.assertTrue(self.store.recover(identifier, 0)["partial_creation"])
        self.assertFalse(path.exists())
        path.mkdir(mode=0o711)
        (path / "unknown").write_text("do not remove")
        with self.assertRaises(SecurityError):
            self.store.recover(identifier, 0)
        self.assertEqual((path / "unknown").read_text(), "do not remove")

    def test_per_user_instance_quota(self):
        for n in range(privileged.MAX_INSTANCES_PER_UID):
            self.store.create(self.uid, self.gid, "quota-" + str(n))
        with self.assertRaises(SecurityError):
            self.store.create(self.uid, self.gid, "overflow")


if __name__ == "__main__":
    unittest.main()
