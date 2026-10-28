import os
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import stat
import tempfile
import unittest
import signal
from unittest import mock

from multiinstance.helper import ProbeBackend, _require_private_user_namespace
from multiinstance.identities import IdentityPool, binder_device_rules
from multiinstance.privileged import ProtectedStore, SecurityError, _DIR_FLAGS
from multiinstance import privileged


class IdentityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        (base / "instances").mkdir(mode=0o711)
        (base / "binders").mkdir(mode=0o700)
        self.store = ProtectedStore(os.open(base / "instances", _DIR_FLAGS),
                                    os.open(base / "binders", _DIR_FLAGS), os.getuid(), os.getgid())
        self.addCleanup(self.store.close)
        self.a = self.store.create(os.getuid(), os.getgid(), "one")
        self.b = self.store.create(os.getuid(), os.getgid(), "two")

    def test_persistent_distinct_reservations_and_authorization(self):
        pool = IdentityPool(500000, 600000, 2)
        first = self.store.reserve_identity(self.a, os.getuid(), pool)
        self.assertEqual(first, self.store.reserve_identity(self.a, os.getuid(), pool))
        second = self.store.reserve_identity(self.b, os.getuid(), pool)
        self.assertNotEqual(first["uid"], second["uid"])
        self.assertNotEqual(first["gid"], second["gid"])
        with self.assertRaises(PermissionError):
            self.store.reserve_identity(self.a, os.getuid() + 9999, pool)
        with self.assertRaises(SecurityError):
            self.store.reserve_identity(self.a, os.getuid(), IdentityPool(700000, 800000, 2))

    def test_no_identity_reuse_when_pool_is_exhausted(self):
        pool = IdentityPool(500000, 600000, 1)
        self.store.reserve_identity(self.a, os.getuid(), pool)
        with self.assertRaises(SecurityError):
            self.store.reserve_identity(self.b, os.getuid(), pool)

    def test_pool_is_pinned_even_if_existing_identity_still_fits(self):
        self.store.reserve_identity(self.a, os.getuid(), IdentityPool(500000, 600000, 2))
        with self.assertRaisesRegex(SecurityError, "differs"):
            self.store.reserve_identity(self.b, os.getuid(), IdentityPool(500000, 600000, 3))

    def test_malformed_pool_pin_is_not_accepted(self):
        pool = IdentityPool(500000, 600000, 2)
        self.store.reserve_identity(self.a, os.getuid(), pool)
        path = Path(self.tmp.name, "instances", "identity-pool.json")
        record = json.loads(path.read_text())
        record["version"] = True
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(SecurityError, "differs"):
            self.store.reserve_identity(self.b, os.getuid(), pool)

    def test_interruption_before_and_after_identity_publication(self):
        pool = IdentityPool(500000, 600000, 2)
        for after in (False, True):
            with self.subTest(after_publication=after):
                # Each case has its own protected registry and real process locks.
                with tempfile.TemporaryDirectory() as temp:
                    base = Path(temp)
                    (base / "instances").mkdir(mode=0o711)
                    (base / "binders").mkdir(mode=0o700)
                    store = ProtectedStore(os.open(base / "instances", _DIR_FLAGS),
                                           os.open(base / "binders", _DIR_FLAGS), os.getuid(), os.getgid())
                    try:
                        a = store.create(os.getuid(), os.getgid(), "one")
                        b = store.create(os.getuid(), os.getgid(), "two")
                        child = os.fork()
                        if child == 0:
                            original = privileged._write_new
                            def interrupt(parent, name, value, uid, gid):
                                if name == "identity.json":
                                    if after:
                                        original(parent, name, value, uid, gid)
                                    os.kill(os.getpid(), signal.SIGKILL)
                                original(parent, name, value, uid, gid)
                            privileged._write_new = interrupt
                            store.reserve_identity(a, os.getuid(), pool)
                            os._exit(99)
                        _, status = os.waitpid(child, 0)
                        self.assertTrue(os.WIFSIGNALED(status))
                        self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                        first = store.reserve_identity(a, os.getuid(), pool)
                        second = store.reserve_identity(b, os.getuid(), pool)
                        self.assertEqual((first["uid"], first["gid"]), pool.at(0))
                        self.assertEqual((second["uid"], second["gid"]), pool.at(1))
                    finally:
                        store.close()

    def test_concurrent_reservations_do_not_collide(self):
        pool = IdentityPool(500000, 600000, 2)
        with ThreadPoolExecutor(max_workers=2) as executor:
            values = list(executor.map(lambda identifier: self.store.reserve_identity(identifier, os.getuid(), pool),
                                       (self.a, self.b)))
        self.assertNotEqual(values[0]["uid"], values[1]["uid"])
        self.assertNotEqual(values[0]["gid"], values[1]["gid"])

    def test_separate_processes_reserve_distinct_identities(self):
        pool = IdentityPool(500000, 600000, 2)
        children = []
        for identifier in (self.a, self.b):
            read_fd, write_fd = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                try:
                    result = self.store.reserve_identity(identifier, os.getuid(), pool)
                    os.write(write_fd, json.dumps(result).encode())
                finally:
                    os.close(write_fd)
                os._exit(0)
            os.close(write_fd)
            children.append((pid, read_fd))
        values = []
        for pid, read_fd in children:
            with os.fdopen(read_fd, "rb") as pipe:
                values.append(json.load(pipe))
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertEqual({v["uid"] for v in values}, {500000, 500001})
        self.assertEqual({v["gid"] for v in values}, {600000, 600001})

    def test_helper_identity_cannot_equal_owner(self):
        if os.getuid() == 0 or os.getgid() == 0:
            self.skipTest("owner is root; pool intentionally rejects zero")
        with self.assertRaises(SecurityError):
            self.store.reserve_identity(self.a, os.getuid(), IdentityPool(os.getuid(), os.getgid(), 1))

    def test_invalid_pools_and_helper_gate(self):
        for values in ((0, 1, 1), (1, 1, 0), (1, 1, 65), (True, 1, 1), (2**32 - 2, 1, 2)):
            with self.assertRaises(ValueError):
                IdentityPool(*values)
        backend = ProbeBackend(self.store, IdentityPool(500000, 600000, 2), "/unused")
        with mock.patch.object(self.store, "reserve_identity") as reserve, \
             mock.patch("multiinstance.helper.subprocess.run") as launch:
            with self.assertRaisesRegex(SecurityError, "cgroup"):
                backend.probe(self.a, os.getuid())
            reserve.assert_not_called()
            launch.assert_not_called()

    def test_private_test_cannot_run_with_host_root_mapping(self):
        with mock.patch("os.geteuid", return_value=0), \
             mock.patch("builtins.open", mock.mock_open(read_data="0 0 4294967295\n")):
            with self.assertRaisesRegex(SecurityError, "host root"):
                _require_private_user_namespace()

    def test_cgroup_fragment_uses_exact_device_numbers(self):
        infos = [mock.Mock(st_mode=stat.S_IFCHR, st_rdev=os.makedev(235, n)) for n in (1, 2, 3)]
        with mock.patch("os.stat", side_effect=infos):
            rules = binder_device_rules(["a", "b", "c"])
        self.assertEqual(rules, ["lxc.cgroup2.devices.deny = a"] +
                         [f"lxc.cgroup2.devices.allow = c 235:{n} rw" for n in (1, 2, 3)])
        with mock.patch("os.stat", return_value=mock.Mock(st_mode=stat.S_IFREG, st_rdev=0)):
            with self.assertRaises(ValueError):
                binder_device_rules(["a", "b", "c"])

    def test_system_pool_rejects_subordinate_overlap(self):
        base = Path(self.tmp.name) / "etc"
        (base / "waydroid-multi").mkdir(parents=True, mode=0o700)
        (base / "waydroid-multi" / "identities.json").write_text(json.dumps(
            {"version": 1, "uid_start": 200000, "gid_start": 200000, "count": 2}))
        (base / "subuid").write_text("alice:100000:65536\n")
        (base / "subgid").write_text("alice:100000:65536\n")
        with mock.patch.object(privileged, "_open_fixed_anchor", side_effect=lambda _path: os.open(base, _DIR_FLAGS)), \
             mock.patch.object(privileged, "_check"), \
             mock.patch.object(privileged.pwd, "getpwuid", side_effect=KeyError), \
             mock.patch.object(privileged.grp, "getgrgid", side_effect=KeyError):
            pool = privileged.load_system_identity_pool()
            self.assertEqual(pool.at(0), (200000, 200000))
            (base / "subuid").write_text("alice:199999:2\n")
            with self.assertRaisesRegex(SecurityError, "overlaps subordinate"):
                privileged.load_system_identity_pool()


if __name__ == "__main__":
    unittest.main()
