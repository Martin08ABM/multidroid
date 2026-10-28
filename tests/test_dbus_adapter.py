import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import dbus
from multiinstance.dbus_service import Manager, AccessDenied


class AdapterTest(unittest.TestCase):
    def setUp(self):
        self.manager = object.__new__(Manager)
        self.manager.store = mock.Mock()
        self.connection = mock.Mock()
        self.daemon = mock.Mock()

    def test_resolves_uid_from_unique_sender_and_passes_it_to_store(self):
        self.daemon.GetConnectionUnixUser.return_value = dbus.UInt32(1234)
        self.manager.store.inspect.return_value = {"uid": 1234}
        with mock.patch("multiinstance.dbus_service.dbus.Interface", return_value=self.daemon):
            value = self.manager.Inspect("a" * 32, sender=":1.9", connection=self.connection)
        self.daemon.GetConnectionUnixUser.assert_called_once_with(":1.9")
        self.manager.store.inspect.assert_called_once_with("a" * 32, 1234)
        self.assertEqual(json.loads(value)["uid"], 1234)

    def test_rejects_spoofed_sender_and_other_owner(self):
        with self.assertRaises(AccessDenied):
            self.manager.Inspect("a" * 32, sender="id.fake.Service", connection=self.connection)
        self.daemon.GetConnectionUnixUser.return_value = 1234
        self.manager.store.inspect.side_effect = PermissionError("different owner")
        with mock.patch("multiinstance.dbus_service.dbus.Interface", return_value=self.daemon):
            with self.assertRaises(AccessDenied):
                self.manager.Inspect("b" * 32, sender=":1.9", connection=self.connection)

    def test_service_helper_is_disabled_without_backend(self):
        self.manager.helper_backend = None
        self.daemon.GetConnectionUnixUser.return_value = 1234
        with mock.patch("multiinstance.dbus_service.dbus.Interface", return_value=self.daemon):
            with self.assertRaises(AccessDenied):
                self.manager.ProbeBinder("a" * 32, sender=":1.9", connection=self.connection)

    def test_review_staging_contains_service_and_policy(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(["make", "stage-multi-privileged", "DESTDIR=" + tmp], cwd=root,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(Path(tmp, "usr/lib/waydroid-multi/multiinstance/dbus_service.py").is_file())
            self.assertTrue(Path(tmp, "usr/lib/waydroid-multi/multiinstance/identities.py").is_file())
            self.assertTrue(Path(tmp, "usr/lib/waydroid-multi/multiinstance/cgroup_anchor.py").is_file())
            self.assertTrue(Path(tmp, "usr/lib/waydroid-multi/multiinstance/bpf_policy.py").is_file())
            self.assertTrue(Path(tmp, "usr/lib/waydroid-multi/multiinstance/supervisor.py").is_file())
            self.assertTrue(Path(tmp, "usr/lib/waydroid-multi/waydroid-helper-launcher.py").is_file())
            self.assertTrue(Path(tmp, "usr/lib/waydroid-multi/waydroid-binder-helper.py").is_file())
            self.assertTrue(Path(tmp, "usr/share/dbus-1/system.d/id.waydro.Multi.Container.conf").is_file())
            self.assertTrue(Path(tmp, "usr/lib/systemd/system/waydroid-multi-container.service").is_file())


if __name__ == "__main__":
    unittest.main()
