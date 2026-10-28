import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from multiinstance import binder
from multiinstance.resources import Resources
from tools.helpers import drivers, ipc


class ResourcesTest(unittest.TestCase):
    def setUp(self):
        self.a = Resources("a" * 32)
        self.b = Resources("b" * 32)

    def test_layout_and_invalid_ids(self):
        self.assertEqual(str(self.a.work), "/var/lib/waydroid-multi/instances/" + "a" * 32 + "/work")
        self.assertEqual(self.a.system_bus, self.b.system_bus)
        self.assertNotEqual(self.a.container_object, self.b.container_object)
        self.assertNotEqual(self.a.session_bus, self.b.session_bus)
        self.assertTrue(set(self.a.binder_nodes).isdisjoint(self.b.binder_nodes))
        for invalid in ("../escape", "a" * 31, "A" * 32, "a" * 32 + "/data"):
            with self.assertRaises(ValueError):
                Resources(invalid)

    def test_dbus_client_routes_by_instance_and_preserves_default(self):
        bus = mock.Mock()
        with mock.patch.object(ipc.dbus, "SystemBus", return_value=bus), \
             mock.patch.object(ipc.dbus, "SessionBus", return_value=bus), \
             mock.patch.object(ipc.dbus, "Interface"):
            ipc.DBusContainerService(resources=self.a)
            bus.get_object.assert_called_with(self.a.system_bus, self.a.container_object)
            ipc.DBusSessionService(resources=self.b)
            bus.get_object.assert_called_with(self.b.session_bus, self.b.session_object)
            ipc.DBusContainerService()
            bus.get_object.assert_called_with("id.waydro.Container", "/ContainerManager")
            ipc.DBusSessionService()
            bus.get_object.assert_called_with("id.waydro.Session", "/SessionManager")

    def test_real_private_bus_keeps_second_name_after_first_release(self):
        code = """
import dbus, json, sys
a, b = sys.argv[1:]
bus_a = dbus.SessionBus(private=True)
bus_b = dbus.SessionBus(private=True)
assert bus_a.request_name(a, dbus.bus.NAME_FLAG_DO_NOT_QUEUE) == dbus.bus.REQUEST_NAME_REPLY_PRIMARY_OWNER
assert bus_b.request_name(b, dbus.bus.NAME_FLAG_DO_NOT_QUEUE) == dbus.bus.REQUEST_NAME_REPLY_PRIMARY_OWNER
assert bus_a.get_name_owner(a) != bus_b.get_name_owner(b)
bus_a.release_name(a)
assert not bus_b.name_has_owner(a)
assert bus_b.name_has_owner(b)
print(json.dumps({'ok': True}))
"""
        result = subprocess.run(["dbus-run-session", "--", sys.executable, "-c", code,
                                 self.a.session_bus, self.b.session_bus], text=True, capture_output=True)
        if result.returncode and "Failed to bind socket" in result.stderr and "Operation not permitted" in result.stderr:
            self.skipTest("sandbox blocks the private D-Bus socket")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"ok": True})

    def test_binder_allocation_opens_control_safely_and_never_reuses_collision(self):
        with mock.patch.object(binder.os, "open", return_value=99) as open_file, \
             mock.patch.object(binder.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFCHR)), \
             mock.patch.object(binder.os, "close") as close, \
             mock.patch.object(binder.fcntl, "ioctl", side_effect=FileExistsError("collision")):
            with self.assertRaises(FileExistsError):
                binder.allocate_nodes("/separate/binderfs")
        self.assertTrue(open_file.call_args.args[1] & os.O_NOFOLLOW)
        close.assert_called_once_with(99)

    def test_binder_allocation_submits_three_distinct_names(self):
        with mock.patch.object(binder.os, "open", return_value=99), \
             mock.patch.object(binder.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFCHR)), \
             mock.patch.object(binder.os, "close"), \
             mock.patch.object(binder.fcntl, "ioctl") as ioctl:
            nodes = binder.allocate_nodes("/separate/binderfs")
        self.assertEqual([path.name for path in nodes], list(binder.BINDER_NAMES))
        self.assertEqual([struct.unpack("256sII", call.args[2])[0].rstrip(b"\0").decode()
                          for call in ioctl.call_args_list], list(binder.BINDER_NAMES))
        self.assertTrue(all(call.args[1] == binder.BINDER_CTL_ADD for call in ioctl.call_args_list))

    def test_binder_rejects_partial_or_untrusted_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "binder").touch()
            with self.assertRaisesRegex(ValueError, "partially populated"):
                binder.initialize_fresh_nodes(path)
            (path / "hwbinder").touch()
            (path / "vndbinder").symlink_to("binder")
            with self.assertRaisesRegex(ValueError, "not a Binder character device"):
                binder.initialize_fresh_nodes(path)

    def test_binder_paths_are_confined_to_explicit_forms(self):
        self.assertEqual(drivers.binder_node_path("anbox-binder"), "/dev/anbox-binder")
        self.assertEqual(drivers.binder_node_path("/proc/self/fd/9/binder"), "/proc/self/fd/9/binder")
        valid = "/run/waydroid-multi/binderfs/" + "a" * 32 + "/hwbinder"
        self.assertEqual(drivers.binder_node_path(valid), valid)
        for value in ("../binder", "/etc/passwd", "/proc/self/fd/9/../../etc/passwd", "/dev/binder"):
            with self.assertRaises(ValueError):
                drivers.binder_node_path(value)

    def test_access_configuration_rejects_non_binderfs_and_root_group(self):
        with mock.patch.object(binder.os, "geteuid", return_value=0), tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                binder.configure_private_access(tmp, 0)
            with self.assertRaisesRegex(ValueError, "not binderfs"):
                binder.configure_private_access(tmp, 1234)


if __name__ == "__main__":
    unittest.main()
