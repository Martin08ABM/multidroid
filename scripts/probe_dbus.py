#!/usr/bin/env python3
"""Exercise the adapter against a disposable real session bus and registry."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
from multiinstance.dbus_service import BUS_NAME, OBJECT_PATH, INTERFACE, Manager
from multiinstance.privileged import ProtectedStore, _DIR_FLAGS


def server(root):
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    name = dbus.service.BusName(BUS_NAME, bus, do_not_queue=True)
    root = Path(root)
    store = ProtectedStore(os.open(root / "instances", _DIR_FLAGS), os.open(root / "binders", _DIR_FLAGS), os.getuid(), os.getgid())
    manager = Manager(bus, store)
    try:
        GLib.MainLoop().run()
    finally:
        manager.remove_from_connection()
        store.close()
    return name


def client(root):
    proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "server", root],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        bus = dbus.SessionBus(private=True)
        deadline = time.monotonic() + 8
        while not bus.name_has_owner(BUS_NAME):
            if proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("private service did not start")
            time.sleep(0.05)
        client = dbus.Interface(bus.get_object(BUS_NAME, OBJECT_PATH), INTERFACE)
        created = json.loads(client.Create("dbus-probe"))
        records = json.loads(client.List())
        info = json.loads(client.Inspect(created["id"]))
        recovered = json.loads(client.Recover(created["id"]))
        try:
            client.ProbeBinder(created["id"])
        except dbus.DBusException as exc:
            helper_denied = exc.get_dbus_name().endswith("AccessDenied")
        else:
            helper_denied = False
        no_identity = not Path(root, "instances", created["id"], "identity.json").exists()
        try:
            bus.call_blocking(BUS_NAME, OBJECT_PATH, INTERFACE, "Create", "su", ("spoof", dbus.UInt32(0)))
        except dbus.DBusException:
            spoof_rejected = True
        else:
            spoof_rejected = False
        result = {"created_owner_is_real_uid": info["uid"] == os.getuid(),
                  "listed": len(records) == 1 and records[0]["id"] == created["id"],
                  "recover_idempotent": recovered["cleaned"] is False,
                  "production_helper_denied": helper_denied and no_identity,
                  "extra_uid_argument_rejected": spoof_rejected}
        if not all(result.values()):
            raise RuntimeError(str(result))
        print(json.dumps(result))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "server":
        return server(sys.argv[2])
    if len(sys.argv) == 3 and sys.argv[1] == "client":
        return client(sys.argv[2])
    with tempfile.TemporaryDirectory(prefix="waydroid-multi-dbus-") as tmp:
        Path(tmp, "instances").mkdir(mode=0o711)
        Path(tmp, "binders").mkdir(mode=0o700)
        result = subprocess.run(["dbus-run-session", "--", sys.executable, str(Path(__file__).resolve()), "client", tmp],
                                text=True, capture_output=True)
        if result.returncode:
            sys.exit(result.stderr)
        print(json.dumps(json.loads(result.stdout), indent=2))


if __name__ == "__main__":
    main()
