#!/usr/bin/env python3
"""System bus entry point. Never starts Android or installs any policy."""
import os
import signal
import sys

if sys.flags.isolated:
    sys.path.insert(0, "/usr/lib/waydroid-multi")

if __name__ == "__main__" and os.geteuid() != 0:
    sys.exit("root is required")

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
from multiinstance.dbus_service import BUS_NAME, Manager
from multiinstance.privileged import ProtectedStore


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(BUS_NAME, bus, do_not_queue=True)
    store = ProtectedStore.system(create=False)
    store.recover_all()
    manager = Manager(bus, store)
    loop = GLib.MainLoop()
    def shutdown(*_args):
        loop.quit()
        return False
    GLib.unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGTERM, shutdown)
    GLib.unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGINT, shutdown)
    try:
        loop.run()
    finally:
        manager.remove_from_connection()
        store.recover_all()
        store.close()
    return name


if __name__ == "__main__":
    main()
