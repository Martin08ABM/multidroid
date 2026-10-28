# Copyright 2022 Alessandro Astone
# SPDX-License-Identifier: GPL-3.0-or-later

# Currently implemented as FIFO
import os
import dbus

def DBusContainerService(object_path="/ContainerManager", intf="id.waydro.ContainerManager", resources=None):
    destination = "id.waydro.Container"
    if resources is not None:
        destination, object_path = resources.system_bus, resources.container_object
    return dbus.Interface(dbus.SystemBus().get_object(destination, object_path), intf)

def DBusSessionService(object_path="/SessionManager", intf="id.waydro.SessionManager", resources=None):
    destination = "id.waydro.Session"
    if resources is not None:
        destination, object_path = resources.session_bus, resources.session_object
    return dbus.Interface(dbus.SessionBus().get_object(destination, object_path), intf)
