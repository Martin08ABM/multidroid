"""Experimental D-Bus adapter; the bus, not the client, supplies each UID."""
import json
import logging
import threading

import dbus
import dbus.service

from multiinstance.privileged import owner_from_uid

BUS_NAME = "id.waydro.Multi.Container"
OBJECT_PATH = "/id/waydro/Multi"
INTERFACE = "id.waydro.Multi.Manager1"


class RequestError(dbus.DBusException):
    _dbus_error_name = "id.waydro.Multi.Error.RequestFailed"


class AccessDenied(dbus.DBusException):
    _dbus_error_name = "org.freedesktop.DBus.Error.AccessDenied"


class Manager(dbus.service.Object):
    def __init__(self, bus, store, helper_backend=None):
        self.store = store
        self.helper_backend = helper_backend
        self.guardians = {}
        self.guardian_lock = threading.Lock()
        super().__init__(bus, OBJECT_PATH)

    def _uid(self, sender, connection):
        if not sender or not str(sender).startswith(":"):
            raise AccessDenied("unique sender required")
        daemon = dbus.Interface(connection.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus"),
                                "org.freedesktop.DBus")
        try:
            uid = int(daemon.GetConnectionUnixUser(sender))
        except dbus.DBusException as exc:
            raise AccessDenied("cannot authenticate sender") from exc
        if uid < 0 or uid > 2**32 - 2:
            raise AccessDenied("invalid sender uid")
        return uid

    def _call(self, sender, connection, fn):
        uid = self._uid(sender, connection)
        try:
            return json.dumps(fn(uid), sort_keys=True)
        except PermissionError as exc:
            raise AccessDenied("not authorized") from exc
        except Exception as exc:
            logging.warning("manager request failed: %s", exc)
            raise RequestError("operation failed") from exc

    def _guardian(self, identifier, uid):
        """Return (or lazily create) a Guardian for this instance + caller.

        Guardians are keyed per instance per caller UID and removed on stop.
        """
        with self.guardian_lock:
            key = (identifier, uid)
            if key not in self.guardians:
                from multiinstance.guardian import Guardian
                self.guardians[key] = Guardian(self.store, identifier, uid)
            return self.guardians[key]

    def _drop_guardian(self, identifier, uid):
        with self.guardian_lock:
            self.guardians.pop((identifier, uid), None)

    @dbus.service.method(INTERFACE, in_signature="", out_signature="s", sender_keyword="sender", connection_keyword="connection")
    def List(self, sender=None, connection=None):
        return self._call(sender, connection, lambda uid: self.store.list(uid))

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
    def Create(self, name, sender=None, connection=None):
        def create(uid):
            owner, gid = owner_from_uid(uid)
            return {"id": self.store.create(owner, gid, str(name))}
        return self._call(sender, connection, create)

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
    def Inspect(self, identifier, sender=None, connection=None):
        return self._call(sender, connection, lambda uid: self.store.inspect(str(identifier), uid))

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
    def BinderStart(self, identifier, sender=None, connection=None):
        return self._call(sender, connection, lambda uid: self.store.binder_start(str(identifier), uid))

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
    def BinderStop(self, identifier, sender=None, connection=None):
        def stop(uid):
            self.store.binder_stop(str(identifier), uid)
            return {"stopped": str(identifier)}
        return self._call(sender, connection, stop)

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
    def StartInstance(self, identifier, sender=None, connection=None):
        def start(uid):
            g = self._guardian(str(identifier), uid)
            try:
                return g.start()
            except Exception:
                # On failure the guardian may retain journals; drop it so a
                # later attempt creates a fresh one instead of reusing broken
                # state.
                self._drop_guardian(str(identifier), uid)
                raise
        return self._call(sender, connection, start)

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
    def StopInstance(self, identifier, sender=None, connection=None):
        def stop(uid):
            g = self._guardian(str(identifier), uid)
            result = g.stop(graceful=True)
            self._drop_guardian(str(identifier), uid)
            return result
        return self._call(sender, connection, stop)

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
    def RestartInstance(self, identifier, sender=None, connection=None):
        def restart(uid):
            g = self._guardian(str(identifier), uid)
            result = g.restart()
            return result
        return self._call(sender, connection, restart)

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
    def InstanceStatus(self, identifier, sender=None, connection=None):
        return self._call(sender, connection,
                          lambda uid: self._guardian(str(identifier), uid).status())

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
    def Recover(self, identifier, sender=None, connection=None):
        return self._call(sender, connection, lambda uid: self.store.recover(str(identifier), uid))

    @dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
    def ProbeBinder(self, identifier, sender=None, connection=None):
        def probe(uid):
            if self.helper_backend is None:
                raise PermissionError("helper disabled until identity and cgroup isolation are verified")
            return self.helper_backend.probe(str(identifier), uid)
        return self._call(sender, connection, probe)
