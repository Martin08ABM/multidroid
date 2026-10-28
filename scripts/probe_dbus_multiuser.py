#!/usr/bin/env python3
"""Real two-UID D-Bus authorization probe in a private user namespace."""
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
from multiinstance.dbus_service import BUS_NAME, Manager
from multiinstance.helper import ProbeBackend
from multiinstance.identities import IdentityPool
from multiinstance.privileged import ProtectedStore, _DIR_FLAGS


CLIENT = r'''
import dbus, json, os, sys
bus = dbus.SessionBus(private=True)
action, *args = sys.argv[1:]
try:
    if action == "OwnService":
        value = int(bus.request_name("id.waydro.Multi.Container", dbus.bus.NAME_FLAG_DO_NOT_QUEUE))
    else:
        signature = "" if action == "List" else "s"
        value = json.loads(bus.call_blocking("id.waydro.Multi.Container", "/id/waydro/Multi", "id.waydro.Multi.Manager1", action, signature, args, timeout=5))
    print(json.dumps({"uid": os.getuid(), "result": value}))
except dbus.DBusException as error:
    print(json.dumps({"uid": os.getuid(), "error": error.get_dbus_name()}))
'''


def server(root):
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    name = dbus.service.BusName(BUS_NAME, bus, do_not_queue=True)
    root = Path(root)
    store = ProtectedStore(os.open(root / "instances", _DIR_FLAGS), os.open(root / "binders", _DIR_FLAGS))
    worker = str(Path(__file__).resolve().parents[1] / "waydroid-binder-helper.py")
    # This private test intentionally does not claim cgroup device enforcement.
    backend = ProbeBackend(store, IdentityPool(60000, 60000, 8), worker, private_test=True)
    manager = Manager(bus, store, helper_backend=backend)
    GLib.MainLoop().run()
    return name, manager


def child(root):
    root = Path(root)
    os.chmod(root, 0o755)
    (root / "instances").mkdir(mode=0o711)
    (root / "binders").mkdir(mode=0o700)
    socket = root / "bus"
    policy = Path(__file__).resolve().parents[1] / "packaging/dbus/id.waydro.Multi.Container.conf"
    config = root / "bus.conf"
    config.write_text(f'''<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:path={socket}</listen><auth>EXTERNAL</auth>
<policy context="default"><allow user="*"/><allow send_destination="org.freedesktop.DBus"/><allow send_requested_reply="true"/><allow receive_requested_reply="true"/><allow receive_sender="*"/></policy>
<include>{policy}</include></busconfig>''')
    daemon = subprocess.Popen(["dbus-daemon", "--nofork", "--config-file", str(config), "--print-address=1"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    service = None
    try:
        address = daemon.stdout.readline().strip()
        if not address:
            raise RuntimeError("private D-Bus daemon failed: " + daemon.stderr.read())
        env = {**os.environ, "DBUS_SESSION_BUS_ADDRESS": address}
        service = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "server", str(root)],
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        bus = dbus.bus.BusConnection(address)
        deadline = time.monotonic() + 8
        while not bus.name_has_owner(BUS_NAME):
            if service.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("private service failed")
            time.sleep(0.05)

        def call(uid, action, *args):
            def drop():
                os.setgroups([])
                os.setgid(uid)
                os.setuid(uid)
            result = subprocess.run([sys.executable, "-c", CLIENT, action, *args], env=env,
                                    preexec_fn=drop, capture_output=True, text=True, check=True, timeout=10)
            return json.loads(result.stdout)

        a = call(1, "Create", "account-a")
        b = call(2, "Create", "account-b")
        if "result" not in a or "result" not in b:
            raise RuntimeError(f"creation failed: {a}; {b}")
        a_id, b_id = a["result"]["id"], b["result"]["id"]
        a_list, b_list = call(1, "List"), call(2, "List")
        other_inspect = call(1, "Inspect", b_id)
        other_recover = call(2, "Recover", a_id)
        other_start = call(1, "BinderStart", b_id)
        other_stop = call(2, "BinderStop", a_id)
        own_service = call(1, "OwnService")
        a_start, b_start = call(1, "BinderStart", a_id), call(2, "BinderStart", b_id)
        if "result" not in a_start or "result" not in b_start:
            raise RuntimeError(f"Binder start failed: {a_start}; {b_start}")
        a_helper, b_helper = call(1, "ProbeBinder", a_id), call(2, "ProbeBinder", b_id)
        if "result" not in a_helper or "result" not in b_helper:
            service.terminate()
            service.wait(timeout=5)
            raise RuntimeError(f"helper failed: {a_helper}; {b_helper}; {service.stderr.read()}")
        cross_helper = call(1, "ProbeBinder", b_id)
        first, second = a_helper["result"], b_helper["result"]
        def expected_rules(value):
            devices = value["devices"]
            return ["lxc.cgroup2.devices.deny = a"] + [
                f"lxc.cgroup2.devices.allow = c {devices[name]['major']}:{devices[name]['minor']} rw"
                for name in ("binder", "hwbinder", "vndbinder")
            ]
        c = call(1, "Create", "account-c")
        c_id = c["result"]["id"]
        c_start = call(1, "BinderStart", c_id)
        c_helper = call(1, "ProbeBinder", c_id)
        if "result" not in c_start or "result" not in c_helper:
            raise RuntimeError(f"same-owner helper failed: {c_start}; {c_helper}")
        third = c_helper["result"]
        stop_a = call(1, "BinderStop", a_id)
        still_b = call(2, "ProbeBinder", b_id)
        still_c = call(1, "ProbeBinder", c_id)
        stop_c = call(1, "BinderStop", c_id)
        stop_b = call(2, "BinderStop", b_id)
        result = {"distinct_real_uids": a["uid"] == 1 and b["uid"] == 2,
                  "a_sees_only_a": [item["id"] for item in a_list["result"]] == [a_id],
                  "b_sees_only_b": [item["id"] for item in b_list["result"]] == [b_id],
                  "other_inspect_denied": other_inspect.get("error") == "org.freedesktop.DBus.Error.AccessDenied",
                  "other_recover_denied": other_recover.get("error") == "org.freedesktop.DBus.Error.AccessDenied",
                  "other_start_denied": other_start.get("error") == "org.freedesktop.DBus.Error.AccessDenied",
                  "other_stop_denied": other_stop.get("error") == "org.freedesktop.DBus.Error.AccessDenied",
                  "nonroot_cannot_own_service_name": own_service.get("error") == "org.freedesktop.DBus.Error.AccessDenied",
                  "real_helpers_have_distinct_uid_gid": first["uid"] != second["uid"] and first["gid"] != second["gid"],
                  "real_gbinder_constructed": first["gbinder"] and second["gbinder"],
                  "helper_privileges_dropped": first["privileges_dropped"] and second["privileges_dropped"] and third["privileges_dropped"],
                  "helpers_use_distinct_binder": first["devices"]["binder"] != second["devices"]["binder"],
                  "same_owner_helpers_have_distinct_ids_and_binder": first["uid"] != third["uid"] and first["gid"] != third["gid"] and first["devices"]["binder"] != third["devices"]["binder"],
                  "helper_host_and_control_hidden": not first["host_etc_visible"] and not first["control_visible"] and not second["host_etc_visible"] and not second["control_visible"],
                  "cross_helper_denied": cross_helper.get("error") == "org.freedesktop.DBus.Error.AccessDenied",
                  "other_helpers_survive_first_stop": all("result" in item for item in (stop_a, still_b, still_c, stop_c, stop_b)),
                  "cgroup_rules_target_exact_own_devices": first["cgroup_rules_preview"] == expected_rules(first) and second["cgroup_rules_preview"] == expected_rules(second) and set(first["cgroup_rules_preview"][1:]).isdisjoint(second["cgroup_rules_preview"][1:]),
                  "cgroup_not_enforced_in_private_test": not first["cgroup_enforced"] and not second["cgroup_enforced"]}
        if not all(result.values()):
            raise RuntimeError(str(result))
        print(json.dumps(result))
    finally:
        for proc in (service, daemon):
            if proc is not None:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        # The temporary data directories are owned by mapped UIDs 1 and 2.
        # Return only these empty probe directories to the parent owner.
        for instance in (root / "instances").iterdir():
            data = instance / "data"
            if data.is_dir() and not data.is_symlink():
                os.chown(data, 0, 0, follow_symlinks=False)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "server":
        return server(sys.argv[2])
    if len(sys.argv) == 3 and sys.argv[1] == "child":
        return child(sys.argv[2])
    with tempfile.TemporaryDirectory(prefix="waydroid-multi-users-") as tmp:
        result = subprocess.run(["unshare", "--user", "--map-root-user", "--map-auto", "--mount", "--propagation", "private",
                                 sys.executable, str(Path(__file__).resolve()), "child", tmp], capture_output=True, text=True, timeout=45)
        if result.returncode:
            sys.exit(result.stderr)
        print(json.dumps(json.loads(result.stdout), indent=2))


if __name__ == "__main__":
    main()
