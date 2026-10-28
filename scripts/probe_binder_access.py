#!/usr/bin/env python3
"""Probe candidate Binder access under two dedicated groups in a private namespace."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gbinder
from multiinstance.binder import BINDER_NAMES, configure_private_access
from multiinstance.privileged import ProtectedStore, _DIR_FLAGS
from tools.helpers.drivers import binder_node_path


def actor(own_fd, other_fd, uid, gid):
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            def can_open(fd, name):
                try:
                    device = os.open(name, os.O_RDWR | os.O_CLOEXEC, dir_fd=fd)
                    os.close(device)
                    return "opened"
                except OSError as exc:
                    return f"errno:{exc.errno}"
            own = {name: can_open(own_fd, name) for name in BINDER_NAMES}
            other = {name: can_open(other_fd, name) for name in BINDER_NAMES}
            try:
                signal.alarm(4)
                service = gbinder.ServiceManager(binder_node_path(f"/proc/self/fd/{own_fd}/binder"))
                gbinder_result = "constructed" if service else "unavailable"
            except Exception as exc:
                gbinder_result = type(exc).__name__ + ": " + str(exc)
            finally:
                signal.alarm(0)
            os.write(write_fd, json.dumps({"uid": os.getuid(), "gid": os.getgid(), "own": own,
                                          "other": other, "control": can_open(own_fd, "binder-control"),
                                          "gbinder": gbinder_result}).encode())
        finally:
            os._exit(0)
    os.close(write_fd)
    chunks = []
    while True:
        data = os.read(read_fd, 65536)
        if not data:
            break
        chunks.append(data)
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    if not chunks:
        raise RuntimeError(f"actor terminated without results: {status}")
    return json.loads(b"".join(chunks))


def guest_actor(root):
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            os.chroot(root)
            os.chdir("/")
            os.setgroups([])
            os.setgid(10)
            os.setuid(10)
            result = {}
            for name in BINDER_NAMES:
                try:
                    fd = os.open("/dev/" + name, os.O_RDWR)
                    os.close(fd)
                    result[name] = "opened"
                except OSError as exc:
                    result[name] = f"errno:{exc.errno}"
            result["foreign_visible"] = os.path.exists("/foreign/dev/binder")
            os.write(write_fd, json.dumps(result).encode())
        finally:
            os._exit(0)
    os.close(write_fd)
    data = os.read(read_fd, 65536)
    os.close(read_fd)
    os.waitpid(pid, 0)
    if not data:
        raise RuntimeError("guest surrogate failed")
    return json.loads(data)


def child(root):
    base = Path(root)
    instances, binders = base / "instances", base / "binders"
    instances.mkdir(mode=0o711)
    binders.mkdir(mode=0o700)
    store = ProtectedStore(os.open(instances, _DIR_FLAGS), os.open(binders, _DIR_FLAGS))
    try:
        a, b = store.create(0, 0, "access-a"), store.create(0, 0, "access-b")
        store.binder_start(a, 0)
        store.binder_start(b, 0)
        configure_private_access(binders / a, 1)
        configure_private_access(binders / b, 2)
        fd_a = os.open(binders / a, _DIR_FLAGS)
        fd_b = os.open(binders / b, _DIR_FLAGS)
        try:
            first, second = actor(fd_a, fd_b, 1, 1), actor(fd_b, fd_a, 2, 2)
            same_uid = actor(fd_b, fd_a, 1, 2)
        finally:
            os.close(fd_a)
            os.close(fd_b)
        guest = base / "guest-a"
        (guest / "dev").mkdir(parents=True, mode=0o755)
        mounted = []
        try:
            for name in BINDER_NAMES:
                target = guest / "dev" / name
                target.touch()
                subprocess.run(["/usr/bin/mount", "--bind", str(binders / a / name), str(target)], check=True, capture_output=True)
                mounted.append(target)
            guest_result = guest_actor(guest)
        finally:
            for target in reversed(mounted):
                subprocess.run(["/usr/bin/umount", str(target)], check=True, capture_output=True)
        store.binder_stop(a, 0)
        store.binder_stop(b, 0)
        result = {"a": first, "b": second, "same_uid_distinct_group": same_uid, "guest_surrogate": guest_result}
        for actor_result in (first, second, same_uid):
            if not (all(value == "opened" for value in actor_result["own"].values()) and
                    all(value == "errno:13" for value in actor_result["other"].values()) and
                    actor_result["control"] == "errno:13" and
                    actor_result["gbinder"] == "constructed"):
                raise RuntimeError("Binder access probe failed: " + json.dumps(result))
        if any(guest_result[name] != "opened" for name in BINDER_NAMES) or guest_result["foreign_visible"]:
            raise RuntimeError("guest surrogate probe failed: " + json.dumps(result))
        print(json.dumps(result, indent=2))
    finally:
        store.close()


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "child":
        return child(sys.argv[2])
    with tempfile.TemporaryDirectory(prefix="waydroid-multi-access-", dir="/var/tmp") as tmp:
        result = subprocess.run(["unshare", "--user", "--map-root-user", "--map-auto", "--mount", "--propagation", "private",
                                 sys.executable, str(Path(__file__).resolve()), "child", tmp],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            sys.exit(result.stderr)
        print(result.stdout.strip())


if __name__ == "__main__":
    main()
