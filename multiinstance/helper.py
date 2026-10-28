"""One-shot Binder helper backend, intentionally disabled without cgroup enforcement."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from multiinstance.binder import configure_private_access
from multiinstance.identities import binder_device_rules
from multiinstance.privileged import (SecurityError, _DIR_FLAGS, _mount_identity, _mount_source,
                                      _mounts_at, _path_from_fd, _read_json)


def _require_private_user_namespace():
    if os.geteuid() != 0:
        raise SecurityError("private test requires namespace root")
    with open("/proc/self/uid_map", encoding="ascii") as file:
        mappings = [tuple(map(int, line.split())) for line in file if line.strip()]
    if not mappings or any(outer == 0 for _inner, outer, _count in mappings):
        raise SecurityError("private test refuses a namespace mapping host root")


class ProbeBackend:
    def __init__(self, store, pool, worker_path, *, private_test=False):
        self.store, self.pool, self.worker_path = store, pool, worker_path
        self.private_test = private_test

    def probe(self, identifier, caller_uid):
        if not self.private_test:
            raise SecurityError("helper disabled until a verified cgroup device policy is active")
        _require_private_user_namespace()
        identity = self.store.reserve_identity(identifier, caller_uid, self.pool)
        instance = self.store._instance(identifier)
        try:
            with self.store._lock(instance):
                self.store._record(instance, identifier, caller_uid)
                state = _read_json(instance, "binder.json", self.store.uid, self.store.gid)
                current = _mount_identity()
                target = str(Path(_path_from_fd(self.store.binder_fd)) / identifier)
                if (not isinstance(state, dict) or state.get("version") != 3 or state.get("id") != identifier or
                    state.get("boot") != current["boot"] or state.get("namespace") != current["namespace"] or
                    type(state.get("mount_id")) is not int or
                    _mounts_at(target) != [(state["mount_id"], "binder")] or
                    _mount_source(target, state["mount_id"]) != state.get("source")):
                    raise SecurityError("Binder mount cannot be verified")
                configure_private_access(target, identity["gid"])
                fd = os.open(identifier, _DIR_FLAGS, dir_fd=self.store.binder_fd)
                try:
                    if _path_from_fd(fd) != target:
                        raise SecurityError("Binder directory changed")
                    rules = binder_device_rules([Path(target) / name for name in ("binder", "hwbinder", "vndbinder")])
                    root = _path_from_fd(self.store.binder_fd)
                    sandbox = tempfile.mkdtemp(prefix="helper-", dir=root)
                    try:
                        try:
                            result = subprocess.run([sys.executable, "-B", "-I", self.worker_path, str(fd),
                                                     str(identity["uid"]), str(identity["gid"]), sandbox],
                                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                    text=True, timeout=10, pass_fds=(fd,), close_fds=True,
                                                    cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C"}, check=True)
                        except subprocess.CalledProcessError as exc:
                            raise SecurityError("helper failed: " + (exc.stderr or "")[-2000:]) from exc
                        response = json.loads(result.stdout)
                        if (response.get("uid") != identity["uid"] or response.get("gid") != identity["gid"] or
                            not response.get("gbinder") or not response.get("privileges_dropped") or
                            response.get("control_visible") or response.get("host_etc_visible")):
                            raise SecurityError("helper isolation check failed")
                        for name in ("binder", "hwbinder", "vndbinder"):
                            info = os.stat(Path(target) / name, follow_symlinks=False)
                            device = response.get("devices", {}).get(name, {})
                            if device.get("major") != os.major(info.st_rdev) or device.get("minor") != os.minor(info.st_rdev):
                                raise SecurityError("helper opened an unexpected Binder device")
                        response["cgroup_rules_preview"] = rules
                        response["cgroup_enforced"] = False
                        return response
                    finally:
                        os.rmdir(sandbox)
                finally:
                    os.close(fd)
        finally:
            os.close(instance)
