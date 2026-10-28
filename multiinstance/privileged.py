"""Root-only registry and narrowly scoped Binder lifecycle.

No Android or networking operations are implemented here. The public CLI uses
fixed system anchors; the injectable anchors below exist for isolated tests.
"""
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import pwd
import grp
import re
import select
import stat
import subprocess
import uuid

from multiinstance.binder import initialize_fresh_nodes
from multiinstance.identities import IdentityPool

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_NOFOLLOW | os.O_CLOEXEC
_BTRFS_MAGIC = 0x9123683E
_TMPFS_MAGIC = 0x01021994
_CGROUP2_MAGIC = 0x63677270
_ID = re.compile(r"[0-9a-f]{32}\Z")
_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
MAX_INSTANCES_PER_UID = 8


class SecurityError(RuntimeError):
    pass


def _no_acl(fd):
    for key in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            os.getxattr(fd, key)
        except OSError as exc:
            if exc.errno not in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
                raise
        else:
            raise SecurityError("extended ACL is not allowed on protected paths")


def _check(fd, uid, gid, mode=None, directory=True):
    info = os.fstat(fd)
    if (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) is False:
        raise SecurityError("unexpected file type")
    if info.st_uid != uid or info.st_gid != gid:
        raise SecurityError("unexpected owner or group")
    actual = stat.S_IMODE(info.st_mode)
    if (mode is not None and actual != mode) or (mode is None and actual & 0o022):
        raise SecurityError("unsafe permissions")
    if not directory and info.st_nlink != 1:
        raise SecurityError("protected file has multiple links")
    _no_acl(fd)
    return info


def _open_dir(parent, name, uid, gid, mode=None, create=False):
    if not name or name in (".", "..") or "/" in name:
        raise SecurityError("invalid path component")
    if create:
        try:
            os.mkdir(name, mode, dir_fd=parent)
        except FileExistsError:
            pass
    fd = os.open(name, _DIR_FLAGS, dir_fd=parent)
    try:
        _check(fd, uid, gid, mode)
    except Exception:
        os.close(fd)
        raise
    return fd


def _open_file(parent, name, uid, gid):
    fd = os.open(name, os.O_RDONLY | _FILE_FLAGS, dir_fd=parent)
    try:
        _check(fd, uid, gid, 0o600, directory=False)
    except Exception:
        os.close(fd)
        raise
    return fd


def _write_new(parent, name, value, uid, gid):
    temporary = ".journal-" + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_FLAGS, 0o600, dir_fd=parent)
    try:
        _check(fd, uid, gid, 0o600, directory=False)
        data = (json.dumps(value, sort_keys=True) + "\n").encode()
        while data:
            written = os.write(fd, data)
            if written <= 0:
                raise OSError("short write")
            data = data[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.renameat2(parent, os.fsencode(temporary), parent, os.fsencode(name), 1) != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), name)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def _read_json(parent, name, uid, gid):
    fd = _open_file(parent, name, uid, gid)
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as file:
            value = json.load(file)
    except Exception:
        raise
    return value


def _filesystem_type(fd):
    buf = ctypes.create_string_buffer(256)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.fstatfs(fd, ctypes.byref(buf)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ctypes.c_ulong.from_buffer(buf).value


def _open_fixed_anchor(path):
    """Traverse fixed system ancestors from / without following symlinks."""
    fd = os.open("/", _DIR_FLAGS)
    try:
        _check(fd, 0, 0)
        for component in path.strip("/").split("/"):
            child = _open_dir(fd, component, 0, 0)
            os.close(fd)
            fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def _mounts_at(path):
    # mountinfo escapes spaces, tab, newline and backslash using octal.
    def unescape(value):
        return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)
    found = []
    with open("/proc/self/mountinfo", encoding="utf-8") as file:
        for line in file:
            left, right = line.rstrip().split(" - ", 1)
            fields, rest = left.split(), right.split()
            if unescape(fields[4]) == path:
                found.append((int(fields[0]), rest[0]))
    return found


def _mount_source(path, mount_id):
    def unescape(value):
        return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)
    with open("/proc/self/mountinfo", encoding="utf-8") as file:
        for line in file:
            left, right = line.rstrip().split(" - ", 1)
            fields, rest = left.split(), right.split()
            if int(fields[0]) == mount_id and unescape(fields[4]) == path:
                return unescape(rest[1])
    return None


def _path_from_fd(fd):
    path = os.readlink(f"/proc/self/fd/{fd}")
    if not path.startswith("/") or path.endswith(" (deleted)"):
        raise SecurityError("directory anchor has been removed")
    a, b = os.fstat(fd), os.stat(path, follow_symlinks=False)
    if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
        raise SecurityError("directory anchor changed")
    return path


def _mount_identity():
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as file:
        boot = file.read().strip()
    return {"boot": boot, "namespace": os.readlink("/proc/self/ns/mnt")}


def _optional_json(parent, name, uid, gid):
    try:
        value = _read_json(parent, name, uid, gid)
    except FileNotFoundError:
        return None
    if value is None:
        raise SecurityError("null journal is not absence")
    return value


def _unlink_checked(parent, name, uid, gid):
    fd = _open_file(parent, name, uid, gid)
    os.close(fd)
    os.unlink(name, dir_fd=parent)
    os.fsync(parent)


def _validate_policy_journal(value, intent, identifier):
    from multiinstance.bpf_policy import expected_instructions
    keys = {"version", "id", "generation", "boot", "program_id", "tag", "devices", "bytecode_sha256"}
    if (not isinstance(value, dict) or set(value) != keys or type(value["version"]) is not int or value["version"] != 1 or
            value["id"] != identifier or value["generation"] != intent["generation"] or value["boot"] != intent["boot"] or
            type(value["program_id"]) is not int or not 0 < value["program_id"] < 2**32 or
            not isinstance(value["tag"], str) or not re.fullmatch(r"[0-9a-f]{16}", value["tag"]) or
            not isinstance(value["devices"], list) or any(not isinstance(pair, list) or len(pair) != 2 for pair in value["devices"]) or
            not isinstance(value["bytecode_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["bytecode_sha256"])):
        raise SecurityError("invalid helper policy journal")
    try:
        digest = hashlib.sha256(expected_instructions([tuple(pair) for pair in value["devices"]])).hexdigest()
    except ValueError as exc:
        raise SecurityError("invalid helper policy devices") from exc
    if digest != value["bytecode_sha256"]:
        raise SecurityError("helper policy digest differs")


def _validate_sandbox_journal(value, intent, identifier):
    keys = {"version", "id", "generation", "boot", "mount_namespace", "name", "parent_dev", "parent_ino", "dev", "ino"}
    if (not isinstance(value, dict) or set(value) != keys or type(value["version"]) is not int or value["version"] != 1 or
            value["id"] != identifier or value["generation"] != intent["generation"] or value["boot"] != intent["boot"] or
            value["mount_namespace"] != intent["mount_namespace"] or
            value["name"] != "sandbox-" + identifier + "-" + intent["generation"] or
            any(type(value[k]) is not int or value[k] <= 0 for k in ("parent_dev", "parent_ino", "dev", "ino")) or
            value["parent_dev"] != value["dev"]):
        raise SecurityError("invalid helper sandbox journal")


class ProtectedStore:
    """Operations anchored at validated root-owned instance and binder dirs."""

    def __init__(self, instances_fd, binder_fd, uid=0, gid=0):
        self.instances_fd, self.binder_fd = instances_fd, binder_fd
        self.uid, self.gid = uid, gid
        _check(instances_fd, uid, gid, 0o711)
        _check(binder_fd, uid, gid, 0o700)

    @classmethod
    def system(cls, create=False):
        if os.geteuid() != 0:
            raise PermissionError("root is required")
        var = _open_fixed_anchor("/var/lib")
        try:
            run = _open_fixed_anchor("/run")
        except Exception:
            os.close(var)
            raise
        opened = []
        try:
            if _filesystem_type(var) != _BTRFS_MAGIC:
                raise SecurityError("/var/lib must be on Btrfs")
            base = _open_dir(var, "waydroid-multi", 0, 0, 0o711, create)
            opened.append(base)
            instances = _open_dir(base, "instances", 0, 0, 0o711, create)
            opened.append(instances)
            runtime = _open_dir(run, "waydroid-multi", 0, 0, 0o700, create)
            opened.append(runtime)
            binder = _open_dir(runtime, "binderfs", 0, 0, 0o700, create)
            opened.append(binder)
            if _filesystem_type(instances) != _BTRFS_MAGIC or _filesystem_type(binder) != _TMPFS_MAGIC:
                raise SecurityError("protected instances must be on Btrfs and binder mounts on tmpfs")
            if os.fstat(var).st_dev != os.fstat(instances).st_dev or os.fstat(run).st_dev != os.fstat(binder).st_dev:
                raise SecurityError("unexpected nested mount under protected roots")
            result = cls(instances, binder)
            opened.remove(instances)
            opened.remove(binder)
            return result
        finally:
            for fd in opened:
                os.close(fd)
            os.close(var)
            os.close(run)

    def close(self):
        os.close(self.instances_fd)
        os.close(self.binder_fd)

    def _instance(self, identifier):
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
            raise SecurityError("invalid instance identifier")
        return _open_dir(self.instances_fd, identifier, self.uid, self.gid, 0o711)

    @contextlib.contextmanager
    def _lock(self, instance):
        fd = os.open("lock", os.O_RDWR | _FILE_FLAGS, dir_fd=instance)
        try:
            _check(fd, self.uid, self.gid, 0o600, directory=False)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def _registry_lock(self):
        fd = os.open("registry.lock", os.O_RDWR | os.O_CREAT | _FILE_FLAGS, 0o600, dir_fd=self.instances_fd)
        try:
            _check(fd, self.uid, self.gid, 0o600, directory=False)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def create(self, owner_uid, owner_gid, name):
        if any(not isinstance(x, int) or isinstance(x, bool) or x < 0 or x > 2**32 - 2 for x in (owner_uid, owner_gid)):
            raise ValueError("invalid owner")
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError("invalid instance name")
        with self._registry_lock():
            owned = 0
            for entry in os.listdir(self.instances_fd):
                if not _ID.fullmatch(entry):
                    continue
                other = self._instance(entry)
                try:
                    record = self._metadata(other, entry, allow_incomplete=True)
                    if record["uid"] == owner_uid:
                        owned += 1
                        if record["name"] == name:
                            raise FileExistsError("instance name already exists for this owner")
                finally:
                    os.close(other)
            if owned >= MAX_INSTANCES_PER_UID:
                raise SecurityError("instance limit reached")
            return self._create_locked(owner_uid, owner_gid, name)

    def _create_locked(self, owner_uid, owner_gid, name):
        identifier = uuid.uuid4().hex
        os.mkdir(identifier, 0o711, dir_fd=self.instances_fd)
        instance = self._instance(identifier)
        try:
            record = {"version": 1, "id": identifier, "name": name, "uid": owner_uid, "gid": owner_gid}
            _write_new(instance, "creation.json", record, self.uid, self.gid)
            self._complete_creation(instance, record)
            os.fsync(self.instances_fd)
            return identifier
        finally:
            os.close(instance)

    def _complete_creation(self, instance, record):
        work = _open_dir(instance, "work", self.uid, self.gid, 0o700, True)
        os.close(work)
        created = False
        try:
            os.mkdir("data", 0o700, dir_fd=instance)
            created = True
        except FileExistsError:
            pass
        data = os.open("data", _DIR_FLAGS, dir_fd=instance)
        try:
            if created:
                os.fchown(data, record["uid"], record["gid"])
            elif os.fstat(data).st_uid == self.uid and record["uid"] != self.uid:
                _check(data, self.uid, self.gid, 0o700)
                if os.listdir(data):
                    raise SecurityError("unowned creation data is not empty")
                os.fchown(data, record["uid"], record["gid"])
            _check(data, record["uid"], record["gid"], 0o700)
        finally:
            os.close(data)
        for name, value in (("lock", {}), ("instance.json", record)):
            existing = _optional_json(instance, name, self.uid, self.gid)
            if existing is None:
                _write_new(instance, name, value, self.uid, self.gid)
            elif existing != value:
                raise SecurityError("creation metadata does not match")
        _unlink_checked(instance, "creation.json", self.uid, self.gid)

    def _metadata(self, instance, identifier, allow_incomplete=False):
        record = _optional_json(instance, "instance.json", self.uid, self.gid)
        if record is None and allow_incomplete:
            record = _optional_json(instance, "creation.json", self.uid, self.gid)
        if not isinstance(record, dict) or set(record) != {"version", "id", "name", "uid", "gid"} or type(record["version"]) is not int or record["version"] != 1 or record["id"] != identifier:
            raise SecurityError("invalid registry record")
        if not isinstance(record["name"], str) or not _NAME.fullmatch(record["name"]):
            raise SecurityError("invalid registry name")
        if any(type(record[k]) is not int or record[k] < 0 or record[k] > 2**32 - 2 for k in ("uid", "gid")):
            raise SecurityError("invalid registry owner")
        return record

    def _record(self, instance, identifier, caller_uid):
        record = self._metadata(instance, identifier)
        if type(caller_uid) is not int or caller_uid not in (0, record["uid"]):
            raise PermissionError("caller does not own this instance")
        work = _open_dir(instance, "work", self.uid, self.gid, 0o700)
        os.close(work)
        data = _open_dir(instance, "data", record["uid"], record["gid"], 0o700)
        os.close(data)
        return record

    def inspect(self, identifier, caller_uid):
        instance = self._instance(identifier)
        try:
            with self._lock(instance):
                return self._record(instance, identifier, caller_uid)
        finally:
            os.close(instance)

    def list(self, caller_uid):
        if type(caller_uid) is not int or caller_uid < 0:
            raise PermissionError("invalid caller")
        records = []
        with self._registry_lock():
            for identifier in sorted(os.listdir(self.instances_fd)):
                if not _ID.fullmatch(identifier):
                    continue
                instance = self._instance(identifier)
                try:
                    record = self._metadata(instance, identifier, allow_incomplete=True)
                    if caller_uid == 0 or caller_uid == record["uid"]:
                        if _optional_json(instance, "instance.json", self.uid, self.gid) is None:
                            records.append({**record, "state": "creating"})
                        else:
                            with self._lock(instance):
                                records.append(self._record(instance, identifier, caller_uid))
                finally:
                    os.close(instance)
        return records

    def reserve_identity(self, identifier, caller_uid, pool):
        """Reserve a persistent helper UID/GID from an administrator-only pool."""
        if not isinstance(pool, IdentityPool):
            raise SecurityError("trusted identity pool is required")
        with self._registry_lock():
            target = self._instance(identifier)
            try:
                with self._lock(target):
                    owner = self._record(target, identifier, caller_uid)
                    expected_pool = {"version": 1, "uid_start": pool.uid_start,
                                     "gid_start": pool.gid_start, "count": pool.count}
                    pinned_pool = _optional_json(self.instances_fd, "identity-pool.json", self.uid, self.gid)
                    if pinned_pool is not None and (not isinstance(pinned_pool, dict) or
                            set(pinned_pool) != set(expected_pool) or
                            any(type(pinned_pool[k]) is not int or pinned_pool[k] != v
                                for k, v in expected_pool.items())):
                        raise SecurityError("identity pool differs from protected registry")
                    used = set()
                    current = None
                    for entry in os.listdir(self.instances_fd):
                        if not _ID.fullmatch(entry):
                            continue
                        other = self._instance(entry)
                        try:
                            value = _optional_json(other, "identity.json", self.uid, self.gid)
                            if value is None:
                                continue
                            if not isinstance(value, dict) or set(value) != {"version", "id", "uid", "gid"} or type(value["version"]) is not int or value["version"] != 1 or value["id"] != entry or type(value["uid"]) is not int or type(value["gid"]) is not int:
                                raise SecurityError("invalid identity record")
                            try:
                                index = pool.index(value["uid"], value["gid"])
                            except ValueError as exc:
                                raise SecurityError("identity outside current pool") from exc
                            if index in used:
                                raise SecurityError("identity collision")
                            used.add(index)
                            if entry == identifier:
                                current = value
                        finally:
                            os.close(other)
                    if current:
                        if current["uid"] == owner["uid"] or current["gid"] == owner["gid"]:
                            raise SecurityError("helper identity overlaps owner")
                        if pinned_pool is None:
                            _write_new(self.instances_fd, "identity-pool.json", expected_pool, self.uid, self.gid)
                        return current
                    free = next((i for i in range(pool.count) if i not in used and
                                 pool.at(i)[0] != owner["uid"] and pool.at(i)[1] != owner["gid"]), None)
                    if free is None:
                        raise SecurityError("identity pool exhausted")
                    uid, gid = pool.at(free)
                    value = {"version": 1, "id": identifier, "uid": uid, "gid": gid}
                    if pinned_pool is None:
                        _write_new(self.instances_fd, "identity-pool.json", expected_pool, self.uid, self.gid)
                    _write_new(target, "identity.json", value, self.uid, self.gid)
                    return value
            finally:
                os.close(target)

    def binder_start(self, identifier, caller_uid):
        instance = self._instance(identifier)
        try:
            with self._lock(instance):
                self._record(instance, identifier, caller_uid)
                self._reject_pending_helper(instance)
                if any(_optional_json(instance, name, self.uid, self.gid) is not None for name in ("binder.json", "binder-intent.json")):
                    raise SecurityError("binder state exists; recover first")
                identity = _mount_identity()
                intent = {"version": 2, "id": identifier, "source": "waydroid-multi-" + uuid.uuid4().hex, **identity}
                _write_new(instance, "binder-intent.json", intent, self.uid, self.gid)
                target = str(Path(_path_from_fd(self.binder_fd)) / identifier)
                mount_id = None
                created = False
                try:
                    os.mkdir(identifier, 0o700, dir_fd=self.binder_fd)
                    created = True
                    target_fd = _open_dir(self.binder_fd, identifier, self.uid, self.gid, 0o700)
                    try:
                        if _path_from_fd(target_fd) != target:
                            raise SecurityError("binder target changed")
                    finally:
                        os.close(target_fd)
                    if _mounts_at(target):
                        raise SecurityError("binder target is already mounted")
                    subprocess.run(["/usr/bin/mount", "-t", "binder", "-o", "max=4", intent["source"], target], check=True, capture_output=True)
                    mounts = _mounts_at(target)
                    if len(mounts) != 1 or mounts[0][1] != "binder":
                        raise SecurityError("could not verify newly created binder mount")
                    mount_id = mounts[0][0]
                    if _mount_source(target, mount_id) != intent["source"]:
                        raise SecurityError("binder mount source does not match intent")
                    initialize_fresh_nodes(target)
                    _write_new(instance, "binder.json", {"version": 3, "id": identifier, "mount_id": mount_id, "source": intent["source"], **identity}, self.uid, self.gid)
                    _unlink_checked(instance, "binder-intent.json", self.uid, self.gid)
                    return {"mount_id": mount_id, "nodes": [str(Path(target) / name) for name in ("binder", "hwbinder", "vndbinder")]}
                except Exception:
                    if mount_id is not None and _mounts_at(target) == [(mount_id, "binder")] and _mount_source(target, mount_id) == intent["source"]:
                        subprocess.run(["/usr/bin/umount", target], check=True, capture_output=True)
                    if not _mounts_at(target):
                        if created:
                            try:
                                os.rmdir(identifier, dir_fd=self.binder_fd)
                            except FileNotFoundError:
                                pass
                        if _optional_json(instance, "binder-intent.json", self.uid, self.gid) is not None:
                            _unlink_checked(instance, "binder-intent.json", self.uid, self.gid)
                    raise
        finally:
            os.close(instance)

    def binder_stop(self, identifier, caller_uid):
        self.recover(identifier, caller_uid)

    def _reject_pending_helper(self, instance):
        # Presence alone blocks Binder teardown, including malformed journals.
        for name in ("helper-intent.json", "helper-cgroup.json", "helper-process.json", "helper-cleanup.json", "helper-policy.json", "helper-sandbox.json"):
            try:
                os.stat(name, dir_fd=instance, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise SecurityError("helper state requires verified recovery before Binder changes")

    def prepare_helper(self, identifier, caller_uid):
        """Persist a generation before creating any helper resource; not a launcher.

        Only internal privileged code may call this. No resource cleanup or
        production helper launch is enabled by this journal.
        """
        instance = self._instance(identifier)
        try:
            with self._lock(instance):
                self._record(instance, identifier, caller_uid)
                self._reject_pending_helper(instance)
                if _optional_json(instance, "binder-intent.json", self.uid, self.gid) is not None:
                    raise SecurityError("Binder setup is incomplete")
                identity = _read_json(instance, "identity.json", self.uid, self.gid)
                if (not isinstance(identity, dict) or set(identity) != {"version", "id", "uid", "gid"} or
                        type(identity["version"]) is not int or identity["version"] != 1 or
                        identity["id"] != identifier or any(type(identity[k]) is not int or identity[k] <= 0 or
                        identity[k] >= 2**32 - 1 for k in ("uid", "gid"))):
                    raise SecurityError("invalid helper identity")
                state = _read_json(instance, "binder.json", self.uid, self.gid)
                current = _mount_identity()
                target = str(Path(_path_from_fd(self.binder_fd)) / identifier)
                if (not isinstance(state, dict) or set(state) != {"version", "id", "mount_id", "source", "boot", "namespace"} or
                        type(state.get("version")) is not int or state["version"] != 3 or state["id"] != identifier or
                        type(state["mount_id"]) is not int or state["mount_id"] <= 0 or
                        not isinstance(state["source"], str) or not re.fullmatch(r"waydroid-multi-[0-9a-f]{32}", state["source"]) or
                        state["boot"] != current["boot"] or state["namespace"] != current["namespace"] or
                        _mounts_at(target) != [(state["mount_id"], "binder")] or
                        _mount_source(target, state["mount_id"]) != state["source"]):
                    raise SecurityError("helper requires a verified Binder mount")
                generation = uuid.uuid4().hex
                intent = {"version": 1, "id": identifier, "generation": generation,
                          "cgroup_name": "wm-" + identifier + "-" + generation,
                          "boot": current["boot"], "mount_namespace": current["namespace"],
                          "cgroup_namespace": os.readlink("/proc/self/ns/cgroup"),
                          "binder_mount_id": state["mount_id"], "binder_source": state["source"],
                          "uid": identity["uid"], "gid": identity["gid"]}
                _write_new(instance, "helper-intent.json", intent, self.uid, self.gid)
                return intent
        finally:
            os.close(instance)

    def remember_helper_cgroup(self, identifier, caller_uid, parent_fd, cgroup_fd):
        """Record cgroup inode evidence; no ownership or cleanup is implied."""
        instance = self._instance(identifier)
        try:
            with self._lock(instance):
                self._record(instance, identifier, caller_uid)
                intent = _read_json(instance, "helper-intent.json", self.uid, self.gid)
                keys = {"version", "id", "generation", "cgroup_name", "boot", "mount_namespace",
                        "cgroup_namespace", "binder_mount_id", "binder_source", "uid", "gid"}
                if (not isinstance(intent, dict) or set(intent) != keys or type(intent.get("version")) is not int or
                        intent["version"] != 1 or intent["id"] != identifier or
                        not isinstance(intent["generation"], str) or not _ID.fullmatch(intent["generation"]) or
                        intent["cgroup_name"] != "wm-" + identifier + "-" + intent["generation"] or
                        any(type(intent[k]) is not int or intent[k] <= 0 for k in ("binder_mount_id", "uid", "gid")) or
                        not isinstance(intent["binder_source"], str) or not re.fullmatch(r"waydroid-multi-[0-9a-f]{32}", intent["binder_source"])):
                    raise SecurityError("invalid helper intent")
                current = _mount_identity()
                if (intent["boot"] != current["boot"] or intent["mount_namespace"] != current["namespace"] or
                        intent["cgroup_namespace"] != os.readlink("/proc/self/ns/cgroup")):
                    raise SecurityError("helper generation belongs to another boot or namespace")
                target = str(Path(_path_from_fd(self.binder_fd)) / identifier)
                if (_mounts_at(target) != [(intent["binder_mount_id"], "binder")] or
                        _mount_source(target, intent["binder_mount_id"]) != intent["binder_source"]):
                    raise SecurityError("helper Binder mount changed")
                parent, child = os.fstat(parent_fd), os.fstat(cgroup_fd)
                if (not stat.S_ISDIR(parent.st_mode) or not stat.S_ISDIR(child.st_mode) or
                        parent.st_uid != self.uid or child.st_uid != self.uid or
                        parent.st_gid != self.gid or child.st_gid != self.gid or
                        (parent.st_mode | child.st_mode) & 0o022 or
                        _filesystem_type(parent_fd) != _CGROUP2_MAGIC or _filesystem_type(cgroup_fd) != _CGROUP2_MAGIC or
                        parent.st_dev != child.st_dev):
                    raise SecurityError("unexpected cgroup filesystem or owner")
                entry = os.stat(intent["cgroup_name"], dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISDIR(entry.st_mode) or (entry.st_dev, entry.st_ino) != (child.st_dev, child.st_ino):
                    raise SecurityError("cgroup descriptor differs from intended child")
                evidence = {"version": 1, "id": identifier, "generation": intent["generation"],
                            "parent_dev": parent.st_dev, "parent_ino": parent.st_ino,
                            "dev": child.st_dev, "ino": child.st_ino}
                _write_new(instance, "helper-cgroup.json", evidence, self.uid, self.gid)
                return evidence
        finally:
            os.close(instance)

    def remember_helper_process(self, identifier, caller_uid, parent_fd, cgroup_fd, pid):
        """Record an observation of a live process in a recorded cgroup.

        This is not an authorization to signal or recover it. Membership can
        change after observation and a pidfd is not persistent across restart.
        """
        if type(pid) is not int or not 1 < pid < 2**31:
            raise SecurityError("invalid helper pid")
        instance = self._instance(identifier)
        try:
            with self._lock(instance):
                self._record(instance, identifier, caller_uid)
                intent = _read_json(instance, "helper-intent.json", self.uid, self.gid)
                cg = _read_json(instance, "helper-cgroup.json", self.uid, self.gid)
                current = _mount_identity()
                intent_keys = {"version", "id", "generation", "cgroup_name", "boot", "mount_namespace",
                               "cgroup_namespace", "binder_mount_id", "binder_source", "uid", "gid"}
                cg_keys = {"version", "id", "generation", "parent_dev", "parent_ino", "dev", "ino"}
                if (not isinstance(intent, dict) or set(intent) != intent_keys or
                        not isinstance(cg, dict) or set(cg) != cg_keys or
                        type(intent.get("version")) is not int or intent["version"] != 1 or
                        type(cg.get("version")) is not int or cg["version"] != 1 or
                        intent.get("id") != identifier or cg.get("id") != identifier or
                        not isinstance(intent.get("generation"), str) or not _ID.fullmatch(intent["generation"]) or
                        intent["cgroup_name"] != "wm-" + identifier + "-" + intent["generation"] or
                        any(type(cg[k]) is not int or cg[k] <= 0 for k in ("parent_dev", "parent_ino", "dev", "ino")) or
                        type(intent["binder_mount_id"]) is not int or intent["binder_mount_id"] <= 0 or
                        not isinstance(intent["binder_source"], str) or not re.fullmatch(r"waydroid-multi-[0-9a-f]{32}", intent["binder_source"]) or
                        any(type(intent[k]) is not int or intent[k] <= 0 for k in ("uid", "gid")) or
                        cg.get("generation") != intent["generation"] or
                        intent.get("boot") != current["boot"] or intent.get("mount_namespace") != current["namespace"] or
                        intent.get("cgroup_namespace") != os.readlink("/proc/self/ns/cgroup")):
                    raise SecurityError("helper journal mismatch")
                target = str(Path(_path_from_fd(self.binder_fd)) / identifier)
                if (_mounts_at(target) != [(intent["binder_mount_id"], "binder")] or
                        _mount_source(target, intent["binder_mount_id"]) != intent["binder_source"]):
                    raise SecurityError("helper Binder mount changed")
                parent, info = os.fstat(parent_fd), os.fstat(cgroup_fd)
                if (not stat.S_ISDIR(info.st_mode) or _filesystem_type(cgroup_fd) != _CGROUP2_MAGIC or
                        not stat.S_ISDIR(parent.st_mode) or _filesystem_type(parent_fd) != _CGROUP2_MAGIC or
                        (parent.st_uid, parent.st_gid) != (self.uid, self.gid) or
                        (info.st_uid, info.st_gid) != (self.uid, self.gid) or
                        (parent.st_mode | info.st_mode) & 0o022 or
                        (parent.st_dev, parent.st_ino) != (cg["parent_dev"], cg["parent_ino"]) or
                        (info.st_dev, info.st_ino) != (cg["dev"], cg["ino"])):
                    raise SecurityError("cgroup descriptor differs from recorded evidence")
                entry = os.stat(intent["cgroup_name"], dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISDIR(entry.st_mode) or (entry.st_dev, entry.st_ino) != (info.st_dev, info.st_ino):
                    raise SecurityError("cgroup entry differs from recorded evidence")
                pidfd = os.pidfd_open(pid, 0)
                try:
                    proc = Path("/proc") / str(pid)
                    with open(proc / "stat", encoding="ascii") as file:
                        raw = file.read(8192)
                    end = raw.rfind(")")
                    fields = raw[end + 2:].split() if end >= 0 else []
                    if len(fields) < 20 or not fields[19].isdigit():
                        raise SecurityError("invalid process stat")
                    ticks = int(fields[19])
                    pid_namespace = os.readlink(proc / "ns/pid")
                    fd = os.open("cgroup.procs", os.O_RDONLY | _FILE_FLAGS, dir_fd=cgroup_fd)
                    try:
                        members = os.read(fd, 1024 * 1024 + 1)
                    finally:
                        os.close(fd)
                    if len(members) > 1024 * 1024 or str(pid).encode() not in members.splitlines():
                        raise SecurityError("helper is not in recorded cgroup")
                    poller = select.poll()
                    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                    if poller.poll(0):
                        raise SecurityError("helper already exited")
                    record = {"version": 1, "id": identifier, "generation": intent["generation"],
                              "boot": intent["boot"], "pid": pid, "start_ticks": ticks,
                              "pid_namespace": pid_namespace}
                    _write_new(instance, "helper-process.json", record, self.uid, self.gid)
                    return record
                finally:
                    os.close(pidfd)
        finally:
            os.close(instance)

    def verify_helper_cgroup(self, identifier, caller_uid, parent_fd, cgroup_fd):
        """Compare current descriptors with the journal; never remove anything.

        This comparison is not proof of exclusive control over the parent or
        protection against inode reuse, and is not a cleanup authorization.
        """
        instance = self._instance(identifier)
        try:
            with self._lock(instance):
                self._record(instance, identifier, caller_uid)
                intent = _read_json(instance, "helper-intent.json", self.uid, self.gid)
                cg = _read_json(instance, "helper-cgroup.json", self.uid, self.gid)
                intent_keys = {"version", "id", "generation", "cgroup_name", "boot", "mount_namespace",
                               "cgroup_namespace", "binder_mount_id", "binder_source", "uid", "gid"}
                cg_keys = {"version", "id", "generation", "parent_dev", "parent_ino", "dev", "ino"}
                if (not isinstance(intent, dict) or set(intent) != intent_keys or
                        not isinstance(cg, dict) or set(cg) != cg_keys or
                        type(intent["version"]) is not int or intent["version"] != 1 or
                        type(cg["version"]) is not int or cg["version"] != 1 or
                        intent["id"] != identifier or cg["id"] != identifier or
                        not isinstance(intent["generation"], str) or not _ID.fullmatch(intent["generation"]) or
                        cg["generation"] != intent["generation"] or
                        intent["cgroup_name"] != "wm-" + identifier + "-" + intent["generation"] or
                        any(type(cg[k]) is not int or cg[k] <= 0 for k in ("parent_dev", "parent_ino", "dev", "ino"))):
                    raise SecurityError("invalid helper cgroup journal")
                current = _mount_identity()
                if (intent["boot"] != current["boot"] or intent["mount_namespace"] != current["namespace"] or
                        intent["cgroup_namespace"] != os.readlink("/proc/self/ns/cgroup")):
                    raise SecurityError("helper cgroup belongs to another boot or namespace")
                parent, child = os.fstat(parent_fd), os.fstat(cgroup_fd)
                if (not stat.S_ISDIR(parent.st_mode) or not stat.S_ISDIR(child.st_mode) or
                        (parent.st_uid, parent.st_gid) != (self.uid, self.gid) or
                        (child.st_uid, child.st_gid) != (self.uid, self.gid) or
                        (parent.st_mode | child.st_mode) & 0o022 or
                        _filesystem_type(parent_fd) != _CGROUP2_MAGIC or _filesystem_type(cgroup_fd) != _CGROUP2_MAGIC or
                        (parent.st_dev, parent.st_ino) != (cg["parent_dev"], cg["parent_ino"]) or
                        (child.st_dev, child.st_ino) != (cg["dev"], cg["ino"])):
                    raise SecurityError("cgroup evidence differs")
                entry = os.stat(intent["cgroup_name"], dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISDIR(entry.st_mode) or (entry.st_dev, entry.st_ino) != (child.st_dev, child.st_ino):
                    raise SecurityError("cgroup entry changed")
                return {"id": identifier, "generation": intent["generation"], "matched": True,
                        "cleanup_authorized": False}
        finally:
            os.close(instance)

    def record_helper_policy(self, identifier, caller_uid, session, cgroup_fd, program_fd):
        """Journal a kernel-verified three-device policy; does not launch a helper."""
        from multiinstance.bpf_policy import expected_instructions, inspect_policy
        from multiinstance.cgroup_anchor import SupervisorSession
        self._require_system_recovery_store()
        if not isinstance(session, SupervisorSession):
            raise SecurityError("verified supervisor session is required")
        session.verify()
        self.verify_helper_cgroup(identifier, caller_uid, session.cgroup, cgroup_fd)
        instance = self._instance(identifier)
        try:
            with self._lock(instance):
                self._record(instance, identifier, caller_uid)
                intent = _read_json(instance, "helper-intent.json", self.uid, self.gid)
                cg = _read_json(instance, "helper-cgroup.json", self.uid, self.gid)
                child = os.fstat(cgroup_fd)
                entry = os.stat(intent["cgroup_name"], dir_fd=session.cgroup, follow_symlinks=False)
                if ((child.st_dev, child.st_ino) != (cg["dev"], cg["ino"]) or
                        (entry.st_dev, entry.st_ino) != (child.st_dev, child.st_ino)):
                    raise SecurityError("cgroup changed before policy recording")
                target = str(Path(_path_from_fd(self.binder_fd)) / identifier)
                if (_mounts_at(target) != [(intent["binder_mount_id"], "binder")] or
                        _mount_source(target, intent["binder_mount_id"]) != intent["binder_source"]):
                    raise SecurityError("helper Binder mount changed")
                directory = os.open(identifier, _DIR_FLAGS, dir_fd=self.binder_fd)
                try:
                    devices = []
                    for name in ("binder", "hwbinder", "vndbinder"):
                        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                        if not stat.S_ISCHR(info.st_mode):
                            raise SecurityError("Binder device is not a character device")
                        devices.append((os.major(info.st_rdev), os.minor(info.st_rdev)))
                finally:
                    os.close(directory)
                verified = inspect_policy(cgroup_fd, program_fd, devices)
                session.verify()
                result = {"version": 1, "id": identifier, "generation": intent["generation"],
                          "boot": intent["boot"], **verified,
                          "bytecode_sha256": hashlib.sha256(expected_instructions(devices)).hexdigest()}
                _write_new(instance, "helper-policy.json", result, self.uid, self.gid)
                return result
        finally:
            os.close(instance)

    def record_helper_sandbox(self, identifier, caller_uid, session, sandbox_fd):
        """Record a verified empty-root sandbox directory; no cleanup authority."""
        from multiinstance.cgroup_anchor import SupervisorSession
        self._require_system_recovery_store()
        if not isinstance(session, SupervisorSession):
            raise SecurityError("verified supervisor session is required")
        session.verify()
        runtime = _open_fixed_anchor("/run/waydroid-multi")
        try:
            _check(runtime, 0, 0, 0o700)
            if _filesystem_type(runtime) != _TMPFS_MAGIC:
                raise SecurityError("sandbox parent is not tmpfs")
            instance = self._instance(identifier)
            try:
                with self._lock(instance):
                    self._record(instance, identifier, caller_uid)
                    intent = _read_json(instance, "helper-intent.json", self.uid, self.gid)
                    now = _mount_identity()
                    if (not isinstance(intent, dict) or intent.get("id") != identifier or
                            not isinstance(intent.get("generation"), str) or not _ID.fullmatch(intent["generation"]) or
                            intent.get("boot") != now["boot"] or intent.get("mount_namespace") != now["namespace"]):
                        raise SecurityError("invalid sandbox generation")
                    name = "sandbox-" + identifier + "-" + intent["generation"]
                    parent, child = os.fstat(runtime), _check(sandbox_fd, 0, 0, 0o700)
                    entry = os.stat(name, dir_fd=runtime, follow_symlinks=False)
                    target = "/run/waydroid-multi/" + name
                    if (not stat.S_ISDIR(entry.st_mode) or (entry.st_dev, entry.st_ino) != (child.st_dev, child.st_ino) or
                            parent.st_dev != child.st_dev or _filesystem_type(sandbox_fd) != _TMPFS_MAGIC or
                            os.listdir(sandbox_fd) or _mounts_at(target)):
                        raise SecurityError("sandbox directory changed or is not empty")
                    result = {"version": 1, "id": identifier, "generation": intent["generation"], "boot": intent["boot"],
                              "mount_namespace": intent["mount_namespace"], "name": name, "parent_dev": parent.st_dev,
                              "parent_ino": parent.st_ino, "dev": child.st_dev, "ino": child.st_ino}
                    session.verify()
                    _write_new(instance, "helper-sandbox.json", result, self.uid, self.gid)
                    return result
            finally:
                os.close(instance)
        finally:
            os.close(runtime)

    def verify_helper_sandbox(self, identifier, caller_uid, session, sandbox_fd):
        """Check a live host-side sandbox inode; never unmount or remove it."""
        from multiinstance.cgroup_anchor import SupervisorSession
        self._require_system_recovery_store()
        if not isinstance(session, SupervisorSession):
            raise SecurityError("verified supervisor session is required")
        session.verify()
        runtime = _open_fixed_anchor("/run/waydroid-multi")
        try:
            _check(runtime, 0, 0, 0o700)
            instance = self._instance(identifier)
            try:
                with self._lock(instance):
                    self._record(instance, identifier, caller_uid)
                    intent = _read_json(instance, "helper-intent.json", self.uid, self.gid)
                    state = _read_json(instance, "helper-sandbox.json", self.uid, self.gid)
                    _validate_sandbox_journal(state, intent, identifier)
                    now = _mount_identity()
                    if intent["boot"] != now["boot"] or intent["mount_namespace"] != now["namespace"]:
                        raise SecurityError("sandbox belongs to another boot or namespace")
                    parent, child = os.fstat(runtime), _check(sandbox_fd, 0, 0, 0o700)
                    entry = os.stat(state["name"], dir_fd=runtime, follow_symlinks=False)
                    if (not stat.S_ISDIR(entry.st_mode) or _filesystem_type(runtime) != _TMPFS_MAGIC or
                            _filesystem_type(sandbox_fd) != _TMPFS_MAGIC or
                            (parent.st_dev, parent.st_ino) != (state["parent_dev"], state["parent_ino"]) or
                            (child.st_dev, child.st_ino) != (state["dev"], state["ino"]) or
                            (entry.st_dev, entry.st_ino) != (child.st_dev, child.st_ino) or
                            _mounts_at("/run/waydroid-multi/" + state["name"])):
                        raise SecurityError("sandbox identity changed")
                    session.verify()
                    return {"id": identifier, "sandbox_verified": True, "cleanup_authorized": False}
            finally:
                os.close(instance)
        finally:
            os.close(runtime)

    def verify_helper_policy(self, identifier, caller_uid, session, cgroup_fd, program_fd):
        """Compare live BPF instructions and effective attachment to its journal."""
        from multiinstance.bpf_policy import expected_instructions, inspect_policy
        from multiinstance.cgroup_anchor import SupervisorSession
        self._require_system_recovery_store()
        if not isinstance(session, SupervisorSession):
            raise SecurityError("verified supervisor session is required")
        session.verify()
        self.verify_helper_cgroup(identifier, caller_uid, session.cgroup, cgroup_fd)
        instance = self._instance(identifier)
        try:
            with self._lock(instance):
                self._record(instance, identifier, caller_uid)
                intent = _read_json(instance, "helper-intent.json", self.uid, self.gid)
                policy = _read_json(instance, "helper-policy.json", self.uid, self.gid)
                _validate_policy_journal(policy, intent, identifier)
                devices = [tuple(pair) for pair in policy["devices"]]
                target = str(Path(_path_from_fd(self.binder_fd)) / identifier)
                if (_mounts_at(target) != [(intent["binder_mount_id"], "binder")] or
                        _mount_source(target, intent["binder_mount_id"]) != intent["binder_source"]):
                    raise SecurityError("helper Binder mount changed")
                directory = os.open(identifier, _DIR_FLAGS, dir_fd=self.binder_fd)
                try:
                    actual = []
                    for name in ("binder", "hwbinder", "vndbinder"):
                        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                        if not stat.S_ISCHR(info.st_mode):
                            raise SecurityError("Binder device is not a character device")
                        actual.append((os.major(info.st_rdev), os.minor(info.st_rdev)))
                finally:
                    os.close(directory)
                if actual != devices:
                    raise SecurityError("Binder devices differ from policy journal")
                verified = inspect_policy(cgroup_fd, program_fd, devices)
                if (verified["program_id"] != policy["program_id"] or verified["tag"] != policy["tag"] or
                        hashlib.sha256(expected_instructions(devices)).hexdigest() != policy["bytecode_sha256"]):
                    raise SecurityError("live helper policy differs from journal")
                session.verify()
                return {"id": identifier, "policy_verified": True, "cleanup_authorized": False}
        finally:
            os.close(instance)

    def observe_helper_pidfd(self, identifier, caller_uid):
        """Pin the recorded live PID for diagnosis, without authorizing signals.

        A matching process identity alone does not establish cgroup ownership,
        executable identity, supervisor ownership or an effective BPF policy.
        The caller must close the returned descriptor.
        """
        instance = self._instance(identifier)
        try:
            with self._lock(instance):
                self._record(instance, identifier, caller_uid)
                intent = _read_json(instance, "helper-intent.json", self.uid, self.gid)
                record = _read_json(instance, "helper-process.json", self.uid, self.gid)
                keys = {"version", "id", "generation", "boot", "pid", "start_ticks", "pid_namespace"}
                if (not isinstance(intent, dict) or not isinstance(record, dict) or set(record) != keys or
                        type(record["version"]) is not int or record["version"] != 1 or
                        record["id"] != identifier or intent.get("id") != identifier or
                        not isinstance(record["generation"], str) or not _ID.fullmatch(record["generation"]) or
                        intent.get("generation") != record["generation"] or
                        type(record["pid"]) is not int or not 1 < record["pid"] < 2**31 or
                        type(record["start_ticks"]) is not int or record["start_ticks"] <= 0 or
                        not isinstance(record["pid_namespace"], str)):
                    raise SecurityError("invalid helper process journal")
                current = _mount_identity()
                if (record["boot"] != current["boot"] or intent.get("boot") != current["boot"] or
                        intent.get("mount_namespace") != current["namespace"] or
                        intent.get("cgroup_namespace") != os.readlink("/proc/self/ns/cgroup")):
                    raise SecurityError("helper belongs to another boot or namespace")
                pid = record["pid"]
                pidfd = os.pidfd_open(pid, 0)
                try:
                    proc = Path("/proc") / str(pid)
                    def start_ticks():
                        with open(proc / "stat", encoding="ascii") as file:
                            raw = file.read(8192)
                        end = raw.rfind(")")
                        fields = raw[end + 2:].split() if end >= 0 else []
                        if len(fields) < 20 or not fields[19].isdigit():
                            raise SecurityError("invalid process stat")
                        return int(fields[19])
                    before = start_ticks()
                    namespace = os.readlink(proc / "ns/pid")
                    after = start_ticks()
                    poller = select.poll()
                    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                    if (before != record["start_ticks"] or after != before or
                            namespace != record["pid_namespace"] or poller.poll(0)):
                        raise SecurityError("helper process identity changed or exited")
                    result = pidfd
                    pidfd = None
                    return result
                finally:
                    if pidfd is not None:
                        os.close(pidfd)
        finally:
            os.close(instance)

    def recover_helper_after_reboot(self, identifier, caller_uid):
        """Clear only stale journals after a boot change and verified absence.

        Internal, deliberately narrow: never signal a PID, remove a cgroup,
        or unmount Binder. Requires the fixed systemd anchor and exclusive
        supervisor lease. This is not yet enabled via the production service.
        """
        self._require_system_recovery_store()
        from multiinstance.cgroup_anchor import acquire_system_supervisor_lease, open_system_service_cgroup
        lease = acquire_system_supervisor_lease()
        try:
            parent_fd = open_system_service_cgroup()
            try:
                instance = self._instance(identifier)
                try:
                    with self._lock(instance):
                        self._record(instance, identifier, caller_uid)
                        cleanup = _optional_json(instance, "helper-cleanup.json", self.uid, self.gid)
                        intent = _optional_json(instance, "helper-intent.json", self.uid, self.gid)
                        had_intent = intent is not None
                        if cleanup is not None:
                            if (not isinstance(cleanup, dict) or set(cleanup) != {"version", "id", "intent", "cgroup", "process"} or
                                    type(cleanup["version"]) is not int or cleanup["version"] != 1 or cleanup["id"] != identifier or
                                    (intent is not None and intent != cleanup["intent"])):
                                raise SecurityError("invalid same-boot cleanup journal")
                            intent = cleanup["intent"]
                        if intent is None:
                            raise SecurityError("helper intent is missing")
                        keys = {"version", "id", "generation", "cgroup_name", "boot", "mount_namespace",
                                "cgroup_namespace", "binder_mount_id", "binder_source", "uid", "gid"}
                        if (not isinstance(intent, dict) or set(intent) != keys or
                                type(intent["version"]) is not int or intent["version"] != 1 or intent["id"] != identifier or
                                not isinstance(intent["generation"], str) or not _ID.fullmatch(intent["generation"]) or
                                intent["cgroup_name"] != "wm-" + identifier + "-" + intent["generation"] or
                                not isinstance(intent["boot"], str) or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", intent["boot"]) or
                                not isinstance(intent["mount_namespace"], str) or not re.fullmatch(r"mnt:\[\d+\]", intent["mount_namespace"]) or
                                not isinstance(intent["cgroup_namespace"], str) or not re.fullmatch(r"cgroup:\[\d+\]", intent["cgroup_namespace"]) or
                                any(type(intent[k]) is not int or intent[k] <= 0 for k in ("binder_mount_id", "uid", "gid")) or
                                any(intent[k] >= 2**32 - 1 for k in ("uid", "gid")) or
                                not isinstance(intent["binder_source"], str) or not re.fullmatch(r"waydroid-multi-[0-9a-f]{32}", intent["binder_source"])):
                            raise SecurityError("invalid helper intent; refusing recovery")
                        if intent["boot"] == _mount_identity()["boot"]:
                            raise SecurityError("helper belongs to current boot; refusing recovery")
                        sandbox = _optional_json(instance, "helper-sandbox.json", self.uid, self.gid)
                        if sandbox is not None:
                            _validate_sandbox_journal(sandbox, intent, identifier)
                        sandbox_name = "sandbox-" + identifier + "-" + intent["generation"]
                        policy = _optional_json(instance, "helper-policy.json", self.uid, self.gid)
                        if policy is not None:
                            _validate_policy_journal(policy, intent, identifier)
                        names = ("helper-process.json", "helper-cgroup.json")
                        current_journals = {name: _optional_json(instance, name, self.uid, self.gid) for name in names}
                        if cleanup is not None and ((not had_intent and any(v is not None for v in current_journals.values())) or
                                (current_journals["helper-process.json"] is not None and current_journals["helper-cgroup.json"] is None)):
                            raise SecurityError("impossible helper cleanup phase")
                        for name in names:
                            value = current_journals[name]
                            if cleanup is not None:
                                snapshot = cleanup["process" if name == "helper-process.json" else "cgroup"]
                                if value is not None and value != snapshot:
                                    raise SecurityError("cleanup journal disagrees with helper state")
                                value = snapshot
                            elif value is None:
                                continue
                            expected = ({"version", "id", "generation", "boot", "pid", "start_ticks", "pid_namespace"}
                                        if name == "helper-process.json" else
                                        {"version", "id", "generation", "parent_dev", "parent_ino", "dev", "ino"})
                            if (not isinstance(value, dict) or set(value) != expected or
                                    type(value["version"]) is not int or value["version"] != 1 or
                                    value["id"] != identifier or value["generation"] != intent["generation"]):
                                raise SecurityError("inconsistent helper journal; refusing recovery")
                            if name == "helper-process.json":
                                if (value["boot"] != intent["boot"] or type(value["pid"]) is not int or not 1 < value["pid"] < 2**31 or
                                        type(value["start_ticks"]) is not int or value["start_ticks"] <= 0 or
                                        not isinstance(value["pid_namespace"], str) or not re.fullmatch(r"pid:\[\d+\]", value["pid_namespace"])):
                                    raise SecurityError("invalid helper process journal")
                            elif (any(type(value[k]) is not int or value[k] <= 0 for k in ("parent_dev", "parent_ino", "dev", "ino")) or
                                    value["parent_dev"] != value["dev"]):
                                raise SecurityError("invalid helper cgroup journal")
                        try:
                            os.stat(intent["cgroup_name"], dir_fd=parent_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        else:
                            raise SecurityError("cgroup name exists in current boot; refusing recovery")
                        target = str(Path(_path_from_fd(self.binder_fd)) / identifier)
                        if _mounts_at(target):
                            raise SecurityError("Binder mount exists in current boot; refusing recovery")
                        try:
                            os.stat(identifier, dir_fd=self.binder_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        else:
                            raise SecurityError("Binder target exists in current boot; refusing recovery")
                        runtime = _open_fixed_anchor("/run/waydroid-multi")
                        try:
                            _check(runtime, self.uid, self.gid, 0o700)
                            sandbox_target = "/run/waydroid-multi/" + sandbox_name
                            if _mounts_at(sandbox_target):
                                raise SecurityError("sandbox mount exists in current boot; refusing recovery")
                            try:
                                os.stat(sandbox_name, dir_fd=runtime, follow_symlinks=False)
                            except FileNotFoundError:
                                pass
                            else:
                                raise SecurityError("sandbox target exists in current boot; refusing recovery")
                        finally:
                            os.close(runtime)
                        for name in (*names, "helper-policy.json", "helper-sandbox.json", "helper-intent.json", "helper-cleanup.json"):
                            if _optional_json(instance, name, self.uid, self.gid) is not None:
                                _unlink_checked(instance, name, self.uid, self.gid)
                        return {"id": identifier, "stale_journals_removed": True, "boot": intent["boot"]}
                finally:
                    os.close(instance)
            finally:
                os.close(parent_fd)
        finally:
            os.close(lease)

    def _require_system_recovery_store(self):
        if (os.geteuid() != 0 or (self.uid, self.gid) != (0, 0) or
                _path_from_fd(self.instances_fd) != "/var/lib/waydroid-multi/instances" or
                _path_from_fd(self.binder_fd) != "/run/waydroid-multi/binderfs" or
                _filesystem_type(self.instances_fd) != _BTRFS_MAGIC or
                _filesystem_type(self.binder_fd) != _TMPFS_MAGIC):
            raise SecurityError("stale recovery requires the fixed system store")
        var = _open_fixed_anchor("/var/lib")
        try:
            run = _open_fixed_anchor("/run")
            try:
                if (os.fstat(var).st_dev != os.fstat(self.instances_fd).st_dev or
                        os.fstat(run).st_dev != os.fstat(self.binder_fd).st_dev):
                    raise SecurityError("stale recovery store has an unexpected mount")
            finally:
                os.close(run)
        finally:
            os.close(var)

    def recover_helper_same_boot_empty(self, identifier, caller_uid, session):
        """Remove an empty, recorded cgroup only after the recorded PID is gone.

        This internal operation requires the cooperative service lease and a
        root-exclusive systemd delegation. It never signals a process. The
        immutable cleanup journal makes interruptions resumable; uncertainty
        about identity, namespace, PID or membership leaves everything blocked.
        """
        from multiinstance.cgroup_anchor import SupervisorSession
        self._require_system_recovery_store()
        if not isinstance(session, SupervisorSession):
            raise SecurityError("verified supervisor session is required")
        session.verify()
        parent_fd = session.cgroup
        instance = self._instance(identifier)
        try:
            with self._lock(instance):
                self._record(instance, identifier, caller_uid)
                if (_optional_json(instance, "helper-policy.json", self.uid, self.gid) is not None or
                        _optional_json(instance, "helper-sandbox.json", self.uid, self.gid) is not None):
                    raise SecurityError("policy or sandbox recovery is not yet verified")
                cleanup = _optional_json(instance, "helper-cleanup.json", self.uid, self.gid)
                intent = _optional_json(instance, "helper-intent.json", self.uid, self.gid)
                cg = _optional_json(instance, "helper-cgroup.json", self.uid, self.gid)
                process = _optional_json(instance, "helper-process.json", self.uid, self.gid)
                if cleanup is None:
                    if any(item is None for item in (intent, cg, process)):
                        raise SecurityError("incomplete helper evidence; refusing same-boot recovery")
                    cleanup = {"version": 1, "id": identifier, "intent": intent, "cgroup": cg, "process": process}
                    prepared = False
                else:
                    if (not isinstance(cleanup, dict) or set(cleanup) != {"version", "id", "intent", "cgroup", "process"} or
                            type(cleanup["version"]) is not int or cleanup["version"] != 1 or cleanup["id"] != identifier):
                        raise SecurityError("invalid helper cleanup journal")
                    for name, item in (("intent", intent), ("cgroup", cg), ("process", process)):
                        if item is not None and item != cleanup[name]:
                            raise SecurityError("helper cleanup journal disagrees with state")
                    if (intent is None and (cg is not None or process is not None)) or (process is not None and cg is None):
                        raise SecurityError("impossible helper cleanup phase")
                    intent, cg, process = cleanup["intent"], cleanup["cgroup"], cleanup["process"]
                    prepared = True
                ikeys = {"version", "id", "generation", "cgroup_name", "boot", "mount_namespace",
                         "cgroup_namespace", "binder_mount_id", "binder_source", "uid", "gid"}
                ckeys = {"version", "id", "generation", "parent_dev", "parent_ino", "dev", "ino"}
                pkeys = {"version", "id", "generation", "boot", "pid", "start_ticks", "pid_namespace"}
                if (not isinstance(intent, dict) or set(intent) != ikeys or not isinstance(cg, dict) or set(cg) != ckeys or
                        not isinstance(process, dict) or set(process) != pkeys or
                        any(type(item.get("version")) is not int or item["version"] != 1 for item in (intent, cg, process)) or
                        any(item.get("id") != identifier for item in (intent, cg, process)) or
                        not isinstance(intent["generation"], str) or not _ID.fullmatch(intent["generation"]) or
                        cg["generation"] != intent["generation"] or process["generation"] != intent["generation"] or
                        intent["cgroup_name"] != "wm-" + identifier + "-" + intent["generation"] or
                        any(type(cg[k]) is not int or cg[k] <= 0 for k in ("parent_dev", "parent_ino", "dev", "ino")) or
                        cg["parent_dev"] != cg["dev"] or type(process["pid"]) is not int or not 1 < process["pid"] < 2**31 or
                        type(process["start_ticks"]) is not int or process["start_ticks"] <= 0 or
                        process["boot"] != intent["boot"]):
                    raise SecurityError("invalid helper identity evidence")
                now = _mount_identity()
                if (intent["boot"] != now["boot"] or intent["mount_namespace"] != now["namespace"] or
                        intent["cgroup_namespace"] != os.readlink("/proc/self/ns/cgroup") or
                        process["pid_namespace"] != os.readlink("/proc/self/ns/pid")):
                    raise SecurityError("helper belongs to another boot or namespace")
                parent = os.fstat(parent_fd)
                if (parent.st_dev, parent.st_ino) != (cg["parent_dev"], cg["parent_ino"]):
                    raise SecurityError("delegated cgroup anchor differs from journal")
                try:
                    pidfd = os.pidfd_open(process["pid"], 0)
                except OSError as exc:
                    if exc.errno != errno.ESRCH:
                        raise
                else:
                    os.close(pidfd)
                    # Even an unrelated reused PID blocks; never signal it.
                    raise SecurityError("recorded PID exists or was reused; refusing recovery")
                try:
                    child_fd = os.open(intent["cgroup_name"], _DIR_FLAGS, dir_fd=parent_fd)
                except FileNotFoundError:
                    child_fd = None
                removed_cgroup = child_fd is not None
                if child_fd is None:
                    # No cgroup is removed here. Under an exclusive delegated
                    # parent, a vanished cgroup and absent PID permit journal
                    # cleanup only; recheck after publishing the cleanup intent.
                    if not prepared:
                        _write_new(instance, "helper-cleanup.json", cleanup, self.uid, self.gid)
                    session.verify()
                    try:
                        os.stat(intent["cgroup_name"], dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise SecurityError("cgroup appeared during recovery")
                if child_fd is not None:
                    try:
                        child = os.fstat(child_fd)
                        entry = os.stat(intent["cgroup_name"], dir_fd=parent_fd, follow_symlinks=False)
                        if (not stat.S_ISDIR(entry.st_mode) or (child.st_dev, child.st_ino) != (cg["dev"], cg["ino"]) or
                                (entry.st_dev, entry.st_ino) != (child.st_dev, child.st_ino) or
                                (child.st_uid, child.st_gid) != (self.uid, self.gid) or
                                child.st_mode & 0o022 or _filesystem_type(child_fd) != _CGROUP2_MAGIC):
                            raise SecurityError("helper cgroup was substituted")
                        for entry_name in os.listdir(child_fd):
                            if stat.S_ISDIR(os.stat(entry_name, dir_fd=child_fd, follow_symlinks=False).st_mode):
                                raise SecurityError("helper cgroup contains children")
                        procs = os.open("cgroup.procs", os.O_RDONLY | _FILE_FLAGS, dir_fd=child_fd)
                        try:
                            if os.read(procs, 1):
                                raise SecurityError("helper cgroup contains processes")
                        finally:
                            os.close(procs)
                        if not prepared:
                            _write_new(instance, "helper-cleanup.json", cleanup, self.uid, self.gid)
                        session.verify()
                        again = os.stat(intent["cgroup_name"], dir_fd=parent_fd, follow_symlinks=False)
                        if (again.st_dev, again.st_ino) != (child.st_dev, child.st_ino):
                            raise SecurityError("helper cgroup changed before removal")
                        os.rmdir(intent["cgroup_name"], dir_fd=parent_fd)
                    finally:
                        os.close(child_fd)
                for name in ("helper-process.json", "helper-cgroup.json", "helper-intent.json", "helper-cleanup.json"):
                    if _optional_json(instance, name, self.uid, self.gid) is not None:
                        _unlink_checked(instance, name, self.uid, self.gid)
                return {"id": identifier, "empty_cgroup_removed": removed_cgroup, "same_boot": True}
        finally:
            os.close(instance)

    def recover(self, identifier, caller_uid):
        # Complete a recorded creation without deleting existing data.
        with self._registry_lock():
            creating = self._instance(identifier)
            try:
                intent = _optional_json(creating, "creation.json", self.uid, self.gid)
                existing = _optional_json(creating, "instance.json", self.uid, self.gid)
                if intent is None and existing is None:
                    if caller_uid != 0:
                        raise PermissionError("unowned partial instance requires root recovery")
                    target = str(Path(_path_from_fd(self.binder_fd)) / identifier)
                    if _mounts_at(target):
                        raise SecurityError("unowned partial instance has a mount")
                    entries = os.listdir(creating)
                    if any(not re.fullmatch(r"\.journal-[0-9a-f]{32}", name) for name in entries):
                        raise SecurityError("unowned partial instance is not empty")
                    for name in entries:
                        _unlink_checked(creating, name, self.uid, self.gid)
                    os.rmdir(identifier, dir_fd=self.instances_fd)
                    os.fsync(self.instances_fd)
                    return {"id": identifier, "cleaned": True, "partial_creation": True}
                if intent is not None:
                    record = self._metadata(creating, identifier, allow_incomplete=True)
                    if intent != record:
                        raise SecurityError("creation journal mismatch")
                    if type(caller_uid) is not int or caller_uid not in (0, record["uid"]):
                        raise PermissionError("caller does not own this instance")
                    self._complete_creation(creating, record)
            finally:
                os.close(creating)
        instance = self._instance(identifier)
        try:
            with self._lock(instance):
                record = self._metadata(instance, identifier)
                if type(caller_uid) is not int or caller_uid not in (0, record["uid"]):
                    raise PermissionError("caller does not own this instance")
                self._reject_pending_helper(instance)
                intent = _optional_json(instance, "binder-intent.json", self.uid, self.gid)
                state = _optional_json(instance, "binder.json", self.uid, self.gid)
                if intent is not None:
                    expected = {"version", "id", "boot", "namespace"}
                    if isinstance(intent, dict) and intent.get("version") == 2:
                        expected.add("source")
                    if not isinstance(intent, dict) or set(intent) != expected or type(intent.get("version")) is not int or intent["version"] not in (1, 2) or intent["id"] != identifier or not isinstance(intent["boot"], str) or not isinstance(intent["namespace"], str) or (intent["version"] == 2 and (not isinstance(intent["source"], str) or not re.fullmatch(r"waydroid-multi-[0-9a-f]{32}", intent["source"]))):
                        raise SecurityError("invalid binder intent")
                if state is not None:
                    keys = {"version", "id", "boot", "namespace", "mount_id"}
                    if isinstance(state, dict) and state.get("version") == 3:
                        keys.add("source")
                    if not isinstance(state, dict) or set(state) != keys or type(state.get("version")) is not int or state["version"] not in (2, 3) or state["id"] != identifier or not isinstance(state["boot"], str) or not isinstance(state["namespace"], str) or (state["version"] == 3 and (not isinstance(state["source"], str) or not re.fullmatch(r"waydroid-multi-[0-9a-f]{32}", state["source"]))):
                        raise SecurityError("invalid binder journal")
                if state is not None and (type(state["mount_id"]) is not int or state["mount_id"] <= 0):
                    raise SecurityError("invalid binder mount id")
                if intent is not None and state is not None and intent["version"] == 2 and state["version"] == 3 and intent["source"] != state["source"]:
                    raise SecurityError("binder journals disagree")
                current = _mount_identity()
                for item in (intent, state):
                    if item and item["boot"] == current["boot"] and item["namespace"] != current["namespace"]:
                        raise SecurityError("binder belongs to another mount namespace")
                target = str(Path(_path_from_fd(self.binder_fd)) / identifier)
                try:
                    target_fd = os.open(identifier, _DIR_FLAGS, dir_fd=self.binder_fd)
                except FileNotFoundError:
                    target_fd = None
                if target_fd is not None:
                    try:
                        if _path_from_fd(target_fd) != target:
                            raise SecurityError("binder target changed")
                    finally:
                        os.close(target_fd)
                    if state is None and intent is None:
                        raise SecurityError("unrecorded binder directory; refusing cleanup")
                mounts = _mounts_at(target)
                if mounts:
                    known = (state is not None and state["version"] == 3 and state["boot"] == current["boot"] and
                             state["namespace"] == current["namespace"] and mounts == [(state["mount_id"], "binder")] and
                             _mount_source(target, state["mount_id"]) == state["source"])
                    intended = (state is None and intent is not None and intent["version"] == 2 and
                                intent["boot"] == current["boot"] and intent["namespace"] == current["namespace"] and
                                len(mounts) == 1 and mounts[0][1] == "binder" and
                                _mount_source(target, mounts[0][0]) == intent["source"])
                    if not (known or intended):
                        raise SecurityError("unverified binder mount; refusing cleanup")
                    subprocess.run(["/usr/bin/umount", target], check=True, capture_output=True)
                    if _mounts_at(target):
                        raise SecurityError("mount remains after unmount")
                if target_fd is not None:
                    directory = _open_dir(self.binder_fd, identifier, self.uid, self.gid, 0o700)
                    os.close(directory)
                    os.rmdir(identifier, dir_fd=self.binder_fd)
                for name, item in (("binder.json", state), ("binder-intent.json", intent)):
                    if item is not None:
                        _unlink_checked(instance, name, self.uid, self.gid)
                return {"id": identifier, "cleaned": bool(intent or state or target_fd is not None)}
        finally:
            os.close(instance)

    def recover_all(self):
        """Clean verified resources on service startup; isolate failures per ID."""
        results = {}
        for identifier in sorted(os.listdir(self.instances_fd)):
            if not _ID.fullmatch(identifier):
                continue
            try:
                results[identifier] = self.recover(identifier, 0)
            except Exception as exc:
                logging.error("could not recover instance %s: %s", identifier, exc)
                results[identifier] = {"error": "manual review required"}
        return results


def owner_from_uid(uid):
    if uid <= 0:
        raise ValueError("instance owner must be a non-root account")
    entry = pwd.getpwuid(uid)
    return entry.pw_uid, entry.pw_gid


def load_system_identity_pool():
    """Read an explicit root-owned pool and reject NSS/subordinate-ID overlap."""
    etc = _open_fixed_anchor("/etc")
    directory = None
    try:
        directory = _open_dir(etc, "waydroid-multi", 0, 0, 0o700)
        config = _read_json(directory, "identities.json", 0, 0)
        if not isinstance(config, dict) or set(config) != {"version", "uid_start", "gid_start", "count"} or type(config["version"]) is not int or config["version"] != 1:
            raise SecurityError("invalid identity pool configuration")
        pool = IdentityPool(config["uid_start"], config["gid_start"], config["count"])
        if min(pool.uid_start, pool.gid_start) < 65536:
            raise SecurityError("system identity pool must start at or above 65536")
        for filename, start in (("subuid", pool.uid_start), ("subgid", pool.gid_start)):
            fd = os.open(filename, os.O_RDONLY | _FILE_FLAGS, dir_fd=etc)
            try:
                _check(fd, 0, 0, None, directory=False)
                with os.fdopen(fd, "r", encoding="utf-8") as file:
                    fd = -1
                    for line in file:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        fields = line.split(":")
                        if len(fields) != 3 or not fields[1].isdigit() or not fields[2].isdigit():
                            raise SecurityError("invalid subordinate ID database")
                        other, count = int(fields[1]), int(fields[2])
                        if start < other + count and other < start + pool.count:
                            raise SecurityError("identity pool overlaps subordinate IDs")
            finally:
                if fd != -1:
                    os.close(fd)
        for index in range(pool.count):
            uid, gid = pool.at(index)
            try:
                pwd.getpwuid(uid)
            except KeyError:
                pass
            else:
                raise SecurityError("identity pool overlaps a system user")
            try:
                grp.getgrgid(gid)
            except KeyError:
                pass
            else:
                raise SecurityError("identity pool overlaps a system group")
        return pool
    finally:
        if directory is not None:
            os.close(directory)
        os.close(etc)
