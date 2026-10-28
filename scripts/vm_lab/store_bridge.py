"""VM-only bridge between the PID 1 experiment and real ProtectedStore journals.

Cleanup is deliberately laboratory-only: PID 1 owns this entire disposable VM
and has already waited for the child and removed its cgroup. This is not a
host recovery implementation.
"""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, "/lab/project")
from multiinstance.identities import IdentityPool
from multiinstance.privileged import ProtectedStore, SecurityError, _DIR_FLAGS


def main():
    if os.geteuid() != 0 or "waydroid_vm_store_lab=1" not in Path("/proc/cmdline").read_text().split():
        raise RuntimeError("requires disposable laboratory VM")
    action = sys.argv[1]
    root = Path("/vmbridge")
    if action == "setup":
        root.mkdir(mode=0o700)
        (root / "instances").mkdir(mode=0o711)
        (root / "binders").mkdir(mode=0o700)
    store = ProtectedStore(os.open(root / "instances", _DIR_FLAGS), os.open(root / "binders", _DIR_FLAGS))
    try:
        if action == "setup":
            ids = [store.create(0, 0, name) for name in ("bridge-a", "bridge-b")]
            for identifier in ids:
                store.reserve_identity(identifier, 0, IdentityPool(1000, 1000, 2))
                store.binder_start(identifier, 0)
            (root / "ids").write_text("\n".join(ids) + "\n")
            return
        index = int(sys.argv[2])
        if index not in (0, 1):
            raise ValueError("invalid laboratory instance")
        identifier = (root / "ids").read_text().splitlines()[index]
        folder = root / "instances" / identifier
        if action == "prepare":
            intent = store.prepare_helper(identifier, 0)
            (root / f"cgname{index}").write_text(intent["cgroup_name"] + "\n")
        elif action == "blocked":
            try:
                store.binder_stop(identifier, 0)
            except SecurityError:
                pass
            else:
                raise RuntimeError("active helper did not block Binder cleanup")
        elif action in ("record", "process", "verify"):
            intent = json.loads((folder / "helper-intent.json").read_text())
            pfd = os.open("/cg", _DIR_FLAGS)
            cfd = os.open(intent["cgroup_name"], _DIR_FLAGS, dir_fd=pfd)
            try:
                if action == "record":
                    store.remember_helper_cgroup(identifier, 0, pfd, cfd)
                elif action == "process":
                    store.remember_helper_process(identifier, 0, pfd, cfd, int(sys.argv[3]))
                    try:
                        store.binder_stop(identifier, 0)
                    except SecurityError:
                        pass
                    else:
                        raise RuntimeError("live helper did not block Binder cleanup")
                else:
                    store.verify_helper_cgroup(identifier, 0, pfd, cfd)
            finally:
                os.close(cfd); os.close(pfd)
        elif action == "clear":
            # This manual action is permitted only in this isolated VM test;
            # PID 1 has already waited for the helper and removed the cgroup.
            intent = json.loads((folder / "helper-intent.json").read_text())
            if (Path("/cg") / intent["cgroup_name"]).exists():
                raise RuntimeError("refusing to clear journal while cgroup exists")
            for name in ("helper-process.json", "helper-cgroup.json", "helper-intent.json"):
                try:
                    (folder / name).unlink()
                except FileNotFoundError:
                    pass
        else:
            raise ValueError("invalid laboratory action")
    finally:
        store.close()


if __name__ == "__main__":
    try:
        main()
    except (SecurityError, FileNotFoundError) as exc:
        if len(sys.argv) > 1 and sys.argv[1] == "verify":
            print("VM_BRIDGE_REFUSED:", exc, file=sys.stderr)
            raise SystemExit(2)
        raise
