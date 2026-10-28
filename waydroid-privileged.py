#!/usr/bin/env python3
"""Experimental root CLI. It cannot start Android or manage networking."""
import argparse
import json
import os
import subprocess
import sys

if sys.flags.isolated:
    sys.path.insert(0, "/usr/lib/waydroid-multi")

from multiinstance.context import InstanceContext
from multiinstance.privileged import ProtectedStore, SecurityError, owner_from_uid
from multiinstance.resources import Resources


def main():
    parser = argparse.ArgumentParser(description="Experimental protected Waydroid registry; root required")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("init", help="prepare fixed protected directories on the host")
    actions.add_parser("list", help="list protected instance records")
    create = actions.add_parser("create", help="create one protected instance record")
    create.add_argument("--uid", required=True, type=int, help="existing non-root owner UID")
    create.add_argument("name", help="instance name")
    for name in ("inspect", "binder-start", "binder-stop", "recover"):
        action = actions.add_parser(name)
        action.add_argument("id", help="32 lowercase hexadecimal instance ID")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("root is required", file=sys.stderr)
        return 1
    try:
        store = ProtectedStore.system(create=args.action == "init")
        try:
            if args.action == "init":
                result = {"initialized": True}
            elif args.action == "list":
                result = store.list(0)
            elif args.action == "create":
                uid, gid = owner_from_uid(args.uid)
                result = {"id": store.create(uid, gid, args.name)}
            elif args.action == "inspect":
                record = store.inspect(args.id, 0)
                resource = Resources(args.id)
                context = InstanceContext(record["name"], str(resource.work), str(resource.data), "waydroid-mi-" + args.id)
                result = {"record": record, "context": context.describe(), "resources": resource.describe()}
            elif args.action == "binder-start":
                result = store.binder_start(args.id, 0)
            elif args.action == "recover":
                result = store.recover(args.id, 0)
            else:
                store.binder_stop(args.id, 0)
                result = {"stopped": args.id}
        finally:
            store.close()
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, SecurityError, subprocess.CalledProcessError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
