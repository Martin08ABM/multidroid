#!/usr/bin/env python3
"""Experimental CLI for instance identity and isolated data directories."""
import argparse
import json
import sys

from multiinstance.registry import Registry, RegistryError, default_root


def main():
    parser = argparse.ArgumentParser(description="Registro experimental de instancias Waydroid; aún no arranca Android")
    parser.add_argument("--root", default=default_root(), help="directorio del registro y datos")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "show"):
        item = commands.add_parser(command)
        item.add_argument("name")
    commands.add_parser("list")
    args = parser.parse_args()
    registry = Registry(args.root)
    try:
        if args.command == "create":
            result = registry.create(args.name)
        elif args.command == "show":
            result = registry.get(args.name)
        else:
            result = registry.list()
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (RegistryError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
