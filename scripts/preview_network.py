#!/usr/bin/env python3
"""Preview network names from current routes and links without host changes."""
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from multiinstance.network import plan, plan_many


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: preview_network.py INSTANCE_ID [INSTANCE_ID ...]")
    routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route", "show", "table", "all"], text=True))
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"], text=True))
    args = ([r["dst"] for r in routes if "dst" in r], [link["ifname"] for link in links],
            [link["address"] for link in links if "address" in link])
    result = plan(sys.argv[1], *args) if len(sys.argv) == 2 else plan_many(sys.argv[1:], *args)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
