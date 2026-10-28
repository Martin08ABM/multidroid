#!/usr/bin/env python3
"""Download signed Arch QEMU packages into a new private directory, without installation."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request

PACKAGES = ("qemu-system-x86", "qemu-common", "qemu-system-x86-firmware", "seabios",
            "capstone", "rdma-core", "libslirp", "vde2", "libxdp", "libcbor", "ndctl", "dtc")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="new private directory; must not exist")
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run as an unprivileged user")
    args.directory.mkdir(mode=0o700)
    output = args.directory.resolve()
    (output / "qemu").mkdir(mode=0o700)

    def fetch(package):
        arch = "any" if package == "seabios" else "x86_64"
        with urllib.request.urlopen(f"https://archlinux.org/packages/extra/{arch}/{package}/json/", timeout=30) as response:
            name = json.load(response)["filename"]
        if not re.fullmatch(r"[A-Za-z0-9+_.:-]+\.pkg\.tar\.zst", name) or not name.startswith(package + "-"):
            raise ValueError("invalid package filename from metadata")
        for suffix in ("", ".sig"):
            subprocess.run(["curl", "-fsSL", "--max-time", "120", "-o", str(output / (name + suffix)),
                            f"https://geo.mirror.pkgbuild.com/extra/os/x86_64/{name}{suffix}"], check=True)
        subprocess.run(["gpgv", "--keyring", "/etc/pacman.d/gnupg/pubring.kbx",
                        str(output / (name + ".sig")), str(output / name)], check=True)
        return name

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        names = list(executor.map(fetch, PACKAGES))
    for name in names:
        subprocess.run(["bsdtar", "-xf", str(output / name), "-C", str(output / "qemu")], check=True)
    print("Verified and extracted:", *names, sep="\n")
    print("QEMU:", output / "qemu/usr/bin/qemu-system-x86_64")
    print("Libraries:", output / "qemu/usr/lib")
    print("Firmware:", output / "qemu/usr/share/qemu")


if __name__ == "__main__":
    main()
