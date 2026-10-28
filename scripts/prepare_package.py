#!/usr/bin/env python3
"""Produce a deterministic source archive and PKGBUILD; never installs."""
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "packaging" / "arch"
NAME = "waydroid-multi-experimental"
VERSION = "0.0.1"
FILES = (
    "LICENSE", "Makefile", "waydroid-multi-service.py", "waydroid-privileged.py", "waydroid-binder-helper.py", "waydroid-helper-launcher.py",
    "multiinstance/__init__.py", "multiinstance/binder.py", "multiinstance/context.py",
    "multiinstance/dbus_service.py", "multiinstance/privileged.py", "multiinstance/resources.py",
    "multiinstance/identities.py", "multiinstance/helper.py", "multiinstance/cgroup_anchor.py", "multiinstance/bpf_policy.py", "multiinstance/supervisor.py",
    "packaging/dbus/id.waydro.Multi.Container.conf",
    "packaging/systemd/waydroid-multi-container.service",
)


def main():
    if os.geteuid() == 0:
        raise SystemExit("prepare the source as an unprivileged user")
    OUT.mkdir(parents=True, exist_ok=True)
    archive = OUT / f"{NAME}-{VERSION}.tar.gz"
    with archive.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for relative in sorted(FILES):
                path = ROOT / relative
                if path.is_symlink() or not path.is_file():
                    raise ValueError(f"source must be a regular file: {relative}")
                data = path.read_bytes()
                entry = tarfile.TarInfo(f"{NAME}-{VERSION}/{relative}")
                entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = "root"
                tar.addfile(entry, io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    pkgbuild = f'''# Experimental review artifact; do not install before AUDITORIA_PRIVILEGIOS.md is resolved.
pkgname={NAME}
pkgver={VERSION}
pkgrel=2
pkgdesc="Experimental isolated Waydroid multi-instance service"
arch=('any')
url='https://github.com/waydroid/waydroid'
license=('GPL-3.0-or-later')
depends=('python' 'python-dbus' 'python-gobject' 'python-gbinder' 'dbus' 'systemd' 'util-linux')
makedepends=('make')
source=("$pkgname-$pkgver.tar.gz")
sha256sums=('{digest}')

package() {{
  make -C "$srcdir/$pkgname-$pkgver" stage-multi-privileged DESTDIR="$pkgdir"
}}
'''
    (OUT / "PKGBUILD").write_text(pkgbuild, encoding="utf-8")
    print(f"archive={archive}\nsha256={digest}\npkgbuild={OUT / 'PKGBUILD'}")


if __name__ == "__main__":
    main()
