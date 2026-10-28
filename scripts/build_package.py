#!/usr/bin/env python3
"""Build twice without touching pacman configuration or installing anything."""
import argparse
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PKGDIR = ROOT / "packaging" / "arch"
PACKAGE = "waydroid-multi-experimental-0.0.1-2-any.pkg.tar.zst"


def main():
    if os.geteuid() == 0:
        raise SystemExit("build as an unprivileged user")
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True, help="existing output directory, without this package")
    args = parser.parse_args()
    output = args.output.resolve(strict=True)
    if not output.is_dir() or (output / PACKAGE).exists():
        raise SystemExit("output must be a directory and package must not exist")
    with tempfile.TemporaryDirectory(prefix="waydroid-multi-build-") as temporary:
        root = Path(temporary)
        config = root / "pacman.conf"
        config.write_text("[options]\nArchitecture = auto\nSigLevel = Required DatabaseOptional\n")
        wrapper = root / "pacman-read-local"
        wrapper.write_text("#!/bin/sh\nexec /usr/bin/pacman --config " + shlex.quote(str(config)) + " \"$@\"\n")
        wrapper.chmod(0o700)
        builddir = root / "build"
        builddir.mkdir()
        hashes = []
        artifacts = []
        for index in (1, 2):
            destination = root / f"package-{index}"
            destination.mkdir()
            env = os.environ.copy()
            for key in ("FAKEROOTKEY", "FAKEROOTDONTTRYCHOWN", "LD_PRELOAD"):
                env.pop(key, None)
            env.update({"PACMAN": str(wrapper), "SOURCE_DATE_EPOCH": "1793059200",
                        "PKGDEST": str(destination), "BUILDDIR": str(builddir)})
            command = ["unshare", "--user", "--map-current-user", "--ipc", "makepkg", "--noconfirm", "--cleanbuild"]
            result = subprocess.run(command, cwd=PKGDIR, env=env, text=True, capture_output=True)
            if result.returncode or "payload not recognized" in result.stderr or "missing required signature" in result.stderr:
                raise SystemExit("build failed or emitted a relevant warning:\n" + result.stdout + result.stderr)
            package = destination / PACKAGE
            artifacts.append(package)
            hashes.append(hashlib.sha256(package.read_bytes()).hexdigest())
        if hashes[0] != hashes[1]:
            raise SystemExit("package builds differ: " + " ".join(hashes))
        with artifacts[0].open("rb") as source, (output / PACKAGE).open("xb") as target:
            shutil.copyfileobj(source, target)
        print(f"package={output / PACKAGE}\nsha256={hashes[0]}\nreproducible_same_builddir=true\n"
              "dependency_checks=enabled\npacman_scope=local_installed_database\nfakeroot_ipc=private")


if __name__ == "__main__":
    main()
