"""Assemble a disposable guest runtime from the installed Python and gbinder.

This copies files for a VM initramfs; it is not a trusted production package.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import sysconfig


def build(root, project, include_store=False):
    import gbinder
    root = Path(root)
    stdlib = Path(sysconfig.get_path("stdlib"))
    guest_stdlib = root / str(stdlib).lstrip("/")
    def ignored(directory, names):
        return {name for name in names if name in {"site-packages", "__pycache__", "test", "tests", "ensurepip", "idlelib", "tkinter"}}
    shutil.copytree(stdlib, guest_stdlib, ignore=ignored, symlinks=False)
    site = guest_stdlib / "site-packages"
    site.mkdir()
    extension = Path(gbinder.__file__)
    shutil.copy2(extension, site / extension.name)
    python = root / "usr/bin/python3"
    python.parent.mkdir(parents=True)
    shutil.copy2(sys.executable, python)
    lab = root / "lab"
    lab.mkdir()
    shutil.copy2(project / "waydroid-binder-helper.py", lab)
    shutil.copy2(project / "scripts/vm_lab/hold_helper.py", lab)
    files = [Path(sys.executable), extension] + list((stdlib / "lib-dynload").glob("*.so"))
    if include_store:
        tree = lab / "project"
        shutil.copytree(project / "multiinstance", tree / "multiinstance", ignore=ignored)
        (tree / "scripts").mkdir()
        shutil.copy2(project / "scripts/probe_privileged.py", tree / "scripts")
        shutil.copy2(project / "scripts/vm_lab/store_bridge.py", lab)
        for name in ("mount", "umount", "sleep"):
            source = Path("/usr/bin") / name
            shutil.copy2(source, root / "usr/bin" / name)
            files.append(source)
    libraries = set()
    for file in files:
        result = subprocess.run(["ldd", str(file)], capture_output=True, text=True)
        if "not found" in result.stdout:
            if file in (Path(sys.executable), extension):
                raise RuntimeError(f"missing dependency: {file}: {result.stdout}")
            # Optional Python modules (for example tkinter) are not used by the lab.
            continue
        for line in result.stdout.splitlines():
            match = re.search(r"(?:=>\s+)?(/[^\s]+)\s+\(", line)
            if match:
                libraries.add(match.group(1))
    for path in sorted(libraries):
        source = Path(path)
        target = root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=True)
    loader = Path("/lib64/ld-linux-x86-64.so.2")
    target = root / str(loader).lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        shutil.copy2(loader, target, follow_symlinks=True)
