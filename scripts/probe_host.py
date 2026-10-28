#!/usr/bin/env python3
"""Probe an isolated temporary filesystem and mount namespace; never touches Waydroid."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from multiinstance.binder import initialize_fresh_nodes


def command(*args):
    return subprocess.run(args, text=True, capture_output=True)


def child(base):
    base = Path(base)
    result = {}
    lower, upper, work, merged = (base / name for name in ("lower", "upper", "ovlwork", "merged"))
    for directory in (lower, upper, work, merged):
        directory.mkdir()
    (lower / "origin").write_text("lower")
    (lower / "deleted").write_text("preserved")
    options = f"lowerdir={lower},upperdir={upper},workdir={work},userxattr"
    mounted = command("mount", "-t", "overlay", "overlay", "-o", options, str(merged))
    result["overlay_mount"] = {"ok": mounted.returncode == 0, "stderr": mounted.stderr.strip()}
    if mounted.returncode == 0:
        try:
            (merged / "origin").write_text("changed")
            (merged / "new").write_text("new")
            (merged / "deleted").unlink()
            result["overlay_isolation"] = {
                "ok": (lower / "origin").read_text() == "lower" and
                      (upper / "origin").read_text() == "changed" and (upper / "new").exists() and
                      (lower / "deleted").read_text() == "preserved" and not (merged / "deleted").exists()
            }
        finally:
            unmount = command("umount", str(merged))
            result["overlay_unmount"] = {"ok": unmount.returncode == 0, "stderr": unmount.stderr.strip()}

    devices = []
    mounted_binders = []
    result["binder_mounts"] = []
    try:
        for name in ("binder-a", "binder-b"):
            mountpoint = base / name
            mountpoint.mkdir()
            mounted = command("mount", "-t", "binder", "-o", "max=4", "binder", str(mountpoint))
            report = {"ok": mounted.returncode == 0, "stderr": mounted.stderr.strip()}
            result["binder_mounts"].append(report)
            if mounted.returncode != 0:
                continue
            mounted_binders.append((mountpoint, report))
            try:
                nodes = initialize_fresh_nodes(mountpoint)
                stats = [node.stat() for node in nodes]
                report["allocated"] = all(stat.S_ISCHR(st.st_mode) for st in stats)
                devices.extend(st.st_rdev for st in stats)
            except (OSError, ValueError) as exc:
                report["allocation_error"] = str(exc)
                report["partial_nodes"] = sorted(p.name for p in mountpoint.iterdir())
        result["binder_distinct_devices"] = len(devices) == 6 and len(set(devices)) == 6
        if len(mounted_binders) == 2:
            first, first_report = mounted_binders.pop(0)
            unmount = command("umount", str(first))
            first_report["unmounted"] = unmount.returncode == 0
            first_report["unmount_error"] = unmount.stderr.strip()
            second = mounted_binders[0][0]
            result["binder_b_survives_a_unmount"] = all((second / name).is_char_device() for name in ("binder", "hwbinder", "vndbinder"))
    finally:
        for mountpoint, report in mounted_binders:
            unmount = command("umount", str(mountpoint))
            report["unmounted"] = unmount.returncode == 0
            report["unmount_error"] = unmount.stderr.strip()
    print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="/var/tmp")
    parser.add_argument("--child")
    args = parser.parse_args()
    if args.child:
        child(args.child)
        return
    with tempfile.TemporaryDirectory(prefix="waydroid-multi-probe-", dir=args.base) as tmp:
        base = Path(tmp)
        probe = base / "probe"
        probe.write_text("ok")
        os.chmod(probe, 0o600)
        fs = command("findmnt", "-n", "-o", "FSTYPE,OPTIONS", "-T", tmp)
        result = {"filesystem": fs.stdout.strip(), "chmod_600": stat.S_IMODE(probe.stat().st_mode) == 0o600}
        try:
            os.setxattr(probe, "user.waydroid_probe", b"ok")
            result["user_xattr"] = os.getxattr(probe, "user.waydroid_probe") == b"ok"
            os.link(probe, base / "hardlink")
            os.symlink("probe", base / "symlink")
            result["links"] = (base / "hardlink").stat().st_ino == probe.stat().st_ino and (base / "symlink").read_text() == "ok"
        except OSError as exc:
            result["filesystem_error"] = str(exc)
        run = command("unshare", "--user", "--map-root-user", "--mount", "--propagation", "private",
                      sys.executable, str(Path(__file__).resolve()), "--child", tmp)
        result["namespace_exit"] = run.returncode
        result["namespace_stderr"] = run.stderr.strip()
        if run.returncode == 0:
            result["namespace"] = json.loads(run.stdout)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
