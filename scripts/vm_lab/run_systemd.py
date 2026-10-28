#!/usr/bin/env python3
"""Boot a minimal systemd guest twice with one newly created disposable disk."""
import argparse
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import uuid

import bundle


def boot_valid(returncode, output, markers):
    return returncode == 0 and all(marker in output.splitlines() for marker in markers)


def stage_candidate_package(root, package):
    """Copy only regular files from the reviewed package into the guest image."""
    prefix = "usr/lib/waydroid-multi/"
    extra = {"usr/lib/systemd/system/waydroid-multi-container.service",
             "usr/share/dbus-1/system.d/id.waydro.Multi.Container.conf"}
    required = {prefix + name for name in ("waydroid-helper-launcher.py", "waydroid-binder-helper.py",
                "multiinstance/supervisor.py", "multiinstance/bpf_policy.py", "multiinstance/privileged.py")}
    seen = set()
    with tarfile.open(package, "r:*") as archive:
        for member in archive:
            name = member.name
            if not member.isfile():
                if member.isdir():
                    continue
                raise RuntimeError("unexpected non-regular package entry")
            if name in {".BUILDINFO", ".PKGINFO", ".MTREE"}:
                continue
            if (not (name.startswith(prefix) or name in extra) or name in seen or
                    any(part in ("", ".", "..") for part in name.split("/")) or
                    member.uid != 0 or member.gid != 0 or member.mode != 0o644 or member.size > 4 * 1024 * 1024):
                raise RuntimeError("unexpected package path, owner or mode")
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o644)
            seen.add(name)
    if not required.issubset(seen) or not extra.issubset(seen):
        raise RuntimeError("candidate package is incomplete")


def copy_elf(root, source):
    target = root / str(source).lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target, follow_symlinks=True)
    result = subprocess.run(["ldd", str(source)], capture_output=True, text=True, check=True)
    if "not found" in result.stdout:
        raise RuntimeError(f"missing library for {source}: {result.stdout}")
    for line in result.stdout.splitlines():
        found = re.search(r"(?:=>\s+)?(/[^\s]+)\s+\(", line)
        if found:
            lib = Path(found.group(1))
            dest = root / str(lib).lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(lib, dest, follow_symlinks=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disk", type=Path, required=True, help="new disk path; creation is exclusive")
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--firmware-dir")
    parser.add_argument("--library-dir")
    parser.add_argument("--kernel", default=f"/usr/lib/modules/{platform.release()}/vmlinuz")
    parser.add_argument("--log", type=Path)
    parser.add_argument("--bpf-helpers", action="store_true", help="exercise real helpers and BPF under systemd")
    parser.add_argument("--candidate", action="store_true", help="exercise the installed one-shot candidate")
    parser.add_argument("--candidate-package", type=Path, help="unpack this candidate package into the disposable guest")
    args = parser.parse_args()
    if args.bpf_helpers and args.candidate:
        parser.error("choose one laboratory mode")
    if args.candidate_package and not args.candidate:
        parser.error("--candidate-package requires --candidate")
    if os.geteuid() == 0 or not os.access("/dev/kvm", os.R_OK | os.W_OK):
        parser.error("run as unprivileged user with access to /dev/kvm")
    diskfd = os.open(args.disk, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.ftruncate(diskfd, 256 * 1024 * 1024)
    # Keep the created file descriptor, avoiding a path substitution before format or boot.
    disk_path = f"/proc/self/fd/{diskfd}"
    subprocess.run(["mkfs.btrfs", "-q", "-f", disk_path], check=True, pass_fds=(diskfd,))
    here = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="multidroid-systemd-vm-", dir="/var/tmp") as tmp:
        root = Path(tmp) / "root"
        root.mkdir()
        bundle.build(root, here.parents[1], True)
        for name in ("systemd", "systemd-executor", "systemd-journald", "systemd-shutdown"):
            copy_elf(root, Path("/usr/lib/systemd") / name)
        shutil.copytree("/usr/lib/systemd/system", root / "usr/lib/systemd/system", symlinks=True)
        copy_elf(root, Path("/usr/bin/systemctl"))
        for name in ("systemd_probe.py", "systemd_control.py", "systemd_bpf_probe.py", "systemd_candidate_probe.py"):
            shutil.copy2(here / name, root / "lab" / name)
        if args.candidate:
            installed = root / "usr/lib/waydroid-multi"
            if args.candidate_package:
                stage_candidate_package(root, args.candidate_package)
            else:
                installed.mkdir(parents=True)
                shutil.copytree(here.parents[1] / "multiinstance", installed / "multiinstance",
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
                for name in ("waydroid-binder-helper.py", "waydroid-helper-launcher.py"):
                    shutil.copy2(here.parents[1] / name, installed / name)
            for path in [installed, *installed.rglob("*")]:
                if path.is_symlink():
                    raise RuntimeError("installed candidate contains a symlink")
                path.chmod(0o755 if path.is_dir() else 0o644)
        system = root / "etc/systemd/system"
        system.mkdir(parents=True)
        (root / "etc/machine-id").write_text(uuid.uuid4().hex + "\n")
        (root / "etc/os-release").write_text('ID=multidroid-vm\nNAME="MultiDroid VM Lab"\n')
        (system / "default.target").write_text("[Unit]\nDefaultDependencies=no\nRequires=waydroid-multi-container.service\nAfter=waydroid-multi-container.service\nAllowIsolate=yes\n")
        (system / "multidroid-control.service").write_text("[Unit]\nDefaultDependencies=no\n[Service]\nExecStart=/usr/bin/python3 -B /lab/systemd_control.py\n")
        program = "systemd_bpf_probe.py" if args.bpf_helpers else ("systemd_candidate_probe.py" if args.candidate else "systemd_probe.py")
        kill_mode = "KillMode=process\n" if args.bpf_helpers else ""
        (system / "waydroid-multi-container.service").write_text(
            "[Unit]\nDefaultDependencies=no\nRequires=multidroid-control.service\nAfter=multidroid-control.service\n"
            "[Service]\nType=simple\nDelegate=yes\nRestart=on-failure\nRestartSec=1\n"
            + kill_mode +
            "StandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n"
            f"ExecStart=/usr/bin/python3 -B /lab/{program}\n")
        subprocess.run(["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", str(here / "systemd_init.c"),
                        "-o", str(root / "init")], check=True)
        archive = Path(tmp) / "initramfs.cpio"
        names = b"".join(os.fsencode(str(p.relative_to(root))) + b"\0" for p in sorted(root.rglob("*")))
        with archive.open("wb") as out:
            subprocess.run(["cpio", "-o", "-H", "newc", "--null", "--owner=0:0", "--quiet"],
                           input=names, cwd=root, stdout=out, check=True)
        command = [args.qemu, "-machine", "q35,accel=kvm", "-cpu", "host", "-m", "1024", "-nodefaults",
                   "-no-reboot", "-display", "none", "-serial", "stdio", "-monitor", "none", "-net", "none"]
        if args.firmware_dir:
            command += ["-L", args.firmware_dir]
        command += ["-drive", f"file={disk_path},format=raw,if=virtio", "-kernel", args.kernel,
                    "-initrd", str(archive), "-append", "console=ttyS0 panic=-1 systemd.log_level=debug waydroid_systemd_lab=1" +
                    (" waydroid_systemd_bpf_lab=1" if args.bpf_helpers else "") +
                    (" waydroid_candidate_lab=1" if args.candidate else "")]
        env = os.environ.copy()
        if args.library_dir:
            env["LD_LIBRARY_PATH"] = args.library_dir
        logs = []
        expected = (("SYSTEMD_MANAGER_SIGKILL_REQUESTED", "SYSTEMD_MANAGER_RESTART_ISOLATED=PASS"),
                    ("SYSTEMD_REPLACEMENT_PRESERVED=PASS", "SYSTEMD_RECOVERY_SIGKILL_REQUESTED",
                     "SYSTEMD_RECOVERY_RESTART_ISOLATED=PASS", "SYSTEMD_STALE_JOURNALS_RECOVERED=PASS",
                     "SYSTEMD_INCOMPLETE_AFTER_REBOOT=PASS", "SYSTEMD_PERSISTENT_REBOOT=PASS"))
        if args.bpf_helpers:
            expected = (("SYSTEMD_BPF_POLICY_JOURNAL=PASS", "SYSTEMD_SANDBOX_JOURNAL=PASS", "SYSTEMD_BPF_ATTACH_FAILURE_BLOCKED=PASS", "SYSTEMD_BPF_BLOCKED_CRASH", "SYSTEMD_BPF_FOREIGN_PID_PRESERVED=PASS",
                         "SYSTEMD_BPF_FOREIGN_CGROUP_PRESERVED=PASS", "SYSTEMD_BPF_CLEANUP_CRASH",
                         "SYSTEMD_BPF_BLOCKED_RECOVERED=PASS", "SYSTEMD_BPF_EMPTY_CGROUP_RECOVERED=PASS",
                         "SYSTEMD_BPF_RUNNING_CRASH", "SYSTEMD_BPF_SAMEBOOT_PASS", "SYSTEMD_BPF_REBOOT_DURING_CLEANUP"),
                        ("SYSTEMD_BPF_INCOMPLETE_STILL_BLOCKED=PASS", "SYSTEMD_BPF_CLEANUP_REBOOT_RECOVERED=PASS", "SYSTEMD_BPF_REBOOT_PASS"))
        if args.candidate:
            expected = (("CANDIDATE_PERSISTENT_B_SURVIVES_A_STOP=PASS", "CANDIDATE_FOREIGN_POLICY_REFUSED=PASS", "CANDIDATE_FOREIGN_SANDBOX_PRESERVED=PASS",
                         "CANDIDATE_BPF_FAILURE_BLOCKED=PASS", "CANDIDATE_INSTALLED_PROBES=PASS",
                         "CANDIDATE_GATE_SIGKILL_REQUESTED", "CANDIDATE_GATE_SIGKILL_BLOCKED=PASS",
                         "CANDIDATE_SAMEBOOT_BLOCKED=PASS"),
                        ("CANDIDATE_REBOOT_RECOVERED=PASS",))
        for attempt, markers in enumerate(expected, 1):
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=45, env=env, pass_fds=(diskfd,))
            except subprocess.TimeoutExpired as exc:
                output = exc.stdout or b""
                if isinstance(output, bytes):
                    output = output.decode(errors="replace")
                logs.append(f"=== VM boot {attempt}: timeout ===\n" + output)
                if args.log:
                    args.log.write_text("\n".join(logs))
                raise RuntimeError(f"guest boot {attempt} timed out; inspect the log") from exc
            logs.append(f"=== VM boot {attempt} ===\n" + result.stdout + result.stderr)
            if not boot_valid(result.returncode, result.stdout, markers):
                if args.log:
                    args.log.write_text("\n".join(logs))
                raise RuntimeError(f"guest boot {attempt} failed; inspect the log")
        if args.log:
            args.log.write_text("\n".join(logs))
        print("SYSTEMD_PERSISTENT_VM=PASS")
        print("Disposable disk:", args.disk)
    os.close(diskfd)


if __name__ == "__main__":
    main()
