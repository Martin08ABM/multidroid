#!/usr/bin/env python3
"""Build and run the diskless, networkless cgroup/Binder lab as a normal user."""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import tempfile


def valid_result(returncode, output, gbinder, store=False):
    lines = output.splitlines()
    if returncode != 0 or lines.count("LAB_RESULT=PASS") != 1 or "LAB_RESULT=FAIL" in lines:
        return False
    if gbinder:
        required = {"REAL_GBINDER_SUPERVISION=PASS", "INTERRUPTED_RUNNING_SUPERVISOR=PASS"}
        required.update(f"REAL_HELPER_FAILED_STAGE_{i}=PASS" for i in range(5))
        if not required.issubset(lines) or lines.count("INTERRUPTED_SUPERVISOR=PASS") != (6 if store else 5):
            return False
    if store and not {"VM_PROTECTED_STORE=PASS", "VM_JOURNALED_SUPERVISION=PASS",
                      "VM_AMBIGUOUS_CGROUP_PRESERVED=PASS", "VM_FOREIGN_CGROUP_PRESERVED=PASS"}.issubset(lines):
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--firmware-dir", help="QEMU firmware directory for a private extraction")
    parser.add_argument("--library-dir", help="library directory for a private extraction")
    parser.add_argument("--kernel", default=f"/usr/lib/modules/{platform.release()}/vmlinuz")
    parser.add_argument("--log", help="write guest console output to this file")
    parser.add_argument("--gbinder", action="store_true", help="include host Python and the real gbinder helper")
    parser.add_argument("--store", action="store_true", help="also exercise ProtectedStore in the guest")
    args = parser.parse_args()
    if args.store and not args.gbinder:
        parser.error("--store requires --gbinder")
    if os.geteuid() == 0:
        parser.error("run the host launcher as an unprivileged user")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        parser.error("/dev/kvm is not accessible; KVM is required for this test")
    source = Path(__file__).resolve().with_name("init.c")
    with tempfile.TemporaryDirectory(prefix="waydroid-vm-lab-", dir="/var/tmp") as tmp:
        tmp = Path(tmp)
        root = tmp / "root"
        root.mkdir()
        build = ["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror"]
        if args.gbinder:
            build.append("-DLAB_REAL_HELPER")
            import bundle
            bundle.build(root, source.parents[2], args.store)
            if args.store:
                build.append("-DLAB_STORE_TEST")
        subprocess.run(build + [str(source), "-o", str(root / "init")], check=True)
        names = b"".join(os.fsencode(str(p.relative_to(root))) + b"\0" for p in sorted(root.rglob("*")))
        with (tmp / "initramfs.cpio").open("wb") as archive:
            subprocess.run(["cpio", "-o", "-H", "newc", "--null", "--owner=0:0", "--quiet"],
                           input=names, cwd=root, stdout=archive, check=True)
        cmd = [args.qemu, "-machine", "q35,accel=kvm", "-cpu", "host", "-m", "1024" if args.gbinder else "512", "-nodefaults",
               "-no-reboot", "-display", "none", "-serial", "stdio", "-monitor", "none", "-net", "none"]
        if args.firmware_dir:
            cmd += ["-L", args.firmware_dir]
        kernel_args = "console=ttyS0 panic=-1 quiet"
        if args.store:
            kernel_args += " waydroid_vm_store_lab=1"
        cmd += ["-kernel", args.kernel, "-initrd", str(tmp / "initramfs.cpio"), "-append", kernel_args]
        env = os.environ.copy()
        if args.library_dir:
            env["LD_LIBRARY_PATH"] = args.library_dir
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=45, env=env)
        print(result.stdout, end="")
        if args.log:
            Path(args.log).write_text(result.stdout, encoding="utf-8")
        if not valid_result(result.returncode, result.stdout, args.gbinder, args.store):
            raise SystemExit("VM lab did not complete successfully")


if __name__ == "__main__":
    main()
