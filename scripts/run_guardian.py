#!/usr/bin/env python3
"""Test harness for the independent guardian.

This script runs both simulated and real tests for the Guardian component.
REAL mode requires a VM with systemd, Btrfs /var/lib, tmpfs /run, and kernel BPF.
SIMULATED mode runs unit tests only, using mocks.

Usage:
    python -B scripts/run_guardian.py --simulated    # Run unit tests only
    python -B scripts/run_guardian.py --real        # Requires VM environment (see LAB_CGROUP.md)
"""

import subprocess
import sys
import os
import argparse
from pathlib import Path


def run_simulated_tests():
    """Run simulated unit tests for Guardian."""
    print("=" * 70)
    print("GUARDIAN SIMULATED TESTS (Unit tests using mocks)")
    print("=" * 70)

    # Run the simulated tests
    result = subprocess.run([
        sys.executable, "-B",
        "-m", "unittest",
        "discover", "-s", "tests",
        "-p", "test_guardian.py",
        "-q"
    ], cwd=Path(__file__).parent.parent)

    if result.returncode == 0:
        print("\n✅ All SIMULATED tests passed!")
        return True
    else:
        print(f"\n❌ SIMULATED tests failed with code {result.returncode}")
        return False


def run_real_tests():
    """Run real integration tests for Guardian.

    This requires a VM with the following setup (see LAB_CGROUP.md for details):
    - VM with systemd, Btrfs /var/lib, tmpfs /run
    - Kernel with cgroup BPF and binderfs
    - QEMU/KVM available with KVM driver
    - systemd with Delegate=yes for waydroid-multi-container.service

    The test procedure:
    1. Ensure VM is running with necessary setup
    2. Inside VM: build package, test guardian lifecycle
    3. Document results

    Currently, this test fails because:
    - No systemd in current environment
    - No real kernel BPF
    - No binderfs
    """
    print("=" * 70)
    print("GUARDIAN REAL TESTS (Integration tests requiring VM)")
    print("=" * 70)
    print("\n⚠️  This test requires a VM environment.")
    print("\nSee LAB_CGROUP.md for VM setup requirements.")
    print("\nPrerequisites:")
    print("  - VM with systemd (not container)")
    print("  - Btrfs /var/lib (persistent)")
    print("  - tmpfs /run")
    print("  - Kernel with cgroup BPF and binderfs")
    print("  - QEMU/KVM with KVM driver")
    print("  - systemd with Delegate=yes for waydroid-multi-container.service")
    print("\nTest procedure (in VM):")
    print("  1. Build package: python -B scripts/build_package.py")
    print("  2. Create instance: systemd-run --unit=waydroid-multi-container.service")
    print("  3. Start guardian: systemctl start --user waydroid-multi-guardian-<id>")
    print("  4. Verify helper responds to ping")
    print("  5. Stop guardian: systemctl stop")
    print("  6. Verify cleanup and journals")
    print("  7. Run recovery: systemctl start --user waydroid-multi-guardian-<id>")
    print("  8. Document results in scripts/vm_lab/resultado-guardian-<date>.txt")

    return False


def main():
    parser = argparse.ArgumentParser(
        description="Test harness for the Guardian component."
    )
    parser.add_argument(
        "--simulated", action="store_true",
        help="Run simulated unit tests (mock/stub components)"
    )
    parser.add_argument(
        "--real", action="store_true",
        help="Run real integration tests (requires VM environment)"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run all tests (simulated and real if possible)"
    )

    args = parser.parse_args()

    if args.simulated or args.all:
        success = run_simulated_tests()
        if not success and not args.all:
            sys.exit(1)

    if args.real or args.all:
        # For real tests, we check if we're in a VM environment first
        if os.path.exists("/sys/fs/cgroup") and os.path.exists("/proc/vz"):
            # Maybe we're in a container, not a real VM
            print("\n⚠️  Running in a containerized environment.")
            print("    Real tests are not automatically run in containers.")
            print("    See LAB_CGROUP.md for detailed VM setup.")

        # We could add VM detection here, but for safety we'll just warn
        success = run_real_tests()
        if not success and args.all:
            sys.exit(1)

    if not (args.simulated or args.real or args.all):
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()