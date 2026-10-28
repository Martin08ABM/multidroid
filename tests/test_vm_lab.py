import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / "scripts/vm_lab/run.py"
spec = importlib.util.spec_from_file_location("vm_lab_run", path)
vm_lab_run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm_lab_run)


class VmLabResultTest(unittest.TestCase):
    def test_gbinder_requires_every_real_gate_and_interruption_check(self):
        lines = ([f"REAL_HELPER_FAILED_STAGE_{i}=PASS" for i in range(5)] +
                 ["INTERRUPTED_SUPERVISOR=PASS"] * 5 +
                 ["INTERRUPTED_RUNNING_SUPERVISOR=PASS", "REAL_GBINDER_SUPERVISION=PASS", "LAB_RESULT=PASS"])
        self.assertTrue(vm_lab_run.valid_result(0, "\n".join(lines), True))
        for line in set(lines):
            truncated = lines.copy()
            truncated.remove(line)
            self.assertFalse(vm_lab_run.valid_result(0, "\n".join(truncated), True), line)
        self.assertFalse(vm_lab_run.valid_result(1, "\n".join(lines), True))
        self.assertFalse(vm_lab_run.valid_result(0, "\n".join(lines + ["LAB_RESULT=FAIL"]), True))
        self.assertFalse(vm_lab_run.valid_result(0, "\n".join(lines), True, True))
        extra = ["VM_PROTECTED_STORE=PASS", "VM_JOURNALED_SUPERVISION=PASS",
                 "VM_AMBIGUOUS_CGROUP_PRESERVED=PASS", "VM_FOREIGN_CGROUP_PRESERVED=PASS",
                 "INTERRUPTED_SUPERVISOR=PASS"]
        self.assertTrue(vm_lab_run.valid_result(0, "\n".join(lines + extra), True, True))

    def test_legacy_lab_does_not_claim_gbinder(self):
        self.assertTrue(vm_lab_run.valid_result(0, "LAB_RESULT=PASS\n", False))
        self.assertFalse(vm_lab_run.valid_result(0, "LAB_RESULT=PASS\n", True))

    @unittest.skipUnless(shutil.which("gcc"), "gcc unavailable")
    def test_vm_init_refuses_execution_outside_pid_one(self):
        source = path.with_name("init.c")
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "init"
            subprocess.run(["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-DLAB_REAL_HELPER",
                            str(source), "-o", str(binary)], check=True, capture_output=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertIn("must run as PID 1", result.stderr)


if __name__ == "__main__":
    unittest.main()
