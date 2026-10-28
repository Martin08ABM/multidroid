import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "waydroid-multi.py"


class InstanceCliTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "registry"
        self.addCleanup(self.temp.cleanup)

    def cli(self, *args, ok=True):
        result = subprocess.run([sys.executable, str(SCRIPT), "--root", str(self.root), *args],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, ok, result.stderr)
        return result

    def test_two_instances_have_independent_data_and_identity(self):
        one = json.loads(self.cli("create", "one").stdout)
        two = json.loads(self.cli("create", "two").stdout)
        for field in ("id", "data", "work", "lxc_path", "lxc_name"):
            self.assertNotEqual(one[field], two[field], field)
        a, b = one["planned_resources"], two["planned_resources"]
        self.assertEqual(a["system_bus"], b["system_bus"])
        for field in ("runtime_dir", "work", "data", "binder_mount", "container_object", "session_bus"):
            self.assertNotEqual(a[field], b[field], field)
        self.assertTrue(set(a["binder_nodes"]).isdisjoint(b["binder_nodes"]))
        Path(one["data"], "marker").write_text("one")
        self.assertFalse(Path(two["data"], "marker").exists())
        self.assertEqual(json.loads(self.cli("show", "one").stdout), one)
        self.assertEqual(len(json.loads(self.cli("list").stdout)), 2)
        self.cli("create", "one", ok=False)
        self.assertEqual(Path(one["data"], "marker").read_text(), "one")

    def test_invalid_name_cannot_escape_registry(self):
        self.cli("create", "../escape", ok=False)
        self.assertFalse(self.root.exists())

    def test_incomplete_instance_is_reported(self):
        (self.root / "instances" / "broken").mkdir(parents=True)
        self.assertIn("error", json.loads(self.cli("list").stdout)[0])
        self.cli("show", "broken", ok=False)


if __name__ == "__main__":
    unittest.main()
