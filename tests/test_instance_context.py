import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from multiinstance.context import default_context, registered_context
from multiinstance.registry import Registry
from tools import config
from tools.helpers import images, lxc

ROOT = Path(__file__).resolve().parents[1]


class ContextTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registry = Registry(Path(self.tmp.name) / "registry")
        self.first = registered_context(self.registry.create("first"))
        self.second = registered_context(self.registry.create("second"))

    def test_templates_isolate_all_lxc_paths_and_name(self):
        for version in ("1", "3"):
            snippets = [ROOT / "data/configs/config_base", ROOT / ("data/configs/config_" + version)]
            first = lxc.render_lxc_config(self.first, snippets, "x86_64", "/test/post-stop")
            second = lxc.render_lxc_config(self.second, snippets, "x86_64", "/test/post-stop")
            for context, rendered in ((self.first, first), (self.second, second)):
                self.assertIn("lxc.rootfs.path = " + context.rootfs, rendered)
                self.assertIn(context.lxc_dir + "/config_nodes", rendered)
                self.assertIn(context.lxc_dir + "/config_session", rendered)
                self.assertIn(context.lxc_dir + "/waydroid.seccomp", rendered)
                self.assertIn(context.lxc_name, rendered)
                self.assertNotIn("/var/lib/waydroid/", rendered)
            self.assertNotIn(self.second.work, first)
            self.assertNotIn(self.first.work, second)

    def test_lxc_lifecycle_targets_context(self):
        args = SimpleNamespace(instance_context=self.first, log=str(Path(self.tmp.name) / "log"))
        with mock.patch.object(lxc.tools.helpers.run, "user", return_value="RUNNING") as run, \
             mock.patch.object(lxc, "wait_for_running"), \
             mock.patch.object(lxc.os, "chmod"):
            lxc.status(args)
            lxc.start(args)
            lxc.stop(args)
            lxc.freeze(args)
            lxc.unfreeze(args)
        for call in run.call_args_list:
            command = call.args[1]
            self.assertEqual(command[command.index("-P") + 1], self.first.lxc_path)
            self.assertEqual(command[command.index("-n") + 1], self.first.lxc_name)
            self.assertNotIn(self.second.lxc_name, command)

    def test_config_generation_writes_only_selected_instance(self):
        def run_command(_args, command, **_kwargs):
            subprocess.run(command, check=True, capture_output=True)
            return 0

        args = SimpleNamespace(instance_context=self.first, work=self.first.work)
        with mock.patch.object(lxc, "get_lxc_version", return_value=7), \
             mock.patch.object(lxc, "get_apparmor_status", return_value=False), \
             mock.patch.object(lxc, "generate_nodes_lxc_config", return_value=[]), \
             mock.patch.object(lxc.tools.helpers.run, "user", side_effect=run_command):
            lxc.set_lxc_config(args)
        rendered = Path(self.first.lxc_dir, "config").read_text()
        self.assertIn(self.first.rootfs, rendered)
        self.assertTrue(Path(self.first.lxc_dir, "waydroid.seccomp").is_file())
        self.assertTrue(Path(self.first.lxc_dir, "config_nodes").is_file())
        self.assertTrue(Path(self.first.lxc_dir, "config_session").is_file())
        self.assertEqual(list(Path(self.second.work).iterdir()), [])

    def test_overlay_cleanup_only_targets_selected_context(self):
        for context in (self.first, self.second):
            for path in (context.overlay_rw, context.overlay_work):
                Path(path).mkdir(parents=True)
                Path(path, "marker").write_text(context.name)
        images.remove_overlay(SimpleNamespace(instance_context=self.first))
        self.assertFalse(Path(self.first.overlay_rw).exists())
        self.assertFalse(Path(self.first.overlay_work).exists())
        self.assertEqual(Path(self.second.overlay_rw, "marker").read_text(), "second")
        self.assertEqual(Path(self.second.overlay_work, "marker").read_text(), "second")

    def test_default_paths_remain_compatible(self):
        context = default_context("/home/test/.local/share/waydroid/data")
        self.assertEqual(context.work, "/var/lib/waydroid")
        self.assertEqual(context.lxc_path, "/var/lib/waydroid/lxc")
        self.assertEqual(context.lxc_dir, "/var/lib/waydroid/lxc/waydroid")
        self.assertEqual(context.lxc_name, "waydroid")

    def test_config_default_images_are_per_instance(self):
        first = SimpleNamespace(instance_context=self.first, config=str(Path(self.first.work) / "waydroid.cfg"))
        second = SimpleNamespace(instance_context=self.second, config=str(Path(self.second.work) / "waydroid.cfg"))
        self.assertEqual(config.load(first)["waydroid"]["images_path"], self.first.images_path)
        self.assertEqual(config.load(second)["waydroid"]["images_path"], self.second.images_path)

    def test_real_cli_inspects_context_and_rejects_runtime(self):
        command = [sys.executable, str(ROOT / "waydroid.py"), "--instance-root", str(self.registry.root),
                   "--instance", "first"]
        result = subprocess.run(command + ["instance-info"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), self.first.describe())
        for action in (["init"], ["session", "start"], ["container", "stop"]):
            result = subprocess.run(command + action, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not implemented", result.stderr)
        self.assertEqual(list(Path(self.first.work).iterdir()), [])
        missing = subprocess.run([sys.executable, str(ROOT / "waydroid.py"), "--instance-root",
                                  str(self.registry.root), "--instance", "missing", "instance-info"],
                                 text=True, capture_output=True)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("Instance context error", missing.stderr)
        self.assertNotIn("Traceback", missing.stderr)

    def test_staged_install_includes_instance_module(self):
        stage = Path(self.tmp.name) / "stage"
        result = subprocess.run(["make", "install", "DESTDIR=" + str(stage)], cwd=ROOT,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        installed = stage / "usr/lib/waydroid/waydroid.py"
        result = subprocess.run([sys.executable, str(installed), "instance-info"],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["lxc_name"], "waydroid")


if __name__ == "__main__":
    unittest.main()
