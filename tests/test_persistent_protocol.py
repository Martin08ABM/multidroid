import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("binder_worker", Path(__file__).resolve().parents[1] / "waydroid-binder-helper.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class PersistentProtocolTest(unittest.TestCase):
    def test_ping_and_stop(self):
        report = mock.Mock()
        worker.serve(report, io.BytesIO(b"ping\nping\nstop\nping\n"))
        self.assertEqual(report.call_count, 2)

    def test_eof_and_invalid_commands_fail_closed(self):
        report = mock.Mock()
        worker.serve(report, io.BytesIO(b""))
        for command in (b"stop", b"unknown\n", b"ping\n" * 0 + b"x" * 100):
            with self.subTest(command=command), self.assertRaises(ValueError):
                worker.serve(report, io.BytesIO(command))
        report.assert_not_called()


if __name__ == "__main__":
    unittest.main()
