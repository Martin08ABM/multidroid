import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest import mock

from multiinstance import cgroup_anchor as anchor
from multiinstance.privileged import SecurityError, _DIR_FLAGS


class CgroupAnchorTest(unittest.TestCase):
    def test_process_death_releases_exclusive_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o700)
            root = os.open(tmp, _DIR_FLAGS)
            read_fd, write_fd = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(read_fd)
                lease = anchor._lease_at(root, os.getuid(), os.getgid())
                os.write(write_fd, b"1")
                signal.pause()
                os.close(lease)
                os._exit(0)
            os.close(write_fd)
            try:
                self.assertEqual(os.read(read_fd, 1), b"1")
                with self.assertRaises(BlockingIOError):
                    anchor._lease_at(root, os.getuid(), os.getgid())
                os.kill(child, signal.SIGKILL)
                _, status = os.waitpid(child, 0)
                self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                child = None
                lease = anchor._lease_at(root, os.getuid(), os.getgid())
                os.close(lease)
            finally:
                if child is not None:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
                os.close(read_fd)
                os.close(root)

    def test_lease_exclusive_and_released_after_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o700)
            root = os.open(tmp, _DIR_FLAGS)
            try:
                first = anchor._lease_at(root, os.getuid(), os.getgid())
                try:
                    with self.assertRaises(BlockingIOError):
                        anchor._lease_at(root, os.getuid(), os.getgid())
                finally:
                    os.close(first)
                second = anchor._lease_at(root, os.getuid(), os.getgid())
                os.close(second)
            finally:
                os.close(root)

    def test_lease_refuses_symlink_and_insecure_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.open(tmp, _DIR_FLAGS)
            try:
                Path(tmp, "supervisor.lock").symlink_to("/etc/passwd")
                with self.assertRaises(OSError):
                    anchor._lease_at(root, os.getuid(), os.getgid())
                os.chmod(tmp, 0o755)
                with self.assertRaises(SecurityError):
                    anchor._lease_at(root, os.getuid(), os.getgid())
            finally:
                os.close(root)

    def test_service_cgroup_requires_exact_membership(self):
        with tempfile.TemporaryDirectory() as tmp:
            for value, should_pass in ((anchor.SERVICE_CGROUP, True), ("/system.slice/other.service", False)):
                fd = os.open(tmp, _DIR_FLAGS)
                with mock.patch.object(anchor.os, "geteuid", return_value=0), \
                     mock.patch.object(anchor, "_open_fixed_anchor", return_value=fd), \
                     mock.patch.object(anchor, "_filesystem_type", return_value=anchor._CGROUP2_MAGIC), \
                     mock.patch.object(anchor.subprocess, "run", return_value=mock.Mock(stdout="yes\n")), \
                     mock.patch("builtins.open", mock.mock_open(read_data="0::" + value + "\n")):
                    if should_pass:
                        os.close(anchor.open_system_service_cgroup())
                    else:
                        with self.assertRaisesRegex(SecurityError, "expected service cgroup"):
                            anchor.open_system_service_cgroup()
                        with self.assertRaises(OSError):
                            os.fstat(fd)

    def test_service_cgroup_rejects_missing_delegation(self):
        with tempfile.TemporaryDirectory() as tmp:
            fd = os.open(tmp, _DIR_FLAGS)
            with mock.patch.object(anchor.os, "geteuid", return_value=0), \
                 mock.patch.object(anchor, "_open_fixed_anchor", return_value=fd), \
                 mock.patch.object(anchor, "_filesystem_type", return_value=anchor._CGROUP2_MAGIC), \
                 mock.patch.object(anchor.subprocess, "run", return_value=mock.Mock(stdout="no\n")), \
                 mock.patch("builtins.open", mock.mock_open(read_data="0::" + anchor.SERVICE_CGROUP + "\n")):
                with self.assertRaisesRegex(SecurityError, "did not delegate"):
                    anchor.open_system_service_cgroup()

    def test_forked_process_cannot_reuse_or_close_session(self):
        session = object.__new__(anchor.SupervisorSession)
        session.pid = os.getpid() + 1
        session.lease = 10
        session.cgroup = 11
        with self.assertRaisesRegex(SecurityError, "not owned"):
            session.verify()
        with self.assertRaisesRegex(SecurityError, "forked child"):
            session.close()


if __name__ == "__main__":
    unittest.main()
