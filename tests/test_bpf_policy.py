import ctypes
import os
import struct
import unittest
from unittest import mock

from multiinstance.bpf_policy import PolicyError, expected_instructions, inspect_policy, install_policy


class BpfPolicyTest(unittest.TestCase):
    def test_instruction_builder_rejects_invalid_devices(self):
        for devices in ([], [(1, 1)] * 3, [(True, 1), (1, 2), (1, 3)], [[1, 1], [1, 2], [1, 3]]):
            with self.assertRaises(ValueError):
                expected_instructions(devices)

    def test_effective_program_and_code_must_match(self):
        devices = [(242, 1), (242, 2), (242, 3)]
        code = expected_instructions(devices)
        def kernel(command, attr):
            if command == 15:
                _, _, pointer = struct.unpack_from("IIQ", attr, 0)
                info = (ctypes.c_ubyte * 256).from_address(pointer)
                address = struct.unpack_from("Q", info, 32)[0]
                if address:
                    ctypes.memmove(address, code, len(code))
                struct.pack_into("II", info, 0, 15, 17)
                struct.pack_into("I", info, 20, len(code))
                ctypes.memmove(pointer + 8, b"12345678", 8)
            elif command == 16:
                pointer = struct.unpack_from("Q", attr, 16)[0]
                ctypes.c_uint32.from_address(pointer).value = 17
                struct.pack_into("I", attr, 24, 1)
            else:
                raise AssertionError(command)
            return 0
        with mock.patch("multiinstance.bpf_policy._bpf", side_effect=kernel):
            self.assertEqual(inspect_policy(9, 10, devices)["program_id"], 17)
            with self.assertRaisesRegex(PolicyError, "instructions"):
                inspect_policy(9, 10, [(242, 1), (242, 2), (242, 4)])

    def test_attach_and_verification_failures_close_fd_and_propagate(self):
        devices = [(242, 1), (242, 2), (242, 3)]
        for stage in ("attach", "verify"):
            with self.subTest(stage=stage):
                fd = os.open("/dev/null", os.O_RDONLY)
                def kernel(command, _attr):
                    if command == 5:
                        return fd
                    if stage == "attach":
                        raise OSError("attach refused")
                    return 0
                with mock.patch("multiinstance.bpf_policy._bpf", side_effect=kernel), \
                     mock.patch("multiinstance.bpf_policy.inspect_policy", side_effect=PolicyError("bad policy")):
                    with self.assertRaises((OSError, PolicyError)):
                        install_policy(9, devices)
                with self.assertRaises(OSError):
                    os.fstat(fd)


if __name__ == "__main__":
    unittest.main()
