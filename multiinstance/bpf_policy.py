"""Inspect the exact experimental cgroup-device BPF program, without loading it.

Only the audited three-Binder allowlist is accepted. This module does not
authorize launching a helper or prove cgroup/sandbox ownership.
"""
import ctypes
import os
import platform
import struct


class PolicyError(RuntimeError):
    pass


def expected_instructions(devices):
    pairs = list(devices)
    if len(pairs) != 3:
        raise ValueError("three distinct devices are required")
    for pair in pairs:
        if (not isinstance(pair, tuple) or len(pair) != 2 or
                any(type(v) is not int or not 0 <= v <= 0x7fffffff for v in pair)):
            raise ValueError("invalid device number")
    if len(set(pairs)) != 3:
        raise ValueError("three distinct devices are required")
    # cgroup-device ctx: type in low 16 bits, operation in high 16 bits.
    ins = [(0x61, 2, 1, 0, 0), (0xbf, 3, 2, 0, 0), (0x57, 2, 0, 0, 0xffff),
           (0x55, 2, 0, 11, 2), (0x77, 3, 0, 0, 16), (0x57, 3, 0, 0, -7),
           (0x55, 3, 0, 8, 0), (0x61, 2, 1, 4, 0), (0x61, 3, 1, 8, 0)]
    for index, (major, minor) in enumerate(pairs):
        jump_index = 10 + 2 * index
        ins += [(0x55, 2, 0, 1, major), (0x15, 3, 0, 17 - jump_index - 1, minor)]
    ins += [(0xb7, 0, 0, 0, 0), (0x95, 0, 0, 0, 0),
            (0xb7, 0, 0, 0, 1), (0x95, 0, 0, 0, 0)]
    return b"".join(struct.pack("<BBhi", code, dst | (src << 4), off, imm)
                    for code, dst, src, off, imm in ins)


def _bpf(command, attr):
    if platform.machine() != "x86_64":
        raise PolicyError("BPF syscall number is only defined for x86_64")
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(321, command, ctypes.byref(attr), ctypes.sizeof(attr))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def open_program(program_id):
    if type(program_id) is not int or not 0 < program_id < 2**32:
        raise ValueError("invalid program id")
    attr = ctypes.create_string_buffer(144)
    struct.pack_into("I", attr, 0, program_id)
    return _bpf(13, attr)  # BPF_PROG_GET_FD_BY_ID


def install_policy(cgroup_fd, devices):
    """Load, attach and independently inspect a policy, retaining its FD.

    Failure after attach can leave a program attached; caller must preserve
    the cgroup and its journal and must not release a helper. This does not
    verify that the cgroup belongs to the caller.
    """
    code = expected_instructions(devices)
    instructions = ctypes.create_string_buffer(code)
    license_ = ctypes.create_string_buffer(b"GPL")
    log = ctypes.create_string_buffer(65536)
    attr = ctypes.create_string_buffer(144)
    struct.pack_into("IIQQIIQ", attr, 0, 15, len(code) // 8, ctypes.addressof(instructions),
                     ctypes.addressof(license_), 1, len(log), ctypes.addressof(log))
    program_fd = _bpf(5, attr)  # BPF_PROG_LOAD
    try:
        attach = ctypes.create_string_buffer(144)
        struct.pack_into("iIII", attach, 0, cgroup_fd, program_fd, 6, 0)
        _bpf(8, attach)  # BPF_PROG_ATTACH
        return program_fd, inspect_policy(cgroup_fd, program_fd, devices)
    except BaseException:
        os.close(program_fd)
        raise


def inspect_policy(cgroup_fd, program_fd, devices):
    """Check type, ID, effective attachment and translated bytecode; read-only."""
    expected = expected_instructions(devices)
    info = ctypes.create_string_buffer(256)
    attr = ctypes.create_string_buffer(144)
    struct.pack_into("IIQ", attr, 0, program_fd, len(info), ctypes.addressof(info))
    _bpf(15, attr)  # BPF_OBJ_GET_INFO_BY_FD
    kind, program_id = struct.unpack_from("II", info, 0)
    length = struct.unpack_from("I", info, 20)[0]
    if kind != 15 or not program_id or length != len(expected):
        raise PolicyError("unexpected BPF program type or instruction length")
    translated = ctypes.create_string_buffer(length)
    info = ctypes.create_string_buffer(256)
    struct.pack_into("I", info, 20, length)
    struct.pack_into("Q", info, 32, ctypes.addressof(translated))
    struct.pack_into("IIQ", attr, 0, program_fd, len(info), ctypes.addressof(info))
    _bpf(15, attr)
    if struct.unpack_from("I", info, 20)[0] != length or translated.raw != expected:
        raise PolicyError("BPF instructions do not match the Binder allowlist")
    ids = (ctypes.c_uint32 * 16)()
    query = ctypes.create_string_buffer(144)
    struct.pack_into("IIIIQI", query, 0, cgroup_fd, 6, 1, 0, ctypes.addressof(ids), 16)
    _bpf(16, query)  # BPF_PROG_QUERY, effective
    count = struct.unpack_from("I", query, 24)[0]
    if count != 1 or ids[0] != program_id:
        raise PolicyError("effective cgroup program does not match")
    return {"program_id": program_id, "tag": bytes(info.raw[8:16]).hex(),
            "devices": [[a, b] for a, b in devices]}
