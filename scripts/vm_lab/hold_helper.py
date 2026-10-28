"""VM-only wrapper that keeps the real one-shot gbinder object alive."""
import importlib.util
import errno
import os
import sys
import time

spec = importlib.util.spec_from_file_location("binder_helper", "/lab/waydroid-binder-helper.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
own = os.readlink("/proc/self/fd/" + sys.argv[1])
paths = (os.environ.get("WAYDROID_VM_BINDER_A", "/a"), os.environ.get("WAYDROID_VM_BINDER_B", "/b"))
if own not in paths:
    raise RuntimeError("unexpected laboratory Binder mount")
for directory in paths:
    for name in ("binder", "hwbinder", "vndbinder", "binder-control"):
        allowed = directory == own and name != "binder-control"
        try:
            fd = os.open(directory + "/" + name, os.O_RDWR | os.O_CLOEXEC)
        except OSError as exc:
            if allowed or exc.errno != errno.EPERM:
                raise
        else:
            os.close(fd)
            if not allowed:
                raise RuntimeError("device cgroup did not deny access")
print("REAL_HELPER_ACCESS=PASS", flush=True)
service = module.main()
for command in sys.stdin:
    if command.strip() == "quit":
        break
    if command.strip() != "check" or not service:
        raise RuntimeError("invalid laboratory command")
    fd = os.open("/dev/binder", os.O_RDWR | os.O_CLOEXEC)
    os.close(fd)
    print("HELPER_CHECK=PASS", flush=True)
if os.environ.get("WAYDROID_VM_KEEP_AFTER_EOF") == "1":
    # Laboratory B keeps exercising its Binder after its manager is killed.
    while True:
        fd = os.open("/dev/binder", os.O_RDWR | os.O_CLOEXEC)
        os.close(fd)
        time.sleep(0.1)
