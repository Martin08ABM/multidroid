"""Explicit path and LXC identity for one Waydroid instance.

Named instances are not yet safe to run. Their registry is user-controlled and
must not be trusted by privileged runtime code until authorization is designed.
"""
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class InstanceContext:
    name: str
    work: str
    user_data: str
    lxc_name: str

    @property
    def rootfs(self): return str(Path(self.work) / "rootfs")
    @property
    def images_path(self): return str(Path(self.work) / "images")
    @property
    def overlay(self): return str(Path(self.work) / "overlay")
    @property
    def overlay_rw(self): return str(Path(self.work) / "overlay_rw")
    @property
    def overlay_work(self): return str(Path(self.work) / "overlay_work")
    @property
    def data_mount(self): return str(Path(self.work) / "data")
    @property
    def host_perms(self): return str(Path(self.work) / "host-permissions")
    @property
    def lxc_path(self): return str(Path(self.work) / "lxc")
    @property
    def lxc_dir(self): return str(Path(self.lxc_path) / self.lxc_name)

    def describe(self):
        result = asdict(self)
        for key in ("rootfs", "images_path", "overlay", "overlay_rw", "overlay_work",
                    "data_mount", "host_perms", "lxc_path", "lxc_dir"):
            result[key] = getattr(self, key)
        return result


def default_context(user_data):
    return InstanceContext("default", "/var/lib/waydroid", user_data, "waydroid")


def registered_context(record):
    return InstanceContext(record["name"], record["work"], record["data"], record["lxc_name"])
