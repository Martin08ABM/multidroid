"""Resource names and protected runtime layout; this module creates nothing."""
from dataclasses import dataclass
from pathlib import PurePosixPath
import re

_ID = re.compile(r"[0-9a-f]{32}\Z")
SYSTEM_BUS = "id.waydro.Multi.Container"
RUNTIME_ROOT = PurePosixPath("/var/lib/waydroid-multi/instances")
BINDER_ROOT = PurePosixPath("/run/waydroid-multi/binderfs")


@dataclass(frozen=True)
class Resources:
    identifier: str

    def __post_init__(self):
        if not isinstance(self.identifier, str) or not _ID.fullmatch(self.identifier):
            raise ValueError("invalid instance identifier")

    @property
    def instance_dir(self): return RUNTIME_ROOT / self.identifier
    @property
    def work(self): return self.instance_dir / "work"
    @property
    def data(self): return self.instance_dir / "data"
    @property
    def binder_mount(self): return BINDER_ROOT / self.identifier
    @property
    def binder_nodes(self):
        return tuple(self.binder_mount / name for name in ("binder", "hwbinder", "vndbinder"))
    @property
    def system_bus(self): return SYSTEM_BUS
    @property
    def container_object(self): return "/id/waydro/Multi/Instances/i" + self.identifier
    @property
    def session_bus(self): return "id.waydro.Multi.i" + self.identifier + ".Session"
    @property
    def session_object(self): return "/id/waydro/Multi/Session"

    def describe(self):
        return {
            "runtime_dir": str(self.instance_dir), "work": str(self.work), "data": str(self.data),
            "binder_mount": str(self.binder_mount), "binder_nodes": [str(p) for p in self.binder_nodes],
            "system_bus": self.system_bus, "container_object": self.container_object,
            "session_bus": self.session_bus, "session_object": self.session_object,
        }
