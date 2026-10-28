"""Create and inspect instance identities without touching Waydroid services."""

import json
import os
from pathlib import Path
import re
import uuid
from multiinstance.resources import Resources


NAME = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
IDENTIFIER = re.compile(r"[0-9a-f]{32}\Z")


class RegistryError(Exception):
    pass


def default_root():
    data_home = os.environ.get("XDG_DATA_HOME")
    if not data_home or not Path(data_home).is_absolute():
        data_home = Path.home() / ".local" / "share"
    return Path(data_home) / "waydroid-multi"


def validate_name(name):
    if not NAME.fullmatch(name):
        raise RegistryError("El nombre debe empezar por una letra minúscula y contener hasta 32 letras minúsculas, números o guiones")
    return name


def describe(root, name, identifier):
    validate_name(name)
    if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
        raise RegistryError("Identificador de instancia inválido")
    base = Path(root).expanduser().resolve() / "instances" / name
    resources = Resources(identifier)
    return {
        "name": name,
        "id": identifier,
        "data": str(base / "data"),
        "work": str(base / "work"),
        "lxc_path": str(base / "work" / "lxc"),
        "lxc_name": "waydroid-mi-" + identifier,
        "planned_resources": resources.describe(),
        "runtime": "not-implemented",
    }


class Registry:
    def __init__(self, root):
        self.root = Path(root).expanduser().resolve()
        self.instances = self.root / "instances"

    def create(self, name):
        validate_name(name)
        self.instances.mkdir(mode=0o700, parents=True, exist_ok=True)
        base = self.instances / name
        try:
            base.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise RegistryError(f"La instancia '{name}' ya existe o su directorio está ocupado") from exc
        # A failed creation remains visible as incomplete; no existing data is removed.
        (base / "data").mkdir(mode=0o700)
        (base / "work").mkdir(mode=0o700)
        identifier = uuid.uuid4().hex
        with (base / "instance.json").open("x", encoding="utf-8") as manifest:
            json.dump({"version": 1, "name": name, "id": identifier}, manifest, indent=2)
            manifest.write("\n")
        return describe(self.root, name, identifier)

    def get(self, name):
        validate_name(name)
        base = self.instances / name
        if base.is_symlink():
            raise RegistryError(f"La instancia '{name}' es un enlace simbólico")
        try:
            with (base / "instance.json").open(encoding="utf-8") as manifest:
                record = json.load(manifest)
        except (OSError, ValueError) as exc:
            raise RegistryError(f"No se puede leer la instancia '{name}': {exc}") from exc
        if not isinstance(record, dict) or record.get("version") != 1 or record.get("name") != name:
            raise RegistryError(f"Manifiesto inválido para '{name}'")
        return describe(self.root, name, record.get("id"))

    def list(self):
        if not self.instances.exists():
            return []
        records = []
        for base in sorted(self.instances.iterdir()):
            try:
                records.append(self.get(base.name))
            except RegistryError as exc:
                records.append({"name": base.name, "error": str(exc)})
        return records
