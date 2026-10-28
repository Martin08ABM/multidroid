# Fork experimental de Waydroid multiinstancia

Esta copia parte del Waydroid oficial, commit `db7294c4c2bd43157bab94cf8a3015e22d9f1ad8`. La instalación del sistema es independiente de este directorio. El alcance y el estado están en [MULTIINSTANCE_PLAN.md](MULTIINSTANCE_PLAN.md), [ARQUITECTURA_RUNTIME.md](ARQUITECTURA_RUNTIME.md) y [PROGRESO.md](PROGRESO.md).

El código incluye un registro de identidades y un contexto experimental de rutas y nombres LXC, no un gestor Android operativo. `create` **no inicializa imágenes ni arranca un contenedor**. `data` es una carpeta reservada, aún no es el `/data` de Android. Las acciones con `--instance` se rechazan hasta que el runtime esté aislado; `instance-info` solo muestra el contexto resuelto.

Para probar el registro sin privilegios, desde esta carpeta:

```sh
python waydroid-multi.py --root /tmp/waydroid-multi-demo create caja1
python waydroid-multi.py --root /tmp/waydroid-multi-demo create caja2
python waydroid-multi.py --root /tmp/waydroid-multi-demo list
python waydroid-multi.py --root /tmp/waydroid-multi-demo show caja1
python waydroid.py --instance-root /tmp/waydroid-multi-demo --instance caja1 instance-info
python -m unittest discover -s tests -v
```

El directorio de demostración debe ser nuevo; el comando rechaza nombres ya existentes y no elimina datos. Sin `--root`, el registro se crea bajo `${XDG_DATA_HOME:-$HOME/.local/share}/waydroid-multi`. El JSON muestra identidades previstas para LXC, D-Bus y Binder: son nombres reservados, no recursos creados. El formato es experimental y puede cambiar antes de que exista un runtime.

La ubicación del código en NTFS es válida para desarrollo. Para el runtime se ha elegido Btrfs, con espacio protegido previsto bajo `/var/lib/waydroid-multi/instances/<id>` y Binder temporal bajo `/run/waydroid-multi`. Esa ubicación es un diseño, todavía no se ha creado ni conectado al runtime. El directorio `work` del registro de usuario es exclusivamente experimental. No se usará `/var/lib/waydroid` de la instalación existente para las instancias nuevas. No instales esta copia sobre el paquete del sistema.

Existe una CLI root experimental `waydroid-privileged.py` para el registro protegido y el ciclo de vida Binder. No ejecutes la copia de desarrollo como root: el checkout es escribible por el usuario y aún falta instalar el código en una ubicación confiable y auditarlo. Para una prueba real autocontenida sin root del host, `python -B scripts/probe_privileged.py` utiliza directorios temporales Btrfs y un espacio de nombres privado de usuario y montaje; requiere que el kernel permita `unshare`.
