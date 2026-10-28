# Plan técnico: Waydroid multiinstancia

Fecha inicial: 2026-10-27. Base: Waydroid oficial `db7294c4c2bd43157bab94cf8a3015e22d9f1ad8`, versión 1.6.3. Objetivo: dos Android simultáneos en CachyOS/KDE Wayland, cada uno con datos y configuración propios, y con parada y reinicio independientes. La compatibilidad de HiOpos es una fase posterior y aún no se ha comprobado.

## Referencias estudiadas

- [Waydroid, solicitud de multiinstancia #566](https://github.com/waydroid/waydroid/issues/566): describe la necesidad de contenedores distintos.
- [PR #1990 de taksan](https://github.com/waydroid/waydroid/pull/1990): propuesta abierta con `--instance`, directorios, contenedores, redes y políticas D-Bus separadas. Véase [ANALISIS_PR_1990.md](ANALISIS_PR_1990.md) para compatibilidad, defectos de red, Binder y adaptación; su demostración no verifica este equipo ni esta versión.
- [x11droid](https://github.com/thereisnotime/x11droid) y su [documentación de instancias](https://github.com/thereisnotime/x11droid/blob/master/docs/ADVANCED.md): proyecto alternativo con Podman, datos por instancia y presentación X11. Es una referencia de diseño distinta, no un backend validado para este fork en Plasma Wayland.

## Mapa de suposiciones de instancia única

| Área | Código actual | Cambio previsto |
| --- | --- | --- |
| Identidad y configuración | `tools/__init__.py:prep_args`, `tools/config/__init__.py`: `work`, `rootfs`, overlays, configuración, logs y rutas globales. | Pasar un contexto de instancia explícito por toda la llamada; configuración, logs, rootfs, overlays y metadatos independientes. El registro experimental ya asigna identidad y rutas, pero todavía no las usa Waydroid. |
| Contenedores y sesiones | `tools/helpers/lxc.py` usa el nombre `waydroid`; `container_manager.py` guarda una sola `args.session`; `session_manager.py` registra un único gestor. | Un contenedor LXC y una sesión por ID; registro de sesiones por ID con operaciones y limpieza dirigidas a cada una. El estado observado vendrá de LXC y de la sesión, no solo de un manifiesto. |
| Datos e imágenes | `tools/config/__init__.py:session_defaults`, `lxc.py:generate_session_lxc_config` y `images.py`: ruta de usuario y montajes globales. | `/data`, configuración, `overlay_rw`, `overlay_work`, propiedades, rootfs y puntos de montaje propios. Solo imágenes base inmutables pueden compartirse; nunca compartir capa superior ni datos. |
| D-Bus y privilegios | `tools/helpers/ipc.py`, `container_manager.py`, `session_manager.py`, `dbus/` y `systemd/`: nombres y políticas fijos. | Propuesta: un servicio de sistema de este fork, con API por ID y autorización por UID, coexistente con el servicio instalado; un nombre de sesión diferente por ID. Auditar objeto, políticas, activación y callbacks. Las identidades reservadas en el registro son provisionales; el diseño final del servicio puede cambiarlas. |
| Binder y kernel | `tools/helpers/drivers.py` detecta nodos globales; `lxc.py` los monta; servicios `gbinder` consumen esos nodos. | Crear tres contextos Binder diferentes por Android mediante binderfs, sin reutilizar los nodos de la instalación existente. Pasar las rutas reales tanto a LXC como a todos los clientes gbinder. Definir propiedad y ciclo de vida; no desmontar recursos compartidos mientras estén en uso. Validar cgroups, namespaces, overlayfs y dispositivos de manera explícita. |
| Red | `data/scripts/waydroid-net.sh` usa `waydroid0`, subnet fija, `/run/waydroid-lxc`, dnsmasq y tablas nft `lxc`; `helpers/net.py` consulta leases fijos; configuraciones LXC tienen MAC fija. | Diseñar recursos con dueño inequívoco: bridge, MAC, subnet sin solapamiento, dnsmasq, leases, reglas nft y estado por instancia, o un recurso compartido con referencias y limpieza segura. No usar `flush/delete table lxc` ni borrar reglas ajenas. Resolver DHCP, DNS, NAT, IPv6 y recuperación ante fallo. |
| Ventanas, GPU y escritorio | `lxc.py:generate_session_lxc_config` monta sockets Wayland/audio; `services/user_manager.py` genera iconos y accesos; GPU es un recurso compartido. | Un socket/sesión de usuario por instancia y en la primera versión solo UI completa, sin escribir accesos de escritorio secundarios. Confirmar compositor KDE, audio y aislamiento de ventanas. Compartir GPU de forma controlada; medir memoria y compatibilidad NVIDIA. |

La ruta del registro experimental vive en espacio de usuario; **no debe convertirse automáticamente en entrada de confianza para procesos root**. Antes de gestionar LXC, definir almacenamiento del servicio protegido, validación de rutas y enlaces, dueño, permisos, autorización D-Bus y prevención de sustitución de archivos durante operaciones privilegiadas. El registro actual no proporciona esas garantías.

## Decisiones iniciales

1. Mantener la copia del fork separada de la instalación y sus datos. Ningún comando del prototipo modifica `/var/lib/waydroid`, sus unidades, su D-Bus, sus dispositivos ni sus reglas de red.
2. Preferir un gestor de sistema para las instancias del fork, separado del servicio instalado, y nombres identificados por instancia para la sesión de usuario. Es un diseño a validar, no una implementación terminada.
3. Crear almacenamiento privado por instancia para estado mutable. La fuente puede permanecer en NTFS; se elige Btrfs del host para el runtime. El montaje NTFS del proyecto tiene `nodev,nosuid` y propietario fijo, y OverlayFS necesita atributos y características de sistema de archivos adecuados ([documentación Linux](https://docs.kernel.org/filesystems/overlayfs.html)). OverlayFS con `userxattr` se probó en Btrfs de `/var/tmp` dentro de un espacio de nombres privado; falta verificar el montaje rootful y el destino definitivo. El gestor experimental separa el registro privilegiado del registro editable por el usuario; falta probarlo con root del host y auditarlo.
4. Imágenes base de solo lectura compartibles únicamente después de verificar montajes y actualizaciones; no copiar datos de la instalación existente. Descargar o seleccionar imágenes aparte para las pruebas.
5. Mantener operaciones de parada/reinicio dirigidas y transaccionales: incluso si el arranque falla, liberar exclusivamente recursos propios. No ofrecer comandos operativos hasta implementar y verificar esta propiedad.
6. Dejar integración de escritorio, aplicaciones y HiOpos para después de probar dos UI completas; no confundir ventanas múltiples del mismo Android con instancias separadas.

## Fases y criterios de aceptación

### 0. Inventario y diseño — iniciado

Identificar versión y paquetes, kernel, GPU, sesión, permisos, servicios y estado de imágenes. Revisar fuente y alternativas. **Aceptación:** informe reproducible que distinga observaciones del sandbox de las del host; preservar instalación existente. Ver `PROGRESO.md`.

### 1. Identidad y rutas — iniciado

Registro CLI, nombres validados e ID estable, datos y configuración separados. Introducir contexto por instancia en Waydroid y eliminar rutas fijas de generación de configuración y montajes. **Aceptación:** pruebas de dos contextos, rutas y nombres sin colisiones, persistencia, entradas inválidas y sin acceso al estado original. Se han adaptado los consumidores principales de rutas y comandos LXC y se han añadido pruebas; aún faltan la arquitectura privilegiada, las demás dependencias globales y pruebas reales.

### 2. Runtime aislado y una instancia

Preparar almacenamiento seguro, imágenes separadas, LXC, Binder y un servicio experimental en el propio espacio del fork. Implementar `init`, `start`, `status`, `stop`, logs y limpieza por ID. Comprobar montaje, arranque, identidad de UID y recuperación de errores. **Aceptación:** Android inicia y persiste datos tras reinicio en una instancia; la instalación anterior no cambia. Capturar versiones y evidencias.

### 3. Dos instancias simultáneas

Completar gestión de sesiones, D-Bus, Binder, red, propiedades, sockets y recursos gráficos por instancia; evitar colisiones de nombres y reglas. **Aceptación:** A y B arrancan a la vez, tienen `/data` diferentes, mantienen marcadores y aplicaciones propios; detener, reiniciar y volver a arrancar A no altera B ni la instalación existente; repetir en orden inverso y tras un fallo simulado. Comprobar estados reales de LXC, Binder, red, imágenes y UI, no solo los registros.

### 4. Robustez y operación

Probar concurrencia de comandos, fallos parciales, reinicio del servicio y limpieza sin borrar recursos ajenos; diagnóstico de logs, permisos, red, espacio, RAM y GPU. **Aceptación:** fallos reproducibles no corrompen otra instancia; operación repetible tras reiniciar el host; sin colisiones con Waydroid instalado.

### 5. HiOpos

Determinar distribución oficial, requisitos, versión de Android, arquitectura y dependencias, registro/licencia y acceso a periféricos; no se conocen todavía. **Aceptación:** instalar legítimamente en A y B, configurar datos separados, ejecutar al mismo tiempo y comprobar el flujo relevante para el usuario, incluido reinicio independiente. Registrar límites de ARM en x86_64, Play Services, integridad, red y dispositivos cuando se conozcan.

## Riesgos y requisitos pendientes

- Privilegios para LXC, montaje, binderfs y red; una prueba real precisa acceso al host y al D-Bus de sistema. Los cambios privilegiados deben quedar aislados y ser reversibles.
- Núcleo con binderfs y namespaces configurados no garantiza nodos asignables, dispositivos GPU visibles, imágenes disponibles ni soporte del compositor; verificar en ejecución.
- Btrfs/NTFS y OverlayFS: `/` y `/home` son Btrfs y están montados `rw` en el host; comprobar compatibilidad del directorio superior, permisos y atributos de Android antes de escoger una ruta. El sandbox los presenta como `ro`.
- NVIDIA RTX 4050 y paquete `waydroid-nvidia-bin`: compatibilidad de aceleración, memoria y renderizado simultáneo por validar. `/dev/dri` existe en el host, aunque no era visible en el sandbox.
- Gestión de subredes y nftables con otras aplicaciones; colisiones y limpieza destructiva son bloqueantes.
- El gestor experimental crea y limpia Binder en una prueba real privada; aún faltan permisos y uso desde Android. Las identidades D-Bus planificadas no tienen servicio ni autorización en el bus de sistema. Asignación de interfaz/subred/MAC se hará con detección de colisiones, no por truncar un UUID sin comprobación.
- HiOpos, servicios externos, compatibilidad de CPU y licencias no se han validado. No prometer funcionamiento simultáneo antes de las pruebas de la fase 5.
