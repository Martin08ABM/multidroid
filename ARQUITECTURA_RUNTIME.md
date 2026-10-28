# Runtime protegido, Binder y D-Bus

Diseño e implementación experimentales, 2026-10-27. Existen un gestor root por CLI y un adaptador D-Bus, pero no se han instalado en el host ni se han creado los directorios de runtime. El arranque Android de instancias nombradas sigue bloqueado.

## Rutas y permisos previstos

La fuente permanece en NTFS. El runtime persistente irá en Btrfs del host bajo `/var/lib/waydroid-multi/instances/<id>/`, donde `<id>` es un UUID hexadecimal de 32 caracteres, no un nombre arbitrario ni una ruta recibida del cliente. No usa `/var/lib/waydroid`.

| Ruta | Propiedad y modo previstos | Contenido |
| --- | --- | --- |
| `/var/lib/waydroid-multi` y `instances` | root:root, `0711` | Raíz administrada por el servicio, sin escritura para usuarios. |
| `instances/<id>` | root:root, `0711` | Punto de acceso a una instancia; el ID no es una credencial. |
| `instances/<id>/work` | root:root, `0700` | Configuración, LXC, rootfs, imágenes, overlays, puntos de montaje y metadatos de gestión. |
| `instances/<id>/data` | UID/GID autorizado, `0700` | Datos de usuario Android por instancia. El servicio determinará y verificará el UID/GID, nunca los aceptará como autoridad del manifiesto de usuario. |
| `/run/waydroid-multi/binderfs/<id>` | gestionado por root; acceso del usuario de sesión pendiente de diseño y prueba | Montaje binderfs transitorio independiente, no persistente en Btrfs. |

Estos modos se implementan para directorios que cree el gestor, pero aún no se han aplicado al host. Hay que comprobar cómo acceden a `data` Android, servicios de usuario y LXC con sus UID y namespaces. El registro previo bajo `~/.local/share/waydroid-multi` es editable por el usuario y no participa en la autorización del gestor.

`multiinstance/privileged.py` implementa un registro protegido: nombres validados y únicos por UID, UUID generado por el gestor, metadatos root `0600`, bloqueo de registro y de instancia, y validación del UID de quien solicita cada operación. La CLI root resuelve el GID principal desde la cuenta del sistema; no permite especificar rutas. Se recorren los anclajes fijos desde `/` con `O_DIRECTORY|O_NOFOLLOW`; se comprueban propiedad root, modo, ACL, enlaces duros de metadatos, Btrfs en el registro y tmpfs en Binder. No se aceptan montajes anidados en las raíces protegidas. El acceso posterior al contenido usa descriptores de directorio. `data` se valida pero no se recorren ni eliminan datos del usuario.

`waydroid-privileged.py` ofrece `init`, `create`, `list`, `inspect`, `binder-start`, `binder-stop` y `recover` únicamente para root. `inspect` construye un contexto usando los datos del registro protegido. Hay un adaptador D-Bus implementado y probado en privado; **no hay servicio D-Bus instalado en el host ni arranque Android**. No ejecutar la copia de desarrollo como root: véase [AUDITORIA_PRIVILEGIOS.md](AUDITORIA_PRIVILEGIOS.md).

Los diarios de creación permiten completar operaciones interrumpidas sin borrar datos. Si se interrumpe el proceso tras montar y antes de registrar el ID de Binder, la recuperación rehúsa desmontar el recurso ambiguo. Cambiar los permisos de `data` provoca que las operaciones ordinarias fallen hasta restaurarlos; la recuperación de Binder solo consulta la propiedad del registro y no modifica `data`.

`multiinstance/resources.py` calcula la disposición propuesta sin crear archivos. El `work` de `waydroid.py --instance ... instance-info` procede del registro experimental; el contexto de la CLI root procede del registro protegido. Antes de habilitar acciones de Android hay que conectar el contexto al gestor de confianza.

## Binder

Un binderfs recién montado por instancia en `/run/waydroid-multi/binderfs/<id>` proporcionará tres dispositivos independientes: `binder`, `hwbinder` y `vndbinder`. Se montarán en el `/dev` del contenedor y se pasarán también a los clientes gbinder correspondientes. No se crean enlaces globales en `/dev`, a diferencia de la PR #1990.

`multiinstance/binder.py` inicializa los nodos. El gestor registra la intención, crea un directorio nuevo bajo el anclaje protegido, monta binderfs y guarda tipo, ID, boot y namespace del montaje. Si el kernel crea los nodos en ese montaje nuevo, se aceptan si los tres son dispositivos de carácter distintos; una población parcial se rechaza. `binder-stop` y recuperación desmontan solo cuando la identidad coincide; no usan desmontaje perezoso ni borran datos Android. Faltan permisos para clientes gbinder, cgroups, recuperación operativa de montajes ambiguos y conexión a Android.

En una prueba real con dos binderfs privados en un espacio de nombres se observaron seis números de dispositivo distintos; al desmontar A, los tres nodos de B seguían presentes. Una segunda prueba utilizó el propio gestor con dos registros y verificó la limpieza individual. Esto verifica la separación de nodos y su ciclo de vida básico, no el funcionamiento de dos Android, el acceso gbinder ni el gestor de servicios Android. [Documentación binderfs del kernel](https://docs.kernel.org/admin-guide/binderfs.html).

## D-Bus

- Un servicio de sistema separado del Waydroid instalado tendrá el nombre `id.waydro.Multi.Container`; los objetos de instancia serán `/id/waydro/Multi/Instances/i<id>`.
- Cada sesión de usuario tendrá su nombre `id.waydro.Multi.i<id>.Session` y objeto `/id/waydro/Multi/Session`. El nombre incorpora un prefijo alfanumérico antes del UUID para cumplir la sintaxis D-Bus.
- Diseño de autorización: cada llamada derivará el UID del remitente único del bus mediante `org.freedesktop.DBus.GetConnectionUnixUser`, lo contrastará con el registro protegido y pasará ese UID a `_record`; el UID, GID o ruta suministrados por el cliente nunca serán autoridad. El alta derivará GID desde la cuenta del sistema y requerirá una política explícita para recursos privilegiados. El propietario de sesión debe corresponder al propietario del registro; las desconexiones deben limpiar solo su propia sesión.
- `multiinstance/dbus_service.py` obtiene el UID del bus y lo pasa al gestor. La política preparada restringe la propiedad del nombre del servicio a root; se ha aplicado solo en pruebas privadas. Dos UID reales en un user namespace no pudieron acceder a las instancias ajenas. No se ha instalado ni probado la política en el bus de sistema.
- La API actual exporta un objeto gestor `/id/waydro/Multi`; la separación de objetos de contenedor y sesiones D-Bus sigue planificada. Las llamadas Waydroid existentes siguen usando el servicio predeterminado. Faltan integración de sesión, señales, recuperación ante desconexión y permisos de los nodos.

## Comprobación de almacenamiento y montajes

El script `python scripts/probe_host.py --base /var/tmp` crea una carpeta temporal, realiza las pruebas dentro de un espacio de nombres privado de usuario y montaje y limpia la carpeta al terminar. En el host se comprobó `/var/tmp` Btrfs `rw`: modo `0600`, xattr `user.*`, enlace simbólico y enlace duro; también se montó OverlayFS con `userxattr` sobre lower/upper/work Btrfs, se probaron copia al escribir y borrado sin modificar la capa inferior, y se desmontó correctamente. Se verificaron dos binderfs en ese mismo espacio de nombres.

Esto no demuestra que el montaje rootful del servicio en el espacio de nombres inicial funcione, ni valida xattrs `trusted.*`, ACL, etiquetas de seguridad, compatibilidad de las imágenes de Android, consumo de recursos o durabilidad tras fallo. `/var/tmp` es otro subvolumen que `/var/lib`; hay que comprobar las opciones y permisos concretos del destino final antes de crear runtime real. Los upper y work de cada overlay deben estar en el mismo sistema de archivos y nunca compartirse entre instancias. [Documentación OverlayFS del kernel](https://docs.kernel.org/filesystems/overlayfs.html).
