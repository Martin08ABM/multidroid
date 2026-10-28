# Análisis de la PR Waydroid #1990

Revisada el 2026-10-27: [PR #1990](https://github.com/waydroid/waydroid/pull/1990) y su código descargado como `origin/pr-1990`. La cabeza es `bcd79d5fc522fdac514fae1a06efd5f1d4e0d545` (2025-07-29). Su ancestro común con nuestra base es `2c41162d8bfef5bf83333a6ce4834af0c3c2b535`: la PR tiene 3 commits propios y nuestra base `db7294c4c2bd43157bab94cf8a3015e22d9f1ad8` tiene 74 desde ese ancestro. El diff de la PR toca 14 archivos (+211/-45).

## Qué hace

- Añade `--instance`/`-n` y valida nombres. `tools/helpers/instance.py` extrae la opción **al importar el módulo**, vuelve a analizar los argumentos y guarda el resultado como variable global. A partir de ella deriva rutas, nombres D-Bus, red y Binder.
- Para una instancia con nombre usa `/var/lib/waydroid.<nombre>` y un directorio de datos de usuario distinto; mantiene la ruta histórica si se omite. Sigue llamando `waydroid` al contenedor LXC, diferenciándolo mediante el `-P` de LXC y los directorios de trabajo. Adapta las plantillas de configuración y los comandos de ciclo de vida.
- Añade sufijos a los nombres de los servicios de contenedor y sesión D-Bus. Inicialización genera una política de sistema por instancia; cada instancia sigue teniendo su propio daemon de contenedor y su `args.session`. Las interfaces y rutas de objeto siguen compartiendo sus nombres.
- Modifica Binder para asignar nodos con sufijos mediante un directorio binderfs por instancia y enlaces en `/dev`.
- Asigna nombres de interfaz, directorios de `/run`, direcciones y rango DHCP por instancia; invoca el script de red con el nombre. Su README propone hasta 16 instancias y muestra `show-full-ui`.

## Problemas y límites observados en código y revisión

- **Compatibilidad:** `git diff <ancestro> origin/pr-1990 | git apply --check` falla en 11 archivos contra nuestra base, incluidos inicializador, gestores, argumentos, Binder y LXC. No es aplicable directamente y una aplicación automática parcial no sería suficiente. Los mecanismos upstream de inicialización y servicios han cambiado; hay que adaptar y verificar cada cambio.
- **Red:** el hash usa `NET_ID = hash % 16 + 241`: dos nombres pueden obtener la misma subred, no se consulta el enrutamiento existente, y el resultado puede ser `256`, un octeto IPv4 inválido. `SUB_ADDR = hash % 16 + 2` puede producir 16 o 17, dentro del rango DHCP 16–254. La MAC del bridge sigue fija. En la PR se mantienen `flush table` y `delete table` de tablas nft llamadas `lxc`, compartidas con otros contenedores; una parada puede afectar a otra instancia o a LXC ajeno. Un comentario de la PR también informa de la colisión de nftables. Los nombres largos de interfaz pueden superar el límite de Linux.
- **D-Bus y ciclo de vida:** el mantenimiento upstream propuso un único gestor de sistema con sesiones por instancia y limitar inicialmente la integración de escritorio. La PR todavía crea varios daemons y políticas en el sistema. Aislamiento de autorización, activación, limpieza, sesiones y compatibilidad con el servicio instalado requiere diseño y pruebas adicionales. Un nombre que empiece por cifra, permitido por el validador de la PR, puede formar un componente inválido del nombre D-Bus.
- **Binder:** la PR intenta separar nodos, pero sigue gestionando enlaces globales en `/dev`; no demuestra en nuestro equipo asignación, permisos, aislamiento de contextos y limpieza segura. En la conversación se reporta un error de nodo Binder ausente. No se ha probado esta rama en hardware.
- **Datos y escritorio:** las rutas separadas no demuestran independencia de Android, y los iconos, notificaciones, audio, ADB y recursos gráficos necesitan revisión. No se deben confiar rutas de usuario a un daemon privilegiado sin validar propietario, enlaces y carreras.
- **Ingeniería:** leer `argv` al importar un módulo hace la identidad global y dificulta probar múltiples contextos en un proceso. No se encontraron pruebas añadidas por el diff de la PR. La documentación de la PR afirma simultaneidad, pero aquí no la hemos reproducido.

## Adaptación en este fork

Se adopta la idea de direccionar por instancia las rutas, el LXC y las plantillas, pero con `InstanceContext` explícito y sin analizar argumentos durante importación. La instancia predeterminada conserva los nombres y rutas de upstream. Los contextos registrados tienen `work`, datos de usuario, rootfs, overlays, imágenes y nombre LXC propios. Se cambiaron los consumidores de esas rutas y la configuración renderizada; los comandos LXC reciben el `-P` y el `-n` del contexto. Se probaron rutas, comandos simulados y generación en directorios temporales.

Las operaciones con `--instance` están bloqueadas antes de iniciar el logger, D-Bus o el runtime. **No** se ha adaptado todavía la gestión de servicios, Binder ni red de la PR; las plantillas siguen incluyendo `waydroid0` y la MAC upstream. Tampoco se ha aplicado el código de la PR. `instance-info` es solo inspección. El siguiente paso es definir el modelo de confianza del gestor privilegiado y adaptar sesiones, D-Bus y Binder antes de habilitar arranques.

Para revisar el código localmente: `git show origin/pr-1990:tools/helpers/instance.py`, `git diff 2c41162d8bfef5bf83333a6ce4834af0c3c2b535 origin/pr-1990` y `git diff --stat 2c41162d8bfef5bf83333a6ce4834af0c3c2b535 origin/pr-1990`.
