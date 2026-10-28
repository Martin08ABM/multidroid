# Laboratorio de cgroup de dispositivos

## Guardian Tests

### SIMULATED (Unit Tests)
- `tests/test_guardian.py` — 11 tests that verify guardian logic, state management, recovery flow, and protocol using mock/stub components
  - No real kernel BPF, no real systemd, no real helper
  - Tests verify Guardian initialization, lifecycle sequence, recovery conditions
  - Tests validate that operations require the fixed system store (`/var/lib/waydroid-multi`)
  - All 11 tests pass on the host without VM

### REAL (VM Lab Tests)
- Requires: VM with systemd, Btrfs `/var/lib`, tmpfs `/run`, KVM, binderfs, cgroup BPF
- Test scenarios:
  | Test | Description | Status |
  |------|-------------|--------|
  | Guardian start/stop | Full lifecycle with real helper, BPF, cgroup | **Pending** |
  | Two guardians coexist | A and B running simultaneously | **Pending** |
  | Stop A, verify B alive | B responds to ping after A stopped | **Pending** |
  | Manager crash + recovery | SIGKILL manager, new manager recovers A | **Pending** |
  | Restart A with B alive | Full restart cycle, B unaffected | **Pending** |
  | Rejected recovery cases | PID reused, cgroup substituted, incomplete journals | **Pending** |
  | Helper crash recovery | Helper dies unexpectedly, guardian restarts it | **Pending** |
  | Concurrent Start/Stop | Race conditions on same instance | **Pending** |
  | D-Bus integration | StartInstance/StopInstance via system bus | **Pending** |

Each real test run produces:
- `scripts/vm_lab/resultado-guardian-<date>.txt` — full console output
- Machine-readable summary (JSON) with pass/fail per test case
- Clear marking: **REAL** (VM with real kernel, systemd, BPF) vs **SIMULATED** (unit tests, mocks)

### Real vs Simulated Distinction

- **SIMULATED tests** use `tempfile.TemporaryDirectory()` for instances and binders, mock `SupervisorSession`, and verify that operations require the fixed system store at `/var/lib/waydroid-multi`. They never require root, KVM, or real BPF. The 11 simulated tests all pass without a VM.

- **REAL tests** require a disposable VM (QEMU/KVM) with:
  - `run_systemd.py --bpf-helpers` mode creates a new Btrfs disk, boots systemd with BPF helpers
  - Guardian is integrated via D-Bus (`Manager.StartInstance`/`StopInstance`)
  - Two persistent gbinder helpers are started, their BPF policies verified, and isolation confirmed
  - Stopping A while B remains alive; verifying B responds to ping
  - Restarting A with B still alive; B unaffected
  - SIGKILL manager → new manager recovers A → start A succeeds
  - Rejecting recovery when PID reused / cgroup substituted
  - Helper crashes and is restarted with new generation

- **The critical distinction**: SIMULATED tests verify the guardian's *logic and state management* using mocks. REAL tests verify the guardian's *actual kernel interaction* (BPF attachment, cgroup membership, Binder isolation, PID identity persistence). The simulated tests already pass (11/11). Real tests are deferred until a VM with the required environment is available.

---

## 2026-10-28: helpers persistentes en candidato empaquetado

La VM desechable ejecutó los archivos del paquete candidato, con unidad de laboratorio `Type=simple` y cgroup delegado. El helper admite `ping` y `stop` por stdin, conservando la comprobación de Binder y la barrera BPF del candidato. A y B permanecieron activos a la vez; después de detener A, B respondió, se verificó su programa BPF efectivo y volvió a responder. Un reinicio de A fue rechazado por los diarios pendientes; esta prueba no demuestra reinicio independiente de A. B fue detenido antes de interrumpir el gestor, por lo que no demuestra supervivencia del helper al fallo del servicio. El modo sale cuando se cierra el pipe y no es un guardian independiente.

También se probaron rechazo de programa y sandbox sustituidos, fallo real de attach y SIGKILL antes de liberar otro launcher, con bloqueo y recuperación limitada tras reboot. Registro: [resultado-persistente-2026-10-28.txt](scripts/vm_lab/resultado-persistente-2026-10-28.txt). No se instalaron ni probaron pacman, la unidad `Type=dbus` o el bus real. Para repetir, usar el comando `--candidate --candidate-package` de la sección siguiente, con el paquete recompilado y un disco nuevo; las dependencias de QEMU privado y KVM siguen siendo las mismas.

## 2026-10-28: paquete candidato y barrera interrumpida

`run_systemd.py --candidate --candidate-package` lee el paquete experimental, acepta solo archivos regulares de las rutas previstas con UID/GID 0 y modo 0644, y los incorpora al initramfs de la VM. El invitado comprueba root:root y permisos. Es un desempaquetado aislado, no una instalación pacman ni ejecución de la unidad de producción. La VM usa systemd `Type=simple`, `Delegate=yes`, capacidades completas y el KillMode predeterminado; no tiene bus de sistema de producción ni red.

En dos arranques de una VM KVM con disco Btrfs nuevo se ejecutó el supervisor candidato instalado en `/usr/lib/waydroid-multi`: dos helpers gbinder de corta duración llegaron a estar vivos simultáneamente y completaron sus probes. Se verificó el BPF efectivo, se rechazó un programa distinto y se preservó un sandbox sustituido; un attach real sobre FD inválido bloqueó el lanzamiento. Se envió `SIGKILL` al gestor antes de escribir el byte de liberación de un nuevo launcher: la barrera no se abrió y el reinicio mantuvo los diarios bloqueados. Otro reinicio del gestor confirmó el bloqueo del mismo boot; tras reiniciar la VM se recuperaron diarios antiguos solo después de validar ausencia de recursos. [Registro completo](scripts/vm_lab/resultado-candidato-2026-10-28.txt). La comprobación no muestra que B permanezca activo durante la recuperación de A ni prueba parada y reinicio independientes del candidato; los probes ya habían finalizado. Para B persistente véase el ensayo anterior, que dependió del wrapper de laboratorio.

Repetición desde la raíz del fork, usando disco y log nuevos y el paquete recién construido:

```sh
python -B scripts/vm_lab/run_systemd.py --candidate \
  --candidate-package /var/tmp/multidroid-package-20261028-candidate/waydroid-multi-experimental-0.0.1-2-any.pkg.tar.zst \
  --disk /var/tmp/multidroid-candidate-prueba-nueva.raw \
  --qemu /var/tmp/waydroid-vm-lab/qemu/usr/bin/qemu-system-x86_64 \
  --firmware-dir /var/tmp/waydroid-vm-lab/qemu/usr/share/qemu \
  --library-dir /var/tmp/waydroid-vm-lab/qemu/usr/lib \
  --log /var/tmp/multidroid-candidate-prueba-nueva.log
```

El aviso de kmod del systemd mínimo persiste; el kernel del ensayo tiene lo necesario integrado. No se aplicó la unidad propuesta, ni se alteró el host como root.

## 2026-10-28: helpers gbinder/BPF integrados con systemd

`run_systemd.py --bpf-helpers` crea un disco Btrfs nuevo y arranca dos veces una VM sin red. El supervisor experimental usa la concesión `SupervisorSession`, cgroup delegado y diarios de `ProtectedStore`; compila una biblioteca BPF solo para el invitado y ejecuta dos helpers gbinder reales. El supervisor verifica los filtros efectivos y registra el proceso antes de liberarlo. La unidad del laboratorio usa expresamente `KillMode=process` y un wrapper que mantiene B vivo al cerrar el pipe del gestor; esta política no está instalada ni aprobada para el servicio de producción.

Con B vivo y aún en su cgroup BPF, el test forzó un attach fallido, mató al gestor con A antes y después de liberarlo, rechazó un PID que apuntaba a B y un cgroup sustituto, interrumpió la limpieza de diarios con `SIGKILL`, recuperó un cgroup A vacío y apagó la VM durante otra limpieza. En el segundo arranque completó la limpieza desde el journal y confirmó el bloqueo del estado incompleto. Ningún helper sobrevive al reboot; solo se reabrió Binder B después. Los estados ambiguos se conservan y el fixture no usa la operación de producción para eliminar el cgroup sustituido. La salida completa está en [resultado-systemd-bpf-2026-10-28.txt](scripts/vm_lab/resultado-systemd-bpf-2026-10-28.txt).

Para repetir, añadir `--bpf-helpers` al comando de la sección siguiente y elegir nombres de disco y log nuevos. Se requiere kernel con cgroup BPF y binderfs, además de las dependencias indicadas. El kernel de prueba incorporaba los componentes; la VM registró un aviso de kmod no disponible. Esta prueba no establece seguridad frente a root no cooperativo, no verifica la unidad D-Bus de producción ni ejecuta Android.

## 2026-10-28: systemd y dos arranques con Btrfs persistente

`scripts/vm_lab/run_systemd.py` crea un archivo de disco **nuevo** con `O_EXCL`, lo formatea Btrfs usando el descriptor abierto y arranca dos veces un invitado sin red con systemd PID 1 y ese único disco, montado en `/var/lib`. El initramfs se monta en RAM y toma copias de Python, systemd y bibliotecas del host; no es una imagen de producción ni un despliegue del sistema. No usa QEMU como runtime de Android. La unidad de laboratorio usa el mismo nombre del servicio y `Delegate=yes`, pero es `Type=simple` y no reproduce las capacidades ni D-Bus de producción.

En el primer arranque se interrumpió con `SIGKILL` al gestor con registros de A y una intención incompleta; systemd reinició la unidad y se comprobaron Binder B y un proceso de control de otra unidad. El cgroup incompleto estaba ausente tras ese reinicio. En el segundo arranque se conservó un cgroup sustituto y se rehusó recuperar A hasta que el fixture retiró el recurso que él había creado. La limpieza de diarios antiguos se interrumpió tras la primera eliminación, el servicio se reinició y completó el resto sin afectar a B. Los helpers son procesos de prueba; el ensayo previo de gbinder/BPF se ejecutó por separado. La salida completa está en [resultado-systemd-2026-10-28.txt](scripts/vm_lab/resultado-systemd-2026-10-28.txt).

Para repetir desde el fork, usar un nombre de disco que **no exista**:

```sh
python -B scripts/vm_lab/run_systemd.py --disk /var/tmp/multidroid-systemd-prueba-nueva.raw \
  --qemu /var/tmp/waydroid-vm-lab/qemu/usr/bin/qemu-system-x86_64 \
  --firmware-dir /var/tmp/waydroid-vm-lab/qemu/usr/share/qemu \
  --library-dir /var/tmp/waydroid-vm-lab/qemu/usr/lib \
  --log /var/tmp/multidroid-systemd-prueba-nueva.log
```

Requiere `mkfs.btrfs`, `gcc` estático, `cpio`, systemd y Python/gbinder instalados y KVM accesible. El disco queda para inspección; eliminarlo solo si se reconoce ese archivo de prueba. La VM mínima registró un aviso de kmod no disponible; no se cargaron módulos. No demuestra recuperación del supervisor real del mismo boot ni una transacción Android.

## 2026-10-28: supervisor integrado con diarios en VM

En el modo `--gbinder --store`, el supervisor de PID 1 usa ahora `ProtectedStore` para las mismas dos instancias cuyos Binder reciben los helpers. Antes de liberarlos publica intención, evidencia del cgroup y evidencia de proceso; carga y consulta BPF y comprueba que Binder no se puede recuperar mientras hay diario. Se repitieron parada/reinicio de A con B activo, fallos e interrupciones, incluida la ventana anterior a registrar el cgroup. Un cgroup sin evidencia y otro sustituido con el mismo nombre fueron preservados al rechazar su verificación; el fixture los retiró manualmente después, con conocimiento exclusivo de lo que creó dentro de la VM.

La salida está en [resultado-integrado-2026-10-28.txt](scripts/vm_lab/resultado-integrado-2026-10-28.txt). El comando `--gbinder --store` de la sección siguiente reproduce este flujo actualizado. `VM_JOURNALED_SUPERVISION=PASS` verifica la conexión de laboratorio, no que el servicio de producción sea recuperable: `store_bridge.py` y la limpieza PID 1 dependen de una VM totalmente controlada. No se ha ensayado reinicio con disco persistente ni una acción destructiva contra un recurso cuya propiedad sea ambigua.

## 2026-10-28: prueba adicional de ProtectedStore

La prueba adicional `VM_PROTECTED_STORE=PASS` sigue siendo un ejercicio independiente del `ProtectedStore`: dos binderfs, un cgroup y un proceso reales; tres publicaciones interrumpidas con `SIGKILL`; y rechazo de recuperación que conserva el proceso y la otra instancia. El test retira manualmente sus recursos propios conocidos. Esa marca sola no demuestra el flujo integrado, que ahora se comprueba por separado con `VM_JOURNALED_SUPERVISION=PASS` como se describe arriba. No se ha probado persistencia del disco, reinicio ni recuperación automática.

Con la extracción de QEMU de la sesión, ejecutar el comando siguiente. La salida se guardó en [resultado-store-2026-10-28.txt](scripts/vm_lab/resultado-store-2026-10-28.txt).

```sh
python -B scripts/vm_lab/run.py --gbinder --store \
  --qemu /var/tmp/waydroid-vm-lab/qemu/usr/bin/qemu-system-x86_64 \
  --firmware-dir /var/tmp/waydroid-vm-lab/qemu/usr/share/qemu \
  --library-dir /var/tmp/waydroid-vm-lab/qemu/usr/lib
```

El invitado copia temporalmente Python, librerías, `mount`, `umount`, `sleep`, el registro y el test al initramfs. `--store` exige `--gbinder`, un marcador de arranque y el test como hijo directo de PID 1; estos controles limitan errores de uso, no convierten el laboratorio en software seguro para el host. El servicio real sigue deshabilitado.

## Helper gbinder real supervisado

`scripts/vm_lab/init.c` contiene ahora una ruta experimental que crea y elimina un cgroup y un filtro BPF por ejecución del helper, verifica el ID efectivo, traslada un hijo bloqueado y lo libera solo tras completar la verificación. `scripts/vm_lab/bundle.py` copia al initramfs el Python, gbinder y bibliotecas instalados; `hold_helper.py` mantiene vivo el objeto retornado por `waydroid-binder-helper.py`. No es un paquete de producción: se copia código y bibliotecas del usuario/host a un invitado aislado. El init rechaza ejecutarse fuera de PID 1. `run.py` rechaza el resultado si faltan las marcas de fallo e interrupción del modo gbinder.

Para reproducir, añadir `--gbinder` al comando de más abajo. Requiere Python con `gbinder` instalado, bibliotecas dinámicas disponibles y unos recursos mayores; el invitado usa 1 GiB de RAM. El resultado real de esta sesión está en [resultado-gbinder-2026-10-27.txt](scripts/vm_lab/resultado-gbinder-2026-10-27.txt). El supervisor mantiene a B funcionando durante pruebas de fallos e interrupciones de A, luego detiene y reinicia A y vuelve a verificar B. Los accesos negativos de BPF se comprobaron en el wrapper del mismo proceso antes del chroot; el helper real comprobó después su entorno privado y sus propios dispositivos. Los UID/GID 1000 y 1001 son identidades internas desechables, no reservas del host.

Los fallos forzados de BPF load, attach y query son llamadas reales inválidas; el fallo de traslado es una ruta inexistente y el último fallo antes de liberar es una cancelación deliberada. Se probó `SIGKILL` al supervisor en cinco etapas antes de liberar y una vez con el helper activo; un PID 1 de prueba recupera exclusivamente los recursos conocidos y espera a los hijos. El helper activo termina por EOF en el wrapper de prueba. No hay prueba de recuperación persistente, reinicio, caída de PID 1 o integración del servicio D-Bus con BPF. Tampoco se ha demostrado que dos Android funcionen.

## Resultado de esta sesión

Se ejecutó una VM QEMU/KVM desechable como usuario, sin discos, red, carpetas compartidas ni instalaciones en el host. Su único initramfs contiene el ejecutable estático de `scripts/vm_lab/init.c`; inicia como PID 1 y apaga la VM al acabar. Es administrable modificando el programa y reiniciando, pero **no es una distribución general ni usa systemd**. El kernel fue el kernel del equipo `6.18.55-2-cachyos-lts`, SHA-256 `672537d2d9812ce4fbcabcba365fb5c1914550fca6fe66b788cb315b1ae8b784`, con Binder y cgroup BPF integrados. La comparación previa de configuraciones oficiales Alpine encontró que `virt` no incluye Binder, mientras que `lts` sí; no se descargó ni arrancó Alpine.

El PID 1 montó dos binderfs y un cgroup2, cargó dos programas BPF de dispositivos de denegación por defecto, adjuntó uno a cada cgroup y consultó `BPF_F_QUERY_EFFECTIVE`, exigiendo exactamente el ID del programa esperado. Se abrieron los tres dispositivos propios con `BINDER_VERSION` correcto; abrir los tres ajenos y ambos `binder-control` devolvió `EPERM`. Para atribuir las denegaciones a cgroup se hicieron accesibles por DAC los directorios y los ocho nodos: estas permisivas condiciones existen **solo en el invitado efímero**. `mknod` de un Binder funcionó antes de entrar al cgroup y devolvió `EPERM` al proceso root dentro de cada cgroup. Dos procesos permanecieron activos, se detuvo y creó de nuevo el primero y el segundo repitió sus comprobaciones correctamente. Son procesos de prueba, no Android ni el helper gbinder real.

Un hijo de prueba esperó en una tubería cerrada sin liberar código de trabajo al provocar errores reales por argumentos inválidos en `BPF_PROG_LOAD`, `BPF_PROG_ATTACH` y `BPF_PROG_QUERY`, y por una ruta inexistente en la operación de traslado. El marcador no se escribió. Esto comprueba la sincronización del experimento, **no** la lógica de un launcher de producción; tampoco se ha probado una interrupción del supervisor ni fallo tras liberar al hijo. La consulta se hizo antes de liberar cada hijo, no se monitorizó continuamente. La salida completa está en [resultado-2026-10-27.txt](scripts/vm_lab/resultado-2026-10-27.txt).

El host no tiene QEMU instalado; `/dev/kvm` fue accesible. Se extrajeron QEMU 11.1.2 y dependencias en `/var/tmp/waydroid-vm-lab/qemu`, tras verificar las firmas de los paquetes Arch con el llavero del host. No se instaló ningún paquete. Las bibliotecas del host siguen interviniendo; esto no es un entorno de compilación hermético. El primer arranque con el modelo de CPU predeterminado terminó en `SIGILL` del init estático; `-cpu host` con KVM resolvió el problema en la prueba. Los archivos de `/var/tmp` son temporales y pueden desaparecer.

Para repetir con la extracción de esta sesión, desde el fork:

```sh
python -B scripts/vm_lab/run.py \
  --qemu /var/tmp/waydroid-vm-lab/qemu/usr/bin/qemu-system-x86_64 \
  --firmware-dir /var/tmp/waydroid-vm-lab/qemu/usr/share/qemu \
  --library-dir /var/tmp/waydroid-vm-lab/qemu/usr/lib \
  --log /var/tmp/waydroid-vm-lab/resultado.log
```

Para preparar otra extracción privada sin root ni pacman, elegir un directorio nuevo en Btrfs y ejecutar `python -B scripts/vm_lab/download_qemu.py /var/tmp/waydroid-qemu-nuevo`; después usar sus tres rutas `qemu/usr/...` con los argumentos anteriores. Se probó este descargador en `/var/tmp/waydroid-qemu-repro-20261027` y se repitió la VM con resultado `PASS`. Requiere red, `curl`, `gpgv`, el llavero de pacman, `bsdtar`, GCC estático, `cpio`, KVM y un kernel compatible legible. El descargador consulta los paquetes actuales de Arch y comprueba firmas antes de extraer; sus versiones y bibliotecas pueden cambiar. No concede confianza independiente a un llavero comprometido. Si ya existe QEMU instalado, `python -B scripts/vm_lab/run.py` usa ese binario. El lanzador se niega a ejecutarse como root en el host y exige `LAB_RESULT=PASS`, además de un código de salida satisfactorio. Ningún resultado desbloquea automáticamente el servicio.

## Trabajo pendiente

En el host, un usuario puede crear un cgroup delegado, pero `BPF_PROG_LOAD` y `BPF_PROG_QUERY` devuelven `EPERM`, también dentro de un user namespace con todas sus capacidades. `scripts/probe_cgroup_preflight.py` reproduce estas comprobaciones sin adjuntar programas ni arrancar helpers. No ejecutarlo como root. El experimento de la VM sí verifica una política aislada, pero no ha validado el servicio, el entorno systemd, la integración ni una instalación del host.

Usar una VM sin discos del host ni acceso a la instalación Waydroid, kernel con `CONFIG_CGROUP_BPF` y binderfs, systemd como PID 1 y root disponible dentro de la VM. Preparar exclusivamente código revisado en una ruta root:root no escribible por otros. El administrador de la VM debe crear una unidad de laboratorio `Delegate=yes` y dar al supervisor capacidades suficientes para cargar, adjuntar y consultar BPF; hay que comprobarlas en el kernel concreto, incluidos `CAP_BPF`/`CAP_SYS_ADMIN`, y no asumir que la delegación de ficheros las concede. Los cgroups y binderfs serán exclusivos del laboratorio y solo se limpiarán al verificar su identidad.

La implementación futura debe crear dos binderfs y registrar sus números de dispositivo, mantener el supervisor fuera de los dos cgroups de helpers, crear cada cgroup hijo y cargar y adjuntar una política de denegación por defecto que permita `rw` exactamente a los tres dispositivos propios, sin `mknod`. Debe comprobar el resultado de carga y attach **y consultar el programa efectivo y su identidad**, incluyendo restricciones heredadas de ancestros; cualquier error o discrepancia impide crear o liberar el helper. Un canal sincronizado debe mantener el proceso hijo detenido antes de ejecutar código no confiable, hasta que el supervisor confirme cgroup, política, credenciales y descriptores. No pasar descriptores ya abiertos de dispositivos ajenos: el filtro de dispositivo controla aperturas y creación, no invalida descriptores heredados. El helper no debe poder mover procesos, cambiar el cgroup ni sustituir la política.

Con los dos helpers ejecutándose simultáneamente y en igualdad de permisos DAC para que el resultado negativo sea atribuible a cgroup, probar apertura y `BINDER_VERSION` de los tres nodos propios y `EPERM` al abrir los tres ajenos y ambos `binder-control`; probar también `mknod` denegado. Confirmar en el kernel la política efectiva antes y durante la prueba, y distinguir errores DAC (`EACCES`) o rutas inexistentes de denegaciones cgroup. Parar un helper y verificar el otro. Inyectar fallos en carga, attach, consulta, traslado y sincronización, y comprobar con marcadores y observación de procesos que nunca se ejecuta código del helper cuando falla cualquiera de esos pasos. Repetir tras interrupción del supervisor y documentar cómo se destruyen o conservan únicamente recursos identificados. Estas pruebas no sustituyen probar gbinder con Android.

El servicio real seguirá bloqueado hasta disponer de esa implementación y de resultados positivos de laboratorio, revisión de privilegios, pool reservado y revalidado, dispositivos adicionales, red y demás requisitos. La variante `private_test` existente no aplica cgroups y solo sirve para las pruebas aisladas ya documentadas.
