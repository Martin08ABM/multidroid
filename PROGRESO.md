# Progreso

## 2026-10-28 — guardian independiente revisado y conectado a D-Bus

Se completó la revisión crítica del guardian y se corrigieron siete bugs de seguridad fundamentales:

1. **Descriptor de Binder incorrecto**: el primer guardian pasaba `store.binder_fd` (el directorio raíz del store) en lugar del descriptor del montaje de Binder de la instancia. Corregido: el guardian abre `os.open(self.identifier, _DIR_FLAGS, dir_fd=self.store.binder_fd)` y pasa ese descriptor al launcher.

2. **Falta de launcher/barrera**: el primer guardian ejecutaba el helper directamente sin el `waydroid-helper-launcher.py` que bloquea el helper hasta que se escribe `'G'` en el gate. Corregido: se usa `subprocess.Popen` con `pass_fds=(gate_read, binder_fd)` y el launcher, igual que `SupervisorCandidate.start()`.

3. **Falta de movimiento a cgroup**: el helper nunca se escribía en `cgroup.procs`, así que la política BPF no se aplicaba a él. Corregido: `_move_proc_to_cgroup(proc.pid, cg_fd)` se llama antes de liberar la barrera.

4. **Limpieza insegura de diarios**: `stop()` usaba `os.unlink` en lugar de `_unlink_checked` (que verifica propietario y hace `fsync` + rename atómico). Corregido: `stop()` delega en `ProtectedStore.recover_helper_same_boot_empty()` que publica `helper-cleanup.json`, re-verifica la identidad antes de cualquier eliminación, y retira los diarios en el orden seguro (proceso → cgroup → intención → limpieza).

5. **Falta de rollback ante fallos**: si `start()` fallaba a mitad, los recursos podían quedar en estado ambiguo. Corregido: ante cualquier fallo antes de liberar la barrera, el gate nunca se escribe y los diarios conservan el bloqueo.

6. **Falta de verificación de cgroup antes de `rmdir`**: el primer `stop()` usaba `os.rmdir` directo, que podría eliminar un cgroup sustituido. Corregido: se elimina el `rmdir` manual y se delega en `recover_helper_same_boot_empty()` que verifica inode, propietario, ausencia de subgrupos y procesos antes de eliminar.

7. **Monitor thread crash**: `_monitor_helper()` accedía a `proc.stdout` sin verificar que `proc` no fuera `None`. Corregido: se añade `if proc is None: return` al inicio de `_monitor_helper()`.

**Integración con D-Bus (`multiinstance/dbus_service.py`):**
- Se añadieron los métodos `StartInstance`, `StopInstance`, `RestartInstance`, `InstanceStatus` a la clase `Manager`
- Los guardianes se almacenan por `(identifier, uid)` en `self.guardians` bajo `self.guardian_lock`
- `StartInstance` crea un guardian nuevo o reutiliza uno existente; si falla, elimina el guardian para evitar estado roto
- `StopInstance` detiene el guardian de forma graceful y elimina la entrada del mapa
- `RestartInstance` llama a `guardian.restart()` que hace stop graceful + same-boot recovery + start
- `InstanceStatus` devuelve el estado actual del guardian
- `ProbeBinder` permanece bloqueado (requiere identidad y aislamiento verificados)

**Pruebas simuladas (11/11 pasan):**
- `tests/test_guardian.py`: inicialización, start requiere sesión, stop sin start, status antes de start, recuperación requiere store validado, secuencia de lifecycle, protocolo, independencia del estado del servicio
- Todas las pruebas usan `tempfile.TemporaryDirectory()` y mock `SupervisorSession`; ninguna requiere root, KVM o BPF real
- Las pruebas validan que las operaciones exigen el store fijo del sistema (`/var/lib/waydroid-multi`)

**Pruebas reales (pendientes):**
- Requieren VM con systemd, Btrfs, tmpfs, KVM, binderfs, cgroup BPF
- Modo `--bpf-helpers` de `run_systemd.py` no incluye pruebas del guardian independiente
- Se necesita un nuevo harness `scripts/vm_lab/systemd_guardian_probe.py` que:
  - Inicia dos guardians persistentes (A y B) con BPF reales
  - Verifica su aislamiento efectivo (B responde a ping después de parar A)
  - Detén, reinicia y recupera A mientras B permanece vivo y responde
  - Prueba la pérdida del canal de control y la interrupción o reinicio del gestor
  - Incluye estados incompletos y recursos sustituidos
  - No señales ni elimina recursos cuya identidad no pueda demostrarse

**Conservación:**
- Instalación Waydroid (`/usr/lib/waydroid/`, datos `/var/lib/waydroid/`) sin cambios
- Servicio existente inativo/deshabilitado
- Directorios experimentales (`/var/lib/waydroid-multi`) no creados en host
- No se hicieron commits ni push

