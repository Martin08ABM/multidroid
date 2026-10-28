# Guardian Design: Independent Per-Instance Resource Management

**Date:** 2026-10-28  
**Context:** MultiDroid fork — continuation from PROGRESO.md experimental supervisor and persistent helper  
**Goal:** Design an independent per-instance guardian with safe same-boot resource recovery

---

## 1. Motivation

Current state (from PROGRESO.md):
- `SupervisorCandidate` launches helpers one-shot with journaling but is "not wired to D-Bus"
- Persistent helper (`waydroid-binder-helper.py` with `--persistent`) supports `ping`/`stop` via stdin but "does not guarantee survival past the manager"
- Recovery methods exist (`recover_helper_same_boot_empty`, `recover_helper_after_reboot`) but require manual invocation
- Testing used `KillMode=process` and a wrapper to keep B alive — these are not production settings
- D-Bus `ProbeBinder` remains disabled; no Android transactions

The guardian must:
- Run as an independent long-lived process per instance
- Own its cgroup, BPF policy, sandbox, and helper lifecycle
- Recover safely after manager crash/restart in the **same boot**
- Expose authenticated control (start/stop/restart/status) via D-Bus
- Not rely on `KillMode=process` or the laboratory wrapper

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    waydroid-multi-container.service             │
│  (systemd Type=dbus, Delegate=yes, CAP_SYS_ADMIN, CAP_BPF, ...) │
│                     ┌─────────────────────┐                     │
│                     │  Manager (D-Bus)    │                     │
│                     │  - List/Create/Inspect│                    │
│                     │  - BinderStart/Stop   │                     │
│                     │  - Recover             │                     │
│                     └──────────┬────────────┘                     │
│                                │                                 │
│         ┌──────────────────────┼──────────────────────┐          │
│         ▼                      ▼                      ▼          │
│  ┌─────────────┐        ┌─────────────┐        ┌─────────────┐  │
│  │ Guardian A  │        │ Guardian B  │        │ Guardian C  │  │
│  │ (scope)     │        │ (scope)     │        │ (scope)     │  │
│  │             │        │             │        │             │  │
│  │ - Lease     │        │ - Lease     │        │ - Lease     │  │
│  │ - cgroup    │        │ - cgroup    │        │ - cgroup    │  │
│  │ - BPF prog  │        │ - BPF prog  │        │ - BPF prog  │  │
│  │ - sandbox   │        │ - sandbox   │        │ - sandbox   │  │
│  │ - Helper    │        │ - Helper    │        │ - Helper    │  │
│  └─────────────┘        └─────────────┘        └─────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.1 Systemd Integration

Each guardian runs as a **systemd scope** under the delegated cgroup tree:

```ini
# Created dynamically via systemd-run or bus API
# Properties set by the guardian itself:
Type=scope
Delegate=yes
KillMode=control-group
MemoryAccounting=yes
CPUAccounting=yes
TasksAccounting=yes
```

The manager service holds the **supervisor lease** (flock on `/run/waydroid-multi/supervisor.lock`) and the **service cgroup anchor**. Each guardian:
- Acquires its own sub-lease (optional, for coordination)
- Creates its cgroup child under the service cgroup
- Loads/attaches its BPF program
- Spawns the persistent helper via the existing launcher
- Communicates with helper via stdin/stdout (ping/stop protocol)

### 2.2 Guardian Lifecycle

```
START (D-Bus StartInstance)
  ├─ acquire guardian lease (if used)
  ├─ verify SupervisorSession (service anchor + lease)
  ├─ prepare_helper → intent + generation
  ├─ create cgroup child (wm-<id>-<gen>)
  ├─ install BPF policy (3 Binder devices)
  ├─ create sandbox directory
  ├─ record cgroup/sandbox/policy journals
  ├─ spawn launcher (holds gate) → helper (persistent)
  ├─ verify policy/sandbox/pidfd/cgroup membership
  ├─ release gate (write 'G')
  └─ monitor helper (pidfd poll + periodic ping)

STOP (D-Bus StopInstance or helper 'stop')
  ├─ send 'stop\n' to helper stdin
  ├─ wait for helper exit (pidfd)
  ├─ verify cgroup empty
  ├─ rmdir cgroup
  ├─ remove journals (process → cgroup → intent → cleanup)
  └─ release guardian lease

RESTART
  ├─ STOP (graceful)
  ├─ recover_helper_same_boot_empty (if journals remain)
  ├─ START (new generation)
  └─ verify new helper responds to ping

SAME-BOOT RECOVERY (after manager crash)
  ├─ new manager starts, recover_all()
  ├─ for each instance with pending journals:
  │   ├─ verify SupervisorSession
  │   ├─ call recover_helper_same_boot_empty
  │   ├─ if cgroup removed → journals cleared
  │   ├─ if helper still alive → reject recovery (PID exists)
  │   └─ if cgroup substituted → reject (inode mismatch)
  └─ instance ready for new StartInstance
```

### 2.3 Same-Boot Recovery Guarantees

`recover_helper_same_boot_empty` (already implemented in `ProtectedStore`):
- Requires `SupervisorSession` (validated lease + cgroup anchor)
- Requires consistent boot ID, mount namespace, cgroup namespace, PID namespace
- If recorded PID exists (even if reused) → **blocks**
- If cgroup exists:
  - Must match recorded inode, owner, no children, no processes
  - Publishes immutable `helper-cleanup.json` before `rmdir`
  - Re-verifies after publish before removal
- If cgroup absent → only publishes cleanup journal, re-verifies absence
- Removes journals in order: process → cgroup → intent → cleanup
- **Never signals** any process

### 2.4 Helper Protocol (Existing)

```python
# waydroid-binder-helper.py serve()
while True:
    cmd = commands.readline(16)
    if cmd == b"ping\n":
        report()  # re-opens 3 Binder devices, calls BINDER_VERSION
    elif cmd in (b"stop\n", b""):
        return    # clean exit
    else:
        raise ValueError("invalid helper command")
```

The guardian owns the stdin/stdout pipes. On manager crash, pipes close → helper sees EOF → exits. This is **not** survival; it's clean termination. The guardian's job is to restart it with a new generation.

---

## 3. Implementation Plan

### 3.1 `multiinstance/guardian.py`

```python
class Guardian:
    """Independent per-instance resource owner and helper supervisor."""
    
    def __init__(self, store: ProtectedStore, identifier: str, caller_uid: int):
        self.store = store
        self.identifier = identifier
        self.caller_uid = caller_uid
        self.session = None  # SupervisorSession
        self.cgroup_fd = None
        self.sandbox_fd = None
        self.program_fd = None
        self.helper_proc = None
        self.helper_stdin = None
        self.helper_stdout = None
        self.intent = None
        self.generation = None
        self._monitor_thread = None
        self._stop_monitor = threading.Event()
    
    def start(self) -> dict:
        """Full start sequence: intent → cgroup → BPF → sandbox → helper → verify → release."""
        
    def stop(self, graceful: bool = True) -> dict:
        """Stop helper, clean cgroup, remove journals."""
        
    def restart(self) -> dict:
        """Graceful stop + same-boot recovery + new start."""
        
    def status(self) -> dict:
        """Current state: running, generation, helper_pid, BPF verified, sandbox verified."""
        
    def recover_same_boot(self) -> dict:
        """Call ProtectedStore.recover_helper_same_boot_empty with verified session."""
        
    def _monitor_helper(self):
        """Background thread: pidfd poll + periodic ping via stdin."""
        
    def _verify_session(self):
        """Create and verify SupervisorSession."""
        
    def close(self):
        """Cleanup FDs, stop monitor thread."""
```

### 3.2 Manager Integration (`multiinstance/dbus_service.py`)

Add to `Manager` class:
```python
def __init__(self, bus, store, helper_backend=None):
    ...
    self.guardians = {}  # identifier -> Guardian
    self.guardian_lock = threading.Lock()

@dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
def StartInstance(self, identifier, sender=None, connection=None):
    ...

@dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
def StopInstance(self, identifier, sender=None, connection=None):
    ...

@dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
def RestartInstance(self, identifier, sender=None, connection=None):
    ...

@dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender", connection_keyword="connection")
def InstanceStatus(self, identifier, sender=None, connection=None):
    ...

# On service startup:
def _recover_all_guardians(self):
    for identifier in store.list(0):  # root sees all
        g = Guardian(store, identifier, 0)
        try:
            g.recover_same_boot()
        except SecurityError:
            pass  # logged, instance stays blocked
        finally:
            g.close()
```

### 3.3 Systemd Scope Creation

Two options:
1. **systemd-run --scope** from guardian start (requires CAP_DAC_OVERRIDE or polkit)
2. **Pre-created scope units** via generator or manager

Given the delegated cgroup, the guardian can simply `mkdir` its cgroup child and write to `cgroup.procs` — systemd will notice the process in the delegated tree. To make it a proper scope with accounting, we need `systemd-run --scope --unit=waydroid-multi-guardian-<id> --slice=waydroid-multi.slice`.

For initial implementation, use direct cgroup manipulation (as SupervisorCandidate does) and register with systemd via `sd_pid_notify_with_fds` if needed. Full scope integration can follow.

---

## 4. Testing Strategy

### 4.1 Simulated Tests (Unit Tests)
- Guardian start/stop/restart with mocked ProtectedStore, SupervisorSession
- Recovery logic with various journal states (complete, incomplete, mismatched)
- Helper monitor thread behavior (ping response, timeout, EOF)
- Concurrent guardian operations (locking)
- Error paths: BPF attach failure, sandbox creation failure, helper spawn failure

### 4.2 Real Tests (VM Lab)
Requires: VM with systemd, Btrfs `/var/lib`, tmpfs `/run`, KVM, binderfs, cgroup BPF

| Test | Description | Real/Simulated |
|------|-------------|----------------|
| Guardian start/stop | Full lifecycle with real helper, BPF, cgroup | **Real** |
| Two guardians coexist | A and B running simultaneously | **Real** |
| Stop A, verify B alive | B responds to ping after A stopped | **Real** |
| Manager crash + recovery | SIGKILL manager, new manager recovers A | **Real** |
| Restart A with B alive | Full restart cycle, B unaffected | **Real** |
| Rejected recovery cases | PID reused, cgroup substituted, incomplete journals | **Real** |
| Helper crash recovery | Helper dies unexpectedly, guardian restarts it | **Real** |
| Concurrent Start/Stop | Race conditions on same instance | **Real** |
| D-Bus integration | StartInstance/StopInstance via system bus | **Real** |

### 4.3 Documentation
Each test run produces:
- `scripts/vm_lab/resultado-guardian-<date>.txt` — full console output
- Machine-readable summary (JSON) with pass/fail per test case
- Clear marking: **REAL** (VM with real kernel, systemd, BPF) vs **SIMULATED** (unit tests, mocks)

---

## 3. Critical Bugs Found and Corrected

The following critical security bugs were identified in the initial `Guardian` implementation through code review against the `SupervisorCandidate` pattern and the `ProtectedStore` interface:

| # | Bug | Correction |
|---|-----|------------|
| 1 | **Wrong binder_fd passed to helper** — `store.binder_fd` (the store's root binder directory) was passed instead of the instance's binder mount fd. | Fixed: guardian opens the instance's binder directory under `store.binder_fd` (`os.open(self.identifier, _DIR_FLAGS, dir_fd=self.store.binder_fd)`) and passes that fd to the launcher. |
| 2 | **Missing launcher/gate mechanism** — helper was spawned directly without the `waydroid-helper-launcher.py` gate, meaning no BPF verification barrier existed before the helper executed. | Fixed: guardian uses `subprocess.Popen` with `pass_fds=(gate_read, binder_fd)` and the `waydroid-helper-launcher.py`, which reads `'G'` from the gate before exec'ing the helper, matching `SupervisorCandidate.start()`. |
| 3 | **Missing cgroup process movement** — helper process was never written to `cgroup.procs`, so BPF policy did not apply to it. | Fixed: `_move_proc_to_cgroup(proc.pid, cg_fd)` is called before releasing the gate, verified with `cgroup.procs` write before `'G'` is published. |
| 4 | **Unsafe `os.unlink` in `stop()`** — journals were removed with raw `os.unlink` instead of `_unlink_checked` which validates ownership and performs `fsync` + atomic rename. | Fixed: `stop()` now delegates to `ProtectedStore.recover_helper_same_boot_empty()` which publishes immutable `helper-cleanup.json`, re-verifies identity before any removal, and removes journals in the safe order (process → cgroup → intent → cleanup). |
| 5 | **No failure rollback / leaked resources** — if `start()` failed mid-way, the gate was never written (helper blocked) but journals could remain in an ambiguous state. | Fixed: on any failure before gate release (step 14), gate is never written, journals retain the blockade, and same-boot recovery refuses until the state is unambiguous after reboot. |
| 6 | **No cgroup identity verification before `rmdir` in `stop()`** — raw `os.rmdir` could remove the wrong cgroup if substituted. | Fixed: stopped manual cgroup rmdir; now delegates to `recover_helper_same_boot_empty()` which verifies inode, ownership, no children, no processes, and publishes `helper-cleanup.json` before removal. |
| 7 | **Monitor thread crash on None `self.helper_proc`** — `_monitor_helper()` accessed `proc.stdout` without null guard. | Fixed: added `if proc is None: return` guard at entry of `_monitor_helper()`. |

---

## 4. Implementation Order

1. **GUARDIAN.md** (this document) ✓
2. **`multiinstance/guardian.py`** — core guardian implementation
3. **`multiinstance/dbus_service.py`** — add guardian management methods
4. **`tests/test_guardian.py`** — simulated unit tests
5. **`scripts/vm_lab/systemd_guardian_probe.py`** — real VM test harness
6. **Run real tests in VM**, document in PROGRESO.md
7. **Integrate with systemd scope** (proper accounting/limits)
8. **Full D-Bus service test** with production policy

---

## 5. Security Considerations

| Threat | Mitigation |
|--------|------------|
| PID reuse during recovery | `recover_helper_same_boot_empty` blocks if PID exists (even reused) |
| Cgroup substitution | Inode + parent inode + ownership verified at every step |
| BPF policy substitution | Bytecode digest + effective program ID verified before release |
| Sandbox substitution | Inode + parent inode + tmpfs verified; mount namespace checked |
| Manager crash during recovery | `helper-cleanup.json` makes interruption resumable; blocks on uncertainty |
| Helper compromised | No_new_privs, dropped caps, empty groups, chroot, isolated namespaces |
| Root host adversary | Not addressed — model assumes cooperative root |

---

## 7. Open Questions

1. **Scope vs raw cgroup**: Use `systemd-run --scope` for proper accounting, or manage cgroup directly? Direct is simpler for MVP; scope can be added later.
2. **Guardian lease**: Need a per-guardian lease file, or is the service-level lease sufficient? Service-level is sufficient for MVP.
3. **Helper restart policy**: On helper crash, guardian should restart with new generation. How many retries? Backoff?
4. **D-Bus object per instance**: Current design has single Manager object. Should add `/id/waydro/Multi/Instances/i<id>` objects for per-instance control.
5. **Resource limits**: Memory/CPU/Tasks limits per guardian — where configured? Pool config or per-instance?

---

## 8. Acceptance Criteria (for this phase)

- [ ] Guardian module implemented with start/stop/restart/status/recover_same_boot
- [ ] Unit tests pass (simulated)
- [ ] VM real tests: start A, start B, stop A → B responds, restart A → B responds
- [ ] VM real test: SIGKILL manager → new manager recovers A → start A succeeds
- [ ] VM real test: reject recovery when PID reused / cgroup substituted
- [ ] All tests documented with REAL/SIMULATED distinction
- [ ] PROGRESO.md updated with results
- [ ] Waydroid installation unchanged, service inactive