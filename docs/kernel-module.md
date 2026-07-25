# The `nemclass_mod` kernel backend (Linux)

nemclass ships an optional out-of-tree Linux **kernel module**, `nemclass_mod`
(under `linux/nemclass_mod/`), that provides a privileged memory backend and a
non-ptrace debugger. It is what powers the `linux-kernel` provider.

> This guide documents the **userspace** side (how nemclass talks to the module)
> and how to load it. The module's C sources are maintained separately.

## Why a kernel module?

- **Ptrace-free memory access.** Reads/writes go through the module
  (`access_process_vm` in ring 0) instead of `process_vm_readv`, so they work
  where `yama/ptrace_scope`, seccomp, or hardened containers would deny the
  syscall path.
- **A real debugger.** The module can arm **hardware breakpoints/watchpoints**
  and **uprobes** on a target and deliver hit events to userspace — without
  attaching as a ptrace tracer.

## Loading it

The module is packaged for DKMS. Once built/installed, load it with a
symmetric **auth key**, supplied as *raw hex with no `0x` prefix*:

```text
sudo modprobe nemclass_mod key=1337
```

> The key is decoded from hex, so `key="0x1337"` is rejected with
> `Invalid argument` — pass `key=1337`, not `key=0x1337`.

Userspace reaches the module through `/proc/nemclass/attach`, gated by a
live-reloaded UID/GID allowlist.

## The client API (`nemclass-core`)

Two layers sit on top of the module's ioctl ABI:

- **`KernelClient`** — the thin ioctl wrapper. It `open()`s the device,
  negotiates the ABI (`check_abi`), and authenticates (`auth(key)`), then exposes
  `read_mem` / `write_mem` / `enum_regions`, plus the debugger primitives
  (hardware breakpoints, uprobes, wait-for-event, ptrace status/hide).
- **`KernelBackend`** — a `MemoryBackend` that routes `read_buf`/`write_buf`
  through a `KernelClient` bound to a pid. `KernelProvider::open` builds one,
  performing the ABI check + auth handshake first.

The module **fails closed**: every privileged ioctl (read/write/enumerate/
breakpoint) requires a successful auth handshake on the fd, or returns `EACCES`.
That is why the UI needs the auth key before attaching via `linux-kernel`.

## The debugger

`Debugger` (in `nemclass-core`) is the ergonomic controller layered over a
`KernelClient`:

```rust,ignore
let dbg = Debugger::attach(pid, key_bytes)?;      // open + check_abi + auth
let id  = dbg.set_breakpoint(BreakpointSpec::execute(addr))?;
let ev  = dbg.wait_event(timeout)?;               // DebugEvent { pid, tid, address, kind, registers }
dbg.clear_breakpoint(id)?;
```

- `set_breakpoint` dispatches to a hardware watchpoint or a uprobe.
- `wait_event` blocks (with a timeout) for the next breakpoint hit and returns
  the faulting thread + register snapshot.
- `ptrace_status` / `ptrace_hide` support anti-debug inspection use cases.

The **Debugger** tab in the UI drives this: enter the auth key, attach, set
execute/read/write breakpoints, and watch the event log.

## The ioctl ABI (reference)

The client speaks a small, versioned ioctl ABI — at a high level:
`VERSION`, `AUTH`, `READ`, `WRITE`, `ENUM_REGIONS`, `BP_SET`, `BP_CLEAR`,
`WAIT_EVENT`, `PTRACE_QUERY`, `PTRACE_HIDE`. The Rust `#[repr(C)]` mirror of the
ABI structs lives in `nemclass-core`'s `kernel` module and is checked against the
module's reported ABI revision at attach time (`Error::AbiMismatch` on skew).
