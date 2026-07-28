# Memory backends

nemclass reads and writes a target process's memory through a two-layer trait
design in `nemclass-core`. This keeps the raw-IO mechanism separate from the
per-platform process lifecycle, so new backends slot in without touching the
model or UI.

## The two traits

### `MemoryBackend` — raw IO on an opened target

```rust,ignore
pub trait MemoryBackend {
    fn read_buf(&self, address: usize, buf: &mut [u8]) -> Result<usize>;
    fn read_buf_batch(&self, regions: &mut [(usize, &mut [u8])]) -> Result<usize>;
    fn write_buf(&self, address: usize, buf: &[u8]) -> Result<usize>;
    fn write_buf_batch(&self, regions: &[(usize, &[u8])]) -> Result<usize>;
}
```

Reads are **short-read safe**: `read_buf` returns the number of bytes actually
transferred, so hitting an unmapped page yields a short count rather than a hard
error. Callers decide whether a partial transfer is acceptable.

### `ProcessProvider` — lifecycle above raw IO

```rust,ignore
pub trait ProcessProvider {
    fn name(&self) -> &str;
    fn enumerate_processes(&self) -> Result<Vec<ProcessEntry>>;
    fn open(&self, pid: Pid) -> Result<Process>;
    fn enumerate_sections_and_modules(&self, pid: Pid) -> Result<(Vec<Section>, Vec<Module>)>;
}
```

## `Process` — typed access

`open()` yields a `Process` that wraps a boxed `MemoryBackend` and adds typed
helpers on top of `read_buf`, using `bytemuck::Pod` (no hand-rolled `unsafe`):

- `read::<T>(addr) -> Result<T>`
- `read_batch::<T>(&[addr]) -> Result<Vec<T>>`
- `write::<T>(addr, value) -> Result<()>`
- `read_buf(addr, &mut [u8]) -> Result<usize>`
- `modules()` — enumerate loaded modules (Linux, via `/proc/<pid>/maps`)

## The registry

`ProviderRegistry` maps a name to a boxed provider. `ProviderRegistry::default()`
pre-registers the platform's providers so the UI can present a picker:

| Name | Provider | Mechanism |
|------|----------|-----------|
| `linux-native` | `LinuxProvider` | `process_vm_readv` / `process_vm_writev`, `/proc` enumeration. Ptrace-free; the default. |
| `linux-kernel` | `KernelProvider` | Reads/writes routed through the `nemclass_mod` char device — bypasses ptrace/Yama. Requires the module loaded **and** the auth key. |
| `windows-native` | `WindowsProvider` | `OpenProcess` + `ReadProcessMemory`/`WriteProcessMemory`, Toolhelp enumeration (`#[cfg(windows)]`). |

The kernel provider is always *registered* even when the module is absent — its
`open()` fails cleanly with `Error::DeviceUnavailable`, so a UI can offer it as a
higher-privilege fallback and drop back to `linux-native`.

## Choosing a backend in the UI

The left panel's **Backend** combo lists the registry names. When `linux-kernel`
is selected an **Auth key (hex)** field appears — the module fails closed, so the
key you loaded it with must be supplied before `open()` (and therefore any read)
succeeds. Process enumeration (a `/proc` walk) works without the key; only
attaching and reading require it. See [kernel-module.md](kernel-module.md).

## Adding a backend

Implement `MemoryBackend` (raw IO) and, if it introduces a new discovery/lifecycle
path, `ProcessProvider`; then register it in a `ProviderRegistry`. Everything
above core — the model, scanner, and UI — is written against the traits and needs
no changes.
