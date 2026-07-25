//! Platform lifecycle seam above the raw [`MemoryBackend`] IO.
//!
//! [`ProcessProvider`] is the higher of the two backend traits: enumerate
//! processes, open one (yielding a [`Process`] wired to a [`MemoryBackend`]),
//! and enumerate its sections and modules. It mirrors ReClass.NET's
//! `ICoreProcessFunctions` contract (`EnumerateProcesses`, `OpenRemoteProcess`,
//! `EnumerateRemoteSectionsAndModules`) — behaviour ported, not structure.
//!
//! [`ProviderRegistry`] maps a backend name to a boxed provider so the UI can
//! offer a backend picker (ReClass.NET's `CoreFunctionsManager`); the default
//! entry is `"linux-native"`.

use std::collections::HashMap;

use crate::internal::process::{
    Module, Pid, Process, ProcessEntry, Section,
};

#[cfg(target_os = "linux")]
use crate::internal::process::{
    ProcessIterator,
    SectionType,
    kernel::{KernelBackend, KernelClient},
};

/// Name of the default, built-in provider registered by
/// [`ProviderRegistry::default`] on Linux.
#[cfg(target_os = "linux")]
pub const LINUX_NATIVE: &str = "linux-native";

/// Name of the privileged, kernel-module-backed provider registered by
/// [`ProviderRegistry::default`] on Linux. Reads/writes go through
/// `/proc/nemclass/attach` (bypassing ptrace/Yama) instead of `process_vm_readv`.
#[cfg(target_os = "linux")]
pub const LINUX_KERNEL: &str = "linux-kernel";

/// Name of the default, built-in provider registered by
/// [`ProviderRegistry::default`] on Windows: the native
/// `ReadProcessMemory`/`WriteProcessMemory` backend. Mirrors [`LINUX_NATIVE`].
#[cfg(windows)]
pub const WINDOWS_NATIVE: &str = "windows-native";

/// Platform lifecycle above raw memory IO: process enumeration, opening a target
/// (into a [`Process`] backed by a [`crate::MemoryBackend`]), and enumerating
/// its sections and modules.
///
/// Object-safe so registries can hold `Box<dyn ProcessProvider>`. Implementors:
/// [`LinuxProvider`] today; a future `WindowsProvider` / `LeechCoreProvider`.
pub trait ProcessProvider {
    /// The provider's stable, human-readable name (its registry key).
    fn name(&self) -> &str;

    /// Enumerates all processes visible to this provider.
    fn enumerate_processes(&self) -> crate::Result<Vec<ProcessEntry>>;

    /// Opens the process `pid`, returning a [`Process`] whose typed reads/writes
    /// go through this provider's [`crate::MemoryBackend`].
    fn open(&self, pid: Pid) -> crate::Result<Process>;

    /// Enumerates the target's memory [`Section`]s and loaded [`Module`]s
    /// (ReClass.NET's `EnumerateRemoteSectionsAndModules`).
    fn enumerate_sections_and_modules(
        &self,
        pid: Pid,
    ) -> crate::Result<(Vec<Section>, Vec<Module>)>;
}

/// Native Linux provider: enumerates via `/proc`, opens the
/// `process_vm_readv`/`writev` backend, and reads sections/modules from
/// `/proc/<pid>/maps`. Reuses [`ProcessIterator`] and the `maps` parsers.
#[cfg(target_os = "linux")]
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxProvider;

#[cfg(target_os = "linux")]
impl ProcessProvider for LinuxProvider {
    fn name(&self) -> &str {
        LINUX_NATIVE
    }

    fn enumerate_processes(&self) -> crate::Result<Vec<ProcessEntry>> {
        Ok(ProcessIterator::new()?.collect())
    }

    fn open(&self, pid: Pid) -> crate::Result<Process> {
        Process::attach(pid)
    }

    fn enumerate_sections_and_modules(
        &self,
        pid: Pid,
    ) -> crate::Result<(Vec<Section>, Vec<Module>)> {
        // Open a handle so module sizing can read PE headers (Wine `SizeOfImage`).
        let process = Process::attach(pid)?;
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))
            .map_err(|_| crate::Error::ProcessDied)?;

        let sections = super::parse_maps_sections(&maps);
        let modules = process.modules()?.collect();
        Ok((sections, modules))
    }
}

/// Privileged Linux provider backed by the `nemclass_mod` kernel /proc interface.
///
/// Enumeration reuses `/proc` (process listing) exactly like [`LinuxProvider`];
/// the difference is [`open`](ProcessProvider::open), which wires the target's
/// [`Process`] to a [`KernelBackend`] so reads/writes go through the module
/// (bypassing ptrace/Yama) instead of `process_vm_readv`. Opening fails with
/// [`crate::Error::DeviceUnavailable`] when the module is not loaded, so a UI
/// can offer this as a higher-privilege fallback and fall back to
/// `"linux-native"` when it is absent.
///
/// # Authentication
///
/// The module fails **closed**: every privileged ioctl (`READ`/`WRITE`/
/// `ENUM_REGIONS`) requires a successful `NEMCLASS_IOC_AUTH` handshake on the
/// fd first, or it returns `EACCES`. So this provider carries the module's
/// [`key`](KernelProvider::key) and authenticates each fd it opens — the same
/// handshake [`crate::Debugger::attach`] performs. The default (keyless)
/// provider registered by [`ProviderRegistry::default`] can enumerate
/// processes (a `/proc` walk needs no auth) but [`open`](ProcessProvider::open)
/// will fail with `EACCES` until a key is supplied via [`with_key`]; a UI
/// should re-register a keyed provider once the user enters the key.
///
/// The kernel-side debugger (hardware breakpoints / uprobes) lives on
/// [`KernelBackend::client`], reachable via the opened [`Process`]'s backend;
/// it is not part of the [`ProcessProvider`] contract.
///
/// [`with_key`]: KernelProvider::with_key
#[cfg(target_os = "linux")]
#[derive(Debug, Default, Clone)]
pub struct KernelProvider {
    /// Raw auth-key bytes the module was loaded with (`key=<hex>` decoded to
    /// bytes). Empty means "no key" — [`open`](ProcessProvider::open) still
    /// attempts the handshake and surfaces the module's fail-closed `EACCES`.
    key: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl KernelProvider {
    /// A keyless provider — the form registered by
    /// [`ProviderRegistry::default`]. It can enumerate processes, but opening a
    /// target fails with `EACCES` until a key is supplied; use [`with_key`] for
    /// a usable provider.
    ///
    /// [`with_key`]: KernelProvider::with_key
    pub fn new() -> Self {
        Self::default()
    }

    /// A provider that authenticates every fd it opens with `key` — the raw
    /// bytes the module was loaded with (`key=<hex>` decoded to bytes).
    pub fn with_key(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Opens `/proc/nemclass/attach`, verifies the module's ABI, and authenticates with
    /// the configured key — the handshake every privileged ioctl requires.
    /// Mirrors [`crate::Debugger::attach`]. Returns the authed client so callers
    /// can reuse the one fd for both memory IO and enumeration.
    fn open_authed_client(&self) -> crate::Result<KernelClient> {
        let client = KernelClient::open()?;
        // ABI check first: a mismatched module could lay out every subsequent
        // ioctl struct differently.
        client.check_abi()?;
        client.auth(&self.key)?;
        Ok(client)
    }
}

#[cfg(target_os = "linux")]
impl ProcessProvider for KernelProvider {
    fn name(&self) -> &str {
        LINUX_KERNEL
    }

    fn enumerate_processes(&self) -> crate::Result<Vec<ProcessEntry>> {
        // Process discovery is a `/proc` walk regardless of the IO backend, so
        // it needs no device access or auth.
        Ok(ProcessIterator::new()?.collect())
    }

    fn open(&self, pid: Pid) -> crate::Result<Process> {
        // Open + ABI-check + authenticate, then bind the *authed* client to the
        // backend so reads/writes don't hit the module's fail-closed `EACCES`.
        // Surfaces `DeviceUnavailable` if the module is not loaded, `AbiMismatch`
        // on a version skew, or `EACCES` if the key is absent/wrong.
        let client = self.open_authed_client()?;
        let backend = KernelBackend::with_client(client, pid);
        Ok(Process::from_backend(pid, Box::new(backend)))
    }

    fn enumerate_sections_and_modules(
        &self,
        pid: Pid,
    ) -> crate::Result<(Vec<Section>, Vec<Module>)> {
        // Sections come from the module's VMA enumeration (kernel-side, so it
        // works where `/proc/<pid>/maps` is inaccessible). The ABI's region
        // record carries no backing-file name, so every section is classified
        // `Mapped` with no module — module aggregation stays with the native
        // `/proc/<pid>/maps` path (`Process::modules`), used here for parity.
        // `enum_regions` is a privileged ioctl, so open an *authed* client.
        let client = self.open_authed_client()?;
        let sections = client
            .enum_regions(pid)?
            .into_iter()
            .map(|r| Section {
                base: r.from,
                size: r.to.saturating_sub(r.from),
                prot: r.prot,
                kind: SectionType::Mapped,
                module: None,
            })
            .collect();

        // Reuse the well-tested `/proc/<pid>/maps` module aggregation (Wine PE
        // sizing and all) for the module list.
        let process = Process::attach(pid)?;
        let modules = process.modules()?.collect();
        Ok((sections, modules))
    }
}

/// Registry mapping a backend name to a boxed [`ProcessProvider`], so a UI can
/// list and select backends. [`ProviderRegistry::default`] pre-registers the
/// `"linux-native"` provider on Linux.
pub struct ProviderRegistry {
    providers: HashMap<String, Box<dyn ProcessProvider>>,
}

impl ProviderRegistry {
    /// Creates an empty registry with no providers.
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    /// Registers `provider` under its own [`ProcessProvider::name`], replacing
    /// any provider previously registered under that name.
    pub fn register(&mut self, provider: Box<dyn ProcessProvider>) {
        self.providers.insert(provider.name().to_owned(), provider);
    }

    /// Looks up a provider by name.
    pub fn get(&self, name: &str) -> Option<&dyn ProcessProvider> {
        self.providers.get(name).map(|b| b.as_ref())
    }

    /// The registered provider names, in arbitrary order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.providers.keys().map(String::as_str)
    }
}

impl Default for ProviderRegistry {
    /// A registry pre-loaded with the platform's native provider — on Linux, the
    /// `"linux-native"` [`LinuxProvider`] plus the privileged, kernel-module
    /// `"linux-kernel"` [`KernelProvider`] fallback; on Windows, the
    /// `"windows-native"` [`WindowsProvider`] (`ReadProcessMemory`/`OpenProcess`).
    /// On any other platform it is empty until a provider is registered.
    ///
    /// The kernel provider is registered even when the module is not loaded:
    /// registration only names it, and `KernelProvider::open` reports
    /// [`crate::Error::DeviceUnavailable`] so a UI can probe availability and
    /// fall back to `"linux-native"`.
    fn default() -> Self {
        let mut registry = Self::new();
        #[cfg(target_os = "linux")]
        {
            registry.register(Box::new(LinuxProvider));
            // Keyless by default: it can enumerate, but a UI must re-register a
            // `KernelProvider::with_key(..)` before opening a target succeeds.
            registry.register(Box::new(KernelProvider::new()));
        }
        #[cfg(windows)]
        {
            registry.register(Box::new(super::WindowsProvider));
        }
        registry
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_linux_native() {
        let registry = ProviderRegistry::default();
        assert!(registry.get(LINUX_NATIVE).is_some());
        assert_eq!(registry.get(LINUX_NATIVE).unwrap().name(), LINUX_NATIVE);
        assert!(registry.get("does-not-exist").is_none());
    }

    #[test]
    fn default_registry_has_kernel_fallback() {
        // The privileged kernel provider is always registered (its `open` fails
        // gracefully when the module is absent), so it can be offered as a
        // higher-privilege fallback in the backend picker.
        let registry = ProviderRegistry::default();
        assert!(registry.get(LINUX_KERNEL).is_some());
        assert_eq!(registry.get(LINUX_KERNEL).unwrap().name(), LINUX_KERNEL);
    }

    #[test]
    fn keyed_kernel_provider_keeps_its_name() {
        // A UI supplies the module's auth key by re-registering a keyed provider
        // over the keyless default; it must register under the same name so the
        // backend picker's selection still resolves it.
        let keyed = KernelProvider::with_key(vec![0x13, 0x37]);
        assert_eq!(keyed.name(), LINUX_KERNEL);

        let mut registry = ProviderRegistry::default();
        registry.register(Box::new(keyed));
        assert_eq!(registry.get(LINUX_KERNEL).unwrap().name(), LINUX_KERNEL);
        // Still exactly the two Linux providers — the keyed one replaced the
        // keyless default rather than adding a duplicate.
        assert_eq!(registry.names().count(), 2);
    }

    /// Live typed read/write against *our own* memory. A process may always
    /// `process_vm_readv`/`writev` itself, so this normally runs; but on locked
    /// down kernels (restrictive `yama/ptrace_scope`, seccomp, hardened
    /// containers) the syscall can still be denied — in that case we SKIP with a
    /// clear message rather than fail.
    #[test]
    fn self_attach_typed_io_round_trip() {
        let pid = std::process::id() as Pid;
        let provider = LinuxProvider;
        let process = provider.open(pid).expect("open self");

        // A known value at a known address: a heap-boxed u64 we own.
        let cell = Box::new(0xDEAD_BEEF_1234_5678u64);
        let addr = cell.as_ref() as *const u64 as usize;

        // Read it back through the backend.
        match process.read::<u64>(addr) {
            Ok(v) => assert_eq!(v, 0xDEAD_BEEF_1234_5678u64, "typed read mismatch"),
            Err(e) => {
                eprintln!(
                    "SKIP self_attach_typed_io_round_trip: process_vm_readv denied \
                     on this host ({e}); ptrace/process_vm_* is restricted."
                );
                return;
            }
        }

        // Write a new value and confirm both the raw cell and a re-read see it.
        let new_val = 0x0102_0304_0506_0708u64;
        if let Err(e) = process.write::<u64>(addr, new_val) {
            eprintln!(
                "SKIP self_attach_typed_io_round_trip (write): process_vm_writev \
                 denied on this host ({e})."
            );
            return;
        }
        assert_eq!(*cell, new_val, "write did not land in target memory");
        assert_eq!(process.read::<u64>(addr).unwrap(), new_val, "re-read mismatch");

        // Batched read of two adjacent values.
        let pair = Box::new([11u32, 22u32]);
        let base = pair.as_ref().as_ptr() as usize;
        match process.read_batch::<u32>(&[base, base + 4]) {
            Ok(vals) => assert_eq!(vals, vec![11u32, 22u32], "batched read mismatch"),
            Err(e) => eprintln!("SKIP batched read portion ({e})."),
        }
    }
}
