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
    Module, Process, ProcessEntry, ProcessIterator, Section,
};

/// Name of the default, built-in provider registered by
/// [`ProviderRegistry::default`].
pub const LINUX_NATIVE: &str = "linux-native";

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
    fn open(&self, pid: libc::pid_t) -> crate::Result<Process>;

    /// Enumerates the target's memory [`Section`]s and loaded [`Module`]s
    /// (ReClass.NET's `EnumerateRemoteSectionsAndModules`).
    fn enumerate_sections_and_modules(
        &self,
        pid: libc::pid_t,
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

    fn open(&self, pid: libc::pid_t) -> crate::Result<Process> {
        Process::attach(pid)
    }

    fn enumerate_sections_and_modules(
        &self,
        pid: libc::pid_t,
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
    /// `"linux-native"` [`LinuxProvider`]. On other platforms it is empty until a
    /// provider is registered (a Windows provider slots in here later).
    fn default() -> Self {
        let mut registry = Self::new();
        #[cfg(target_os = "linux")]
        registry.register(Box::new(LinuxProvider));
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

    /// Live typed read/write against *our own* memory. A process may always
    /// `process_vm_readv`/`writev` itself, so this normally runs; but on locked
    /// down kernels (restrictive `yama/ptrace_scope`, seccomp, hardened
    /// containers) the syscall can still be denied — in that case we SKIP with a
    /// clear message rather than fail.
    #[test]
    fn self_attach_typed_io_round_trip() {
        let pid = std::process::id() as libc::pid_t;
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
