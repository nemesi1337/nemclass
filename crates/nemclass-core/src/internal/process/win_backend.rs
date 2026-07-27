//! Native Windows memory backend and process provider.
//!
//! This is the `#[cfg(windows)]` mirror of the Linux
//! [`IovecProcessMemoryBackend`](crate::internal::process::memory::IovecProcessMemoryBackend)
//! / [`LinuxProvider`](crate::internal::process::LinuxProvider): the same two
//! layered seams, implemented over the Win32 API via `windows-sys` so a Windows
//! build is a drop-in.
//!
//! Behaviour is ported from ReClass.NET's `NativeCore/Windows/`:
//! - [`WindowsBackend`] wraps an open process `HANDLE` and moves bytes with
//!   `ReadProcessMemory` / `WriteProcessMemory` (ReClass's `ReadRemoteMemory` /
//!   `WriteRemoteMemory`). Windows has no scatter/gather memory syscall, so the
//!   `*_batch` variants loop one call per region.
//! - [`WindowsProvider`] enumerates processes with the Toolhelp snapshot API
//!   (`EnumerateProcesses.cpp`), opens a target with `OpenProcess`
//!   (`OpenRemoteProcess.cpp`), and enumerates sections/modules with a
//!   `VirtualQueryEx` walk plus `EnumProcessModules` / `GetModuleInformation`
//!   (`EnumerateRemoteSectionsAndModules.cpp`).

use core::ffi::c_void;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_PARTIAL_COPY, FALSE, HANDLE, HMODULE, INVALID_HANDLE_VALUE, MAX_PATH,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY, VirtualProtectEx, VirtualQueryEx,
};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

use crate::Error;
use crate::internal::process::provider::WINDOWS_NATIVE;
use crate::internal::process::{
    MemoryBackend, Module, Pid, Process, ProcessEntry, ProcessProvider, Protection, Section,
    SectionType,
};

/// Access rights requested when opening a target: a deliberate least-privilege
/// subset of ReClass.NET's `ProcessAccess::Full` (`OpenRemoteProcess.cpp`). We
/// keep only what memory RE needs — VM read + write, the `VM_OPERATION` right
/// `VirtualProtectEx`/writes require, and `QUERY_INFORMATION` for the module and
/// section enumeration — and drop the reference's `PROCESS_TERMINATE` /
/// `SYNCHRONIZE` / `STANDARD_RIGHTS_REQUIRED` bits (we never terminate or wait on
/// the target), so opening succeeds against processes we couldn't get full rights
/// to.
const DESIRED_ACCESS: u32 =
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;

/// An `OpenProcess` handle that is safe to move and share across threads.
///
/// A raw `HANDLE` is a `*mut c_void`, so the compiler infers `!Send`/`!Sync`. But
/// a handle returned by `OpenProcess` names a process-scoped kernel object with no
/// thread affinity (unlike, e.g., window handles): it is valid to use — and to
/// `CloseHandle` — from any thread, and the kernel synchronises the read/write
/// syscalls per handle internally. All access here is through `&self`, so shared
/// concurrent reads are sound. This assertion is what lets [`MemoryBackend`]
/// (hence `Arc<Process>`) carry the `Send + Sync` bound the UI's background
/// workers require.
struct SendHandle(HANDLE);

// SAFETY: see the `SendHandle` doc — `OpenProcess` handles are thread-agnostic
// kernel objects; using/closing one from another thread is well-defined, and all
// access here goes through `&self` (no `&mut` aliasing of the handle itself).
unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}

/// Native Windows [`MemoryBackend`] over an open process `HANDLE`.
///
/// Backed by `ReadProcessMemory` / `WriteProcessMemory`, the direct analogue of
/// the Linux `process_vm_readv` / `process_vm_writev` backend. Owns the handle
/// and closes it on [`Drop`].
///
/// `Send`/`Sync` via [`SendHandle`]: an `OpenProcess` handle has no thread
/// affinity, so the backend can be shared as `Arc<Process>` and driven from a
/// background `spawn_blocking` worker (the trait now requires `Send + Sync`).
pub struct WindowsBackend {
    handle: SendHandle,
}

impl WindowsBackend {
    /// Opens the process `pid` with full read/write access and wraps its handle.
    ///
    /// Fails with [`Error::WinApi`] carrying `GetLastError` when `OpenProcess`
    /// returns null (no such pid, or insufficient privilege — the caller may need
    /// `SeDebugPrivilege`).
    pub fn open(pid: Pid) -> crate::Result<Self> {
        // SAFETY: `OpenProcess` takes scalar args and returns a handle (or null on
        // failure); it has no memory-safety preconditions. A Windows pid is a
        // `DWORD`, so the neutral signed `Pid` is widened back to `u32`.
        let handle = unsafe { OpenProcess(DESIRED_ACCESS, FALSE, pid as u32) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Error::last_win32();
        }
        Ok(WindowsBackend { handle: SendHandle(handle) })
    }

    /// The raw process handle, for callers that need further Win32 calls.
    pub fn handle(&self) -> HANDLE {
        self.handle.0
    }
}

impl Drop for WindowsBackend {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is a live handle returned by `OpenProcess` and
        // never closed elsewhere (we own it), so this is the single, valid close.
        // Closing from a non-opening thread is well-defined (see `SendHandle`).
        unsafe {
            CloseHandle(self.handle.0);
        }
    }
}

impl MemoryBackend for WindowsBackend {
    fn read_buf(&self, address: usize, buf: &mut [u8]) -> crate::Result<usize> {
        let mut read: usize = 0;
        // SAFETY: `buf` is a live, uniquely-borrowed slice of `buf.len()` writable
        // bytes, matching `nsize`; `read` is a valid out-pointer. `lpbaseaddress`
        // is only dereferenced by the kernel in the target's address space, so an
        // unmapped range fails (returns FALSE / short count) rather than faulting
        // us. `self.handle` is a live process handle.
        let ok = unsafe {
            ReadProcessMemory(
                self.handle.0,
                address as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut read,
            )
        };
        if ok != FALSE {
            // Full success: `read` equals the requested length.
            return Ok(read);
        }
        // `ReadProcessMemory` is documented all-or-nothing: it verifies the whole
        // range up front and fails (FALSE) if any of it is inaccessible. When the
        // range merely *crosses* a mapping boundary it fails with
        // `ERROR_PARTIAL_COPY`, and — unlike the Linux `process_vm_readv` backend —
        // often reports `read == 0` even though the leading pages were readable.
        // Normalise that to [`Error::PartialTransfer`] so a boundary-spanning bulk
        // read behaves like the Linux peer (the typed layer then decides), and
        // surface any other failure as the raw Win32 error.
        // SAFETY: `GetLastError` is a thread-local read with no preconditions.
        let last = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if last == ERROR_PARTIAL_COPY {
            return Err(Error::PartialTransfer {
                requested: buf.len(),
                actual: read,
            });
        }
        Error::last_win32()
    }

    fn read_buf_batch(&self, regions: &mut [(usize, &mut [u8])]) -> crate::Result<usize> {
        // No scatter/gather on Windows: one `ReadProcessMemory` per region.
        let mut total = 0;
        for (address, buf) in regions.iter_mut() {
            total += self.read_buf(*address, buf)?;
        }
        Ok(total)
    }

    fn write_buf(&self, address: usize, buf: &[u8]) -> crate::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Port of ReClass.NET's `WriteRemoteMemory.cpp`: temporarily make the
        // target range `PAGE_EXECUTE_READWRITE` so writes to read-only / code /
        // copy-on-write pages (patching `.text`, editing RO data) land instead of
        // failing with `ERROR_NOACCESS`. The original protection is restored by
        // `_restore` on every exit path (including the early `?` below).
        let _restore = ProtectionGuard::apply(self.handle.0, address, buf.len(), PAGE_EXECUTE_READWRITE);

        let mut written: usize = 0;
        // SAFETY: `buf` is a live, readable slice of `buf.len()` bytes matching
        // `nsize`; `written` is a valid out-pointer. `lpbaseaddress` is only
        // dereferenced by the kernel in the target; an unmapped range fails (FALSE)
        // rather than faulting us. `self.handle` is a live handle.
        let ok = unsafe {
            WriteProcessMemory(
                self.handle.0,
                address as *const c_void,
                buf.as_ptr() as *const c_void,
                buf.len(),
                &mut written,
            )
        };
        if ok == FALSE && written == 0 {
            return Error::last_win32();
        }
        Ok(written)
    }

    fn write_buf_batch(&self, regions: &[(usize, &[u8])]) -> crate::Result<usize> {
        let mut total = 0;
        for (address, buf) in regions.iter() {
            total += self.write_buf(*address, buf)?;
        }
        Ok(total)
    }
}

/// Native Windows [`ProcessProvider`]: enumerates via Toolhelp, opens via
/// `OpenProcess` (into a [`WindowsBackend`]), and enumerates sections/modules via
/// `VirtualQueryEx` + `EnumProcessModules`. The `#[cfg(windows)]` mirror of
/// [`LinuxProvider`](crate::internal::process::LinuxProvider).
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsProvider;

impl ProcessProvider for WindowsProvider {
    fn name(&self) -> &str {
        WINDOWS_NATIVE
    }

    /// Two deliberate divergences from ReClass.NET's `EnumerateProcesses.cpp`,
    /// both simplifications for the native listing:
    /// - the name comes from `PROCESSENTRY32W.szExeFile` (the snapshot's short exe
    ///   name) instead of opening each process and calling `GetModuleFileNameExW`
    ///   — more robust (no per-process open, no privilege dependency) and enough
    ///   for a picker;
    /// - every process is returned, rather than filtering to the host bitness
    ///   (the reference's `GetProcessPlatform` X86-vs-X64 filter is omitted).
    fn enumerate_processes(&self) -> crate::Result<Vec<ProcessEntry>> {
        // SAFETY: `CreateToolhelp32Snapshot` takes scalar flags and returns a
        // handle (or INVALID_HANDLE_VALUE); no memory-safety preconditions.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Error::last_win32();
        }

        // Close the snapshot however we leave this function.
        let _guard = HandleGuard(snapshot);

        let mut entry = PROCESSENTRY32W {
            // `dwSize` MUST be set before the first `Process32FirstW`, or it fails.
            dwSize: core::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut processes = Vec::new();

        // SAFETY: `snapshot` is a live snapshot handle; `entry` is a live, sized
        // `PROCESSENTRY32W` with `dwSize` set, exactly what the API writes into.
        let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) };
        while ok != FALSE {
            processes.push(ProcessEntry {
                id: entry.th32ProcessID,
                parent_id: entry.th32ParentProcessID,
                name: wide_to_string(&entry.szExeFile),
            });
            // SAFETY: same invariants as `Process32FirstW`; `entry` stays valid.
            ok = unsafe { Process32NextW(snapshot, &mut entry) };
        }

        Ok(processes)
    }

    fn open(&self, pid: Pid) -> crate::Result<Process> {
        let backend = WindowsBackend::open(pid)?;
        Ok(Process::from_backend(pid, Box::new(backend)))
    }

    fn enumerate_sections_and_modules(
        &self,
        pid: Pid,
    ) -> crate::Result<(Vec<Section>, Vec<Module>)> {
        let backend = WindowsBackend::open(pid)?;
        let handle = backend.handle();

        let sections = enumerate_sections(handle);
        let modules = enumerate_modules(handle)?;
        Ok((sections, modules))
    }
}

/// Walks the target's committed memory with `VirtualQueryEx`, one [`Section`] per
/// region (ReClass.NET's `VirtualQueryEx` loop). Only `MEM_COMMIT` regions are
/// reported; reserved/free ranges are skipped.
fn enumerate_sections(handle: HANDLE) -> Vec<Section> {
    let mut sections = Vec::new();
    let mut address: usize = 0;

    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: `mbi` is a live, sized `MEMORY_BASIC_INFORMATION` out-buffer;
        // `handle` is a live process handle. `lpaddress` is a bare integer the
        // kernel interprets in the target and never dereferences in our space.
        let written = unsafe {
            VirtualQueryEx(
                handle,
                address as *const c_void,
                &mut mbi,
                core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        // A zero return means we walked off the end of the address space (or an
        // error) — stop.
        if written == 0 {
            break;
        }

        if mbi.State == MEM_COMMIT {
            sections.push(Section {
                base: mbi.BaseAddress as usize,
                size: mbi.RegionSize,
                prot: protection_from_page_flags(mbi.Protect),
                kind: section_type_from_mem_type(mbi.Type),
                // The `VirtualQueryEx` record carries no backing-file name; module
                // attribution would require correlating with `enumerate_modules`,
                // which the caller has separately. Left `None`, like the Linux
                // kernel provider's section enumeration.
                module: None,
            });
        }

        // Advance past this region; guard against wrap-around at the top of the
        // address space (the C++ loop's `address + RegionSize > address` check).
        let Some(next) = (mbi.BaseAddress as usize).checked_add(mbi.RegionSize) else {
            break;
        };
        if next <= address {
            break;
        }
        address = next;
    }

    sections
}

/// Enumerates the target's loaded modules via `EnumProcessModules` +
/// `GetModuleInformation` / `GetModuleFileNameExW` (ReClass.NET's
/// `EnumerateRemoteModulesWinapi`). Returns base/size/name per module.
fn enumerate_modules(handle: HANDLE) -> crate::Result<Vec<Module>> {
    // First call learns the required byte size; then allocate and re-query. A
    // process can load thousands of modules, so we grow to whatever it reports.
    let mut needed: u32 = 0;
    // SAFETY: passing a null module array with `cb = 0` is the documented way to
    // ask `EnumProcessModules` only for the required size via `lpcbneeded`.
    let ok = unsafe { EnumProcessModules(handle, core::ptr::null_mut(), 0, &mut needed) };
    if ok == FALSE {
        return Error::last_win32();
    }

    let count = needed as usize / core::mem::size_of::<HMODULE>();
    let mut modules: Vec<HMODULE> = vec![core::ptr::null_mut(); count];
    if count == 0 {
        return Ok(Vec::new());
    }

    let cb = (modules.len() * core::mem::size_of::<HMODULE>()) as u32;
    // SAFETY: `modules` is a live buffer of `count` `HMODULE`s; `cb` is its exact
    // byte length; `needed` is a valid out-pointer. `handle` is a live handle.
    let ok = unsafe { EnumProcessModules(handle, modules.as_mut_ptr(), cb, &mut needed) };
    if ok == FALSE {
        return Error::last_win32();
    }
    // The set can shrink between the two calls; clamp to what the second reports.
    modules.truncate(needed as usize / core::mem::size_of::<HMODULE>());

    let mut out = Vec::with_capacity(modules.len());
    for hmodule in modules {
        let mut info = MODULEINFO::default();
        // SAFETY: `info` is a live, sized `MODULEINFO` out-buffer; `hmodule` is a
        // handle just returned by `EnumProcessModules`; `handle` is live. A stale
        // module (unloaded between calls) fails cleanly and is skipped.
        let ok = unsafe {
            GetModuleInformation(
                handle,
                hmodule,
                &mut info,
                core::mem::size_of::<MODULEINFO>() as u32,
            )
        };
        if ok == FALSE {
            continue;
        }

        // `GetModuleFileNameExW` writes up to `nsize` UTF-16 code units and
        // returns the count (0 on failure). Take just the file name.
        let mut buf = [0u16; MAX_PATH as usize];
        // SAFETY: `buf` is a live array of `buf.len()` `u16`s matching `nsize`;
        // `hmodule`/`handle` are live. On failure it returns 0 and we skip.
        let len = unsafe {
            GetModuleFileNameExW(handle, hmodule, buf.as_mut_ptr(), buf.len() as u32)
        };
        let full = wide_to_string(&buf[..len as usize]);
        let name = full
            .rsplit(['\\', '/'])
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(&full)
            .to_owned();

        out.push(Module {
            base: info.lpBaseOfDll as usize,
            size: info.SizeOfImage as usize,
            name,
        });
    }

    Ok(out)
}

/// Maps a Win32 `PAGE_*` protection mask to the neutral [`Protection`] bits.
///
/// Mirrors the `Protect` decoding in ReClass.NET's
/// `EnumerateRemoteSectionsAndModules.cpp`; the copy-on-write variants read as
/// readable+writable (the write bit reflects that the page is writable), and the
/// `PAGE_GUARD`/`PAGE_NOCACHE` modifier bits are ignored for r/w/x purposes.
fn protection_from_page_flags(protect: u32) -> Protection {
    // The low 8 bits carry the base protection; `PAGE_GUARD` (0x100) etc. are
    // modifiers we mask off before matching the base constant.
    let base = protect & 0xFF;
    match base {
        p if p == PAGE_EXECUTE => Protection::X,
        p if p == PAGE_EXECUTE_READ => Protection::RX,
        p if p == PAGE_EXECUTE_READWRITE => Protection::RWX,
        p if p == PAGE_EXECUTE_WRITECOPY => Protection::RWX,
        p if p == PAGE_READONLY => Protection::R,
        p if p == PAGE_READWRITE => Protection::RW,
        p if p == PAGE_WRITECOPY => Protection::RW,
        // PAGE_NOACCESS and anything unrecognised: no access.
        _ => Protection::empty(),
    }
}

/// Maps a `VirtualQueryEx` region `Type` to the neutral [`SectionType`].
fn section_type_from_mem_type(mem_type: u32) -> SectionType {
    match mem_type {
        t if t == MEM_IMAGE => SectionType::Image,
        t if t == MEM_MAPPED => SectionType::Mapped,
        // MEM_PRIVATE (heap/stack/private) — anonymous, like Linux's `Mapped`.
        _ => SectionType::Mapped,
    }
}

/// Decodes a fixed-size UTF-16 buffer (as Win32 `WCHAR[]` fields are) into a
/// `String`, stopping at the first NUL and replacing any lone surrogates rather
/// than failing (these come from the OS and should never panic the caller).
fn wide_to_string(wide: &[u16]) -> String {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

/// RAII closer for a Toolhelp snapshot (or any `HANDLE` closed with
/// `CloseHandle`), so early returns don't leak it.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live handle we own for the guard's lifetime and
        // close exactly once here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// RAII page-protection change for a target range (ReClass.NET's
/// `WriteRemoteMemory.cpp` protect/write/restore dance).
///
/// [`apply`](ProtectionGuard::apply) flips `[address, address+size)` to
/// `new_protect` and, on [`Drop`], restores whatever protection was there before.
/// If the initial `VirtualProtectEx` fails (e.g. the range is already suitably
/// writable, spans multiple protections, or can't be reprotected), the guard is
/// inert and the write proceeds best-effort — matching the common case where the
/// target is already writable, and never masking the real write error.
struct ProtectionGuard {
    handle: HANDLE,
    address: usize,
    size: usize,
    /// The protection to restore, if we successfully changed it.
    old_protect: Option<PAGE_PROTECTION_FLAGS>,
}

impl ProtectionGuard {
    fn apply(handle: HANDLE, address: usize, size: usize, new_protect: u32) -> Self {
        let mut old_protect: PAGE_PROTECTION_FLAGS = 0;
        // SAFETY: `old_protect` is a valid out-pointer; `lpaddress`/`dwsize` name a
        // range the kernel validates in the target (a bad range fails FALSE, it
        // never dereferences our memory); `handle` is a live process handle.
        let ok = unsafe {
            VirtualProtectEx(
                handle,
                address as *const c_void,
                size,
                new_protect,
                &mut old_protect,
            )
        };
        ProtectionGuard {
            handle,
            address,
            size,
            old_protect: (ok != FALSE).then_some(old_protect),
        }
    }
}

impl Drop for ProtectionGuard {
    fn drop(&mut self) {
        let Some(old) = self.old_protect else {
            return;
        };
        let mut prev: PAGE_PROTECTION_FLAGS = 0;
        // SAFETY: same range/handle as the successful `apply` call, restoring the
        // exact protection it reported; `prev` is a throwaway out-pointer. Failure
        // to restore is non-fatal (and unreportable from `Drop`), so ignored.
        unsafe {
            VirtualProtectEx(
                self.handle,
                self.address as *const c_void,
                self.size,
                old,
                &mut prev,
            );
        }
    }
}
