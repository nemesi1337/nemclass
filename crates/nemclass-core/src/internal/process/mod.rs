pub mod memory;
mod iter;
mod types;
mod protection;
mod provider;

// Wine detection is Linux-specific glue.
#[cfg(target_os = "linux")]
mod windows;

// PE header parsing is platform-neutral (used by Wine detection today, a future
// Windows backend tomorrow), so it is always compiled and publicly exposed.
pub mod pe;

use std::collections::HashMap;
use std::fs;
pub use iter::*;
pub use types::*;
pub use protection::*;
pub use provider::*;
pub use memory::MemoryBackend;

use crate::Error;
use crate::internal::process::memory::IovecProcessMemoryBackend;

/// A handle to an opened target process: its [`ProcessEntry`] identity plus the
/// [`MemoryBackend`] its typed reads/writes go through.
///
/// Construct one with [`Process::attach`] (opens the default Linux backend) or,
/// for a specific backend, via [`crate::ProcessProvider::open`].
pub struct Process {
    pid: libc::pid_t,
    backend: Box<dyn MemoryBackend>,
}

impl Process {
    /// Builds a `Process` from an already-opened backend. Used by providers.
    pub(crate) fn from_backend(pid: libc::pid_t, backend: Box<dyn MemoryBackend>) -> Self {
        Process { pid, backend }
    }

    /// Attaches to the process with the given `pid` using the default native
    /// backend (Linux `process_vm_readv`/`writev`).
    ///
    /// This does not stop the target or verify liveness up front — a dead or
    /// inaccessible pid surfaces on the first read/write as an [`Error`].
    #[cfg(target_os = "linux")]
    pub fn attach(pid: libc::pid_t) -> crate::Result<Self> {
        Ok(Process::from_backend(
            pid,
            Box::new(IovecProcessMemoryBackend::new(pid)),
        ))
    }

    /// The process id this handle is attached to.
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Returns full path to the process.
    pub fn path(&self) -> crate::Result<String> {
        Ok(fs::read_link(format!("/proc/{}/exe", self.pid))
            .map_err(|_| Error::ProcessDied)?
            .to_string_lossy()
            .into_owned())
    }

    /// Returns the name of the process
    pub fn name(&self) -> crate::Result<String> {
        Ok(fs::read_link(format!("/proc/{}/exe", self.pid))
            .map_err(|_| Error::ProcessDied)?
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default())
    }

    /// Reads a single `T` from `address`.
    ///
    /// `T: Pod` guarantees every bit pattern is a valid `T`, so the read-back
    /// bytes are reinterpreted with `bytemuck` (no hand-rolled `unsafe`). A short
    /// read (target died mid-read, address partly unmapped) is reported as
    /// [`Error::PartialTransfer`].
    pub fn read<T: bytemuck::Pod>(&self, address: usize) -> crate::Result<T> {
        let mut value = T::zeroed();
        let buf = bytemuck::bytes_of_mut(&mut value);
        let requested = buf.len();
        let read = self.backend.read_buf(address, buf)?;
        if read != requested {
            return Err(Error::PartialTransfer {
                requested,
                actual: read,
            });
        }
        Ok(value)
    }

    /// Reads one `T` from each address in `addresses`, in a single batched
    /// backend call (chunked to `IOV_MAX` under the hood).
    pub fn read_batch<T: bytemuck::Pod>(&self, addresses: &[usize]) -> crate::Result<Vec<T>> {
        let size = core::mem::size_of::<T>();
        // A zero-sized `T` transfers nothing; return one value per address rather
        // than letting the chunking below silently collapse to an empty `Vec`.
        if size == 0 {
            return Ok(vec![T::zeroed(); addresses.len()]);
        }
        // Back the batch with one flat byte buffer, then split it into per-value
        // sub-slices to hand the backend as `(address, &mut [u8])` regions.
        let mut bytes = vec![0u8; size * addresses.len()];
        {
            let mut regions: Vec<(usize, &mut [u8])> = addresses
                .iter()
                .copied()
                .zip(bytes.chunks_mut(size.max(1)))
                .collect();
            let requested = size * addresses.len();
            let read = self.backend.read_buf_batch(&mut regions)?;
            if read != requested {
                return Err(Error::PartialTransfer {
                    requested,
                    actual: read,
                });
            }
        }
        Ok(bytes
            .chunks(size.max(1))
            .map(bytemuck::pod_read_unaligned::<T>)
            .collect())
    }

    /// Bulk-reads bytes starting at `address` into `buf` in a single backend
    /// call (one `process_vm_readv` on Linux). Returns the number of bytes read,
    /// which may be short if the region is partly unmapped. Prefer this over
    /// per-byte [`Process::read`]/[`Process::read_batch`] when snapshotting a
    /// whole class/struct region for display.
    pub fn read_buf(&self, address: usize, buf: &mut [u8]) -> crate::Result<usize> {
        self.backend.read_buf(address, buf)
    }

    /// Writes a single `T` to `address`. A short write is reported as
    /// [`Error::PartialTransfer`].
    pub fn write<T: bytemuck::Pod>(&self, address: usize, value: T) -> crate::Result<()> {
        let buf = bytemuck::bytes_of(&value);
        let requested = buf.len();
        let written = self.backend.write_buf(address, buf)?;
        if written != requested {
            return Err(Error::PartialTransfer {
                requested,
                actual: written,
            });
        }
        Ok(())
    }

    /// Enumerates the target's loaded modules, aggregating the many
    /// `/proc/<pid>/maps` mappings of one image into a single base/size/name.
    pub fn modules(&self) -> crate::Result<impl Iterator<Item = ModuleInfoWithName>> {
        let s = fs::read_to_string(format!("/proc/{}/maps", self.pid))
            .map_err(|_| crate::Error::ProcessDied)?;

        let mut out = Vec::new();
        for RawModule { name, base, end } in parse_maps_modules(&s) {
            // The span of section mappings undercounts a Wine PE (alignment
            // gaps, header-only tail pages), so prefer the true `SizeOfImage`
            // read from the PE header mapped at the image base. Native objects
            // have no PE header there, so fall back to the measured span.
            let mut size = end.saturating_sub(base);
            let lower = name.to_ascii_lowercase();
            if (lower.ends_with(".exe") || lower.ends_with(".dll"))
                && let Some(image_size) = pe::size_of_image(self, base)
                && image_size != 0
            {
                size = image_size as usize;
            }

            out.push(ModuleInfoWithName { name, base, size });
        }

        Ok(out.into_iter())
    }
}

/// Parses `/proc/<pid>/maps` text into one span per mapped file.
///
/// Robust to the two things that break naive whitespace splitting under Wine:
/// - **paths with spaces** (`drive_c/Program Files/…`) and the **`(deleted)`**
///   suffix — the pathname is taken as everything from the first `/` (the
///   address/perms/offset/dev/inode columns never contain one);
/// - **fragmented PE images** — Wine maps one PE as many section mappings, which
///   are merged here by full path (so 32- and 64-bit copies under WoW64 stay
///   distinct). The reported base is the mapping at file offset 0 (the PE
///   headers / true image base), falling back to the lowest mapping. Modules are
///   returned in first-seen order.
fn parse_maps_modules(maps: &str) -> Vec<RawModule> {
    struct Acc {
        name: String,
        image_base: Option<usize>,
        lowest: usize,
        end: usize,
    }

    let mut order: Vec<String> = Vec::new();
    let mut acc: HashMap<String, Acc> = HashMap::new();

    for line in maps.lines() {
        // File-backed mappings are exactly the lines with a pathname, which
        // starts at the first '/'. Anonymous / [heap] / [stack] have none.
        let Some(slash) = line.find('/') else {
            continue;
        };
        let path = line[slash..].trim_end();
        let path = path
            .strip_suffix("(deleted)")
            .map(str::trim_end)
            .unwrap_or(path);
        let Some(name) = path.rsplit('/').next().filter(|n| !n.is_empty()) else {
            continue;
        };

        // The columns before the pathname: address perms offset dev inode.
        let mut fields = line[..slash].split_whitespace();
        let Some((from, to)) = fields.next().and_then(|r| r.split_once('-')) else {
            continue;
        };
        let (Ok(start), Ok(end)) =
            (usize::from_str_radix(from, 16), usize::from_str_radix(to, 16))
        else {
            continue;
        };
        let _perms = fields.next();
        let offset = fields
            .next()
            .and_then(|s| usize::from_str_radix(s, 16).ok())
            .unwrap_or(0);

        let entry = acc.entry(path.to_owned()).or_insert_with(|| {
            order.push(path.to_owned());
            Acc {
                name: name.to_owned(),
                image_base: None,
                lowest: start,
                end,
            }
        });
        // The offset-0 mapping holds the MZ/NT headers and sits at the true image
        // base; `start - offset` is unreliable when section alignments differ.
        if offset == 0 && entry.image_base.is_none() {
            entry.image_base = Some(start);
        }
        entry.lowest = entry.lowest.min(start);
        entry.end = entry.end.max(end);
    }

    order
        .into_iter()
        .filter_map(|path| acc.remove(&path))
        .map(|a| RawModule {
            name: a.name,
            base: a.image_base.unwrap_or(a.lowest),
            end: a.end,
        })
        .collect()
}

/// Parses `/proc/<pid>/maps` text into one [`Section`] per mapping.
///
/// Unlike [`parse_maps_modules`], this keeps every mapping as its own section
/// (ReClass.NET's `EnumerateRemoteSectionData`): file-backed mappings are
/// [`SectionType::Image`] and carry their module file name; anonymous mappings
/// are [`SectionType::Mapped`]. Sections are returned in `maps` order.
fn parse_maps_sections(maps: &str) -> Vec<Section> {
    let mut out = Vec::new();

    for line in maps.lines() {
        // Split the fixed leading columns (address perms offset dev inode) from
        // the optional pathname, which — when present — starts at the first '/'.
        let (head, path) = match line.find('/') {
            Some(slash) => (&line[..slash], Some(line[slash..].trim_end())),
            None => (line, None),
        };

        let mut fields = head.split_whitespace();
        let Some((from, to)) = fields.next().and_then(|r| r.split_once('-')) else {
            continue;
        };
        let (Ok(start), Ok(end)) =
            (usize::from_str_radix(from, 16), usize::from_str_radix(to, 16))
        else {
            continue;
        };
        let perms = fields.next().unwrap_or("----");
        // Protection is the r/w/x of the first three perm chars ('p'/'s' is the
        // 4th and irrelevant here).
        let prot = Protection::parse(&perms[..perms.len().min(3)]);

        // A file-backed mapping is one with a real path (starts with '/'); the
        // pseudo-mappings [heap]/[stack]/[vvar] start with '[' and are anonymous.
        let (kind, module) = match path {
            Some(p) if p.starts_with('/') => {
                let p = p.strip_suffix("(deleted)").map(str::trim_end).unwrap_or(p);
                let name = p.rsplit('/').next().filter(|n| !n.is_empty()).map(str::to_owned);
                (SectionType::Image, name)
            }
            _ => (SectionType::Mapped, None),
        };

        out.push(Section {
            base: start,
            size: end.saturating_sub(start),
            prot,
            kind,
            module,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // A trimmed but representative `/proc/<pid>/maps`, including the Wine
    // pitfalls the parser must survive: a path with spaces, a `(deleted)`
    // suffix, a fragmented PE (multiple mappings of one image, offset-0 giving
    // the base), and anonymous [heap]/[stack] lines.
    const SAMPLE_MAPS: &str = "\
55d000001000-55d000002000 r--p 00000000 08:01 100   /usr/bin/app
55d000002000-55d000004000 r-xp 00001000 08:01 100   /usr/bin/app
7f0000000000-7f0000001000 r--p 00000000 08:01 200   /drive_c/Program Files/game.exe
7f0000001000-7f0000005000 r-xp 00001000 08:01 200   /drive_c/Program Files/game.exe (deleted)
7f0000006000-7f0000007000 rw-p 00000000 00:00 0     [heap]
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0     [stack]
7f0000009000-7f000000a000 ---p 00000000 00:00 0 ";

    #[test]
    fn parse_maps_modules_merges_fragments_and_handles_paths() {
        let mods = parse_maps_modules(SAMPLE_MAPS);
        assert_eq!(mods.len(), 2, "one module per distinct file path");

        // First-seen order: the native app, then the Wine PE.
        assert_eq!(mods[0].name, "app");
        assert_eq!(mods[0].base, 0x55d000001000);
        // End of the last app mapping.
        assert_eq!(mods[0].end, 0x55d000004000);

        // A path-with-spaces + `(deleted)` file, merged across two mappings; the
        // offset-0 mapping fixes the base.
        assert_eq!(mods[1].name, "game.exe");
        assert_eq!(mods[1].base, 0x7f0000000000);
        assert_eq!(mods[1].end, 0x7f0000005000);
    }

    #[test]
    fn parse_maps_sections_classifies_each_mapping() {
        let secs = parse_maps_sections(SAMPLE_MAPS);
        assert_eq!(secs.len(), 7, "one section per mapping line");

        // First section: r--p image page of the native app.
        assert_eq!(secs[0].base, 0x55d000001000);
        assert_eq!(secs[0].size, 0x1000);
        assert_eq!(secs[0].prot, Protection::R);
        assert_eq!(secs[0].kind, SectionType::Image);
        assert_eq!(secs[0].module.as_deref(), Some("app"));

        // r-xp code page.
        assert_eq!(secs[1].prot, Protection::RX);

        // `(deleted)` suffix stripped from the module name.
        assert_eq!(secs[3].module.as_deref(), Some("game.exe"));
        assert_eq!(secs[3].kind, SectionType::Image);

        // [heap] is an anonymous, writable mapping.
        assert_eq!(secs[4].kind, SectionType::Mapped);
        assert_eq!(secs[4].prot, Protection::RW);
        assert_eq!(secs[4].module, None);

        // Trailing `---p` anonymous mapping with no name column.
        assert_eq!(secs[6].kind, SectionType::Mapped);
        assert_eq!(secs[6].prot, Protection::empty());
    }
}
