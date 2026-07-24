pub mod memory;
mod iter;
mod types;
mod protection;
mod windows;

use std::collections::HashMap;
use std::fs;
pub use iter::*;
pub use types::*;
pub use protection::*;

use crate::Error;
use crate::internal::process::memory::ProcessMemoryBackend;
use crate::internal::process::windows::size_of_image;

pub struct Process {
    pid: libc::pid_t,
    backend: Box<dyn ProcessMemoryBackend>,
}

impl Process {
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

    pub fn read<T>(&self, address: usize) -> crate::Result<T> {
        todo!()
    }

    pub fn read_batch<T>(&self, addresses: &[usize]) -> crate::Result<Vec<T>> {
        todo!()
    }

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
            if lower.ends_with(".exe") || lower.ends_with(".dll") {
                if let Some(image_size) = size_of_image(self, base) {
                    if image_size != 0 {
                        size = image_size as usize;
                    }
                }
            }

            out.push(ModuleInfoWithName {
                name,
                base,
                size,
            });
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