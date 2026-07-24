use std::fs;
use std::path::Path;
use crate::internal::process::ProcessEntry;
use crate::internal::process::windows::windows_exe_name;

pub struct ProcessIterator(Box<dyn Iterator<Item = ProcessEntry>>);

impl ProcessIterator {
    /// Creates new iterator over all processes in the system.
    /// # Unix
    /// Always returns Ok(I).
    pub fn new() -> crate::Result<Self> {
        fn get_parent_id(proc: &Path) -> u32 {
            let status = fs::read_to_string(proc.join("status")).unwrap();

            let parent_id = status
                .lines()
                .find_map(|l: &str| {
                    if l.starts_with("PPid:") {
                        l.split_once(':').map(|(_, tail)| tail.trim().to_owned())
                    } else {
                        None
                    }
                })
                .and_then(|p| p.parse::<u32>().ok())
                .unwrap();

            parent_id
        }

        let iter = fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter_map(|de| Some((de.file_name().to_str()?.parse::<u32>().ok()?, de)))
            .filter_map(|(id, de)| {
                let entry = de.path();

                let path = fs::read_link(entry.join("exe")).ok()?;
                let mut name = path.file_name()?.to_str()?.to_owned();
                let parent_id = get_parent_id(&entry);

                // A Wine process's ELF image is just the loader (wine-preloader,
                // wine64-preloader, ...), so every Wine game lists under the same
                // useless name. Surface the actual Windows program it runs. Gate
                // on the loader name so we only scan maps for likely candidates.
                if name.to_ascii_lowercase().starts_with("wine") {
                    if let Some(exe) = windows_exe_name(id) {
                        name = format!("{name} ({exe})");
                    }
                }

                Some(ProcessEntry {
                    id,
                    name,
                    parent_id,
                })
            });

        Ok(Self(Box::new(iter)))
    }
}

impl Iterator for ProcessIterator {
    type Item = ProcessEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}
