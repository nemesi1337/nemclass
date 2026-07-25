//! `UiHostApi` — main-thread implementation of `nemclass_script::HostApi`.
//!
//! This entire module is gated on `#[cfg(feature = "scripting")]` because
//! `HostApi` itself only exists under that feature.  Every item below is
//! therefore only compiled when the feature is active.
//!
//! # Design
//!
//! `UiHostApi` is built **fresh each frame** in `NemclassApp::logic`, borrowing
//! disjoint fields from `NemclassApp`:
//!
//! - `project: &'a mut Project` — receives `declare_class` / `declare_type`.
//! - `node_registry: &'a NodeRegistry` — needed by `declare_class` for potential
//!   future node construction (held here so the call signature is stable).
//! - `process: Option<&'a Process>` — needed for `pattern_scan`; `None` means
//!   not attached.
//! - `log: ScriptLog` — an `Rc` **clone** (not a borrow) so it can live in this
//!   struct without conflicting with the other `&mut` borrows above.
//! - `last_error: &'a mut Option<String>` — receives the first host-level error
//!   string, surfaced in the UI status bar.
//!
//! The `Rc<RefCell<…>>` log is safe here because the UI crate is entirely
//! single-threaded.

#[cfg(feature = "scripting")]
mod inner {
    use nemclass_core::Process;
    use nemclass_model::{ClassNode, EnumDescription, Project};
    use nemclass_script::{HostApi, LogLevel, scan_module};

    use super::super::script_log::{LogKind, ScriptLog, push};

    /// Main-thread `HostApi` implementation built fresh each frame.
    pub struct UiHostApi<'a> {
        /// The open project; receives `declare_class` / `declare_type` mutations.
        pub project: &'a mut Project,
        /// Attached process, or `None` when not attached.
        pub process: Option<&'a Process>,
        /// Shared log buffer.  An `Rc` clone rather than a borrow so the struct
        /// can also hold `&mut project` without a lifetime conflict.
        pub log: ScriptLog,
        /// Receives the first error message for display in the UI status bar.
        pub last_error: &'a mut Option<String>
    }

    impl<'a> HostApi for UiHostApi<'a> {
        /// IDA-style byte-pattern scan over a named module in the attached process.
        ///
        /// Finds the module by case-insensitive name, reads its full byte range
        /// via `Process::read_buf`, then delegates to `scan_module` (from
        /// `nemclass_script`) to get absolute hit addresses.
        fn pattern_scan(&mut self, module: &str, pattern: &str) -> Result<Vec<usize>, String> {
            let proc = self.process.ok_or_else(|| "not attached".to_string())?;

            // Enumerate modules (Linux: /proc/<pid>/maps aggregation).
            let modules: Vec<_> = proc
                .modules()
                .map_err(|e| format!("enumerate modules: {e}"))?
                .collect();

            let info = modules
                .iter()
                .find(|m| m.name.eq_ignore_ascii_case(module))
                .ok_or_else(|| format!("module not found: {module}"))?;

            let base = info.base;
            let size = info.size;

            // Read the full module image into a local buffer.
            let mut bytes = vec![0u8; size];
            let _ = proc.read_buf(base, &mut bytes);

            let hits = scan_module(base, &bytes, pattern);

            push(
                &self.log,
                LogKind::Info,
                format!("pattern_scan({module:?}, {pattern:?}): {} hit(s)", hits.len()),
            );

            Ok(hits)
        }

        /// Declares a custom enum type into the project's enum collection.
        ///
        /// If a type with the same name already exists it is replaced in-place;
        /// otherwise the new description is appended.
        fn declare_type(&mut self, ty: EnumDescription) -> Result<(), String> {
            let name = ty.name.clone();
            if let Some(existing) = self.project.enums.iter_mut().find(|e| e.name == name) {
                *existing = ty;
                push(&self.log, LogKind::Info, format!("declare_type: updated enum {name:?}"));
            } else {
                self.project.enums.push(ty);
                push(&self.log, LogKind::Info, format!("declare_type: added enum {name:?}"));
            }
            Ok(())
        }

        /// Declares a class into the project, updating the address formula if the
        /// class already exists or creating a new `ClassNode` otherwise.
        fn declare_class(&mut self, name: &str, address_formula: &str) -> Result<(), String> {
            // Search for an existing class with this name (order-preserving).
            let existing_uuid = self
                .project
                .classes_in_order()
                .find(|c| c.name == name)
                .map(|c| c.uuid);

            if let Some(uuid) = existing_uuid {
                if let Some(class) = self.project.get_class_mut(&uuid) {
                    class.address_formula = address_formula.to_string();
                    push(
                        &self.log,
                        LogKind::Info,
                        format!("declare_class: updated formula for {name:?}"),
                    );
                }
            } else {
                let mut class = ClassNode::new(name);
                class.address_formula = address_formula.to_string();
                self.project.add_class(class);
                push(
                    &self.log,
                    LogKind::Info,
                    format!("declare_class: added class {name:?}"),
                );
            }
            Ok(())
        }

        /// Maps a script `LogLevel` to a `LogKind` and appends to the shared
        /// script log.  Also copies `Error`-level messages into `last_error` for
        /// the UI status bar.
        fn log(&mut self, level: LogLevel, msg: &str) {
            let kind = match level {
                LogLevel::Info => LogKind::Info,
                LogLevel::Warn => LogKind::Warn,
                LogLevel::Error => LogKind::Error,
            };
            push(&self.log, kind, msg);
            if kind == LogKind::Error && self.last_error.is_none() {
                *self.last_error = Some(msg.to_string());
            }
        }
    }
}

// Re-export the struct at module level so callers can write
// `use crate::views::host_api_impl::UiHostApi;` regardless of the inner mod.
#[cfg(feature = "scripting")]
pub use inner::UiHostApi;
