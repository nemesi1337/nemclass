//! Pure, testable functions for `project.nemclass` New / Open / Save.
//!
//! No egui imports here — these functions operate only on the file system and
//! the model/script crates.  The UI layer calls them and surfaces any errors.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use nemclass_model::{NodeRegistry, Project};
use nemclass_script::write_script_scaffold;

/// Name of the project file inside a project directory.
pub const PROJECT_FILE: &str = "project.nemclass";

// ---------------------------------------------------------------------------
// create_project_at
// ---------------------------------------------------------------------------

/// Create a new project directory layout on disk, write the initial
/// `project.nemclass`, and write the TypeScript scaffold files.
///
/// Creates:
/// - `<dir>/`
/// - `<dir>/src/`
/// - `<dir>/tables/`
/// - `<dir>/project.nemclass`  (serialised `project`)
/// - `<dir>/package.json`      (via `write_script_scaffold`)
/// - `<dir>/tsconfig.json`     (via `write_script_scaffold`)
/// - `<dir>/nemclass.d.ts`     (via `write_script_scaffold`)
///
/// Returns `Ok(())` on success, or the first IO/serialisation error encountered.
pub fn create_project_at(dir: &Path, project: &Project, registry: &NodeRegistry) -> io::Result<()> {
    // Create directory structure.
    fs::create_dir_all(dir)?;
    fs::create_dir_all(dir.join("src"))?;
    fs::create_dir_all(dir.join("tables"))?;

    // Serialise and write the project file.
    let toml = project
        .to_toml(registry)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(dir.join(PROJECT_FILE), toml)?;

    // Write TypeScript scaffold (package.json, tsconfig.json, nemclass.d.ts).
    write_script_scaffold(dir)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// load_project_from
// ---------------------------------------------------------------------------

/// Load a project from a path that is either:
/// - a `project.nemclass` file, or
/// - a directory containing a `project.nemclass` file.
///
/// Returns `(project, project_dir)` on success, where `project_dir` is the
/// canonical directory that contains the project file.
pub fn load_project_from(
    path: &Path,
    registry: &NodeRegistry,
) -> io::Result<(Project, PathBuf)> {
    // Resolve to the actual file path.
    let file_path = if path.is_dir() {
        path.join(PROJECT_FILE)
    } else {
        path.to_path_buf()
    };

    let text = fs::read_to_string(&file_path)?;
    let project = Project::from_toml(&text, registry)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // The project directory is the parent of the project file.
    let project_dir = file_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "project file has no parent dir"))?
        .to_path_buf();

    Ok((project, project_dir))
}

// ---------------------------------------------------------------------------
// save_project_to
// ---------------------------------------------------------------------------

/// Serialise `project` and overwrite `<project_dir>/project.nemclass`.
///
/// The directory must already exist (call `create_project_at` for a fresh
/// project).  This function only writes the project file, not the scaffold.
pub fn save_project_to(
    project_dir: &Path,
    project: &Project,
    registry: &NodeRegistry,
) -> io::Result<()> {
    let toml = project
        .to_toml(registry)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(project_dir.join(PROJECT_FILE), toml)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests (no egui required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use nemclass_model::ClassNode;

    fn make_registry() -> NodeRegistry {
        NodeRegistry::new().with_builtins()
    }

    fn make_project() -> Project {
        use nemclass_model::node::builtins::Int32Node;
        let mut p = Project::new("TestProject");
        let mut cls = ClassNode::new("MyClass");
        cls.children.push(Box::new(Int32Node::new("health")));
        p.add_class(cls);
        p
    }

    #[test]
    fn round_trip_create_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = make_registry();
        let project = make_project();

        create_project_at(dir.path(), &project, &registry).expect("create");

        // The expected files must exist.
        assert!(dir.path().join(PROJECT_FILE).exists(), "project.nemclass missing");
        assert!(dir.path().join("package.json").exists(), "package.json missing");
        assert!(dir.path().join("tsconfig.json").exists(), "tsconfig.json missing");
        assert!(dir.path().join("nemclass.d.ts").exists(), "nemclass.d.ts missing");
        assert!(dir.path().join("src").is_dir(), "src/ missing");
        assert!(dir.path().join("tables").is_dir(), "tables/ missing");

        // Load back and verify.
        let (loaded, loaded_dir) = load_project_from(dir.path(), &registry).expect("load");
        assert_eq!(loaded.name, "TestProject");
        assert_eq!(loaded_dir, dir.path());
        let class = loaded.classes_in_order().next().expect("class");
        assert_eq!(class.name, "MyClass");
        assert_eq!(class.children.len(), 1);
    }

    #[test]
    fn round_trip_save_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = make_registry();
        let project = make_project();

        create_project_at(dir.path(), &project, &registry).expect("create");

        // Modify and save.
        let mut modified = make_project();
        modified.name = "Modified".into();
        save_project_to(dir.path(), &modified, &registry).expect("save");

        let (loaded, _) = load_project_from(dir.path(), &registry).expect("load");
        assert_eq!(loaded.name, "Modified");
    }

    #[test]
    fn load_from_file_path_also_works() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = make_registry();
        let project = make_project();

        create_project_at(dir.path(), &project, &registry).expect("create");

        let file = dir.path().join(PROJECT_FILE);
        let (loaded, loaded_dir) = load_project_from(&file, &registry).expect("load from file");
        assert_eq!(loaded.name, "TestProject");
        assert_eq!(loaded_dir, dir.path());
    }
}
