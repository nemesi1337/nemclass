//! Cross-crate guarantee for the `.ptrmap` file: a path that goes out to disk,
//! comes back, and is rebased onto a relocated process still emits an address
//! formula the real `nemclass_model` grammar accepts.
//!
//! Round-tripping is only worth anything if the result is still usable as a
//! `ClassNode.address_formula` or a cheat-table address, and the export path has
//! several places to lose that — the module-relative anchor, the sign of an
//! offset, the bracket shape each path kind uses. This pins the whole chain.

use std::sync::Arc;

use nemclass_scan::{
    Anchor, ModuleRef, PathKind, PointerPath, PtrMapEntry, PtrMapFile, SpiderPath,
};

const OLD_BASE: usize = 0x1400_0000;
const NEW_BASE: usize = 0x7FFF_0000;

fn assert_parses(formula: &str) {
    nemclass_model::parse_address(formula)
        .unwrap_or_else(|e| panic!("formula {formula:?} failed to parse: {e:?}"));
}

/// Every path shape the pointer scanner can produce, anchored in a module.
fn pointer_cases() -> Vec<PointerPath> {
    vec![
        PointerPath { base: OLD_BASE + 0x1000, offsets: vec![0x40, 0x14] },
        PointerPath { base: OLD_BASE, offsets: vec![0x8] },
        PointerPath { base: OLD_BASE + 0x10, offsets: vec![] },
        PointerPath { base: OLD_BASE + 0xABCD, offsets: vec![0x0, 0x18, 0x220, 0x8] },
        PointerPath { base: OLD_BASE + 0x1000, offsets: vec![-0x10, 0x8] },
        PointerPath { base: OLD_BASE + 0x1000, offsets: vec![-0x8] },
    ]
}

fn spider_cases() -> Vec<SpiderPath> {
    vec![
        SpiderPath {
            root: OLD_BASE + 0x1400,
            parent_offsets: Arc::from([0x18usize, 0x40].as_slice()),
            offset: 0x14,
        },
        SpiderPath {
            root: OLD_BASE,
            parent_offsets: Arc::from([].as_slice()),
            offset: 0x0,
        },
    ]
}

fn file_of(entries: Vec<PtrMapEntry>) -> PtrMapFile {
    PtrMapFile {
        goal: 0xDEAD_BEEF,
        modules: vec![ModuleRef { name: "game.exe".into(), base: OLD_BASE }],
        entries,
        truncated: false,
    }
}

#[test]
fn exported_pointer_paths_reparse_after_a_relocation() {
    let cases = pointer_cases();
    let file = file_of(
        cases
            .iter()
            .map(|p| {
                PtrMapEntry::from_pointer_path(
                    p,
                    Anchor::Module { module: 0, offset: p.base - OLD_BASE },
                )
            })
            .collect(),
    );

    let back = PtrMapFile::from_bytes(&file.to_bytes()).expect("round trip");
    let resolved = back.rebase(&|name| (name == "game.exe").then_some(NEW_BASE), 0);
    assert_eq!(resolved.len(), cases.len());

    for (path, original) in resolved.iter().zip(&cases) {
        // The chain moved with the module...
        let rebased = path.to_pointer_path().expect("still a pointer path");
        assert_eq!(rebased.base, original.base - OLD_BASE + NEW_BASE);
        assert_eq!(rebased.offsets, original.offsets, "offsets must survive verbatim");
        // ...and the formula is still one the model can evaluate.
        assert_parses(&path.to_formula());
        // Anchored at the module, so it survives the next relocation too.
        assert!(path.to_formula().contains("<game.exe>"));
    }
}

#[test]
fn exported_spider_paths_reparse_after_a_relocation() {
    let cases = spider_cases();
    let file = file_of(
        cases
            .iter()
            .map(|p| {
                PtrMapEntry::from_spider_path(
                    p,
                    Anchor::Module { module: 0, offset: p.root - OLD_BASE },
                )
            })
            .collect(),
    );

    let back = PtrMapFile::from_bytes(&file.to_bytes()).expect("round trip");
    let resolved = back.rebase(&|name| (name == "game.exe").then_some(NEW_BASE), 0);

    for (path, original) in resolved.iter().zip(&cases) {
        let rebased = path.to_spider_path().expect("still a spider path");
        assert_eq!(rebased.root, original.root - OLD_BASE + NEW_BASE);
        assert_eq!(rebased.parent_offsets, original.parent_offsets);
        assert_eq!(rebased.offset, original.offset);
        assert_parses(&path.to_formula());
    }
}

#[test]
fn an_unanchored_path_reparses_and_follows_the_manual_delta() {
    // Spider roots are usually heap addresses in no module at all, which is what
    // the hand-typed base override on import is for.
    let path = SpiderPath {
        root: 0x5555_0000,
        parent_offsets: Arc::from([0x18usize].as_slice()),
        offset: 0x8,
    };
    let file = PtrMapFile {
        goal: 0,
        modules: vec![],
        entries: vec![PtrMapEntry::from_spider_path(&path, Anchor::Absolute(path.root))],
        truncated: false,
    };

    let back = PtrMapFile::from_bytes(&file.to_bytes()).expect("round trip");
    let delta = 0x1_0000isize;
    let resolved = &back.rebase(&|_| None, delta)[0];

    assert_eq!(resolved.to_spider_path().unwrap().root, 0x5556_0000);
    assert_parses(&resolved.to_formula());
}

#[test]
fn the_two_path_kinds_produce_different_formulas_from_the_same_offsets() {
    // The bug this guards: `PointerPath` dereferences its base and closes the
    // bracket before each offset; `SpiderPath` does not and encloses it. Loading
    // one as the other would resolve to a completely different address, so the
    // file records the kind and the formulas must not agree.
    let offsets = vec![0x18i64, 0x40];
    let file = PtrMapFile {
        goal: 0,
        modules: vec![],
        entries: vec![
            PtrMapEntry {
                kind: PathKind::Pointer,
                anchor: Anchor::Absolute(0x1400),
                offsets: offsets.clone(),
            },
            PtrMapEntry {
                kind: PathKind::Spider,
                anchor: Anchor::Absolute(0x1400),
                offsets,
            },
        ],
        truncated: false,
    };

    let resolved = file.rebase(&|_| None, 0);
    let pointer = resolved[0].to_formula();
    let spider = resolved[1].to_formula();

    assert_eq!(pointer, "[[0x1400] + 0x18] + 0x40");
    assert_eq!(spider, "[0x1400 + 0x18] + 0x40");
    assert_ne!(pointer, spider);
    assert_parses(&pointer);
    assert_parses(&spider);

    // And neither converts into the other's type.
    assert!(resolved[0].to_spider_path().is_err());
    assert!(resolved[1].to_pointer_path().is_err());
}
