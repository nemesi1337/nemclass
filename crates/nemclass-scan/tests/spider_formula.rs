//! Cross-crate guarantee: every address formula shape
//! [`nemclass_scan::SpiderPath`] can emit parses with the real `nemclass_model`
//! address grammar, so a spider hit can be dropped straight into a
//! `ClassNode.address_formula` or a cheat-table entry's address.

use std::sync::Arc;

use nemclass_scan::SpiderPath;

fn path(root: usize, parents: &[usize], offset: usize) -> SpiderPath {
    SpiderPath {
        root,
        parent_offsets: Arc::from(parents.to_vec()),
        offset,
    }
}

fn assert_parses(formula: &str) {
    nemclass_model::parse_address(formula)
        .unwrap_or_else(|e| panic!("formula {formula:?} failed to parse: {e:?}"));
}

/// A raw-address root: valid until the target restarts, which is what the
/// address list shows when the root is not inside a module image.
#[test]
fn raw_rooted_formulas_parse() {
    let cases = [
        path(0x7f2a10, &[], 0x8),
        path(0x7f2a10, &[0x18], 0x14),
        path(0x7f2a10, &[0x0, 0x18, 0x220, 0x8], 0x40),
        // An unaligned root, where the raw-base offset convention matters.
        path(0x10003, &[0x5], 0x9),
    ];
    for p in &cases {
        assert_parses(&p.to_formula_raw());
    }
}

/// A module-anchored root, which is what survives ASLR.
#[test]
fn module_rooted_formulas_parse() {
    const MODULE_BASE: usize = 0x140000000;
    let cases = [
        // Root exactly at the module base — emitted without a `+ 0x0` term.
        path(MODULE_BASE, &[], 0x10),
        path(MODULE_BASE, &[0x40], 0x14),
        path(MODULE_BASE + 0x1000, &[], 0x8),
        path(MODULE_BASE + 0x1000, &[0x40, 0x18], 0x4),
    ];
    for p in &cases {
        assert_parses(&p.to_formula_at_module("game.exe", MODULE_BASE));
    }
}

/// The rendered shape is the documented one, so a user reading the results table
/// can hand-verify a chain against a debugger.
#[test]
fn formula_shape_is_stable() {
    assert_eq!(path(0x1400, &[], 0x8).to_formula_raw(), "0x1400 + 0x8");
    assert_eq!(path(0x1400, &[0x10], 0x8).to_formula_raw(), "[0x1400 + 0x10] + 0x8");
    assert_eq!(
        path(0x1400, &[0x18, 0x40], 0x14).to_formula_raw(),
        "[[0x1400 + 0x18] + 0x40] + 0x14"
    );
    assert_eq!(
        path(0x140000000, &[0x40], 0x14).to_formula_at_module("game.exe", 0x140000000),
        "[<game.exe> + 0x40] + 0x14"
    );
    assert_eq!(
        path(0x140001000, &[0x40], 0x14).to_formula_at_module("game.exe", 0x140000000),
        "[<game.exe> + 0x1000 + 0x40] + 0x14"
    );
}
