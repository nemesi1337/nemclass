//! Cross-crate guarantee: the address formula emitted by
//! [`nemclass_scan::PointerPath::to_formula`] parses with the real
//! `nemclass_model` address grammar, so a pointer-scan hit can be dropped
//! straight into a `ClassNode.address_formula`.

use nemclass_scan::PointerPath;

fn assert_parses(formula: &str) {
    nemclass_model::parse_address(formula)
        .unwrap_or_else(|e| panic!("formula {formula:?} failed to parse: {e:?}"));
}

#[test]
fn emitted_formulas_parse_in_the_model() {
    let cases = [
        PointerPath { base: 0x140001000, offsets: vec![0x40, 0x14] },
        PointerPath { base: 0x140000000, offsets: vec![0x8] },
        PointerPath { base: 0x140000010, offsets: vec![] },
        PointerPath { base: 0x7f0000abcd, offsets: vec![0x0, 0x18, 0x220, 0x8] },
    ];
    for p in &cases {
        let f = p.to_formula("game.exe", 0x140000000);
        assert_parses(&f);
    }
}
