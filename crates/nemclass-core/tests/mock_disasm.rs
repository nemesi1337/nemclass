//! Exercises the disassembler + `Process` read path against an in-memory
//! [`MockMemoryBackend`] — no live `/proc` target required. This is the seam the
//! UI's panel tests rely on, so keeping it green guarantees the mock plumbing
//! stays usable.
#![cfg(all(target_os = "linux", feature = "test-util"))]

use nemclass_core::{FlowKind, MockMemoryBackend, Process, disassemble_range};

/// `push rbp; mov rbp, rsp; ret` at a known base decodes to the expected three
/// instructions with the right control-flow classification.
#[test]
fn disassembles_known_prologue_from_mock() {
    const CODE: &[u8] = &[0x55, 0x48, 0x89, 0xe5, 0xc3];
    const BASE: usize = 0x1000;

    let backend = Box::new(MockMemoryBackend::new(BASE, CODE.to_vec()));
    let proc = Process::from_backend_for_test(4242, backend);

    let ins = disassemble_range(&proc, BASE as u64, CODE.len()).expect("disassembly succeeds");

    assert_eq!(ins.len(), 3, "three instructions decoded");
    assert_eq!(ins[0].address, BASE as u64);
    assert!(
        ins[0].instruction.contains("push"),
        "first is push, got {:?}",
        ins[0].instruction
    );
    assert!(
        ins[1].instruction.contains("mov"),
        "second is mov, got {:?}",
        ins[1].instruction
    );
    assert_eq!(ins[2].kind, FlowKind::Ret, "third is a ret");
}

/// A `call rel32` yields a resolved near-branch target and the `Call` flow kind —
/// the data the disassembler's clickable follow + Comment column depend on.
#[test]
fn call_has_flow_kind_and_target() {
    // e8 00 00 00 00 = call rip+0 (target = address of the next instruction).
    const CODE: &[u8] = &[0xe8, 0x00, 0x00, 0x00, 0x00];
    const BASE: usize = 0x2000;

    let backend = Box::new(MockMemoryBackend::new(BASE, CODE.to_vec()));
    let proc = Process::from_backend_for_test(7, backend);

    let ins = disassemble_range(&proc, BASE as u64, CODE.len()).expect("disassembly succeeds");
    assert_eq!(ins[0].kind, FlowKind::Call);
    assert_eq!(ins[0].target, Some((BASE + 5) as u64), "rel32 target resolved");
}
