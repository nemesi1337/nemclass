//! Basic-block reconstruction over a decoded instruction listing.
//!
//! The disassembler decodes linearly, which is right for browsing but says
//! nothing about *shape*: where the loops are, which branch falls through, what
//! is straight-line code and what is a join point. This partitions a decoded
//! run into basic blocks — maximal straight-line stretches — and records how
//! they connect.
//!
//! Purely a function of the listing it is given: no reads, no process, so it is
//! testable against hand-built input and works equally on a live listing or a
//! saved one.

use std::collections::{BTreeMap, BTreeSet};

use crate::internal::decoder::{FlowKind, InstructionData};

/// One basic block: a maximal run of instructions with a single entry and a
/// single exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    /// Address of the first instruction.
    pub start: u64,
    /// Address just past the last instruction.
    pub end: u64,
    /// Index range into the instruction slice, `[first, last]` inclusive.
    pub first: usize,
    pub last: usize,
    /// Where control can go next, in ascending order.
    ///
    /// A conditional branch has two: the target and the fall-through. A `ret`
    /// has none. A branch whose target is outside the decoded listing is *not*
    /// listed — the block graph describes what was decoded, and inventing an
    /// edge to an address nothing is known about would be a lie.
    pub successors: Vec<u64>,
    /// Blocks that can reach this one.
    pub predecessors: Vec<u64>,
}

impl BasicBlock {
    /// How many instructions the block holds.
    pub fn len(&self) -> usize {
        self.last + 1 - self.first
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether control can arrive here from more than one place — a join, which
    /// is what makes a block worth naming.
    pub fn is_join(&self) -> bool {
        self.predecessors.len() > 1
    }

    /// Whether this block ends by branching backwards into itself or earlier —
    /// the shape of a loop.
    pub fn is_loop_header(&self) -> bool {
        self.predecessors.iter().any(|&p| p >= self.start)
    }
}

/// Partition `instructions` into basic blocks.
///
/// The listing must be in ascending address order, which is what the linear
/// decoder produces. Gaps are fine — an instruction that does not immediately
/// follow the previous one starts a new block, because whatever is in the gap
/// was not decoded and may be anything.
pub fn basic_blocks(instructions: &[InstructionData]) -> Vec<BasicBlock> {
    if instructions.is_empty() {
        return Vec::new();
    }
    let by_address: BTreeMap<u64, usize> =
        instructions.iter().enumerate().map(|(i, ins)| (ins.address, i)).collect();

    // A leader starts a block: the first instruction, any branch target inside
    // the listing, and anything following a branch or a return.
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    leaders.insert(0);
    for (i, ins) in instructions.iter().enumerate() {
        let terminates = matches!(
            ins.kind,
            FlowKind::Jump | FlowKind::CondJump | FlowKind::Ret | FlowKind::Int3
        );
        if terminates && i + 1 < instructions.len() {
            leaders.insert(i + 1);
        }
        if matches!(ins.kind, FlowKind::Jump | FlowKind::CondJump)
            && let Some(target) = ins.target
            && let Some(&index) = by_address.get(&target)
        {
            leaders.insert(index);
        }
        // A gap in the listing: the next instruction does not continue this one.
        if i + 1 < instructions.len()
            && instructions[i + 1].address != ins.address + ins.length as u64
        {
            leaders.insert(i + 1);
        }
    }

    let starts: Vec<usize> = leaders.into_iter().collect();
    let mut blocks: Vec<BasicBlock> = Vec::with_capacity(starts.len());
    for (n, &first) in starts.iter().enumerate() {
        let last = starts.get(n + 1).map(|&next| next - 1).unwrap_or(instructions.len() - 1);
        let terminator = &instructions[last];
        let end = terminator.address + terminator.length as u64;

        let mut successors = Vec::new();
        match terminator.kind {
            // A return or a breakpoint goes nowhere this listing knows about.
            FlowKind::Ret | FlowKind::Int3 => {}
            FlowKind::Jump => {
                if let Some(t) = terminator.target.filter(|t| by_address.contains_key(t)) {
                    successors.push(t);
                }
            }
            FlowKind::CondJump => {
                if let Some(t) = terminator.target.filter(|t| by_address.contains_key(t)) {
                    successors.push(t);
                }
                // The fall-through.
                if by_address.contains_key(&end) {
                    successors.push(end);
                }
            }
            // A call returns, so the block continues at the next instruction;
            // so does anything the decoder could not classify, which is safer
            // than assuming it terminates the block.
            FlowKind::Call | FlowKind::Seq | FlowKind::Other => {
                if by_address.contains_key(&end) {
                    successors.push(end);
                }
            }
        }
        successors.sort_unstable();
        successors.dedup();

        blocks.push(BasicBlock {
            start: instructions[first].address,
            end,
            first,
            last,
            successors,
            predecessors: Vec::new(),
        });
    }

    // Fill the reverse edges once every block exists.
    let index_of: BTreeMap<u64, usize> =
        blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
    let edges: Vec<(usize, u64)> = blocks
        .iter()
        .flat_map(|b| b.successors.iter().map(move |&s| (s, b.start)))
        .filter_map(|(s, from)| index_of.get(&s).map(|&i| (i, from)))
        .collect();
    for (to, from) in edges {
        blocks[to].predecessors.push(from);
    }
    for block in &mut blocks {
        block.predecessors.sort_unstable();
        block.predecessors.dedup();
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(address: u64, length: usize, kind: FlowKind, target: Option<u64>) -> InstructionData {
        InstructionData {
            address,
            length,
            data: vec![0x90; length],
            static_instruction_bytes: length as i32,
            instruction: format!("{kind:?}"),
            kind,
            target,
            mem_target: None,
        }
    }

    #[test]
    fn straight_line_code_is_one_block() {
        let listing = vec![
            insn(0x1000, 2, FlowKind::Seq, None),
            insn(0x1002, 2, FlowKind::Seq, None),
            insn(0x1004, 1, FlowKind::Ret, None),
        ];
        let blocks = basic_blocks(&listing);
        assert_eq!(blocks.len(), 1);
        assert_eq!((blocks[0].start, blocks[0].end), (0x1000, 0x1005));
        assert_eq!(blocks[0].len(), 3);
        assert!(blocks[0].successors.is_empty(), "a ret goes nowhere known");
    }

    #[test]
    fn a_conditional_branch_splits_into_three_blocks_with_both_edges() {
        // 0x1000 jz 0x1006
        // 0x1002 nop        (fall-through)
        // 0x1004 nop
        // 0x1006 ret        (target, and a join)
        let listing = vec![
            insn(0x1000, 2, FlowKind::CondJump, Some(0x1006)),
            insn(0x1002, 2, FlowKind::Seq, None),
            insn(0x1004, 2, FlowKind::Seq, None),
            insn(0x1006, 1, FlowKind::Ret, None),
        ];
        let blocks = basic_blocks(&listing);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].successors, [0x1002, 0x1006], "target and fall-through");
        assert_eq!(blocks[1].successors, [0x1006]);
        assert!(blocks[2].successors.is_empty());
        assert!(blocks[2].is_join(), "reached from both the branch and the fall-through");
        assert_eq!(blocks[2].predecessors, [0x1000, 0x1002]);
    }

    #[test]
    fn a_backwards_branch_is_recognised_as_a_loop() {
        // 0x1000 nop
        // 0x1002 jmp 0x1000
        let listing = vec![
            insn(0x1000, 2, FlowKind::Seq, None),
            insn(0x1002, 2, FlowKind::Jump, Some(0x1000)),
        ];
        let blocks = basic_blocks(&listing);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].successors, [0x1000]);
        assert!(blocks[0].is_loop_header(), "it branches back into itself");
    }

    #[test]
    fn a_call_continues_the_block_because_it_returns() {
        let listing = vec![
            insn(0x1000, 5, FlowKind::Call, Some(0x2000)),
            insn(0x1005, 1, FlowKind::Ret, None),
        ];
        let blocks = basic_blocks(&listing);
        assert_eq!(blocks.len(), 1, "a call does not end a basic block");
        assert!(blocks[0].successors.is_empty());
    }

    #[test]
    fn a_branch_out_of_the_listing_produces_no_edge_rather_than_a_dangling_one() {
        let listing = vec![insn(0x1000, 5, FlowKind::Jump, Some(0x900000))];
        let blocks = basic_blocks(&listing);
        assert_eq!(blocks.len(), 1);
        assert!(
            blocks[0].successors.is_empty(),
            "nothing is known about the target, so claiming an edge would be a lie"
        );
    }

    #[test]
    fn a_gap_in_the_listing_starts_a_new_block() {
        // The decoder skips a non-executable stretch; what is in it was never
        // decoded, so the two sides are not one straight-line run.
        let listing = vec![
            insn(0x1000, 2, FlowKind::Seq, None),
            insn(0x2000, 2, FlowKind::Seq, None),
        ];
        let blocks = basic_blocks(&listing);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].successors.is_empty(), "0x1002 was not decoded");
    }

    #[test]
    fn an_empty_listing_produces_no_blocks() {
        assert!(basic_blocks(&[]).is_empty());
    }
}
