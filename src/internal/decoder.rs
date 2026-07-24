use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter, OpKind};

/// Idiomatic, safe Rust struct for the UI to consume.
#[derive(Debug, Clone)]
pub struct InstructionData {
    /// The virtual address of the instruction
    pub address: u64,
    /// The length of the instruction in bytes
    pub length: usize,
    /// The actual bytes that make up the instruction
    pub data: Vec<u8>,
    /// How many bytes are considered "static" (-1 if not determined or invalid)
    pub static_instruction_bytes: i32,
    /// The formatted assembly string (e.g., "mov eax, 1")
    pub instruction: String,
}

fn are_operands_static(instruction: &Instruction) -> bool {
    // Check for unconditional and conditional branches
    if instruction.is_jcc_short_or_near() || instruction.is_jmp_short_or_near() {
        if instruction.len() < 5 {
            return true;
        }
    }

    for i in 0..instruction.op_count() {
        match instruction.op_kind(i) {
            // Static length operands
            OpKind::Register
            | OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            // String instruction memory operands (no dynamic displacement)
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI => continue,

            // Dynamic length immediates
            OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64 => return false,

            OpKind::Memory => {
                if instruction.memory_displ_size() < 4 {
                    continue;
                }

                // On x64, RIP-relative memory references are often considered static
                // relative to the instruction block.
                #[cfg(target_pointer_width = "64")]
                if instruction.is_ip_rel_memory_operand() {
                    continue;
                }

                return false;
            }

            // Dynamic branches
            OpKind::NearBranch16
            | OpKind::NearBranch32
            | OpKind::NearBranch64
            | OpKind::FarBranch16
            | OpKind::FarBranch32 => return false,

            _ => return false,
        }
    }

    true
}

fn get_static_instruction_bytes(instruction: &Instruction) -> i32 {
    if are_operands_static(instruction) {
        return instruction.len() as i32;
    }

    let mut dynamic_bytes = 0;
    for i in 0..instruction.op_count() {
        match instruction.op_kind(i) {
            OpKind::Memory => {
                dynamic_bytes += instruction.memory_displ_size();
            }
            OpKind::Immediate32 | OpKind::Immediate32to64 => {
                dynamic_bytes += 4;
            }
            OpKind::Immediate64 => {
                dynamic_bytes += 8;
            }
            OpKind::NearBranch32 | OpKind::FarBranch32 => {
                dynamic_bytes += 4;
            }
            _ => {}
        }
    }

    (instruction.len() as u32 - dynamic_bytes) as i32
}

/// Disassembles a safe slice of bytes.
///
/// `code`: The machine code to disassemble.
/// `virtual_address`: The base address where this code conceptually lives in memory.
/// `determine_static_bytes`: Whether to calculate static vs dynamic byte length.
/// `callback`: A closure called for each instruction. If it returns `false`, disassembly stops.
pub fn disassemble_instructions<F>(
    code: &[u8],
    virtual_address: u64,
    determine_static_bytes: bool,
    mut callback: F,
) where
    F: FnMut(InstructionData) -> bool,
{
    if code.is_empty() {
        return;
    }

    let bitness = if cfg!(target_pointer_width = "64") {
        64
    } else {
        32
    };

    let mut decoder = Decoder::with_ip(bitness, code, virtual_address, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    formatter
        .options_mut()
        .set_space_after_operand_separator(true);

    // Track our position in the `code` slice to extract the raw bytes safely
    let mut offset = 0;

    while decoder.can_decode() {
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);

        let len = instruction.len();

        // Fail-safe to prevent infinite loops on completely unreadable memory
        if instruction.is_invalid() && len == 0 {
            break;
        }

        // Safely extract the exact bytes for this instruction from the slice
        let instruction_bytes = if offset + len <= code.len() {
            &code[offset..offset + len]
        } else {
            &code[offset..]
        };

        let (instruction_str, static_bytes) = if instruction.is_invalid() {
            (String::from("???"), -1)
        } else {
            let mut formatted_str = String::new();
            formatter.format(&instruction, &mut formatted_str);

            let static_b = if determine_static_bytes {
                get_static_instruction_bytes(&instruction)
            } else {
                -1
            };

            (formatted_str, static_b)
        };

        let data = InstructionData {
            address: instruction.ip(),
            length: len,
            data: instruction_bytes.to_vec(),
            static_instruction_bytes: static_bytes,
            instruction: instruction_str,
        };

        // Pass to the UI/caller closure. Stop if it returns false.
        if !callback(data) {
            break;
        }

        offset += len;

        if offset >= code.len() {
            break;
        }
    }
}
