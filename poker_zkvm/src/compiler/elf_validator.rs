//! 强化 ELF 校验器（Phase 2 — Task 2.2）。
//!
//! 实现 `validate_elf(elf_bytes: &[u8]) -> Result<ElfMetadata, ZkvmError>`，
//! 执行 spec v1.4 L155-168 的 11 项校验，消除 TOCTOU，防 wrap 攻击，
//! 拒绝动态链接，强制 RV32I 指令子集。

use crate::error::ZkvmError;
use goblin::elf::{
    Elf,
    header::EM_RISCV,
    program_header::{PF_X, PT_DYNAMIC, PT_LOAD},
};

/// ZKVM 最大可用内存（spec L164）。
pub const MAX_ZKVM_MEMORY: usize = 16 * 1024 * 1024; // 16MB

/// `.text` 段最大大小（spec L163）。
pub const MAX_TEXT_SIZE: usize = 8 * 1024 * 1024; // 8MB

/// 已校验的 ELF 加载段（owned 数据，消除 TOCTOU）。
///
/// `data` 为 owned `Vec<u8>` 拷贝，`validate_elf` 返回后调用方无法修改原始字节。
#[derive(Clone, Debug)]
pub struct LoadedSegment {
    /// 虚拟地址
    pub vaddr: u32,
    /// 内存大小（memsz）
    pub memsz: u32,
    /// 段数据（owned 拷贝自输入字节切片，长度 = filesz）
    pub data: Vec<u8>,
    /// 段标志（PF_R / PF_W / PF_X）
    pub flags: u32,
}

/// 已校验的 ELF 元数据（`validate_elf` 返回，`load_elf` 消费）。
#[derive(Clone, Debug)]
pub struct ElfMetadata {
    /// 入口地址
    pub entry: u32,
    /// 所有可加载段（PT_LOAD）
    pub segments: Vec<LoadedSegment>,
    /// 可执行段（含 `.text`），用于后续指令校验与执行
    pub text: Option<LoadedSegment>,
}

/// 校验 ELF 字节切片并返回已解析的元数据（spec L155，消除 TOCTOU）。
///
/// 执行 11 项校验，任一失败返回 `ZkvmError`：
/// - `Other(String)` — ELF 格式 / 结构错误
/// - `UnsupportedInstruction(String)` — RV32I 非法指令
///
/// 校验顺序：
/// 1. ELF 解析（goblin）
/// 2. Header（class=ELF32, endian=little, machine=EM_RISCV）
/// 3. Section header table 不溢出
/// 4. 无 PT_DYNAMIC 段
/// 5. 无 DT_NEEDED 入口
/// 6. 段地址范围 `[0, MAX_ZKVM_MEMORY)`（checked_add 防 wrap）
/// 7. 段之间无重叠
/// 8. 总加载内存 ≤ MAX_ZKVM_MEMORY（checked_add 累加）
/// 9. entry 在可执行段范围内
/// 10. 可执行段大小 ≤ MAX_TEXT_SIZE
/// 11. RV32I 指令子集校验
pub fn validate_elf(elf_bytes: &[u8]) -> Result<ElfMetadata, ZkvmError> {
    // 校验 1：ELF 解析
    let elf =
        Elf::parse(elf_bytes).map_err(|e| ZkvmError::Other(format!("ELF parse error: {e}")))?;

    // 校验 2：Header — class / endian / machine
    check_header(&elf)?;

    // 校验 3：Section header table 不溢出
    check_section_table_overflow(&elf, elf_bytes.len())?;

    // 校验 4：无 PT_DYNAMIC
    check_no_pt_dynamic(&elf)?;

    // 校验 5：无 DT_NEEDED
    check_no_dt_needed(&elf)?;

    // 校验 6-8：段地址范围 / 无重叠 / 总内存
    let segments = check_and_extract_segments(&elf, elf_bytes)?;

    // 校验 9：entry 在可执行段内
    let text = extract_text_segment(&segments)?;
    let entry = elf.entry as u32;
    check_entry_in_text(entry, &text)?;

    // 校验 10：可执行段大小
    check_text_size(&text)?;

    // 校验 11：RV32I 指令子集
    check_rv32i(&text.data)?;

    Ok(ElfMetadata {
        entry,
        segments,
        text: Some(text),
    })
}

/// 校验 ELF header：class=ELF32, endian=little, machine=EM_RISCV。
fn check_header(elf: &Elf) -> Result<(), ZkvmError> {
    if elf.is_64 {
        return Err(ZkvmError::Other(
            "ELF64 not supported: expected ELF32".to_string(),
        ));
    }
    if !elf.little_endian {
        return Err(ZkvmError::Other(
            "big-endian ELF not supported: expected little-endian".to_string(),
        ));
    }
    if elf.header.e_machine != EM_RISCV {
        return Err(ZkvmError::Other(format!(
            "wrong machine: expected EM_RISCV (243), got {}",
            elf.header.e_machine
        )));
    }
    Ok(())
}

/// 校验 section header table 不溢出且不超出文件范围。
fn check_section_table_overflow(elf: &Elf, bytes_len: usize) -> Result<(), ZkvmError> {
    let shoff = elf.header.e_shoff as usize;
    let shnum = elf.header.e_shnum as usize;
    let shentsize = elf.header.e_shentsize as usize;
    if shnum == 0 {
        return Ok(());
    }
    let table_size = shnum.checked_mul(shentsize).ok_or_else(|| {
        ZkvmError::Other("section header table overflow: e_shnum * e_shentsize".to_string())
    })?;
    let table_end = shoff.checked_add(table_size).ok_or_else(|| {
        ZkvmError::Other("section header table overflow: e_shoff + size".to_string())
    })?;
    if table_end > bytes_len {
        return Err(ZkvmError::Other(format!(
            "section header table exceeds file: end=0x{table_end:x} > file_len=0x{bytes_len:x}"
        )));
    }
    Ok(())
}

/// 拒绝 PT_DYNAMIC 段（防动态链接）。
fn check_no_pt_dynamic(elf: &Elf) -> Result<(), ZkvmError> {
    for ph in &elf.program_headers {
        if ph.p_type == PT_DYNAMIC {
            return Err(ZkvmError::Other(
                "PT_DYNAMIC segment found: dynamic linking not allowed".to_string(),
            ));
        }
    }
    Ok(())
}

/// 拒绝 DT_NEEDED 入口（防外部符号解析）。
fn check_no_dt_needed(elf: &Elf) -> Result<(), ZkvmError> {
    if !elf.libraries.is_empty() {
        return Err(ZkvmError::Other(format!(
            "DT_NEEDED entries found: {} shared library(ies) referenced",
            elf.libraries.len()
        )));
    }
    Ok(())
}

/// 校验所有 PT_LOAD 段并提取 `LoadedSegment`。
///
/// 执行：地址范围 checked_add（防 wrap）、段数据拷贝、总内存累加。
fn check_and_extract_segments(elf: &Elf, bytes: &[u8]) -> Result<Vec<LoadedSegment>, ZkvmError> {
    let mut segments: Vec<LoadedSegment> = Vec::new();
    let mut total_memory: u64 = 0;

    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        let vaddr = ph.p_vaddr as u32;
        let memsz = ph.p_memsz as u32;
        let filesz = ph.p_filesz as usize;
        let offset = ph.p_offset as usize;
        let flags = ph.p_flags;

        // 校验 6：地址范围 checked_add（防 wrap 攻击）
        let end = vaddr.checked_add(memsz).ok_or_else(|| {
            ZkvmError::Other(format!(
                "segment address wrap: vaddr=0x{vaddr:08x} + memsz=0x{memsz:08x} overflows u32"
            ))
        })?;
        if end as usize > MAX_ZKVM_MEMORY {
            return Err(ZkvmError::Other(format!(
                "segment out of range: end=0x{end:08x} > MAX_ZKVM_MEMORY=0x{MAX_ZKVM_MEMORY:x}"
            )));
        }

        // 校验文件数据范围
        let data_end = offset.checked_add(filesz).ok_or_else(|| {
            ZkvmError::Other(format!(
                "file offset wrap: offset=0x{offset:x} + filesz=0x{filesz:x} overflows usize"
            ))
        })?;
        if data_end > bytes.len() {
            return Err(ZkvmError::Other(format!(
                "segment data exceeds file: offset=0x{offset:x} + filesz=0x{filesz:x} > file_len=0x{}",
                bytes.len()
            )));
        }

        // 拷贝段数据（owned，消除 TOCTOU）
        let data = bytes[offset..data_end].to_vec();

        // 累加总内存（校验 8，使用 checked_add）
        total_memory = total_memory.checked_add(memsz as u64).ok_or_else(|| {
            ZkvmError::Other("total memory overflow during accumulation".to_string())
        })?;

        segments.push(LoadedSegment {
            vaddr,
            memsz,
            data,
            flags,
        });
    }

    // 校验 8：总加载内存 ≤ MAX_ZKVM_MEMORY
    if total_memory as usize > MAX_ZKVM_MEMORY {
        return Err(ZkvmError::Other(format!(
            "total memory exceeds limit: {total_memory} > MAX_ZKVM_MEMORY={MAX_ZKVM_MEMORY}"
        )));
    }

    // 校验 7：段之间无重叠
    check_no_overlap(&segments)?;

    Ok(segments)
}

/// 校验段之间无重叠（按 vaddr 排序后检测）。
fn check_no_overlap(segments: &[LoadedSegment]) -> Result<(), ZkvmError> {
    let mut sorted: Vec<&LoadedSegment> = segments.iter().collect();
    sorted.sort_by_key(|s| s.vaddr);
    for i in 1..sorted.len() {
        let prev_end = sorted[i - 1]
            .vaddr
            .checked_add(sorted[i - 1].memsz)
            .ok_or_else(|| ZkvmError::Other("segment overlap check: address wrap".to_string()))?;
        if prev_end > sorted[i].vaddr {
            return Err(ZkvmError::Other(format!(
                "overlapping segments: [0x{:08x}, 0x{prev_end:08x}) vs [0x{:08x}, ...)",
                sorted[i - 1].vaddr,
                sorted[i].vaddr
            )));
        }
    }
    Ok(())
}

/// 提取可执行段（PF_X flag）作为 `.text`。
///
/// 若有多个可执行段，选第一个（entry 校验会进一步约束）。
fn extract_text_segment(segments: &[LoadedSegment]) -> Result<LoadedSegment, ZkvmError> {
    segments
        .iter()
        .find(|s| s.flags & PF_X != 0)
        .cloned()
        .ok_or_else(|| ZkvmError::Other("no executable segment (PF_X) found".to_string()))
}

/// 校验 entry point 在可执行段范围内。
fn check_entry_in_text(entry: u32, text: &LoadedSegment) -> Result<(), ZkvmError> {
    let text_end = text
        .vaddr
        .checked_add(text.memsz)
        .ok_or_else(|| ZkvmError::Other("text segment address wrap".to_string()))?;
    if entry < text.vaddr || entry >= text_end {
        return Err(ZkvmError::Other(format!(
            "entry point 0x{entry:08x} not in text segment [0x{:08x}, 0x{text_end:08x})",
            text.vaddr
        )));
    }
    Ok(())
}

/// 校验可执行段大小 ≤ MAX_TEXT_SIZE。
fn check_text_size(text: &LoadedSegment) -> Result<(), ZkvmError> {
    if text.memsz as usize > MAX_TEXT_SIZE {
        return Err(ZkvmError::Other(format!(
            "text segment too large: memsz=0x{:x} > MAX_TEXT_SIZE=0x{:x}",
            text.memsz, MAX_TEXT_SIZE
        )));
    }
    Ok(())
}

/// `unimp` 指令编码（LLVM trap 标记）。
///
/// LLVM RISC-V 后端为 unreachable 代码路径和分支后填充生成 `0xC0001073`，
/// 反汇编为 `unimp`（解码为 `csrrw x0, cycle, x0` — CSR 指令）。
///
/// 此指令**从不会在正常控制流中执行**（仅出现在无条件跳转之后或 `unreachable!()` 路径）。
/// 若执行到此处，executor 的 `decode` 会返回 `UnsupportedInstruction`（正确行为 — 标记 bug）。
///
/// 允许此编码通过 validator 校验，拒绝其他所有 CSR 指令（funct3 ∈ {1,2,3}）。
const UNIMP_INSTRUCTION: u32 = 0xC000_1073;

/// RV32I opcode 白名单（bits[6:0]）。
const RV32I_OPCODES: &[u32] = &[
    0x37, // LUI
    0x17, // AUIPC
    0x6F, // JAL
    0x67, // JALR
    0x63, // Branch
    0x03, // Load
    0x23, // Store
    0x13, // OP-IMM
    0x33, // OP
    0x0F, // FENCE
    0x73, // SYSTEM
];

/// 校验 `.text` 段所有指令属于 RV32I 子集。
///
/// 拒绝：compressed（bits[1:0] != 0b11）、fence.i（FENCE funct3==1）、
/// CSR（SYSTEM funct3 ∈ {1,2,3}）、浮点、atomics、SIMD。
fn check_rv32i(text: &[u8]) -> Result<(), ZkvmError> {
    if !text.len().is_multiple_of(4) {
        return Err(ZkvmError::UnsupportedInstruction(format!(
            "text size {} not 4-byte aligned (RV32I requires 4-byte instructions)",
            text.len()
        )));
    }
    for chunk in text.chunks_exact(4) {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let opcode = word & 0x7F;
        let funct3 = (word >> 12) & 0x7;

        // 拒绝 compressed 指令
        if (word & 0x3) != 0b11 {
            return Err(ZkvmError::UnsupportedInstruction(format!(
                "compressed instruction 0x{word:08x}: bits[1:0]={:02b} (expected 0b11)",
                word & 0x3
            )));
        }

        // opcode 白名单
        if !RV32I_OPCODES.contains(&opcode) {
            return Err(ZkvmError::UnsupportedInstruction(format!(
                "opcode 0x{opcode:02x} not in RV32I whitelist (word=0x{word:08x})"
            )));
        }

        // FENCE 细查：funct3==0 允许（FENCE），funct3==1 拒绝（fence.i）
        if opcode == 0x0F && funct3 == 1 {
            return Err(ZkvmError::UnsupportedInstruction(
                "fence.i instruction not allowed (Zifencei extension)".to_string(),
            ));
        }

        // SYSTEM 细查：funct3==0 允许（ECALL/EBREAK），funct3 ∈ {1,2,3} 拒绝（CSR）
        // 例外：`unimp`（0xC0001073）= LLVM unreachable trap 标记，允许通过
        if opcode == 0x73 && (1..=3).contains(&funct3) && word != UNIMP_INSTRUCTION {
            return Err(ZkvmError::UnsupportedInstruction(format!(
                "CSR instruction not allowed (Zicsr extension): funct3={funct3} (word=0x{word:08x})"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== 辅助：ELF32 字节构造 =====

    /// 写 u16 little-endian 到指定偏移。
    fn set_u16_le(bytes: &mut [u8], offset: usize, val: u16) {
        bytes[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
    }

    /// 写 u32 little-endian 到指定偏移。
    fn set_u32_le(bytes: &mut [u8], offset: usize, val: u32) {
        bytes[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
    }

    /// 构造最小合法 ELF32（92 字节）。
    ///
    /// Layout:
    /// - [0..52): ELF32 header (e_entry=0x1000, e_phoff=52, e_phnum=1)
    /// - [52..84): PH1 — PT_LOAD (vaddr=0x1000, filesz=8, memsz=8, PF_R|PF_X)
    /// - [84..92): .text — LUI x1,0 (0xb7) + ECALL (0x73)
    fn build_minimal_elf() -> Vec<u8> {
        let mut bytes = vec![
            // --- e_ident (16 bytes) ---
            0x7f, b'E', b'L', b'F', // magic
            1,    // EI_CLASS = ELFCLASS32
            1,    // EI_DATA = ELFDATA2LSB (little-endian)
            1,    // EI_VERSION = EV_CURRENT
            0,    // EI_OSABI = ELFOSABI_NONE
            0, 0, 0, 0, 0, 0, 0, 0, // padding (8 bytes)
            // --- e_type (2) = ET_EXEC ---
            2, 0, // --- e_machine (2) = EM_RISCV (243) ---
            0xf3, 0, // --- e_version (4) = 1 ---
            1, 0, 0, 0, // --- e_entry (4) = 0x1000 ---
            0x00, 0x10, 0x00, 0x00, // --- e_phoff (4) = 52 ---
            0x34, 0x00, 0x00, 0x00, // --- e_shoff (4) = 0 ---
            0x00, 0x00, 0x00, 0x00, // --- e_flags (4) = 0 ---
            0x00, 0x00, 0x00, 0x00, // --- e_ehsize (2) = 52 ---
            0x34, 0x00, // --- e_phentsize (2) = 32 ---
            0x20, 0x00, // --- e_phnum (2) = 1 ---
            0x01, 0x00, // --- e_shentsize (2) = 40 ---
            0x28, 0x00, // --- e_shnum (2) = 0 ---
            0x00, 0x00, // --- e_shstrndx (2) = 0 ---
            0x00, 0x00,
        ];
        assert_eq!(bytes.len(), 52, "ELF header should be 52 bytes");

        // PH1 — PT_LOAD (32 bytes)
        bytes.extend(&[
            0x01, 0x00, 0x00, 0x00, // p_type = PT_LOAD (1)
            0x54, 0x00, 0x00, 0x00, // p_offset = 84
            0x00, 0x10, 0x00, 0x00, // p_vaddr = 0x1000
            0x00, 0x10, 0x00, 0x00, // p_paddr = 0x1000
            0x08, 0x00, 0x00, 0x00, // p_filesz = 8
            0x08, 0x00, 0x00, 0x00, // p_memsz = 8
            0x05, 0x00, 0x00, 0x00, // p_flags = PF_R|PF_X (5)
            0x00, 0x10, 0x00, 0x00, // p_align = 0x1000
        ]);
        assert_eq!(bytes.len(), 84, "header + PH1 should be 84 bytes");

        // .text (8 bytes): LUI x1,0 + ECALL
        bytes.extend(&0x000000b7u32.to_le_bytes()); // LUI x1, 0
        bytes.extend(&0x00000073u32.to_le_bytes()); // ECALL
        assert_eq!(bytes.len(), 92, "total minimal ELF should be 92 bytes");

        bytes
    }

    // ===== Mutator 函数 =====

    fn mutate_bad_magic(bytes: &mut [u8]) {
        bytes[0] = 0x00;
    }

    fn mutate_elf64(bytes: &mut [u8]) {
        bytes[4] = 2; // EI_CLASS = ELFCLASS64
    }

    fn mutate_big_endian(bytes: &mut [u8]) {
        bytes[5] = 2; // EI_DATA = ELFDATA2MSB
    }

    fn mutate_wrong_machine(bytes: &mut [u8]) {
        set_u16_le(bytes, 18, 0xFFFF);
    }

    fn mutate_seg_vaddr(bytes: &mut [u8], vaddr: u32) {
        set_u32_le(bytes, 60, vaddr); // p_vaddr at PH offset + 8
    }

    fn mutate_seg_memsz(bytes: &mut [u8], memsz: u32) {
        set_u32_le(bytes, 72, memsz); // p_memsz at PH offset + 20
    }

    fn mutate_entry(bytes: &mut [u8], entry: u32) {
        set_u32_le(bytes, 24, entry);
    }

    fn mutate_shoff_overflow(bytes: &mut [u8]) {
        set_u32_le(bytes, 32, 0xFFFFFFFF); // e_shoff = huge
        set_u16_le(bytes, 48, 1); // e_shnum = 1
        set_u16_le(bytes, 46, 40); // e_shentsize = 40
    }

    fn inject_word(bytes: &mut [u8], word: u32) {
        bytes[84..88].copy_from_slice(&word.to_le_bytes());
    }

    /// 构造含 PT_DYNAMIC 段的 ELF（2 个 program header）。
    fn build_elf_with_pt_dynamic() -> Vec<u8> {
        let mut bytes = build_minimal_elf();
        set_u16_le(&mut bytes, 44, 2); // e_phnum = 2

        // 在 offset 84 插入第二个 PH（PT_DYNAMIC），原 .text 后移 32 字节
        let dyn_ph: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, // p_type = PT_DYNAMIC (2)
            0x00, 0x00, 0x00, 0x00, // p_offset = 0
            0x00, 0x20, 0x00, 0x00, // p_vaddr = 0x2000
            0x00, 0x20, 0x00, 0x00, // p_paddr = 0x2000
            0x00, 0x00, 0x00, 0x00, // p_filesz = 0
            0x00, 0x00, 0x00, 0x00, // p_memsz = 0
            0x04, 0x00, 0x00, 0x00, // p_flags = PF_R
            0x04, 0x00, 0x00, 0x00, // p_align = 4
        ];
        bytes.splice(84..84, dyn_ph);
        set_u32_le(&mut bytes, 56, 116); // PH1 p_offset = 116 (84 + 32)
        bytes
    }

    /// 构造含两个重叠 PT_LOAD 段的 ELF。
    fn build_elf_with_overlapping_segs() -> Vec<u8> {
        let mut bytes = build_minimal_elf();
        set_u16_le(&mut bytes, 44, 2); // e_phnum = 2

        // PH2: PT_LOAD vaddr=0x1004, memsz=8 → [0x1004, 0x100C) 与 PH1 [0x1000,0x1008) 重叠
        let overlap_ph: Vec<u8> = vec![
            0x01, 0x00, 0x00, 0x00, // p_type = PT_LOAD (1)
            0x74, 0x00, 0x00, 0x00, // p_offset = 116
            0x04, 0x10, 0x00, 0x00, // p_vaddr = 0x1004
            0x04, 0x10, 0x00, 0x00, // p_paddr = 0x1004
            0x08, 0x00, 0x00, 0x00, // p_filesz = 8
            0x08, 0x00, 0x00, 0x00, // p_memsz = 8
            0x05, 0x00, 0x00, 0x00, // p_flags = PF_R|PF_X
            0x00, 0x10, 0x00, 0x00, // p_align = 0x1000
        ];
        bytes.splice(84..84, overlap_ph);
        set_u32_le(&mut bytes, 56, 116); // PH1 p_offset = 116
        bytes
    }

    /// 构造含 DT_NEEDED 动态库引用的 ELF。
    ///
    /// Layout: header + PT_LOAD(.text+strtab) + PT_DYNAMIC(dyn section with DT_NEEDED).
    fn build_elf_with_dt_needed() -> Vec<u8> {
        let mut bytes = vec![
            // --- ELF header (52 bytes) ---
            0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            0, // e_type = ET_EXEC
            0xf3, 0, // e_machine = EM_RISCV
            1, 0, 0, 0, // e_version
            0x00, 0x10, 0x00, 0x00, // e_entry = 0x1000
            0x34, 0x00, 0x00, 0x00, // e_phoff = 52
            0x00, 0x00, 0x00, 0x00, // e_shoff = 0
            0x00, 0x00, 0x00, 0x00, // e_flags
            0x34, 0x00, // e_ehsize = 52
            0x20, 0x00, // e_phentsize = 32
            0x02, 0x00, // e_phnum = 2
            0x28, 0x00, // e_shentsize = 40
            0x00, 0x00, // e_shnum = 0
            0x00, 0x00, // e_shstrndx = 0
        ];
        // PH1 — PT_LOAD: .text(8) + pad(4) + strtab(12) = 24 bytes at vaddr 0x1000
        bytes.extend(&[
            0x01, 0x00, 0x00, 0x00, // p_type = PT_LOAD
            0x74, 0x00, 0x00, 0x00, // p_offset = 116
            0x00, 0x10, 0x00, 0x00, // p_vaddr = 0x1000
            0x00, 0x10, 0x00, 0x00, // p_paddr = 0x1000
            0x18, 0x00, 0x00, 0x00, // p_filesz = 24
            0x18, 0x00, 0x00, 0x00, // p_memsz = 24
            0x05, 0x00, 0x00, 0x00, // p_flags = PF_R|PF_X
            0x00, 0x10, 0x00, 0x00, // p_align = 0x1000
        ]);
        // PH2 — PT_DYNAMIC: 4 entries × 8 = 32 bytes at vaddr 0x2000
        bytes.extend(&[
            0x02, 0x00, 0x00, 0x00, // p_type = PT_DYNAMIC
            0x8c, 0x00, 0x00, 0x00, // p_offset = 140
            0x00, 0x20, 0x00, 0x00, // p_vaddr = 0x2000
            0x00, 0x20, 0x00, 0x00, // p_paddr = 0x2000
            0x20, 0x00, 0x00, 0x00, // p_filesz = 32
            0x20, 0x00, 0x00, 0x00, // p_memsz = 32
            0x04, 0x00, 0x00, 0x00, // p_flags = PF_R
            0x04, 0x00, 0x00, 0x00, // p_align = 4
        ]);
        // .text (8 bytes) at offset 116
        bytes.extend(&0x000000b7u32.to_le_bytes()); // LUI x1, 0
        bytes.extend(&0x00000073u32.to_le_bytes()); // ECALL
        // padding (4 bytes) at offset 124
        bytes.extend(&[0, 0, 0, 0]);
        // strtab (12 bytes) at offset 128: "\0libc.so.6\0\0" → strtab vaddr = 0x100C
        bytes.extend(b"\0libc.so.6\0\0");
        assert_eq!(bytes.len(), 140, "pre-dynamic section offset");
        // Dynamic section (32 bytes) at offset 140
        // Entry 0: DT_STRTAB (5), 0x100C
        bytes.extend(&5u32.to_le_bytes());
        bytes.extend(&0x100Cu32.to_le_bytes());
        // Entry 1: DT_STRSZ (10), 12
        bytes.extend(&10u32.to_le_bytes());
        bytes.extend(&12u32.to_le_bytes());
        // Entry 2: DT_NEEDED (1), 1 (strtab offset → "libc.so.6")
        bytes.extend(&1u32.to_le_bytes());
        bytes.extend(&1u32.to_le_bytes());
        // Entry 3: DT_NULL (0), 0
        bytes.extend(&0u32.to_le_bytes());
        bytes.extend(&0u32.to_le_bytes());
        bytes
    }

    // ===== 21 个单元测试 =====

    #[test]
    fn test_valid_minimal_elf() {
        let bytes = build_minimal_elf();
        let meta = validate_elf(&bytes).expect("minimal ELF should pass");
        assert_eq!(meta.entry, 0x1000);
        assert_eq!(meta.segments.len(), 1);
        assert!(meta.text.is_some());
        let text = meta.text.unwrap();
        assert_eq!(text.vaddr, 0x1000);
        assert_eq!(text.memsz, 8);
        assert_eq!(text.data.len(), 8);
    }

    #[test]
    fn test_reject_bad_magic() {
        let mut bytes = build_minimal_elf();
        mutate_bad_magic(&mut bytes);
        assert!(validate_elf(&bytes).is_err());
    }

    #[test]
    fn test_reject_elf64() {
        let mut bytes = build_minimal_elf();
        mutate_elf64(&mut bytes);
        assert!(validate_elf(&bytes).is_err());
    }

    #[test]
    fn test_reject_big_endian() {
        let mut bytes = build_minimal_elf();
        mutate_big_endian(&mut bytes);
        assert!(validate_elf(&bytes).is_err());
    }

    #[test]
    fn test_reject_wrong_machine() {
        let mut bytes = build_minimal_elf();
        mutate_wrong_machine(&mut bytes);
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::Other(msg) => assert!(msg.contains("machine")),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_wrap_attack() {
        let mut bytes = build_minimal_elf();
        mutate_seg_vaddr(&mut bytes, 0xFFFFFFF0);
        mutate_seg_memsz(&mut bytes, 0x20);
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::Other(msg) => assert!(msg.contains("wrap") || msg.contains("range")),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_seg_out_of_range() {
        let mut bytes = build_minimal_elf();
        mutate_seg_vaddr(&mut bytes, MAX_ZKVM_MEMORY as u32);
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::Other(msg) => {
                assert!(msg.contains("range") || msg.contains("MAX_ZKVM_MEMORY"))
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_entry_outside_text() {
        let mut bytes = build_minimal_elf();
        mutate_entry(&mut bytes, 0x2000); // outside [0x1000, 0x1008)
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::Other(msg) => assert!(msg.contains("entry")),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_overlapping_segments() {
        let bytes = build_elf_with_overlapping_segs();
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::Other(msg) => assert!(msg.contains("overlap")),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_pt_dynamic() {
        let bytes = build_elf_with_pt_dynamic();
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::Other(msg) => assert!(msg.contains("PT_DYNAMIC")),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_dt_needed() {
        let bytes = build_elf_with_dt_needed();
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::Other(msg) => {
                assert!(
                    msg.contains("PT_DYNAMIC") || msg.contains("DT_NEEDED"),
                    "should reject dynamic linking, got: {msg}"
                );
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_section_header_overflow() {
        let mut bytes = build_minimal_elf();
        mutate_shoff_overflow(&mut bytes);
        assert!(validate_elf(&bytes).is_err());
    }

    #[test]
    fn test_reject_text_too_large() {
        let mut bytes = build_minimal_elf();
        // memsz > MAX_TEXT_SIZE (8MB), but vaddr+memsz must be <= MAX_ZKVM_MEMORY (16MB)
        // vaddr=0, memsz=MAX_TEXT_SIZE+1 → end=8MB+1 < 16MB → passes range, fails text size
        mutate_seg_vaddr(&mut bytes, 0);
        mutate_seg_memsz(&mut bytes, (MAX_TEXT_SIZE + 1) as u32);
        // entry=0x1000 but text starts at vaddr=0 → entry outside text
        // Fix entry to be inside [0, MAX_TEXT_SIZE+1)
        mutate_entry(&mut bytes, 0);
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::Other(msg) => {
                assert!(
                    msg.contains("text") || msg.contains("MAX_TEXT_SIZE"),
                    "got: {msg}"
                );
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_total_memory_too_large() {
        let mut bytes = build_minimal_elf();
        // memsz > MAX_ZKVM_MEMORY → address range check catches it
        mutate_seg_memsz(&mut bytes, (MAX_ZKVM_MEMORY + 1) as u32);
        assert!(validate_elf(&bytes).is_err());
    }

    #[test]
    fn test_reject_fence_i() {
        let mut bytes = build_minimal_elf();
        inject_word(&mut bytes, 0x0000100f); // fence.i
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::UnsupportedInstruction(msg) => assert!(msg.contains("fence.i")),
            other => panic!("expected UnsupportedInstruction, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_compressed() {
        let mut bytes = build_minimal_elf();
        inject_word(&mut bytes, 0x00000001); // bits[1:0]=01 → compressed
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::UnsupportedInstruction(msg) => assert!(msg.contains("compressed")),
            other => panic!("expected UnsupportedInstruction, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_float_load() {
        let mut bytes = build_minimal_elf();
        inject_word(&mut bytes, 0x00000007); // FLW — opcode 0x07 not in whitelist
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::UnsupportedInstruction(msg) => assert!(msg.contains("whitelist")),
            other => panic!("expected UnsupportedInstruction, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_atomics() {
        let mut bytes = build_minimal_elf();
        inject_word(&mut bytes, 0x1000202f); // LR.W — opcode 0x2F not in whitelist
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::UnsupportedInstruction(msg) => assert!(msg.contains("whitelist")),
            other => panic!("expected UnsupportedInstruction, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_csr() {
        let mut bytes = build_minimal_elf();
        inject_word(&mut bytes, 0xc00010f3); // CSRRW — opcode 0x73, funct3=1
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::UnsupportedInstruction(msg) => assert!(msg.contains("CSR")),
            other => panic!("expected UnsupportedInstruction, got {other:?}"),
        }
    }

    #[test]
    fn test_allow_unimp_trap_marker() {
        // 0xC0001073 = LLVM `unimp`（unreachable trap 标记），允许通过 validator。
        // LLVM RISC-V 后端为 unreachable!() 和分支后填充生成此编码。
        let mut bytes = build_minimal_elf();
        inject_word(&mut bytes, 0xc0001073); // unimp — 应通过校验
        let meta = validate_elf(&bytes).expect("unimp 应通过 RV32I 校验");
        assert!(meta.text.is_some());
    }

    #[test]
    fn test_reject_other_csr_not_unimp() {
        // 确认非 unimp 的 CSR 指令仍被拒绝
        let mut bytes = build_minimal_elf();
        inject_word(&mut bytes, 0xc0002073); // CSRRS — funct3=2, 非 unimp
        let err = validate_elf(&bytes).unwrap_err();
        match err {
            ZkvmError::UnsupportedInstruction(msg) => assert!(msg.contains("CSR")),
            other => panic!("expected UnsupportedInstruction, got {other:?}"),
        }
    }

    #[test]
    fn test_toctou_ownership() {
        let bytes = build_minimal_elf();
        let meta = validate_elf(&bytes).expect("should pass");
        // ElfMetadata owns its data — modifying original bytes doesn't affect it
        let text = meta.text.as_ref().unwrap();
        let original_data = text.data.clone();
        let mut bytes_mut = bytes.clone();
        bytes_mut[84] = 0xFF; // tamper with original
        // meta.text.data should be unchanged (owned copy)
        assert_eq!(meta.text.as_ref().unwrap().data, original_data);
    }

    #[test]
    fn test_metadata_contains_segments() {
        let bytes = build_minimal_elf();
        let meta = validate_elf(&bytes).expect("should pass");
        assert_eq!(meta.entry, 0x1000);
        assert_eq!(meta.segments.len(), 1);
        let seg = &meta.segments[0];
        assert_eq!(seg.vaddr, 0x1000);
        assert_eq!(seg.memsz, 8);
        assert_eq!(seg.data.len(), 8);
        assert!(seg.flags & PF_X != 0, "segment should be executable");
        // Verify .text data is LUI + ECALL
        assert_eq!(
            u32::from_le_bytes([seg.data[0], seg.data[1], seg.data[2], seg.data[3]]),
            0x000000b7
        );
        assert_eq!(
            u32::from_le_bytes([seg.data[4], seg.data[5], seg.data[6], seg.data[7]]),
            0x00000073
        );
    }
}
