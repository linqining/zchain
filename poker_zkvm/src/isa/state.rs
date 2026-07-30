//! VM 状态与内存模型（Phase 3 — Task 3.2）。
//!
//! 本模块提供：
//! - [`VmState`] — VM 状态（pc / registers / memory）
//! - [`MemoryMap`] — 分页内存模型（BTreeMap + 字节级初始化位图）
//! - `load_elf` — 将已校验的 ELF 段加载到 VM 内存
//!
//! # 内存模型
//!
//! 采用分页 BTreeMap + 字节级初始化位图（设计决策 D1）：
//! - `PAGE_SIZE = 4096` 字节
//! - 每页含 `data: [u8; 4096]` + `init_mask: [u8; 512]`（1 bit/byte）
//! - 页基址为 key，按 BTreeMap 有序存储（确定性迭代）
//! - 总分配内存上限 `MAX_ZKVM_MEMORY = 16MB`（spec L266）
//!
//! # 对齐规则（设计决策 D2）
//!
//! 自然对齐（标准 RISC-V 语义）：
//! - LW/SW → 4 字节对齐
//! - LH/SH/LHU → 2 字节对齐
//! - LB/SB/LBU → 1 字节（任意地址）
//! - 未对齐返回 `ZkvmError::UnalignedAccess`

use crate::compiler::elf_validator::{ElfMetadata, LoadedSegment, MAX_ZKVM_MEMORY};
use crate::error::ZkvmError;
use alloc::collections::BTreeMap;

/// 页大小（字节）。
const PAGE_SIZE: usize = 4096;

/// 栈顶地址（spec L264，向下生长）。
pub const STACK_TOP: u32 = 0x8000_0000;

/// 堆起始地址（spec L264，向上生长）。
pub const HEAP_START: u32 = 0x1000_0000;

/// 堆大小（必须与 `guest_sdk::allocator::HEAP_SIZE` 保持一致）。
///
/// guest 的 bump allocator 返回**未初始化**内存（仅前进 HEAP_NEXT 指针，不清零）。
/// `Vec::with_capacity(n)` 分配 n 字节未初始化内存；写入 `len < n` 字节后，
/// Vec 增长时 `ptr::copy_nonoverlapping` 被编译为 LW（字级 4 字节加载），
/// 可能读取超出 `len` 的未初始化字节，触发 VM 的严格初始化检查 `UninitializedRead`。
///
/// 与栈预清零同理，host 在加载 ELF 后预清零整个堆区域，
/// 使这些读返回确定值 0，而非终止执行。
pub const HEAP_SIZE: u32 = 8 * 1024 * 1024; // 8MB

// ===========================================================================
// Page
// ===========================================================================

/// 单个内存页（4KB 数据 + 512B 初始化位图）。
#[derive(Clone, Debug)]
struct Page {
    /// 页数据
    data: [u8; PAGE_SIZE],
    /// 初始化位图（1 bit/byte，1 = 已写入）
    init_mask: [u8; PAGE_SIZE / 8],
}

impl Page {
    /// 创建全零页（所有字节未初始化）。
    fn zeroed() -> Self {
        Self {
            data: [0u8; PAGE_SIZE],
            init_mask: [0u8; PAGE_SIZE / 8],
        }
    }

    /// 检查页内某字节是否已初始化。
    fn is_initialized(&self, offset: usize) -> bool {
        let byte_idx = offset / 8;
        let bit_idx = offset % 8;
        (self.init_mask[byte_idx] >> bit_idx) & 1 == 1
    }

    /// 标记页内某字节为已初始化。
    fn set_initialized(&mut self, offset: usize) {
        let byte_idx = offset / 8;
        let bit_idx = offset % 8;
        self.init_mask[byte_idx] |= 1 << bit_idx;
    }
}

// ===========================================================================
// MemoryMap
// ===========================================================================

/// 分页内存映射（设计决策 D1）。
///
/// 使用 `BTreeMap<u32, Box<Page>>` 存储，key 为页基址（addr & !(PAGE_SIZE-1)）。
/// `total_allocated` 跟踪已分配页数 × PAGE_SIZE，用于 16MB 上限检查。
#[derive(Clone, Debug)]
pub struct MemoryMap {
    /// 页表（key = 页基址）
    pages: BTreeMap<u32, Box<Page>>,
    /// 已分配总字节数
    total_allocated: usize,
}

impl MemoryMap {
    /// 创建空内存映射。
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            total_allocated: 0,
        }
    }

    /// 获取页基址（addr 向下对齐到 PAGE_SIZE）。
    fn page_base(addr: u32) -> u32 {
        addr & !(PAGE_SIZE as u32 - 1)
    }

    /// 获取页内偏移。
    fn page_offset(addr: u32) -> usize {
        (addr as usize) & (PAGE_SIZE - 1)
    }

    /// 确保页存在，返回可变引用。分配新页时检查 16MB 上限。
    fn ensure_page(&mut self, addr: u32) -> Result<&mut Box<Page>, ZkvmError> {
        let base = Self::page_base(addr);
        if !self.pages.contains_key(&base) {
            // 检查 16MB 上限
            let new_total = self
                .total_allocated
                .checked_add(PAGE_SIZE)
                .ok_or(ZkvmError::OutOfMemory)?;
            if new_total > MAX_ZKVM_MEMORY {
                return Err(ZkvmError::OutOfMemory);
            }
            self.pages.insert(base, Box::new(Page::zeroed()));
            self.total_allocated = new_total;
        }
        Ok(self.pages.get_mut(&base).expect("just inserted"))
    }

    /// 获取页的只读引用（若不存在返回 None）。
    fn get_page(&self, addr: u32) -> Option<&Page> {
        self.pages.get(&Self::page_base(addr)).map(|v| &**v)
    }

    /// 零初始化一段内存范围 `[start, start + len)`。
    ///
    /// 对范围内每个页：分配页（若不存在）→ 全部字节置 0 → 标记为已初始化。
    /// 用于在执行开始前预清零栈区域，使编译器生成的代码读取栈填充/padding 字节时
    /// 返回确定值 0 而非触发 `UninitializedRead`。
    ///
    /// # Errors
    /// - `OutOfMemory` — 超 16MB 上限
    /// - `Other` — start + len 溢出
    pub(crate) fn zero_init_range(&mut self, start: u32, len: u32) -> Result<(), ZkvmError> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| ZkvmError::Other("zero_init_range: start + len overflow".to_string()))?;
        let mut addr = start;
        while addr < end {
            let base = Self::page_base(addr);
            let page = self.ensure_page(addr)?;
            // 整页置零 + 标记为已初始化
            for byte in page.data.iter_mut() {
                *byte = 0;
            }
            for mask_byte in page.init_mask.iter_mut() {
                *mask_byte = 0xFF; // 所有 8 位都标记为已初始化
            }
            // 跳到下一页
            addr = base.checked_add(PAGE_SIZE as u32).ok_or_else(|| {
                ZkvmError::Other("zero_init_range: page addr overflow".to_string())
            })?;
        }
        Ok(())
    }

    /// 读取单字节（检查初始化状态）。
    fn read_byte(&self, addr: u32) -> Result<u8, ZkvmError> {
        let offset = Self::page_offset(addr);
        match self.get_page(addr) {
            Some(page) if page.is_initialized(offset) => Ok(page.data[offset]),
            _ => Err(ZkvmError::UninitializedRead { addr }),
        }
    }

    /// 写入单字节（自动分配页 + 标记初始化）。
    fn write_byte(&mut self, addr: u32, val: u8) -> Result<(), ZkvmError> {
        let offset = Self::page_offset(addr);
        let page = self.ensure_page(addr)?;
        page.data[offset] = val;
        page.set_initialized(offset);
        Ok(())
    }

    /// 读取 2 字节（小端序），不检查对齐。
    fn read_halfword_raw(&self, addr: u32) -> Result<u16, ZkvmError> {
        let b0 = self.read_byte(addr)?;
        let b1 = self.read_byte(addr.checked_add(1).ok_or(ZkvmError::OutOfMemory)?)?;
        Ok(u16::from_le_bytes([b0, b1]))
    }

    /// 写入 2 字节（小端序），不检查对齐。
    fn write_halfword_raw(&mut self, addr: u32, val: u16) -> Result<(), ZkvmError> {
        let bytes = val.to_le_bytes();
        self.write_byte(addr, bytes[0])?;
        let next = addr.checked_add(1).ok_or(ZkvmError::OutOfMemory)?;
        self.write_byte(next, bytes[1])?;
        Ok(())
    }

    /// 读取 4 字节（小端序），不检查对齐。
    fn read_word_raw(&self, addr: u32) -> Result<u32, ZkvmError> {
        let b0 = self.read_byte(addr)?;
        let b1 = self.read_byte(addr.checked_add(1).ok_or(ZkvmError::OutOfMemory)?)?;
        let b2 = self.read_byte(addr.checked_add(2).ok_or(ZkvmError::OutOfMemory)?)?;
        let b3 = self.read_byte(addr.checked_add(3).ok_or(ZkvmError::OutOfMemory)?)?;
        Ok(u32::from_le_bytes([b0, b1, b2, b3]))
    }

    /// 写入 4 字节（小端序），不检查对齐。
    fn write_word_raw(&mut self, addr: u32, val: u32) -> Result<(), ZkvmError> {
        let bytes = val.to_le_bytes();
        self.write_byte(addr, bytes[0])?;
        let mut next = addr;
        for &b in &bytes[1..4] {
            next = next.checked_add(1).ok_or(ZkvmError::OutOfMemory)?;
            self.write_byte(next, b)?;
        }
        Ok(())
    }
}

impl Default for MemoryMap {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// VmState
// ===========================================================================

/// VM 状态（spec L263-264）。
///
/// 包含：
/// - `pc` — 程序计数器
/// - `registers` — 通用寄存器 x0-x31（x0 恒为 0）
/// - `memory` — 分页内存映射
#[derive(Clone, Debug)]
pub struct VmState {
    /// 程序计数器
    pub pc: u32,
    /// 通用寄存器 x0-x31
    pub registers: [u32; 32],
    /// 内存映射
    pub memory: MemoryMap,
}

impl VmState {
    /// 创建默认 VM 状态。
    ///
    /// pc=0, registers 全 0（sp/x2 会被 trampoline 初始化为 STACK_TOP）。
    pub fn new() -> Self {
        Self {
            pc: 0,
            registers: [0u32; 32],
            memory: MemoryMap::new(),
        }
    }

    /// 读取寄存器（x0 恒返回 0）。
    #[must_use]
    pub fn read_register(&self, idx: u8) -> u32 {
        if idx == 0 {
            0
        } else {
            self.registers[idx as usize]
        }
    }

    /// 写入寄存器（写 x0 丢弃）。
    pub fn write_register(&mut self, idx: u8, val: u32) {
        if idx != 0 {
            self.registers[idx as usize] = val;
        }
    }

    /// 读取单字节（任意对齐）。
    ///
    /// # Errors
    /// - `UninitializedRead` — 地址未写入
    pub fn read_memory_byte(&self, addr: u32) -> Result<u8, ZkvmError> {
        self.memory.read_byte(addr)
    }

    /// 写入单字节（任意对齐）。
    ///
    /// # Errors
    /// - `OutOfMemory` — 超 16MB 上限
    pub fn write_memory_byte(&mut self, addr: u32, val: u8) -> Result<(), ZkvmError> {
        self.memory.write_byte(addr, val)
    }

    /// 零初始化一段内存范围 `[start, start + len)`（页对齐批量写入）。
    ///
    /// 对范围内每个页：分配页（若不存在）→ 全部字节置 0 → 标记为已初始化。
    /// 用于在执行开始前预清零栈区域，使编译器生成的代码读取栈填充/padding 字节时
    /// 返回确定值 0 而非触发 `UninitializedRead`。
    ///
    /// # Errors
    /// - `OutOfMemory` — 超 16MB 上限
    /// - `Other` — start + len 溢出
    pub fn zero_init_range(&mut self, start: u32, len: u32) -> Result<(), ZkvmError> {
        self.memory.zero_init_range(start, len)
    }

    /// 读取半字（2 字节，需 2 字节对齐）。
    ///
    /// # Errors
    /// - `UnalignedAccess` — addr % 2 != 0
    /// - `UninitializedRead` — 任一字节未初始化
    pub fn read_memory_halfword(&self, addr: u32) -> Result<u16, ZkvmError> {
        if !addr.is_multiple_of(2) {
            return Err(ZkvmError::UnalignedAccess { addr });
        }
        self.memory.read_halfword_raw(addr)
    }

    /// 写入半字（2 字节，需 2 字节对齐）。
    ///
    /// # Errors
    /// - `UnalignedAccess` — addr % 2 != 0
    /// - `OutOfMemory` — 超 16MB 上限
    pub fn write_memory_halfword(&mut self, addr: u32, val: u16) -> Result<(), ZkvmError> {
        if !addr.is_multiple_of(2) {
            return Err(ZkvmError::UnalignedAccess { addr });
        }
        self.memory.write_halfword_raw(addr, val)
    }

    /// 读取字（4 字节，需 4 字节对齐）。
    ///
    /// # Errors
    /// - `UnalignedAccess` — addr % 4 != 0
    /// - `UninitializedRead` — 任一字节未初始化
    pub fn read_memory_word(&self, addr: u32) -> Result<u32, ZkvmError> {
        if !addr.is_multiple_of(4) {
            return Err(ZkvmError::UnalignedAccess { addr });
        }
        self.memory.read_word_raw(addr)
    }

    /// 写入字（4 字节，需 4 字节对齐）。
    ///
    /// # Errors
    /// - `UnalignedAccess` — addr % 4 != 0
    /// - `OutOfMemory` — 超 16MB 上限
    pub fn write_memory_word(&mut self, addr: u32, val: u32) -> Result<(), ZkvmError> {
        if !addr.is_multiple_of(4) {
            return Err(ZkvmError::UnalignedAccess { addr });
        }
        self.memory.write_word_raw(addr, val)
    }

    /// 从当前 PC 取指（4 字节，需 PC 4 字节对齐）。
    ///
    /// # Errors
    /// - `UnalignedAccess` — pc % 4 != 0
    /// - `UninitializedRead` — PC 指向未初始化内存
    pub fn fetch_word(&self) -> Result<u32, ZkvmError> {
        self.read_memory_word(self.pc)
    }
}

impl Default for VmState {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// load_elf
// ===========================================================================

/// 加载已校验的 ELF 元数据到 VM 内存（设计决策 D8，消除 TOCTOU）。
///
/// 遍历所有 PT_LOAD 段，逐字节写入 VM 内存（自动标记初始化 + 16MB 检查），
/// 然后设置 `state.pc = metadata.entry`。
///
/// # Errors
/// - `OutOfMemory` — 段加载超 16MB
/// - `UnalignedAccess` — 不会发生（write_memory_byte 无对齐要求）
pub fn load_elf(state: &mut VmState, metadata: &ElfMetadata) -> Result<(), ZkvmError> {
    for segment in &metadata.segments {
        load_segment(state, segment)?;
    }
    state.pc = metadata.entry;
    Ok(())
}

/// 加载单个段到 VM 内存。
fn load_segment(state: &mut VmState, segment: &LoadedSegment) -> Result<(), ZkvmError> {
    let mut addr = segment.vaddr;
    for &byte in &segment.data {
        state.write_memory_byte(addr, byte)?;
        addr = addr
            .checked_add(1)
            .ok_or_else(|| ZkvmError::Other("segment vaddr + len overflow".to_string()))?;
    }
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::elf_validator::{ElfMetadata, LoadedSegment};

    #[test]
    fn test_vmstate_new_defaults() {
        let state = VmState::new();
        assert_eq!(state.pc, 0);
        assert_eq!(state.registers, [0u32; 32]);
    }

    #[test]
    fn test_read_write_register_x0() {
        let mut state = VmState::new();
        state.write_register(0, 42);
        assert_eq!(state.read_register(0), 0, "x0 must always be 0");
    }

    #[test]
    fn test_read_write_register_normal() {
        let mut state = VmState::new();
        state.write_register(5, 0xABCD);
        assert_eq!(state.read_register(5), 0xABCD);
        state.write_register(31, 0xFFFF_FFFF);
        assert_eq!(state.read_register(31), 0xFFFF_FFFF);
    }

    #[test]
    fn test_write_read_memory_word_aligned() {
        let mut state = VmState::new();
        state.write_memory_word(0x1000, 0xDEAD_BEEF).unwrap();
        let val = state.read_memory_word(0x1000).unwrap();
        assert_eq!(val, 0xDEAD_BEEF, "word roundtrip (LE)");
    }

    #[test]
    fn test_unaligned_word_access() {
        let mut state = VmState::new();
        // read unaligned
        let err = state.read_memory_word(0x1001).unwrap_err();
        assert!(matches!(err, ZkvmError::UnalignedAccess { addr: 0x1001 }));
        // write unaligned
        let err = state.write_memory_word(0x1002, 42).unwrap_err();
        assert!(matches!(err, ZkvmError::UnalignedAccess { addr: 0x1002 }));
    }

    #[test]
    fn test_unaligned_halfword_access() {
        let mut state = VmState::new();
        let err = state.read_memory_halfword(0x1001).unwrap_err();
        assert!(matches!(err, ZkvmError::UnalignedAccess { addr: 0x1001 }));
        let err = state.write_memory_halfword(0x1003, 42).unwrap_err();
        assert!(matches!(err, ZkvmError::UnalignedAccess { addr: 0x1003 }));
    }

    #[test]
    fn test_byte_access_any_alignment() {
        let mut state = VmState::new();
        state.write_memory_byte(0x1001, 0xAB).unwrap();
        assert_eq!(state.read_memory_byte(0x1001).unwrap(), 0xAB);
        state.write_memory_byte(0x1002, 0xCD).unwrap();
        assert_eq!(state.read_memory_byte(0x1002).unwrap(), 0xCD);
    }

    #[test]
    fn test_uninitialized_read() {
        let state = VmState::new();
        let err = state.read_memory_byte(0x2000).unwrap_err();
        assert!(matches!(err, ZkvmError::UninitializedRead { addr: 0x2000 }));
    }

    #[test]
    fn test_memory_limit_16mb() {
        let mut state = VmState::new();
        // 16MB = 4096 pages × 4096 bytes
        // 写入 4096 页应成功，第 4097 页应失败
        for page_idx in 0..4096u32 {
            let addr = page_idx * 4096;
            state.write_memory_byte(addr, 0xAA).unwrap();
        }
        // 第 4097 页应失败
        let err = state.write_memory_byte(4096 * 4096, 0xBB).unwrap_err();
        assert!(
            matches!(err, ZkvmError::OutOfMemory),
            "expected OutOfMemory, got {err:?}"
        );
    }

    #[test]
    fn test_load_elf_and_fetch_word() {
        let mut state = VmState::new();
        // 构造 ElfMetadata：entry=0x1000, segment vaddr=0x1000, data = NOP (0x00000513 = ADDI x10, x0, 0)
        // LE bytes: 0x13 0x05 0x00 0x00
        let segment = LoadedSegment {
            vaddr: 0x1000,
            memsz: 4,
            data: vec![0x13, 0x05, 0x00, 0x00],
            flags: 0x05, // PF_R | PF_X
        };
        let metadata = ElfMetadata {
            entry: 0x1000,
            segments: vec![segment.clone()],
            text: Some(segment),
        };
        load_elf(&mut state, &metadata).unwrap();
        assert_eq!(state.pc, 0x1000, "pc should be set to entry");
        let word = state.fetch_word().unwrap();
        assert_eq!(word, 0x0000_0513, "fetched NOP word (LE)");
    }
}
