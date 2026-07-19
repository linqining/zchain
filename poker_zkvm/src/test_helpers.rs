//! 共享测试辅助模块 — RV32I 指令编码器 + ELF32 构建器。
//!
//! 仅供测试和基准测试使用，通过 `test-helpers` feature 或 `#[cfg(test)]` 门控。
//!
//! ## 功能
//!
//! - RV32I 指令编码器（6 种类型：R / I / S / B / U / J）
//! - 便捷指令函数（`addi` / `add` / `sw` / `lw` / `bne` / `lui` / `ecall` 等）
//! - 最小 ELF32 构建器（单 PT_LOAD 段，EM_RISCV）
//! - NOP ELF 生成器（精确控制 trace 步数，供基准测试使用）

// ===========================================================================
// RV32I 指令编码器
// ===========================================================================

/// 编码 R-type 指令。
///
/// 布局：funct7(7) | rs2(5) | rs1(5) | funct3(3) | rd(5) | opcode(7)
pub fn encode_r(opcode: u32, funct3: u8, funct7: u8, rd: u8, rs1: u8, rs2: u8) -> u32 {
    ((funct7 as u32) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | ((rd as u32) << 7)
        | opcode
}

/// 编码 I-type 指令。
///
/// 布局：imm[11:0](12) | rs1(5) | funct3(3) | rd(5) | opcode(7)
pub fn encode_i(opcode: u32, funct3: u8, rd: u8, rs1: u8, imm12: u32) -> u32 {
    ((imm12 & 0xFFF) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | ((rd as u32) << 7)
        | opcode
}

/// 编码 S-type 指令。
///
/// 布局：imm[11:5](7) | rs2(5) | rs1(5) | funct3(3) | imm[4:0](5) | opcode(7)
pub fn encode_s(opcode: u32, funct3: u8, rs1: u8, rs2: u8, imm12: u32) -> u32 {
    let imm_hi = (imm12 >> 5) & 0x7F;
    let imm_lo = imm12 & 0x1F;
    (imm_hi << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | (imm_lo << 7)
        | opcode
}

/// 编码 B-type 指令。
///
/// 布局：imm[12](1) | imm[10:5](6) | rs2(5) | rs1(5) | funct3(3) | imm[4:1](4) | imm[11](1) | opcode(7)
///
/// `imm13` 为 13 位有符号字节偏移（含符号位），最低位忽略。
pub fn encode_b(opcode: u32, funct3: u8, rs1: u8, rs2: u8, imm13: u32) -> u32 {
    let b12 = (imm13 >> 12) & 0x1;
    let b11 = (imm13 >> 11) & 0x1;
    let b10_5 = (imm13 >> 5) & 0x3F;
    let b4_1 = (imm13 >> 1) & 0xF;
    (b12 << 31)
        | (b10_5 << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | (b4_1 << 8)
        | (b11 << 7)
        | opcode
}

/// 编码 U-type 指令。
///
/// 布局：imm[31:12](20) | rd(5) | opcode(7)
pub fn encode_u(opcode: u32, rd: u8, imm20: u32) -> u32 {
    ((imm20 & 0xFFFFF) << 12) | ((rd as u32) << 7) | opcode
}

/// 编码 J-type 指令。
///
/// 布局：imm[20](1) | imm[10:1](10) | imm[11](1) | imm[19:12](8) | rd(5) | opcode(7)
pub fn encode_j(opcode: u32, rd: u8, imm21: u32) -> u32 {
    let b20 = (imm21 >> 20) & 0x1;
    let b10_1 = (imm21 >> 1) & 0x3FF;
    let b11 = (imm21 >> 11) & 0x1;
    let b19_12 = (imm21 >> 12) & 0xFF;
    (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | ((rd as u32) << 7) | opcode
}

// ===========================================================================
// 便捷指令编码函数
// ===========================================================================

/// NOP = `ADDI x0, x0, 0` = 0x00000013
pub fn nop() -> u32 {
    0x00000013
}

/// `ADDI rd, rs1, imm` — I-type, opcode=0x13, funct3=0
pub fn addi(rd: u8, rs1: u8, imm: i32) -> u32 {
    encode_i(0x13, 0, rd, rs1, (imm as u32) & 0xFFF)
}

/// `ADD rd, rs1, rs2` — R-type, opcode=0x33, funct3=0, funct7=0
pub fn add(rd: u8, rs1: u8, rs2: u8) -> u32 {
    encode_r(0x33, 0, 0, rd, rs1, rs2)
}

/// `SUB rd, rs1, rs2` — R-type, opcode=0x33, funct3=0, funct7=0x20
pub fn sub(rd: u8, rs1: u8, rs2: u8) -> u32 {
    encode_r(0x33, 0, 0x20, rd, rs1, rs2)
}

/// `SLT rd, rs1, rs2` — R-type, opcode=0x33, funct3=2, funct7=0
pub fn slt(rd: u8, rs1: u8, rs2: u8) -> u32 {
    encode_r(0x33, 2, 0, rd, rs1, rs2)
}

/// `SW rs2, imm(rs1)` — S-type, opcode=0x23, funct3=2
pub fn sw(rs2: u8, rs1: u8, imm: i32) -> u32 {
    encode_s(0x23, 2, rs1, rs2, (imm as u32) & 0xFFF)
}

/// `SB rs2, imm(rs1)` — S-type, opcode=0x23, funct3=0
pub fn sb(rs2: u8, rs1: u8, imm: i32) -> u32 {
    encode_s(0x23, 0, rs1, rs2, (imm as u32) & 0xFFF)
}

/// `LW rd, imm(rs1)` — I-type, opcode=0x03, funct3=2
pub fn lw(rd: u8, rs1: u8, imm: i32) -> u32 {
    encode_i(0x03, 2, rd, rs1, (imm as u32) & 0xFFF)
}

/// `LB rd, imm(rs1)` — I-type, opcode=0x03, funct3=0
pub fn lb(rd: u8, rs1: u8, imm: i32) -> u32 {
    encode_i(0x03, 0, rd, rs1, (imm as u32) & 0xFFF)
}

/// `BNE rs1, rs2, imm` — B-type, opcode=0x63, funct3=1
pub fn bne(rs1: u8, rs2: u8, imm: i32) -> u32 {
    encode_b(0x63, 1, rs1, rs2, (imm as u32) & 0x1FFF)
}

/// `BEQ rs1, rs2, imm` — B-type, opcode=0x63, funct3=0
pub fn beq(rs1: u8, rs2: u8, imm: i32) -> u32 {
    encode_b(0x63, 0, rs1, rs2, (imm as u32) & 0x1FFF)
}

/// `LUI rd, imm20` — U-type, opcode=0x37
pub fn lui(rd: u8, imm20: u32) -> u32 {
    encode_u(0x37, rd, imm20)
}

/// `JAL rd, imm` — J-type, opcode=0x6F
pub fn jal(rd: u8, imm: i32) -> u32 {
    encode_j(0x6F, rd, (imm as u32) & 0x1FFFFF)
}

/// `ECALL` = 0x00000073
pub fn ecall() -> u32 {
    0x00000073
}

// ===========================================================================
// ELF32 构建器
// ===========================================================================

/// 将 u32 指令序列编码为小端字节序列。
pub fn encode_text(words: &[u32]) -> Vec<u8> {
    words.iter().copied().flat_map(u32::to_le_bytes).collect()
}

/// 构建最小 ELF32 文件（单 PT_LOAD 段，EM_RISCV）。
///
/// # 参数
/// - `entry` — 入口地址（通常等于 `text_vaddr`）
/// - `text_vaddr` — text 段虚拟地址
/// - `text_bytes` — text 段字节内容
///
/// # 布局
/// ```text
/// [ELF Header  52B] ─┐ entry=text_vaddr, phoff=52, phnum=1
/// [Prog Header 32B] ─┘ PT_LOAD, offset=84, vaddr=text_vaddr, flags=RX
/// [text_bytes  NB]
/// ```
pub fn build_elf32(entry: u32, text_vaddr: u32, text_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(84 + text_bytes.len());

    // --- ELF Header (52 bytes) ---
    // e_ident (16 bytes)
    bytes.extend_from_slice(&[
        0x7f, b'E', b'L', b'F', // magic
        1,    // EI_CLASS = ELFCLASS32
        1,    // EI_DATA = ELFDATA2LSB (little-endian)
        1,    // EI_VERSION = EV_CURRENT
        0,    // EI_OSABI = ELFOSABI_NONE
        0, 0, 0, 0, 0, 0, 0, 0, // EI_ABIVERSION + padding
    ]);
    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    bytes.extend_from_slice(&0xF3u16.to_le_bytes()); // e_machine = EM_RISCV
    bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version
    bytes.extend_from_slice(&entry.to_le_bytes()); // e_entry
    bytes.extend_from_slice(&52u32.to_le_bytes()); // e_phoff
    bytes.extend_from_slice(&0u32.to_le_bytes()); // e_shoff
    bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    bytes.extend_from_slice(&52u16.to_le_bytes()); // e_ehsize
    bytes.extend_from_slice(&32u16.to_le_bytes()); // e_phentsize
    bytes.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

    // --- Program Header (32 bytes) ---
    let p_offset = 84u32;
    let p_filesz = text_bytes.len() as u32;
    let p_memsz = text_bytes.len() as u32;
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    bytes.extend_from_slice(&p_offset.to_le_bytes()); // p_offset
    bytes.extend_from_slice(&text_vaddr.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&text_vaddr.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&p_filesz.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&p_memsz.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&5u32.to_le_bytes()); // p_flags = PF_R | PF_X
    bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // p_align

    // --- text segment ---
    bytes.extend_from_slice(text_bytes);

    bytes
}

/// 构建 NOP ELF — 产生恰好 `steps` 步 trace。
///
/// 程序 = `(steps - 2)` 个 NOP + `ADDI a7, x0, 2` + `ECALL`
/// trace 长度 = `steps - 2 + 2 = steps`
///
/// 用于基准测试精确控制 trace 步数。
pub fn build_nop_elf(steps: usize) -> Vec<u8> {
    assert!(steps >= 2, "build_nop_elf: steps 须 >= 2");
    let nop_count = steps - 2;
    let mut text: Vec<u32> = Vec::with_capacity(steps);
    for _ in 0..nop_count {
        text.push(nop());
    }
    text.push(addi(17, 0, 2)); // a7 = 2 (commit_output)
    text.push(ecall());
    let text_bytes = encode_text(&text);
    build_elf32(0x1000, 0x1000, &text_bytes)
}

// ===========================================================================
// 扑克牌型评估 v2 + 比较 ELF（Phase B — 5 张牌 rank → u32 评分 → 赢家）
// ===========================================================================

/// 构建扑克牌型评估 v2 电路的 ELF。
///
/// # 输入 / 输出
///
/// - 输入：5 字节，每字节为一张牌的 rank（2..=14）
/// - 输出：4 字节 u32 小端序，格式 `[category:8][max_rank:8][0:8][0:8]`
///   - category：5=straight, 4=trips（含 quads/fullhouse 简化）, 2=pair, 0=highcard
///   - max_rank：5 张牌中最大的 rank
///
/// # RV32I 程序结构（86 条指令，~80 trace 步）
///
/// 1. `read_input(0x2000, 5)` + `LB x1..x5` 加载 5 张牌
/// 2. 初始化 `pair_count=0, max=card[0], min=card[0]`
/// 3. 对 x2..x5 展开 max/min 更新（每张 5 条 = 20 条）
/// 4. 展开 C(5,2)=10 对 pair_count 比较（每对 3 条 = 30 条）
/// 5. category 推断：
///    - `pair_count > 2` → category=4
///    - `pair_count > 0` → category=2
///    - `pair_count == 0 && (max - min) == 4` → category=5
///    - 否则 category=0
/// 6. 输出 `category | (max << 8)` 到 addr 0，`commit_output(0, 4)`
///
/// # 寄存器分配
///
/// | 寄存器 | 用途 |
/// |--------|------|
/// | x20 | 0x2000 输入缓冲区基址 |
/// | x1-x5 | 5 张牌 rank |
/// | x6 | pair_count |
/// | x7 | category |
/// | x8 | max rank |
/// | x9 | min rank |
/// | x10/x11/x17 | syscall 参数 a0/a1/a7 |
/// | x13/x14/x15 | 临时寄存器 |
pub fn build_poker_hand_eval_v2_elf() -> Vec<u8> {
    let text: Vec<u32> = vec![
        // === Setup (5 条) ===
        lui(20, 0x2),    // x20 = 0x2000
        addi(10, 20, 0), // a0 = 0x2000
        addi(11, 0, 5),  // a1 = 5
        addi(17, 0, 1),  // a7 = 1 (read_input)
        ecall(),         // read_input(0x2000, 5)
        // === Load 5 cards (5 条) ===
        lb(1, 20, 0), // x1 = card[0]
        lb(2, 20, 1), // x2 = card[1]
        lb(3, 20, 2), // x3 = card[2]
        lb(4, 20, 3), // x4 = card[3]
        lb(5, 20, 4), // x5 = card[4]
        // === Init accumulators (3 条) ===
        addi(6, 0, 0), // x6 = pair_count = 0
        addi(8, 1, 0), // x8 = max = card[0]
        addi(9, 1, 0), // x9 = min = card[0]
        // === max/min update for x2 (5 条) ===
        slt(14, 8, 2), // x14 = (max < x2) ? 1 : 0
        beq(14, 0, 8), // if max >= x2, skip ADDI (→+8 = 下条 SLT)
        addi(8, 2, 0), // max = x2
        slt(15, 2, 9), // x15 = (x2 < min) ? 1 : 0
        beq(15, 0, 8), // if x2 >= min, skip ADDI
        addi(9, 2, 0), // min = x2
        // === max/min update for x3 (5 条) ===
        slt(14, 8, 3),
        beq(14, 0, 8),
        addi(8, 3, 0),
        slt(15, 3, 9),
        beq(15, 0, 8),
        addi(9, 3, 0),
        // === max/min update for x4 (5 条) ===
        slt(14, 8, 4),
        beq(14, 0, 8),
        addi(8, 4, 0),
        slt(15, 4, 9),
        beq(15, 0, 8),
        addi(9, 4, 0),
        // === max/min update for x5 (5 条) ===
        slt(14, 8, 5),
        beq(14, 0, 8),
        addi(8, 5, 0),
        slt(15, 5, 9),
        beq(15, 0, 8),
        addi(9, 5, 0),
        // === pair_count: 10 pairs (3 × 10 = 30 条) ===
        // (0,1)
        sub(13, 1, 2), // diff = x1 - x2
        bne(13, 0, 8), // if diff != 0, skip
        addi(6, 6, 1), // pair_count++
        // (0,2)
        sub(13, 1, 3),
        bne(13, 0, 8),
        addi(6, 6, 1),
        // (0,3)
        sub(13, 1, 4),
        bne(13, 0, 8),
        addi(6, 6, 1),
        // (0,4)
        sub(13, 1, 5),
        bne(13, 0, 8),
        addi(6, 6, 1),
        // (1,2)
        sub(13, 2, 3),
        bne(13, 0, 8),
        addi(6, 6, 1),
        // (1,3)
        sub(13, 2, 4),
        bne(13, 0, 8),
        addi(6, 6, 1),
        // (1,4)
        sub(13, 2, 5),
        bne(13, 0, 8),
        addi(6, 6, 1),
        // (2,3)
        sub(13, 3, 4),
        bne(13, 0, 8),
        addi(6, 6, 1),
        // (2,4)
        sub(13, 3, 5),
        bne(13, 0, 8),
        addi(6, 6, 1),
        // (3,4)
        sub(13, 4, 5),
        bne(13, 0, 8),
        addi(6, 6, 1),
        // === category inference (15 条) ===
        // category = 0 (default)
        addi(7, 0, 0),  // x7 = category = 0
        // Block A: if pair_count > 2 (>=3), category = 4
        addi(14, 0, 2), // x14 = 2
        slt(15, 14, 6), // x15 = (2 < pair_count) ? 1 : 0
        beq(15, 0, 12), // if not, skip to Block B (→+12)
        addi(7, 0, 4),  // category = 4
        jal(0, 20),     // skip to Block C (→+20)
        // Block B: if pair_count > 0 (>=1), category = 2 (BEQ target +12)
        addi(14, 0, 0), // x14 = 0
        slt(15, 14, 6), // x15 = (0 < pair_count) ? 1 : 0
        beq(15, 0, 8),  // if not, skip to Block C
        addi(7, 0, 2),  // category = 2
        // Block C: straight check (JAL target +20, BEQ target +8)
        bne(6, 0, 20),  // if pair_count != 0, skip to output (→+20)
        sub(13, 8, 9),  // diff = max - min
        addi(14, 0, 4), // x14 = 4
        bne(13, 14, 8), // if diff != 4, skip to output
        addi(7, 0, 5),  // category = 5
        // === Output (8 条) — BNE target +20 / BNE target +8 ===
        sb(7, 0, 0),    // store category to addr 0
        sb(8, 0, 1),    // store max to addr 1
        sb(0, 0, 2),    // store 0 to addr 2
        sb(0, 0, 3),    // store 0 to addr 3
        addi(10, 0, 0), // a0 = 0
        addi(11, 0, 4), // a1 = 4
        addi(17, 0, 2), // a7 = 2 (commit_output)
        ecall(),        // commit_output
    ];

    let text_bytes = encode_text(&text);
    build_elf32(0x1000, 0x1000, &text_bytes)
}

/// 构建扑克牌型比较电路的 ELF。
///
/// # 输入 / 输出
///
/// - 输入：8 字节，两个 u32 小端序评分（P1 score, P2 score）
/// - 输出：1 字节，赢家（1=P1 胜, 2=P2 胜, 0=平局）
///
/// # RV32I 程序（21 条指令，~20 trace 步）
///
/// 1. `read_input(0x2000, 8)` + `LW x1, x2` 加载两个评分
/// 2. `SLT x3, x1, x2`（s1<s2?）+ `SLT x4, x2, x1`（s2<s1?）
/// 3. 若 x4!=0（s1>s2）→ winner=1；若 x3!=0（s2>s1）→ winner=2；否则 winner=0
/// 4. `SB x5, 0(x0)` + `commit_output(0, 1)`
pub fn build_poker_hand_compare_elf() -> Vec<u8> {
    let text: Vec<u32> = vec![
        // === Setup (5 条) ===
        lui(20, 0x2),    // x20 = 0x2000
        addi(10, 20, 0), // a0 = 0x2000
        addi(11, 0, 8),  // a1 = 8
        addi(17, 0, 1),  // a7 = 1 (read_input)
        ecall(),         // read_input(0x2000, 8)
        // === Load scores (2 条) ===
        lw(1, 20, 0), // x1 = score1
        lw(2, 20, 4), // x2 = score2
        // === Compare (4 条) ===
        slt(3, 1, 2),  // x3 = (s1 < s2) ? 1 : 0
        slt(4, 2, 1),  // x4 = (s2 < s1) ? 1 : 0
        bne(4, 0, 16), // if x4 != 0 (s1 > s2), jump to winner=1 (→+16)
        bne(3, 0, 20), // if x3 != 0 (s2 > s1), jump to winner=2 (→+20)
        // === Default: winner = 0 (2 条) ===
        addi(5, 0, 0), // winner = 0
        jal(0, 16),    // skip to output (→+16)
        // === winner = 1 (BNE target +16) ===
        addi(5, 0, 1), // winner = 1
        jal(0, 8),     // skip to output (→+8)
        // === winner = 2 (BNE target +20) ===
        addi(5, 0, 2), // winner = 2
        // === Output (5 条) — JAL target +16 / JAL target +8 ===
        sb(5, 0, 0),    // store winner to addr 0
        addi(10, 0, 0), // a0 = 0
        addi(11, 0, 1), // a1 = 1
        addi(17, 0, 2), // a7 = 2 (commit_output)
        ecall(),        // commit_output
    ];

    let text_bytes = encode_text(&text);
    build_elf32(0x1000, 0x1000, &text_bytes)
}

/// host 端参考实现：计算 5 张牌的评分（与 `build_poker_hand_eval_v2_elf` RV32I 算法一致）。
///
/// 评分格式：`(category as u32) | ((max as u32) << 8)`
/// - category：5=straight, 4=trips, 2=pair, 0=highcard
/// - max：5 张牌中最大值
pub fn poker_hand_eval_v2_expected(cards: &[u8; 5]) -> u32 {
    let mut pair_count = 0u32;
    for i in 0..5 {
        for j in (i + 1)..5 {
            if cards[i] == cards[j] {
                pair_count += 1;
            }
        }
    }
    let mut category: u8 = 0;
    if pair_count >= 3 {
        category = 4;
    } else if pair_count >= 1 {
        category = 2;
    }
    let max = *cards.iter().max().unwrap();
    let min = *cards.iter().min().unwrap();
    if pair_count == 0 && (max - min) == 4 {
        category = 5;
    }
    (category as u32) | ((max as u32) << 8)
}

/// host 端参考实现：比较两个评分，返回赢家（与 `build_poker_hand_compare_elf` RV32I 算法一致）。
///
/// 返回值：1=P1 胜, 2=P2 胜, 0=平局
pub fn poker_hand_compare_expected(s1: u32, s2: u32) -> u8 {
    if s1 > s2 {
        1
    } else if s2 > s1 {
        2
    } else {
        0
    }
}

// ===========================================================================
// 完整一手牌流程 ELF（Phase 2.1 — texas_poker 合约 ELF 化）
// ===========================================================================

/// 构建完整一手牌流程 ELF — 覆盖 init → game_state write/read → card encode/decode →
/// shuffle_verify → BLS hash → 牌型评估(P1+P2) → showdown → commit_output。
///
/// 这是"实际 zkvm 运行方式"的 texas_poker 合约：以手工 RV32I 汇编直接调用 26 个 syscall，
/// 而非通过 trait 抽象。ELF 加载后由 zkvm 解释执行，trace 进入 Hypernova 折叠证明。
///
/// # 输入（62 字节）
///
/// - `[0..52]`：deck（必须是 0..51 的排列，供 `shuffle_verify` MVP 校验）
/// - `[52..57]`：P1 牌 rank（5 字节，值 2..=14）
/// - `[57..62]`：P2 牌 rank（5 字节，值 2..=14）
///
/// # 输出（1 字节）
///
/// - addr 0：winner（1=P1 胜, 2=P2 胜, 0=平局）
///
/// # RV32I 程序结构（220 条指令，~280 trace 步）
///
/// 1. **Setup**（5 条）：`read_input(0x2000, 62)`
/// 2. **GameState write**（5 条）：`game_state_write(SLOT_PLAYER_HANDS=0x02, 0x2000, 52)` — 模拟初始状态上链
/// 3. **GameState read**（5 条）：`game_state_read(slot=0x02, 0x2100, 52)` — 读回验证
/// 4. **CardDecode + CardEncode**（11 条）：对 deck[0] 做 byte → (rank,suit) → byte' 往返
/// 5. **ShuffleVerify**（6 条）：`shuffle_verify(0x2000, 52, 0x2000, 32)` — 用 deck[0..32] 作 mock proof
/// 6. **BLS hash_to_curve**（5 条）：`bls_hash_to_curve(0x2000, 32, 0x2500)` — 模拟洗牌密码学
/// 7. **BLS hash_to_scalar**（5 条）：`bls_hash_to_scalar(0x2000, 32, 0x2600)` — 派生下注签名标量
/// 8. **P1 牌型评估**（79 条）：input[52..57] → (category, max) → (x21, x22)
///    - Load(5) + Init(3) + max/min×4(24) + pair_count×10(30) + category(15) + Save(2)
/// 9. **P2 牌型评估**（79 条）：input[57..62] → (category, max) → (x23, x24)
/// 10. **Compare + Output**（20 条）：(x21,x22) vs (x23,x24) → x13 = winner → `commit_output(0, 1)`
///
/// **合计**：42 + 79 + 79 + 20 = 220 条指令
///
/// # 寄存器分配
///
/// | 寄存器 | 用途 |
/// |--------|------|
/// | x20 | 0x2000 输入缓冲区基址 |
/// | x1-x5 | 当前方 5 张牌 rank |
/// | x6 | pair_count |
/// | x7 | category |
/// | x8 | max rank |
/// | x9 | min rank |
/// | x10/x11/x12/x13/x17 | syscall 参数 a0/a1/a2/a3/a7（兼作临时） |
/// | x14/x15 | 临时寄存器 |
/// | x21/x22 | P1 (category, max) |
/// | x23/x24 | P2 (category, max) |
///
/// # 关键设计决策
///
/// 1. **不使用 SLLI**：test_helpers.rs 无 SLLI 辅助函数，比较逻辑改为两次 SLT + BNE
/// 2. **输入布局**：62 字节 = 52B deck + 5B P1 + 5B P2（拆分避免 shuffle_verify 排列校验矛盾）
/// 3. **shuffle proof 复用**：取 deck[0..32] 作 mock proof（非全零，满足 MVP 校验）
/// 4. **trace 长度**：~217 条指令 → 执行约 250-400 步 → 单 batch（batch_size=256）可容纳
pub fn build_texas_poker_full_hand_elf() -> Vec<u8> {
    let text: Vec<u32> = vec![
        // === Phase 1: Setup (5 条) — read_input(0x2000, 62) ===
        lui(20, 0x2),       // x20 = 0x2000
        addi(10, 20, 0),    // a0 = 0x2000
        addi(11, 0, 62),    // a1 = 62
        addi(17, 0, 1),     // a7 = 1 (read_input)
        ecall(),

        // === Phase 2: GameState write (5 条) — game_state_write(0x02, 0x2000, 52) ===
        // 模拟 ObjectDb 注册初始状态（SLOT_PLAYER_HANDS = 0x02）
        addi(10, 0, 0x02),  // a0 = SLOT_PLAYER_HANDS
        addi(11, 20, 0),    // a1 = 0x2000 (deck[0..52])
        addi(12, 0, 52),    // a2 = 52
        addi(17, 0, 0x21),  // a7 = 0x21 (game_state_write)
        ecall(),

        // === Phase 3: GameState read (5 条) — game_state_read(0x02, 0x2100, 52) ===
        addi(10, 0, 0x02),  // a0 = slot
        addi(11, 20, 0x100),// a1 = 0x2100 (out_ptr)
        addi(12, 0, 52),    // a2 = 52
        addi(17, 0, 0x20),  // a7 = 0x20 (game_state_read)
        ecall(),

        // === Phase 4: CardDecode + CardEncode 往返 (11 条) ===
        // 对 deck[0] 做 byte → (rank, suit) → byte' 校验
        lb(14, 20, 0),      // x14 = deck[0]
        addi(10, 14, 0),    // a0 = byte = deck[0]
        addi(11, 20, 0x200),// a1 = out_rank_ptr = 0x2200
        addi(12, 20, 0x201),// a2 = out_suit_ptr = 0x2201
        addi(17, 0, 0x31),  // a7 = 0x31 (card_decode)
        ecall(),
        // 重新 encode 回 byte'
        lb(10, 20, 0x200),  // a0 = rank
        lb(11, 20, 0x201),  // a1 = suit
        addi(12, 20, 0x202),// a2 = out_ptr = 0x2202
        addi(17, 0, 0x30),  // a7 = 0x30 (card_encode)
        ecall(),

        // === Phase 5: ShuffleVerify (6 条) — shuffle_verify(0x2000, 52, 0x2000, 32) ===
        // 用 deck[0..32] 作 mock proof（非全零，满足 MVP 校验）
        addi(10, 20, 0),    // a0 = deck_ptr = 0x2000
        addi(11, 0, 52),    // a1 = 52
        addi(12, 20, 0),    // a2 = proof_ptr = 0x2000 (复用 deck 前 32B)
        addi(13, 0, 32),    // a3 = 32
        addi(17, 0, 0x32),  // a7 = 0x32 (shuffle_verify)
        ecall(),

        // === Phase 6: BLS hash_to_curve (5 条) — bls_hash_to_curve(0x2000, 32, 0x2500) ===
        addi(10, 20, 0),    // a0 = msg_ptr
        addi(11, 0, 32),    // a1 = 32
        addi(12, 20, 0x500),// a2 = out_ptr = 0x2500 (48B G1 point)
        addi(17, 0, 0x10),  // a7 = 0x10 (bls_hash_to_curve)
        ecall(),

        // === Phase 7: BLS hash_to_scalar (5 条) — bls_hash_to_scalar(0x2000, 32, 0x2600) ===
        addi(10, 20, 0),    // a0 = msg_ptr
        addi(11, 0, 32),    // a1 = 32
        addi(12, 20, 0x600),// a2 = out_ptr = 0x2600 (32B scalar)
        addi(17, 0, 0x15),  // a7 = 0x15 (bls_hash_to_scalar)
        ecall(),

        // === Phase 8: P1 牌型评估 (73 条) — input[52..57] → (x21=cat, x22=max) ===
        // Load P1 cards (5 条)
        lb(1, 20, 52),      // x1 = P1[0]
        lb(2, 20, 53),      // x2 = P1[1]
        lb(3, 20, 54),      // x3 = P1[2]
        lb(4, 20, 55),      // x4 = P1[3]
        lb(5, 20, 56),      // x5 = P1[4]
        // Init accumulators (3 条)
        addi(6, 0, 0),      // x6 = pair_count = 0
        addi(8, 1, 0),      // x8 = max = P1[0]
        addi(9, 1, 0),      // x9 = min = P1[0]
        // max/min update for x2 (6 条)
        slt(14, 8, 2),      // x14 = (max < x2) ? 1 : 0
        beq(14, 0, 8),      // if max >= x2, skip ADDI (→+8 = 下条 SLT)
        addi(8, 2, 0),      // max = x2
        slt(15, 2, 9),      // x15 = (x2 < min) ? 1 : 0
        beq(15, 0, 8),      // if x2 >= min, skip ADDI
        addi(9, 2, 0),      // min = x2
        // max/min update for x3 (6 条)
        slt(14, 8, 3),
        beq(14, 0, 8),
        addi(8, 3, 0),
        slt(15, 3, 9),
        beq(15, 0, 8),
        addi(9, 3, 0),
        // max/min update for x4 (6 条)
        slt(14, 8, 4),
        beq(14, 0, 8),
        addi(8, 4, 0),
        slt(15, 4, 9),
        beq(15, 0, 8),
        addi(9, 4, 0),
        // max/min update for x5 (6 条)
        slt(14, 8, 5),
        beq(14, 0, 8),
        addi(8, 5, 0),
        slt(15, 5, 9),
        beq(15, 0, 8),
        addi(9, 5, 0),
        // pair_count: 10 pairs (30 条)
        sub(13, 1, 2), bne(13, 0, 8), addi(6, 6, 1),  // (0,1)
        sub(13, 1, 3), bne(13, 0, 8), addi(6, 6, 1),  // (0,2)
        sub(13, 1, 4), bne(13, 0, 8), addi(6, 6, 1),  // (0,3)
        sub(13, 1, 5), bne(13, 0, 8), addi(6, 6, 1),  // (0,4)
        sub(13, 2, 3), bne(13, 0, 8), addi(6, 6, 1),  // (1,2)
        sub(13, 2, 4), bne(13, 0, 8), addi(6, 6, 1),  // (1,3)
        sub(13, 2, 5), bne(13, 0, 8), addi(6, 6, 1),  // (1,4)
        sub(13, 3, 4), bne(13, 0, 8), addi(6, 6, 1),  // (2,3)
        sub(13, 3, 5), bne(13, 0, 8), addi(6, 6, 1),  // (2,4)
        sub(13, 4, 5), bne(13, 0, 8), addi(6, 6, 1),  // (3,4)
        // category inference (15 条) — 末尾 BNE 目标为下方 "Save P1" 块
        addi(7, 0, 0),      // x7 = category = 0
        addi(14, 0, 2),     // x14 = 2
        slt(15, 14, 6),     // x15 = (2 < pair_count) ? 1 : 0
        beq(15, 0, 12),     // if not, skip to Block B
        addi(7, 0, 4),      // category = 4
        jal(0, 20),         // skip to Block C
        addi(14, 0, 0),     // Block B: x14 = 0
        slt(15, 14, 6),     // x15 = (0 < pair_count) ? 1 : 0
        beq(15, 0, 8),      // if not, skip to Block C
        addi(7, 0, 2),      // category = 2
        bne(6, 0, 20),      // Block C: if pair_count != 0, skip to Save P1 (→+20)
        sub(13, 8, 9),      // diff = max - min
        addi(14, 0, 4),     // x14 = 4
        bne(13, 14, 8),     // if diff != 4, skip to Save P1 (→+8)
        addi(7, 0, 5),      // category = 5 (straight)

        // === Save P1 (2 条) — BNE 目标 +20/+8 ===
        addi(21, 7, 0),     // x21 = P1 category
        addi(22, 8, 0),     // x22 = P1 max

        // === Phase 9: P2 牌型评估 (73 条) — input[57..62] → (x23=cat, x24=max) ===
        // Load P2 cards (5 条)
        lb(1, 20, 57),      // x1 = P2[0]
        lb(2, 20, 58),      // x2 = P2[1]
        lb(3, 20, 59),      // x3 = P2[2]
        lb(4, 20, 60),      // x4 = P2[3]
        lb(5, 20, 61),      // x5 = P2[4]
        // Init (3 条)
        addi(6, 0, 0),
        addi(8, 1, 0),
        addi(9, 1, 0),
        // max/min (24 条 = 4 cards × 6 instrs)
        slt(14, 8, 2), beq(14, 0, 8), addi(8, 2, 0), slt(15, 2, 9), beq(15, 0, 8), addi(9, 2, 0),
        slt(14, 8, 3), beq(14, 0, 8), addi(8, 3, 0), slt(15, 3, 9), beq(15, 0, 8), addi(9, 3, 0),
        slt(14, 8, 4), beq(14, 0, 8), addi(8, 4, 0), slt(15, 4, 9), beq(15, 0, 8), addi(9, 4, 0),
        slt(14, 8, 5), beq(14, 0, 8), addi(8, 5, 0), slt(15, 5, 9), beq(15, 0, 8), addi(9, 5, 0),
        // pair_count (30 条)
        sub(13, 1, 2), bne(13, 0, 8), addi(6, 6, 1),
        sub(13, 1, 3), bne(13, 0, 8), addi(6, 6, 1),
        sub(13, 1, 4), bne(13, 0, 8), addi(6, 6, 1),
        sub(13, 1, 5), bne(13, 0, 8), addi(6, 6, 1),
        sub(13, 2, 3), bne(13, 0, 8), addi(6, 6, 1),
        sub(13, 2, 4), bne(13, 0, 8), addi(6, 6, 1),
        sub(13, 2, 5), bne(13, 0, 8), addi(6, 6, 1),
        sub(13, 3, 4), bne(13, 0, 8), addi(6, 6, 1),
        sub(13, 3, 5), bne(13, 0, 8), addi(6, 6, 1),
        sub(13, 4, 5), bne(13, 0, 8), addi(6, 6, 1),
        // category inference (15 条) — 末尾 BNE 目标为下方 "Save P2" 块
        addi(7, 0, 0),
        addi(14, 0, 2),
        slt(15, 14, 6),
        beq(15, 0, 12),
        addi(7, 0, 4),
        jal(0, 20),
        addi(14, 0, 0),
        slt(15, 14, 6),
        beq(15, 0, 8),
        addi(7, 0, 2),
        bne(6, 0, 20),      // if pair_count != 0, skip to Save P2 (→+20)
        sub(13, 8, 9),
        addi(14, 0, 4),
        bne(13, 14, 8),     // if diff != 4, skip to Save P2 (→+8)
        addi(7, 0, 5),

        // === Save P2 (2 条) — BNE 目标 +20/+8 ===
        addi(23, 7, 0),     // x23 = P2 category
        addi(24, 8, 0),     // x24 = P2 max

        // === Phase 10: Compare (20 条) — (x21,x22) vs (x23,x24) → x13 = winner ===
        // 不使用 SLLI 合并 score，直接两次 SLT + BNE 比较
        sub(13, 21, 23),    // x13 = cat1 - cat2
        bne(13, 0, 20),     // if cat 不同, jump to cat_diff (→+20 = instr +5)
        sub(13, 22, 24),    // x13 = max1 - max2
        bne(13, 0, 32),     // if max 不同, jump to max_diff (→+32 = instr +8)
        addi(13, 0, 0),     // winner = 0 (平局)
        jal(0, 40),         // skip to output (→+40 = instr +10)
        // cat_diff (BNE target +20):
        slt(14, 21, 23),    // x14 = (cat1 < cat2) ? 1 : 0
        addi(13, 0, 1),     // winner = 1 (default)
        beq(14, 0, 28),     // if cat1 > cat2, jump to output (→+28 = instr +7)
        addi(13, 0, 2),     // winner = 2 (cat1 < cat2)
        jal(0, 20),         // skip to output (→+20 = instr +5)
        // max_diff (BNE target +32):
        slt(14, 22, 24),    // x14 = (max1 < max2) ? 1 : 0
        addi(13, 0, 1),     // winner = 1
        beq(14, 0, 8),      // if max1 > max2, jump to output (→+8 = instr +2)
        addi(13, 0, 2),     // winner = 2
        // output (JAL target +40, JAL target +20, BEQ target +28, BEQ target +8):
        sb(13, 0, 0),       // store winner to addr 0
        addi(10, 0, 0),     // a0 = 0
        addi(11, 0, 1),     // a1 = 1
        addi(17, 0, 2),     // a7 = 2 (commit_output)
        ecall(),
    ];

    let text_bytes = encode_text(&text);
    build_elf32(0x1000, 0x1000, &text_bytes)
}

/// host 端参考实现：计算完整一手牌的赢家（与 `build_texas_poker_full_hand_elf` RV32I 算法一致）。
///
/// 复用 `poker_hand_eval_v2_expected` 计算每方评分，再用 `poker_hand_compare_expected` 比较。
///
/// # 输入
///
/// 62 字节：`[0..52]` deck + `[52..57]` P1 ranks + `[57..62]` P2 ranks
///
/// # 返回值
///
/// 1=P1 胜, 2=P2 胜, 0=平局
pub fn texas_poker_full_hand_expected(input: &[u8]) -> u8 {
    assert_eq!(input.len(), 62, "输入必须为 62 字节");
    let p1: [u8; 5] = input[52..57].try_into().expect("P1 长度");
    let p2: [u8; 5] = input[57..62].try_into().expect("P2 长度");
    let s1 = poker_hand_eval_v2_expected(&p1);
    let s2 = poker_hand_eval_v2_expected(&p2);
    poker_hand_compare_expected(s1, s2)
}

/// 构造完整一手牌测试输入（62 字节）。
///
/// - `deck`：52 字节，必须是 0..51 的排列（默认使用 0,1,2,...,51）
/// - `p1`：P1 的 5 张牌 rank（值 2..=14）
/// - `p2`：P2 的 5 张牌 rank（值 2..=14）
pub fn make_full_hand_input(p1: [u8; 5], p2: [u8; 5]) -> Vec<u8> {
    let mut input = Vec::with_capacity(62);
    input.extend(0..52u8); // deck = [0, 1, 2, ..., 51] — 合法排列
    input.extend_from_slice(&p1);
    input.extend_from_slice(&p2);
    assert_eq!(input.len(), 62);
    input
}

// ===========================================================================
// Stwo POC 测试辅助 — trace 构造（Phase 1.5）
// ===========================================================================

/// 构造最小可执行 Step（Lui x0, 0 + 全零寄存器 + 无内存访问）。
///
/// `step_index` 由调用方指定，用于填充 idx 列。
/// 用于 Stwo POC 测试，绕过 ELF 构造与 `execute_elf`。
///
/// **Phase 2.3.1**：`pc = step_index * 4`（模拟 RV32I 4 字节指令对齐的顺序执行），
/// 使 Group B 约束（`pc[next] == next_pc[cur]`）在 step order 下成立：
/// - `step[i].pc = i * 4`
/// - `step[i].next_pc = compute_next_pc(i*4, Lui, 0, 0) = i*4 + 4 = (i+1)*4 = step[i+1].pc` ✓
///
/// 之前 `pc=0` 会导致所有步骤 pc 相同但 next_pc=4，违反 Group B。
pub fn make_minimal_step(step_index: u64) -> crate::trace::Step {
    use crate::isa::Instruction;
    use crate::trace::{MemAccess, StepLog};
    crate::trace::Step::from_log(
        step_index,
        StepLog {
            pc: (step_index as u32).wrapping_mul(4),
            instruction: Instruction::Lui { rd: 0, imm: 0 },
            registers: [0u32; 32],
            mem_access: Vec::<MemAccess>::new(),
        },
    )
}

/// 构造指定步数的 sequential trace（idx 列严格连续递增 `0..num_steps`）。
///
/// 用于 Stwo POC 测试。`num_steps` 应为 2 的幂且 ≥ 1024
///（SimdBackend `MIN_LOG_SIZE=10` → 2^10=1024 行）。
pub fn make_sequential_trace(num_steps: usize) -> crate::trace::Trace {
    let mut trace = crate::trace::Trace::new();
    for i in 0..num_steps {
        trace.push_step(make_minimal_step(i as u64));
    }
    trace
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop_encoding() {
        assert_eq!(nop(), 0x00000013);
    }

    #[test]
    fn test_ecall_encoding() {
        assert_eq!(ecall(), 0x00000073);
    }

    #[test]
    fn test_addi_encoding() {
        // ADDI x1, x0, 0 → rd=1<<7 | 0x13 = 0x93
        assert_eq!(addi(1, 0, 0), 0x00000093);
        // ADDI x17, x0, 2 → imm=2<<20 | rd=17<<7 | 0x13 = 0x00200893
        assert_eq!(addi(17, 0, 2), 0x00200893);
        // ADDI x4, x4, -1 → imm=0xFFF<<20 | rs1=4<<15 | rd=4<<7 | 0x13 = 0xFFF20213
        assert_eq!(addi(4, 4, -1), 0xFFF20213);
    }

    #[test]
    fn test_add_encoding() {
        // ADD x3, x1, x2 → rs2=2<<20 | rs1=1<<15 | rd=3<<7 | 0x33 = 0x002081B3
        assert_eq!(add(3, 1, 2), 0x002081B3);
    }

    #[test]
    fn test_bne_encoding() {
        // BNE x4, x0, -16 → imm13 = -16 as u32 = 0x1FFF0
        // b12=1, b11=1, b10_5=0x3F, b4_1=0x8
        let word = bne(4, 0, -16);
        // 解码验证：opcode=0x63, funct3=1
        assert_eq!(word & 0x7F, 0x63);
        assert_eq!((word >> 12) & 0x7, 1);
        assert_eq!((word >> 15) & 0x1F, 4); // rs1=4
        assert_eq!((word >> 20) & 0x1F, 0); // rs2=0
    }

    #[test]
    fn test_lui_encoding() {
        // LUI x20, 0x2 → imm20=0x2<<12 | rd=20<<7 | 0x37 = 0x00002A37
        // 执行后 x20 = 0x2 << 12 = 0x2000
        assert_eq!(lui(20, 0x2), 0x00002A37);
    }

    #[test]
    fn test_sw_encoding() {
        // SW x2, 0(x0) → rs2=2, rs1=0, imm=0, opcode=0x23, funct3=2
        let word = sw(2, 0, 0);
        assert_eq!(word & 0x7F, 0x23);
        assert_eq!((word >> 12) & 0x7, 2);
        assert_eq!((word >> 15) & 0x1F, 0); // rs1=0
        assert_eq!((word >> 20) & 0x1F, 2); // rs2=2
    }

    #[test]
    fn test_lb_encoding() {
        // LB x1, 0(x20) → rd=1, rs1=20, imm=0, opcode=0x03, funct3=0
        let word = lb(1, 20, 0);
        assert_eq!(word & 0x7F, 0x03);
        assert_eq!((word >> 12) & 0x7, 0);
        assert_eq!((word >> 7) & 0x1F, 1); // rd=1
        assert_eq!((word >> 15) & 0x1F, 20); // rs1=20
    }

    #[test]
    fn test_build_elf32_minimal() {
        let text = encode_text(&[nop(), ecall()]);
        let elf = build_elf32(0x1000, 0x1000, &text);
        // 最小 ELF = 52 (header) + 32 (prog header) + 8 (2 instructions)
        assert_eq!(elf.len(), 84 + 8);
        // magic
        assert_eq!(&elf[0..4], b"\x7fELF");
        // e_machine = EM_RISCV (0xF3)
        assert_eq!(elf[18], 0xF3);
        assert_eq!(elf[19], 0x00);
    }

    #[test]
    fn test_build_nop_elf_step_count() {
        let elf = build_nop_elf(10);
        assert!(!elf.is_empty());
        // text segment = 10 instructions × 4 bytes = 40 bytes
        // ELF total = 84 + 40 = 124
        assert_eq!(elf.len(), 84 + 40);
    }

    #[test]
    fn test_build_nop_elf_too_few_steps() {
        let result = std::panic::catch_unwind(|| build_nop_elf(1));
        assert!(result.is_err(), "steps < 2 应 panic");
    }

    #[test]
    fn test_encode_text_roundtrip() {
        let words = [0x00000013, 0x00000073, 0x00100093];
        let bytes = encode_text(&words);
        assert_eq!(bytes.len(), 12);
        // 第一条指令的小端字节
        assert_eq!(&bytes[0..4], &[0x13, 0x00, 0x00, 0x00]);
    }

    // ===== Phase 2.1 单元测试 — 完整一手牌流程 ELF =====

    #[test]
    fn test_build_texas_poker_full_hand_elf_size() {
        let elf = build_texas_poker_full_hand_elf();
        // magic
        assert_eq!(&elf[0..4], b"\x7fELF");
        // e_machine = EM_RISCV (0xF3)
        assert_eq!(elf[18], 0xF3);
        // ELF 大小 = 84 (header) + 220 条指令 × 4 字节
        // 指令分布：Phase 1-7=42 + P1 eval=79 + P2 eval=79 + Compare=20 = 220
        let expected_text_bytes = 220 * 4;
        assert_eq!(elf.len(), 84 + expected_text_bytes);
    }

    #[test]
    fn test_make_full_hand_input_layout() {
        let p1 = [14u8, 13, 12, 11, 10]; // A K Q J 10 — straight
        let p2 = [2u8, 2, 3, 4, 5]; // pair of 2s
        let input = make_full_hand_input(p1, p2);
        assert_eq!(input.len(), 62);
        // deck = 0..51
        assert_eq!(input[0], 0);
        assert_eq!(input[51], 51);
        // P1 在 [52..57]
        assert_eq!(&input[52..57], &p1[..]);
        // P2 在 [57..62]
        assert_eq!(&input[57..62], &p2[..]);
    }

    #[test]
    fn test_texas_poker_full_hand_expected_p1_wins() {
        // P1 = A K Q J 10 (straight, category=5, max=14)
        // P2 = 2 2 3 4 5 (pair of 2s, category=2, max=5)
        let input = make_full_hand_input([14, 13, 12, 11, 10], [2, 2, 3, 4, 5]);
        assert_eq!(texas_poker_full_hand_expected(&input), 1, "P1 应胜");
    }

    #[test]
    fn test_texas_poker_full_hand_expected_p2_wins() {
        // P1 = 2 2 3 4 5 (pair)
        // P2 = 14 13 12 11 10 (straight)
        let input = make_full_hand_input([2, 2, 3, 4, 5], [14, 13, 12, 11, 10]);
        assert_eq!(texas_poker_full_hand_expected(&input), 2, "P2 应胜");
    }

    #[test]
    fn test_texas_poker_full_hand_expected_tie() {
        // 两方相同牌型与最大值 → 平局
        let input = make_full_hand_input([10, 9, 8, 7, 6], [10, 9, 8, 7, 6]);
        assert_eq!(texas_poker_full_hand_expected(&input), 0, "应平局");
    }

    #[test]
    fn test_texas_poker_full_hand_expected_same_cat_higher_max() {
        // 两方都是 highcard (category=0)，比 max
        // P1 max = 14, P2 max = 10 → P1 胜
        let input = make_full_hand_input([14, 3, 5, 7, 9], [10, 3, 5, 7, 9]);
        assert_eq!(texas_poker_full_hand_expected(&input), 1, "P1 max 更高应胜");
    }
}
