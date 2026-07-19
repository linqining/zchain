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
}
