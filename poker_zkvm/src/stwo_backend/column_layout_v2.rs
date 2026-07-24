//! # Stwo Trace 列布局 v3.5 — riscv32im M 扩展算术约束（132 列）
//!
//! 在 v3.4（81 列）基础上追加 M 扩展算术约束 witness 列（+51 列）：
//! - MUL carry chain（21 列）：7 carry × (lo8 + hi0 + hi1)
//! - MUL 低位/高位结果（8 列）+ abs/sign（11 列）
//! - DIV witness（11 列）：quotient / remainder / special / sign
//!
//! ## 列布局（132 列）
//!
//! | 范围 | 列名 | 说明 |
//! |------|------|------|
//! | 0-3 | Pc (4×8-bit limb) | 当前 PC |
//! | 4-7 | PcNext (4×8-bit limb) | 下一 PC |
//! | 8-9 | ArithFlag (2 列) | 算术标志（ADD/ADDI=carry, SUB=borrow） |
//! | 10-13 | ValueAEffective (4×8-bit limb) | 操作数 A 有效值（rd=0 时为 0） |
//! | 14-17 | ValueB (4×8-bit limb) | 操作数 B 值 |
//! | 18-21 | ValueC (4×8-bit limb) | 操作数 C 值 |
//! | 22-64 | Is* indicators (43 列) | 指令 one-hot 标记（RV32I 34 + M 扩展 8 + padding 1） |
//! | 65-68 | HelperA (4×8-bit limb) | 复用：LUI imm / JAL/Branch/AUIPC Pc+imm / Load/Store MemAddr / JALR PcNextAux |
//! | 69-72 | HelperB (4×8-bit limb) | 复用：Load mem_value / Store rs2_value |
//! | 73 | Taken | 分支跳转标记 |
//! | 74-77 | MemAddr (4×8-bit limb) | Load/Store 地址（logup claim 用） |
//! | 78 | SyscallId | ECALL syscall ID（1 列 M31） |
//! | 79-80 | PcCarryFlag (2 列) | PC 进位标志 |
//! | 81-87 | MulCarryLo[0..6] (7 列) | M 扩展 carry 低 8 位（MUL/DIV 共享，one-hot 互斥） |
//! | 88-94 | MulCarryHi0[0..6] (7 列) | M 扩展 carry bit-8（binary 约束） |
//! | 95-101 | MulCarryHi1[0..6] (7 列) | M 扩展 carry bit-9（binary 约束） |
//! | 102-105 | MulHigh[0..3] (4×8-bit limb) | 乘积高 32 位 c₄..c₇ |
//! | 106-109 | AbsA[0..3] (4×8-bit limb) | \|rs1\| 绝对值（MULH/MULHSU） |
//! | 110-113 | AbsB[0..3] (4×8-bit limb) | \|rs2\| 绝对值（MULH） |
//! | 114 | SignA | rs1 符号位（binary） |
//! | 115 | SignB | rs2 符号位（binary） |
//! | 116 | LowNonzero | 乘积低 32 位 ≠ 0（补码借位，binary） |
//! | 117-120 | DivQuot[0..3] (4×8-bit limb) | 商 q |
//! | 121-124 | DivRem[0..3] (4×8-bit limb) | 余数 r |
//! | 125 | DivIsSpecial | 除零/溢出标志（binary） |
//! | 126 | DivSignQ | 商符号（有符号 DIV/REM，binary） |
//! | 127 | DivSignR | 余数符号（有符号 DIV/REM，binary） |
//! | 128-131 | MulLow[0..3] (4×8-bit limb) | 乘积低 32 位 c₀..c₃（MUL/MULH/MULHSU/MULHU/DIV carry chain 统一使用） |

/// 32-bit 值的 limb 数量（4×8-bit）。
pub const WORD_LIMB_COUNT: usize = 4;

/// 字大小（字节），与 `WORD_LIMB_COUNT` 一致。
pub const WORD_SIZE: usize = 4;

// ===========================================================================
// 主 trace 列索引常量（132 列）
// ===========================================================================

// ----- PC 相关（4×8-bit limb each）-----
/// col 0-3：当前 PC（4×8-bit limb）
pub const COL_PC_BASE: usize = 0;
/// col 4-7：下一 PC（4×8-bit limb）
pub const COL_PC_NEXT_BASE: usize = 4;

// ----- 算术标志（2 列，ADD/ADDI=carry, SUB=borrow，互斥使用）-----
/// col 8-9：算术标志（ArithFlag，16-bit 边界）
///
/// - ADD/ADDI 行：carry0, carry1（16-bit 加法进位）
/// - SUB 行：borrow0, borrow1（16-bit 减法借位）
/// - 其他行：0
///
/// 合并理由：ADD/ADDI 与 SUB 的 indicator one-hot 互斥，可复用同一组列。
pub const COL_CARRY_FLAG_BASE: usize = 8;

// ----- 操作数值（4×8-bit limb each，移除 ValueA 死列）-----
/// col 10-13：操作数 A 有效值（4×8-bit limb，rd=0 时为 0）
pub const COL_VALUE_A_EFF_BASE: usize = 10;
/// col 14-17：操作数 B 值（4×8-bit limb）
pub const COL_VALUE_B_BASE: usize = 14;
/// col 18-21：操作数 C 值（4×8-bit limb）
pub const COL_VALUE_C_BASE: usize = 18;

// ----- 指令 indicator（43 列，one-hot）-----
/// indicator 列起始索引（col 22-64，共 43 列）
pub const COL_IS_BASE: usize = 22;

// 指令类别 indicator 偏移（与 `crate::constraints::instruction_category` 对齐）
/// LUI indicator（类别 0）
pub const IS_LUI: usize = 22;
/// AUIPC indicator（类别 1）
pub const IS_AUIPC: usize = 23;
/// JAL indicator（类别 2）
pub const IS_JAL: usize = 24;
/// JALR indicator（类别 3）
pub const IS_JALR: usize = 25;
/// BEQ indicator（类别 4）
pub const IS_BEQ: usize = 26;
/// BNE indicator（类别 5）
pub const IS_BNE: usize = 27;
/// BLT indicator（类别 6）
pub const IS_BLT: usize = 28;
/// BGE indicator（类别 7）
pub const IS_BGE: usize = 29;
/// BLTU indicator（类别 8）
pub const IS_BLTU: usize = 30;
/// BGEU indicator（类别 9）
pub const IS_BGEU: usize = 31;
/// LB/LH/LW/LBU/LHU 共用 indicator（类别 10）
pub const IS_LOAD: usize = 32;
/// SB/SH/SW 共用 indicator（类别 11）
pub const IS_STORE: usize = 33;
/// ADDI indicator（类别 12）
pub const IS_ADDI: usize = 34;
/// SLTI indicator（类别 13）
pub const IS_SLTI: usize = 35;
/// SLTIU indicator（类别 14）
pub const IS_SLTIU: usize = 36;
/// XORI indicator（类别 15）
pub const IS_XORI: usize = 37;
/// ORI indicator（类别 16）
pub const IS_ORI: usize = 38;
/// ANDI indicator（类别 17）
pub const IS_ANDI: usize = 39;
/// SLLI indicator（类别 18）
pub const IS_SLLI: usize = 40;
/// SRLI indicator（类别 19）
pub const IS_SRLI: usize = 41;
/// SRAI indicator（类别 20）
pub const IS_SRAI: usize = 42;
/// ADD indicator（类别 21）
pub const IS_ADD: usize = 43;
/// SUB indicator（类别 22）
pub const IS_SUB: usize = 44;
/// SLL indicator（类别 23）
pub const IS_SLL: usize = 45;
/// SLT indicator（类别 24）
pub const IS_SLT: usize = 46;
/// SLTU indicator（类别 25）
pub const IS_SLTU: usize = 47;
/// XOR indicator（类别 26）
pub const IS_XOR: usize = 48;
/// SRL indicator（类别 27）
pub const IS_SRL: usize = 49;
/// SRA indicator（类别 28）
pub const IS_SRA: usize = 50;
/// OR indicator（类别 29）
pub const IS_OR: usize = 51;
/// AND indicator（类别 30）
pub const IS_AND: usize = 52;
/// FENCE indicator（类别 31）
pub const IS_FENCE: usize = 53;
/// ECALL indicator（类别 32）
pub const IS_ECALL: usize = 54;
/// EBREAK indicator（类别 33）
pub const IS_EBREAK: usize = 55;
// ===== M 扩展 indicators（类别 34-41，riscv32im 支持）=====
/// MUL indicator（类别 34）—— M 扩展：低 32 位乘法
pub const IS_MUL: usize = 56;
/// MULH indicator（类别 35）—— M 扩展：有符号×有符号高 32 位
pub const IS_MULH: usize = 57;
/// MULHSU indicator（类别 36）—— M 扩展：有符号×无符号高 32 位
pub const IS_MULHSU: usize = 58;
/// MULHU indicator（类别 37）—— M 扩展：无符号×无符号高 32 位
pub const IS_MULHU: usize = 59;
/// DIV indicator（类别 38）—— M 扩展：有符号除法
pub const IS_DIV: usize = 60;
/// DIVU indicator（类别 39）—— M 扩展：无符号除法
pub const IS_DIVU: usize = 61;
/// REM indicator（类别 40）—— M 扩展：有符号取余
pub const IS_REM: usize = 62;
/// REMU indicator（类别 41）—— M 扩展：无符号取余
pub const IS_REMU: usize = 63;
/// padding 行 indicator（类别 42）
pub const IS_PADDING: usize = 64;

/// indicator 列数量（43 个指令类别 = RV32I 35 + M 扩展 8）
pub const NUM_INSTRUCTION_CATEGORIES: usize = 43;

// ----- 辅助变量（4×8-bit limb each，2 个 helper）-----
/// col 65-68：辅助变量 A（4×8-bit limb）
///
/// 复用模式（LUI/JAL/Branch/AUIPC/Load/Store/JALR 互斥）：
/// - LUI 行：imm 值（用于 rd_eff = imm 约束）
/// - JAL/Branch taken/AUIPC 行：Pc + imm 预计算值
/// - Load/Store 行：MemAddr 值（rs1 + imm，与 MemAddr 列一致）
/// - JALR 行：PcNextAux 值（JALR 目标地址 = (rs1 + imm) & !1）
/// - 其他行：0（不被约束）
pub const COL_HELPER_A_BASE: usize = 65;
/// col 69-72：辅助变量 B（4×8-bit limb）
///
/// 复用模式（Load/Store 互斥）：
/// - Load 行：mem_value（加载值，用于 rd_eff = mem_value 约束）
/// - Store 行：rs2_value（存储值，用于 rs2 = mem_value 约束）
/// - 其他行：0（不被约束）
pub const COL_HELPER_B_BASE: usize = 69;

// ----- 分支辅助 -----
/// col 73：分支跳转标记（0/1）
pub const COL_TAKEN: usize = 73;

// ----- Phase 3：Load/Store 内存地址（4×8-bit limb）-----
/// col 74-77：Load/Store 指令的内存地址（4×8-bit limb，非 Load/Store 时为 0）
///
/// 注：HelperA 在 Load/Store 行也存 MemAddr 值，但 MemAddr 列单独保留用于 logup claim
/// 和调试输出。
pub const COL_MEM_ADDR_BASE: usize = 74;

// ----- Phase 4：ECALL（仅保留 SyscallId 1 列）-----
/// col 78：SyscallId（1 列 M31，直接表示 syscall_id 0-127）。
///
/// ECALL 行填 syscall_id，非 ECALL 行填 0。
/// v3 移除了 v2 的 24 列 Args/Outputs（texas_poker 不使用）。
pub const COL_SYSCALL_ID: usize = 78;

// ----- Phase 4：PC carry（2 列）-----
/// col 79-80：PC 进位标志（16-bit 边界，仅 IsNonFlow=1 或 Branch not-taken 时使用）。
pub const COL_PC_CARRY_FLAG_BASE: usize = 79;

// ===========================================================================
// M 扩展算术约束 witness 列（col 81-131，共 51 列）
// ===========================================================================
// 参考 RISC Zero / SP1 / OpenVM：8-bit 部分积 + carry chain。
// MUL/DIV 共享 carry 列（81-101），one-hot indicator 互斥保证同一行只使用一组。

/// carry chain 的 carry 数量（7 个：carry0..carry6）。
pub const MUL_CARRY_COUNT: usize = 7;

/// col 81-87：carry 低 8 位（7 列）。
///
/// carryₖ = carry_loₖ + hi0ₖ·256 + hi1ₖ·512
/// carry_loₖ ∈ [0,255]（信任，与 ADD limb 一致）
pub const COL_MUL_CARRY_LO_BASE: usize = 81;

/// col 88-94：carry bit-8（7 列，binary 约束）。
pub const COL_MUL_CARRY_HI0_BASE: usize = 88;

/// col 95-101：carry bit-9（7 列，binary 约束）。
pub const COL_MUL_CARRY_HI1_BASE: usize = 95;

/// col 102-105：乘积高 32 位 c₄..c₇（4×8-bit limb）。
///
/// - MUL：高位丢弃（自由值，仅参与 carry chain 完整性）
/// - MULHU：= rd_eff（高 32 位结果）
/// - MULH/MULHSU：unsigned 乘积高位，经符号调整后 = rd_eff
/// - DIV：必须 = 0（因 q·d ≤ n < 2³²）
pub const COL_MUL_HIGH_BASE: usize = 102;

/// col 106-109：|rs1| 绝对值的 4×8-bit limb（MULH/MULHSU 使用）。
pub const COL_ABS_A_BASE: usize = 106;

/// col 110-113：|rs2| 绝对值的 4×8-bit limb（MULH 使用）。
pub const COL_ABS_B_BASE: usize = 110;

/// col 114：rs1 符号位（1=负数，binary）。
pub const COL_SIGN_A: usize = 114;

/// col 115：rs2 符号位（1=负数，binary）。
pub const COL_SIGN_B: usize = 115;

/// col 116：乘积低 32 位 ≠ 0 标志（补码取反借位用，binary）。
///
/// 用于 MULH/MULHSU 结果符号调整：rd_eff = sign ? (2³²−1−high32−low_nonzero) : high32
pub const COL_LOW_NONZERO: usize = 116;

/// col 117-120：商 q 的 4×8-bit limb（DIV/DIVU/REM/REMU 使用）。
pub const COL_DIV_QUOT_BASE: usize = 117;

/// col 121-124：余数 r 的 4×8-bit limb（DIV/DIVU/REM/REMU 使用）。
pub const COL_DIV_REM_BASE: usize = 121;

/// col 125：除零/溢出特殊标志（1=特殊情况，binary）。
///
/// RISC-V 特殊情况：
/// - d=0：q=0xFFFFFFFF，r=n
/// - DIV INT_MIN/−1：q=INT_MIN，r=0
pub const COL_DIV_IS_SPECIAL: usize = 125;

/// col 126：商符号（有符号 DIV/REM，1=负，binary）。
pub const COL_DIV_SIGN_Q: usize = 126;

/// col 127：余数符号（有符号 DIV/REM，1=负，binary）。
pub const COL_DIV_SIGN_R: usize = 127;

/// col 128-131：乘积低 32 位 c₀..c₃（4×8-bit limb）。
///
/// carry chain 统一使用 COL_MUL_LOW 作为 c₀..c₃，COL_MUL_HIGH 作为 c₄..c₇。
/// - MUL：rd_eff = COL_MUL_LOW（低 32 位 = 结果）
/// - MULHU：rd_eff = COL_MUL_HIGH（高 32 位 = 结果）
/// - MULH/MULHSU：rd_eff = sign_adjust(COL_MUL_HIGH)（符号调整后 = 结果）
/// - DIV：COL_MUL_LOW + COL_DIV_REM = COL_ABS_A（q·d+r=n），COL_MUL_HIGH = 0
pub const COL_MUL_LOW_BASE: usize = 128;

// ===========================================================================
// V7 修复：Load 扩展约束 witness 列（复用 M 扩展列，仅 Load 行非 0）
// ===========================================================================
// Load 指令与 MUL/DIV indicator one-hot 互斥（同一行不可能既是 Load 又是 MUL），
// 故 M 扩展列（81-131）在 Load 行全部空闲，可安全复用存放 Load 扩展 witness。
// 这些列仅在 IS_LOAD=1 的行被约束，非 Load 行必须为 0（由 gating 约束保证）。
//
// 设计参考 RISC Zero Zirgen：内存存原始值，扩展在指令电路内约束推导。
// 详见 `.trae/documents/poker_zkvm_v7v8_bytelevel_fix_plan.md` §3。

/// col 81：Load byte 标记（binary，复用 MulCarryLo[0]）。
///
/// - 1 = LB/LBU（byte load，访问 1 字节）
/// - 0 = 其他（LH/LHU/LW/非 Load）
/// 仅 IS_LOAD=1 行可非 0（gating 约束 `(1-IS_LOAD)·IS_LOAD_BYTE=0`）。
pub const COL_IS_LOAD_BYTE: usize = 81;

/// col 82：Load halfword 标记（binary，复用 MulCarryLo[1]）。
///
/// - 1 = LH/LHU（halfword load，访问 2 字节）
/// - 0 = 其他
/// 与 IS_LOAD_BYTE 互斥（`IS_LOAD_BYTE·IS_LOAD_HALF=0`）。
pub const COL_IS_LOAD_HALF: usize = 82;

/// col 83：Load 符号扩展标记（binary，复用 MulCarryLo[2]）。
///
/// - 1 = LB/LH（sign-extend）
/// - 0 = LBU/LHU/LW（zero-extend / identity）
pub const COL_IS_LOAD_SIGN: usize = 83;

/// col 84：原始值符号位（binary，复用 MulCarryLo[3]）。
///
/// - byte load（LB/LBU）：原始字节 bit 7
/// - halfword load（LH/LHU）：原始半字 bit 15（= 高字节 bit 7）
/// - LW/非 Load：0
/// 由 LOAD_BITS[7] 约束推导（`SIGN_BIT = LOAD_BITS[7]`）。
pub const COL_SIGN_BIT: usize = 84;

/// col 85-92：符号承载字节的 8-bit 位分解（binary，复用 MulCarryLo[4..6] + MulCarryHi0[0..4]）。
///
/// - byte load：分解 HelperB[0]（原始字节）
/// - halfword load：分解 HelperB[1]（原始半字高字节，含符号位 bit 15）
/// - LW/非 Load：全 0
/// LOAD_BITS[7] 即为符号位，与 COL_SIGN_BIT 一致。
pub const COL_LOAD_BITS_BASE: usize = 85;

/// LOAD_BITS 位分解的 bit 数量。
pub const COL_LOAD_BITS_COUNT: usize = 8;

// ===========================================================================
// V7 修复：预计算 Load 扩展 gate 列（col 132-133，独立新列，非 M 扩展复用）
// ===========================================================================
// IS_LOAD_BYTE/HALF/SIGN（col 81-83）在 MUL/DIV 行复用为 carry 列（非 0/1），
// 不能直接用作扩展约束的 gate（会在 MUL/DIV 行触发误报）。
// 故新增 2 个预计算 gate 列，由 trace 填充在 Load 行设置、非 Load 行为 0：
//   LOAD_BYTE_GATE = IS_LOAD · IS_LOAD_BYTE（Load-byte 行=1，其余=0）
//   LOAD_HALF_GATE = IS_LOAD · IS_LOAD_HALF（Load-half 行=1，其余=0）
// 扩展约束使用这些 gate（degree 1），使 `gate · IS_LOAD_SIGN · (expr)` = degree 3 ✓。

/// col 132：预计算 Load byte gate = IS_LOAD · IS_LOAD_BYTE（binary，仅 Load-byte 行非 0）。
///
/// - LB/LBU 行：1（byte load）
/// - LH/LHU/LW/非 Load 行：0
/// 独立列（非 M 扩展复用），非 Load 行恒为 0（由 trace 填充保证）。
pub const COL_LOAD_BYTE_GATE: usize = 132;

/// col 133：预计算 Load halfword gate = IS_LOAD · IS_LOAD_HALF（binary，仅 Load-half 行非 0）。
///
/// - LH/LHU 行：1（halfword load）
/// - LB/LBU/LW/非 Load 行：0
/// 独立列（非 M 扩展复用），非 Load 行恒为 0（由 trace 填充保证）。
pub const COL_LOAD_HALF_GATE: usize = 133;

// ===========================================================================
// A3 修复：符号位绑定 witness 列（col 134-149，16 列，v3.7）
// ===========================================================================
// sign_a(col 114)/sign_b(col 115) 原仅约束 binality，未绑定到操作数符号位（bit 31）。
// 新增 SignABits/SignBBits 对 ValueB[3]/ValueC[3] 做 8-bit 位分解，
// 约束 sign_a = SignABits[7]、sign_b = SignBBits[7]。
//
// 互斥性：仅在使用 sign_a/sign_b 的指令行（SLT/SLTI/BLT/BGE/MULH/MULHSU/DIV/REM）非 0，
// 这些指令与 Load 行 one-hot 互斥，与 MULHU/MUL（不使用 sign_a/sign_b）也互斥，安全。

/// col 134-141：SignABits[0..8] — ValueB[3]（rs1 高字节）的 8-bit 位分解。
///
/// - SignABits[7] = rs1 符号位（bit 31），与 sign_a 绑定
/// - 仅使用 sign_a 的指令行非 0（SLT/SLTI/BLT/BGE/MULH/MULHSU/DIV/REM）
/// - 其他行为 0
pub const COL_SIGN_A_BITS_BASE: usize = 134;

/// SignABits 的 bit 数量。
pub const COL_SIGN_A_BITS_COUNT: usize = 8;

/// col 142-149：SignBBits[0..8] — ValueC[3]（rs2 高字节）的 8-bit 位分解。
///
/// - SignBBits[7] = rs2 符号位（bit 31），与 sign_b 绑定
/// - 仅使用 sign_b 的指令行非 0
/// - 其他行为 0
pub const COL_SIGN_B_BITS_BASE: usize = 142;

/// SignBBits 的 bit 数量。
pub const COL_SIGN_B_BITS_COUNT: usize = 8;

// ===========================================================================
// A6 修复：指令字列 + 解码约束 witness 列（col 150-181，32 列，v3.8）
// ===========================================================================
// 无指令字列时，indicator one-hot 完全信任 trace generator。
// 恶意 prover 可伪造 indicator 与实际指令字不匹配。
// 新增 InstrWord 存储原始 32-bit 指令字，InstrBits 做 byte 位分解，
// 解码约束绑定 indicator 与 opcode/funct3/funct7。
// ImmField 存储解码后立即数（供 Phase 4 A1 HelperA 约束使用）。

/// col 150-153：InstrWord[0..3] — 原始 32-bit 指令字（4×8-bit limb，little-endian）。
///
/// - InstrWord[0] = bits 0-7（含 opcode bits 0-6 + rd[0] bit 7）
/// - InstrWord[1] = bits 8-15（含 rd[1-4] + funct3 + rs1[0]）
/// - InstrWord[2] = bits 16-23（含 rs1[1-4] + rs2[0-3]）
/// - InstrWord[3] = bits 24-31（含 rs2[4] + funct7 bits 1-7）
/// 所有行非 0（padding 行 = 0）。
pub const COL_INSTR_WORD_BASE: usize = 150;

/// col 154-161：InstrBitsByte0[0..8] — InstrWord[0] 的 8-bit 位分解。
///
/// - bits 0-6 = opcode，bits 7 = rd[0]
/// - 用于提取 opcode 约束 indicator
/// - binality 约束 + 位分解约束（InstrWord[0] = Σ bits[i]·2^i）
pub const COL_INSTR_BITS_BYTE0_BASE: usize = 154;

/// col 162-169：InstrBitsByte1[0..8] — InstrWord[1] 的 8-bit 位分解。
///
/// - bits 0-3 = rd[1-4]，bits 4-6 = funct3，bit 7 = rs1[0]
/// - 用于提取 funct3 约束 indicator
pub const COL_INSTR_BITS_BYTE1_BASE: usize = 162;

/// col 170-177：InstrBitsByte3[0..8] — InstrWord[3] 的 8-bit 位分解。
///
/// - bit 0 = rs2[4]，bits 1-7 = funct7
/// - 用于提取 funct7 约束 indicator（R-type 指令）
pub const COL_INSTR_BITS_BYTE3_BASE: usize = 170;

/// InstrBits 的 bit 数量（每 byte 8 bit）。
pub const COL_INSTR_BITS_COUNT: usize = 8;

/// col 178-181：ImmField[0..3] — 解码后立即数（4×8-bit limb）。
///
/// 存储 `Instruction::immediate_value()` 的结果：
/// - LUI/AUIPC：imm（已左移 12 位）
/// - JAL/JALR/Branch/Load/Store/OP-IMM：imm（已符号扩展）
/// - SLLI/SRLI/SRAI：shamt
/// - R-type/FENCE/ECALL/EBREAK：0
/// Phase 4 A1 修复将约束 HelperA = rs1/pc + ImmField。
pub const COL_IMM_FIELD_BASE: usize = 178;

// ===========================================================================
// A1/A4 修复：HelperA 加法 carry + JALR 最低位清零 witness 列（col 182-184，3 列，v3.9）
// ===========================================================================
// HelperA 在 LUI/JAL/JALR/Branch/AUIPC/Load/Store 行存预计算值，
// AIR 仅约束 MemAddr/PcNext/rd_eff = HelperA，但 HelperA 本身（rs1+imm / pc+imm）无约束。
// A1 修复：新增 HelperA carry 列，约束 HelperA = rs1/pc + ImmField（16-bit carry 加法）。
// A4 修复：新增 HelperA_half 列，约束 JALR 行 HelperA[0] = 2*HelperA_half（最低位清零）。

/// col 182-183：HelperA carry（2 列，16-bit 边界进位）。
///
/// 用于 A1 修复的 HelperA = rs1/pc + ImmField 加法约束：
/// - carry0：低 16 位加法进位（∈ {0, 1}）
/// - carry1：高 16 位加法进位（∈ {0, 1}）
///
/// 使用指令（one-hot 互斥，可共享 carry 列）：
/// - Load/Store/JALR：HelperA = ValueB + ImmField（rs1 + imm）
/// - JAL/AUIPC/Branch taken：HelperA = Pc + ImmField（pc + imm）
/// - LUI：HelperA = ImmField（无 carry，直接等式）
///
/// 与 COL_CARRY_FLAG_BASE(8-9) 和 COL_PC_CARRY_FLAG_BASE(79-80) 互斥：
/// - COL_CARRY_FLAG_BASE 用于 ADD/SUB/Branch diff/SLT（与 HelperA 指令 one-hot 互斥，但 Branch 同时使用两者）
/// - COL_PC_CARRY_FLAG_BASE 用于 PcNext=Pc+4/rd_eff=Pc+4（JAL/JALR 同时使用两者）
/// 故需独立 carry 列。
///
/// binality 约束无条件执行（不 gating），因非 HelperA 行 carry=0（binary）✓。
pub const COL_HELPER_A_CARRY_BASE: usize = 182;

/// col 184：HelperA_half — JALR 行 HelperA[0] / 2（A4 修复 witness）。
///
/// JALR 目标 = (rs1 + imm) & !1，最低位清零。HelperA[0] 必须为偶数。
/// HelperA_half = HelperA[0] / 2，RangeCheck 确保 ∈ [0, 127]。
///
/// 约束（A4，degree 2）：
/// - IS_JALR * (HelperA[0] - 2 * HelperA_half) = 0
///
/// A1 JALR 低 16 位约束（无需 bit0 witness，用 binality 隐式推导，degree 3）：
/// - 令 x = ValueB_low16 + ImmField_low16 - HelperA_low16 - 65536*carry0
/// - IS_JALR * x * (x - 1) = 0（x = bit0，由 HelperA[0] 偶数 + 约束唯一确定）
///
/// 设计理由：原 XOR 公式 bit0 = ValueB[0] + ImmField[0] - 2*ValueB[0]*ImmField[0]
/// 仅对单 bit 成立，对 8-bit limb 错误。改用 binality(x) 隐式约束 bit0 ∈ {0,1}，
/// 配合 A4（HelperA[0] 偶数）唯一确定 bit0 = (ValueB+ImmField) mod 2。
///
/// 仅 JALR 行非 0，其他行为 0。需 RangeCheck 确保 ∈ [0, 127] ⊂ [0, 255]。
pub const COL_HELPER_A_HALF: usize = 184;

/// v3.9 列布局总列数（185 列）。
///
/// 185 列 = v3.8(182) + A1/A4 HelperA carry(2) + HelperA_half(1)
pub const NUM_COLUMNS: usize = 185;

/// RangeCheck 覆盖的全部 8-bit limb 列索引（v3.9 A8+A6+A1/A4 修复，64 列）。
///
/// v3.6 原 24 列：PC(4) + PcNext(4) + ValueAEff(4) + ValueB(4) + ValueC(4) + MemAddr(4)
/// v3.8 A8 新增 31 列：MulCarryLo(7) + MulHigh(4) + AbsA(4) + AbsB(4)
///                     + DivQuot(4) + DivRem(4) + MulLow(4)
/// v3.8 A6 新增 8 列：InstrWord(4) + ImmField(4)
/// v3.9 A1/A4 新增 1 列：HelperA_half(1)
///
/// **注意**：
/// - MulCarryLo(81-87) 在 Load 行复用为 IS_LOAD_BYTE/HALF/SIGN（binary），值 ∈ {0,1} ⊂ [0,255] ✓
/// - carry_hi0(88-94)/carry_hi1(95-101) 已有通用 binality 约束（无 gating），无需 RangeCheck
/// - SignABits(134-141)/SignBBits(142-149) 已有 A3 binality 约束（gated），无需 RangeCheck
/// - InstrBits(154-177) 已有 A6 binality 约束（gated），无需 RangeCheck
/// - HelperA_carry(182-183) 有无条件 binality 约束，无需 RangeCheck
/// - HelperA_half(184) 需 RangeCheck 确保 ∈ [0, 127] ⊂ [0, 255]
///
/// 此常量须与以下位置的 RANGE_CHECK_COLS 保持一致：
/// - `cpu_air.rs` CpuAir::evaluate（AIR 约束侧，发送 claim）
/// - `prover.rs` gen_cpu_full_interaction_trace（3 组件 prover）
/// - `prover.rs` gen_cpu_range_only_interaction_trace（2 组件 prover）
/// - `trace_native.rs` RANGE_CHECK_LIMB_COLS（RangeCheck yield 计数）
pub const RANGE_CHECK_COL_INDICES: [usize; 64] = {
    let mut arr = [0usize; 64];
    // PC (0-3)
    arr[0] = COL_PC_BASE;
    arr[1] = COL_PC_BASE + 1;
    arr[2] = COL_PC_BASE + 2;
    arr[3] = COL_PC_BASE + 3;
    // PcNext (4-7)
    arr[4] = COL_PC_NEXT_BASE;
    arr[5] = COL_PC_NEXT_BASE + 1;
    arr[6] = COL_PC_NEXT_BASE + 2;
    arr[7] = COL_PC_NEXT_BASE + 3;
    // ValueAEff (10-13)
    arr[8] = COL_VALUE_A_EFF_BASE;
    arr[9] = COL_VALUE_A_EFF_BASE + 1;
    arr[10] = COL_VALUE_A_EFF_BASE + 2;
    arr[11] = COL_VALUE_A_EFF_BASE + 3;
    // ValueB (14-17)
    arr[12] = COL_VALUE_B_BASE;
    arr[13] = COL_VALUE_B_BASE + 1;
    arr[14] = COL_VALUE_B_BASE + 2;
    arr[15] = COL_VALUE_B_BASE + 3;
    // ValueC (18-21)
    arr[16] = COL_VALUE_C_BASE;
    arr[17] = COL_VALUE_C_BASE + 1;
    arr[18] = COL_VALUE_C_BASE + 2;
    arr[19] = COL_VALUE_C_BASE + 3;
    // MemAddr (74-77)
    arr[20] = COL_MEM_ADDR_BASE;
    arr[21] = COL_MEM_ADDR_BASE + 1;
    arr[22] = COL_MEM_ADDR_BASE + 2;
    arr[23] = COL_MEM_ADDR_BASE + 3;
    // MulCarryLo (81-87, 7 列) — A8 新增（A5 修复：carry_lo ∈ [0,255] 不再信任）
    arr[24] = COL_MUL_CARRY_LO_BASE;
    arr[25] = COL_MUL_CARRY_LO_BASE + 1;
    arr[26] = COL_MUL_CARRY_LO_BASE + 2;
    arr[27] = COL_MUL_CARRY_LO_BASE + 3;
    arr[28] = COL_MUL_CARRY_LO_BASE + 4;
    arr[29] = COL_MUL_CARRY_LO_BASE + 5;
    arr[30] = COL_MUL_CARRY_LO_BASE + 6;
    // MulHigh (102-105, 4 列) — A8 新增
    arr[31] = COL_MUL_HIGH_BASE;
    arr[32] = COL_MUL_HIGH_BASE + 1;
    arr[33] = COL_MUL_HIGH_BASE + 2;
    arr[34] = COL_MUL_HIGH_BASE + 3;
    // AbsA (106-109, 4 列) — A8 新增
    arr[35] = COL_ABS_A_BASE;
    arr[36] = COL_ABS_A_BASE + 1;
    arr[37] = COL_ABS_A_BASE + 2;
    arr[38] = COL_ABS_A_BASE + 3;
    // AbsB (110-113, 4 列) — A8 新增
    arr[39] = COL_ABS_B_BASE;
    arr[40] = COL_ABS_B_BASE + 1;
    arr[41] = COL_ABS_B_BASE + 2;
    arr[42] = COL_ABS_B_BASE + 3;
    // DivQuot (117-120, 4 列) — A8 新增
    arr[43] = COL_DIV_QUOT_BASE;
    arr[44] = COL_DIV_QUOT_BASE + 1;
    arr[45] = COL_DIV_QUOT_BASE + 2;
    arr[46] = COL_DIV_QUOT_BASE + 3;
    // DivRem (121-124, 4 列) — A8 新增
    arr[47] = COL_DIV_REM_BASE;
    arr[48] = COL_DIV_REM_BASE + 1;
    arr[49] = COL_DIV_REM_BASE + 2;
    arr[50] = COL_DIV_REM_BASE + 3;
    // MulLow (128-131, 4 列) — A8 新增
    arr[51] = COL_MUL_LOW_BASE;
    arr[52] = COL_MUL_LOW_BASE + 1;
    arr[53] = COL_MUL_LOW_BASE + 2;
    arr[54] = COL_MUL_LOW_BASE + 3;
    // InstrWord (150-153, 4 列) — A6 新增
    arr[55] = COL_INSTR_WORD_BASE;
    arr[56] = COL_INSTR_WORD_BASE + 1;
    arr[57] = COL_INSTR_WORD_BASE + 2;
    arr[58] = COL_INSTR_WORD_BASE + 3;
    // ImmField (178-181, 4 列) — A6 新增
    arr[59] = COL_IMM_FIELD_BASE;
    arr[60] = COL_IMM_FIELD_BASE + 1;
    arr[61] = COL_IMM_FIELD_BASE + 2;
    arr[62] = COL_IMM_FIELD_BASE + 3;
    // HelperA_half (184, 1 列) — A4 新增（JALR 最低位清零 witness ∈ [0, 127]）
    arr[63] = COL_HELPER_A_HALF;
    arr
};

/// Phase 4 ECALL dispatch 列数量（v3 仅 1 列 SyscallId）。
pub const ECALL_DISPATCH_NUM_COLUMNS: usize = 1;

/// 将指令类别 ID（0-42）映射为 indicator 列索引。
#[must_use]
pub fn category_to_indicator_col(category: usize) -> usize {
    assert!(
        category < NUM_INSTRUCTION_CATEGORIES,
        "category_to_indicator_col: category {} >= {}",
        category,
        NUM_INSTRUCTION_CATEGORIES
    );
    COL_IS_BASE + category
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_num_columns() {
        assert_eq!(
            NUM_COLUMNS,
            185,
            "v3.9 列布局应为 185 列（v3.8 182 列 + A1/A4 HelperA carry 2 + HelperA_half 1）"
        );
    }

    #[test]
    fn test_word_limb_count() {
        assert_eq!(WORD_LIMB_COUNT, 4, "4×8-bit limb 方案，WORD_LIMB_COUNT=4");
        assert_eq!(WORD_SIZE, 4);
    }

    #[test]
    fn test_column_ranges_no_overlap() {
        let ranges: [(usize, usize); 32] = [
            (COL_PC_BASE, 4),                     // 0-3
            (COL_PC_NEXT_BASE, 4),                // 4-7
            (COL_CARRY_FLAG_BASE, 2),             // 8-9（合并 carry/borrow）
            (COL_VALUE_A_EFF_BASE, 4),            // 10-13
            (COL_VALUE_B_BASE, 4),                // 14-17
            (COL_VALUE_C_BASE, 4),                // 18-21
            (COL_HELPER_A_BASE, 4),               // 65-68
            (COL_HELPER_B_BASE, 4),               // 69-72
            (COL_MUL_CARRY_LO_BASE, MUL_CARRY_COUNT),    // 81-87
            (COL_MUL_CARRY_HI0_BASE, MUL_CARRY_COUNT),   // 88-94
            (COL_MUL_CARRY_HI1_BASE, MUL_CARRY_COUNT),   // 95-101
            (COL_MUL_HIGH_BASE, 4),               // 102-105
            (COL_ABS_A_BASE, 4),                   // 106-109
            (COL_ABS_B_BASE, 4),                   // 110-113
            (COL_SIGN_A, 1),                       // 114
            (COL_SIGN_B, 1),                       // 115
            (COL_LOW_NONZERO, 1),                  // 116
            (COL_DIV_QUOT_BASE, 4),                // 117-120
            (COL_DIV_REM_BASE, 4),                 // 121-124
            (COL_DIV_IS_SPECIAL, 3),               // 125-127（IsSpecial + SignQ + SignR）
            (COL_MUL_LOW_BASE, 4),                 // 128-131（MulLow c₀..c₃）
            (COL_LOAD_BYTE_GATE, 1),               // 132（V7 预计算 gate）
            (COL_LOAD_HALF_GATE, 1),               // 133（V7 预计算 gate）
            (COL_SIGN_A_BITS_BASE, COL_SIGN_A_BITS_COUNT), // 134-141（A3 符号位绑定）
            (COL_SIGN_B_BITS_BASE, COL_SIGN_B_BITS_COUNT), // 142-149（A3 符号位绑定）
            (COL_INSTR_WORD_BASE, WORD_LIMB_COUNT),             // 150-153（A6 指令字）
            (COL_INSTR_BITS_BYTE0_BASE, COL_INSTR_BITS_COUNT),  // 154-161（A6 位分解 byte0）
            (COL_INSTR_BITS_BYTE1_BASE, COL_INSTR_BITS_COUNT),  // 162-169（A6 位分解 byte1）
            (COL_INSTR_BITS_BYTE3_BASE, COL_INSTR_BITS_COUNT),  // 170-177（A6 位分解 byte3）
            (COL_IMM_FIELD_BASE, WORD_LIMB_COUNT),              // 178-181（A6 立即数）
            (COL_HELPER_A_CARRY_BASE, 2),                        // 182-183（A1 HelperA carry）
            (COL_HELPER_A_HALF, 1),                              // 184（A4 HelperA_half）
        ];
        let mut all_cols = HashSet::new();
        for (base, count) in &ranges {
            for offset in 0..*count {
                let col = base + offset;
                assert!(all_cols.insert(col), "列 {} 重复分配", col);
            }
        }
    }

    #[test]
    fn test_indicator_columns_range() {
        let indicators = [
            IS_LUI, IS_AUIPC, IS_JAL, IS_JALR, IS_BEQ, IS_BNE, IS_BLT, IS_BGE,
            IS_BLTU, IS_BGEU, IS_LOAD, IS_STORE, IS_ADDI, IS_SLTI, IS_SLTIU,
            IS_XORI, IS_ORI, IS_ANDI, IS_SLLI, IS_SRLI, IS_SRAI, IS_ADD, IS_SUB,
            IS_SLL, IS_SLT, IS_SLTU, IS_XOR, IS_SRL, IS_SRA, IS_OR, IS_AND,
            IS_FENCE, IS_ECALL, IS_EBREAK,
            // M 扩展（8）
            IS_MUL, IS_MULH, IS_MULHSU, IS_MULHU, IS_DIV, IS_DIVU, IS_REM, IS_REMU,
            IS_PADDING,
        ];
        assert_eq!(indicators.len(), NUM_INSTRUCTION_CATEGORIES);
        for &col in &indicators {
            assert!(
                col >= COL_IS_BASE && col < COL_IS_BASE + NUM_INSTRUCTION_CATEGORIES,
                "IS_* 列 {} 不在 indicator 范围 [22, {}]",
                col,
                COL_IS_BASE + NUM_INSTRUCTION_CATEGORIES
            );
        }
    }

    #[test]
    fn test_indicator_columns_distinct() {
        let indicators = [
            IS_LUI, IS_AUIPC, IS_JAL, IS_JALR, IS_BEQ, IS_BNE, IS_BLT, IS_BGE,
            IS_BLTU, IS_BGEU, IS_LOAD, IS_STORE, IS_ADDI, IS_SLTI, IS_SLTIU,
            IS_XORI, IS_ORI, IS_ANDI, IS_SLLI, IS_SRLI, IS_SRAI, IS_ADD, IS_SUB,
            IS_SLL, IS_SLT, IS_SLTU, IS_XOR, IS_SRL, IS_SRA, IS_OR, IS_AND,
            IS_FENCE, IS_ECALL, IS_EBREAK,
            // M 扩展（8）
            IS_MUL, IS_MULH, IS_MULHSU, IS_MULHU, IS_DIV, IS_DIVU, IS_REM, IS_REMU,
            IS_PADDING,
        ];
        let unique: HashSet<_> = indicators.iter().collect();
        assert_eq!(unique.len(), indicators.len(), "IS_* 列有重复");
    }

    #[test]
    fn test_category_to_indicator_col() {
        assert_eq!(category_to_indicator_col(0), IS_LUI);
        assert_eq!(category_to_indicator_col(21), IS_ADD);
        // M 扩展：类别 34-41
        assert_eq!(category_to_indicator_col(34), IS_MUL);
        assert_eq!(category_to_indicator_col(41), IS_REMU);
        assert_eq!(category_to_indicator_col(42), IS_PADDING);
    }

    #[test]
    #[should_panic(expected = "category 43 >= 43")]
    fn test_category_to_indicator_col_out_of_range() {
        let _ = category_to_indicator_col(43);
    }

    #[test]
    fn test_helper_columns() {
        assert_eq!(COL_HELPER_A_BASE, 65);
        assert_eq!(COL_HELPER_B_BASE, 69);
        assert_eq!(COL_HELPER_B_BASE + WORD_LIMB_COUNT, 73);
    }

    #[test]
    fn test_auxiliary_columns() {
        assert_eq!(COL_TAKEN, 73);
        assert_eq!(COL_MEM_ADDR_BASE, 74);
        assert_eq!(COL_SYSCALL_ID, 78);
        assert_eq!(ECALL_DISPATCH_NUM_COLUMNS, 1);
        assert_eq!(COL_PC_CARRY_FLAG_BASE, 79);
    }

    #[test]
    fn test_m_extension_columns() {
        // v3.5：M 扩展算术约束 witness 列布局（col 81-131）
        assert_eq!(MUL_CARRY_COUNT, 7);
        assert_eq!(COL_MUL_CARRY_LO_BASE, 81);
        assert_eq!(COL_MUL_CARRY_HI0_BASE, 88);
        assert_eq!(COL_MUL_CARRY_HI1_BASE, 95);
        assert_eq!(COL_MUL_CARRY_HI1_BASE + MUL_CARRY_COUNT, 102); // 95+7=102
        assert_eq!(COL_MUL_HIGH_BASE, 102);
        assert_eq!(COL_ABS_A_BASE, 106);
        assert_eq!(COL_ABS_B_BASE, 110);
        assert_eq!(COL_SIGN_A, 114);
        assert_eq!(COL_SIGN_B, 115);
        assert_eq!(COL_LOW_NONZERO, 116);
        assert_eq!(COL_DIV_QUOT_BASE, 117);
        assert_eq!(COL_DIV_REM_BASE, 121);
        assert_eq!(COL_DIV_IS_SPECIAL, 125);
        assert_eq!(COL_DIV_SIGN_Q, 126);
        assert_eq!(COL_DIV_SIGN_R, 127);
        assert_eq!(COL_MUL_LOW_BASE, 128);
        // M 扩展列结束于 132（最后一个 M 列索引 = 131）
        assert_eq!(COL_MUL_LOW_BASE + WORD_LIMB_COUNT, 132, "M 扩展列结束于 132");
        // V7 预计算 gate 列（132-133，独立新列，非 M 扩展复用）
        assert_eq!(COL_LOAD_BYTE_GATE, 132);
        assert_eq!(COL_LOAD_HALF_GATE, 133);
        // A3 符号位绑定列（134-149，v3.7 新增）
        assert_eq!(COL_SIGN_A_BITS_BASE, 134);
        assert_eq!(COL_SIGN_B_BITS_BASE, 142);
        assert_eq!(COL_SIGN_A_BITS_COUNT, 8);
        assert_eq!(COL_SIGN_B_BITS_COUNT, 8);
        // A6 指令字解码列（150-181，v3.8 新增）
        assert_eq!(COL_INSTR_WORD_BASE, 150, "A6 InstrWord 起始 col 150");
        assert_eq!(COL_INSTR_BITS_BYTE0_BASE, 154, "A6 InstrBitsByte0 起始 col 154");
        assert_eq!(COL_INSTR_BITS_BYTE1_BASE, 162, "A6 InstrBitsByte1 起始 col 162");
        assert_eq!(COL_INSTR_BITS_BYTE3_BASE, 170, "A6 InstrBitsByte3 起始 col 170");
        assert_eq!(COL_INSTR_BITS_COUNT, 8, "A6 每 byte 8 bit");
        assert_eq!(COL_IMM_FIELD_BASE, 178, "A6 ImmField 起始 col 178");
        // A1/A4 HelperA carry + half 列（182-184，v3.9 新增）
        assert_eq!(COL_HELPER_A_CARRY_BASE, 182, "A1 HelperA carry 起始 col 182");
        assert_eq!(COL_HELPER_A_HALF, 184, "A4 HelperA_half col 184");
        // v3.9 总列数 = v3.8(182) + A1/A4(3) = 185
        assert_eq!(NUM_COLUMNS, 185, "v3.9 总列数 = 185");
        // A1/A4 列结束于 185（最后一个列索引 = 184）
        assert_eq!(COL_HELPER_A_HALF + 1, NUM_COLUMNS, "A1/A4 列结束于 185");
    }

    #[test]
    fn test_v7_load_extension_columns() {
        // V7 修复：Load 扩展约束 witness 列（复用 M 扩展列，仅 Load 行非 0）
        assert_eq!(COL_IS_LOAD_BYTE, 81, "复用 MulCarryLo[0]");
        assert_eq!(COL_IS_LOAD_HALF, 82, "复用 MulCarryLo[1]");
        assert_eq!(COL_IS_LOAD_SIGN, 83, "复用 MulCarryLo[2]");
        assert_eq!(COL_SIGN_BIT, 84, "复用 MulCarryLo[3]");
        assert_eq!(COL_LOAD_BITS_BASE, 85, "复用 MulCarryLo[4..6]+MulCarryHi0[0..4]");
        assert_eq!(COL_LOAD_BITS_COUNT, 8, "8 个 binary bit");
        // LOAD_BITS 范围 85-92，不超过 MulCarryHi0 范围（88-94）
        assert_eq!(COL_LOAD_BITS_BASE + COL_LOAD_BITS_COUNT, 93);
        // V7 列全部在 M 扩展列范围 [81, 132) 内（复用，不新增列）
        assert!(COL_IS_LOAD_BYTE >= COL_MUL_CARRY_LO_BASE);
        assert!(COL_LOAD_BITS_BASE + COL_LOAD_BITS_COUNT <= NUM_COLUMNS);
    }
}
