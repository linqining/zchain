//! ZKVM ISA 执行引擎（Phase 3 — Task 3.1-3.3 实现）。
//!
//! 本模块提供：
//! - [`Instruction`] 枚举（RV32I 全部指令 + ECALL/EBREAK/FENCE）
//! - [`decode`] — RV32I 指令解码器（拒绝 compressed 指令）
//! - [`execute`] — 单步执行，返回 [`crate::trace::StepLog`]
//!
//! 子模块：
//! - [`state`] — VM 状态 + 内存模型 + ELF 加载
//! - [`executor`] — 执行循环 + syscall 分派

pub mod executor;
pub mod state;

use crate::error::ZkvmError;

// ===========================================================================
// Instruction 枚举（SubTask 3.1.1）
// ===========================================================================

/// RV32I 解码后的指令（覆盖全部 RV32I + ECALL/EBREAK/FENCE）。
///
/// 共 40 个 variant，按 RISC-V 指令格式分组：
/// - U-type：高位立即数（LUI / AUIPC）
/// - J-type：跳转（JAL）
/// - I-type 跳转：JALR
/// - B-type：条件分支（BEQ / BNE / BLT / BGE / BLTU / BGEU）
/// - I-type Load：LB / LH / LW / LBU / LHU
/// - S-type Store：SB / SH / SW
/// - I-type OP-IMM：ADDI / SLTI / SLTIU / XORI / ORI / ANDI / SLLI / SRLI / SRAI
/// - R-type OP：ADD / SUB / SLL / SLT / SLTU / XOR / SRL / SRA / OR / AND
/// - SYSTEM/MISC：FENCE / ECALL / EBREAK
///
/// # 立即数编码
///
/// `imm` 字段统一以 `u32` 存储符号扩展后的值（two's complement）。
/// 例如 `ADDI x1, x0, -1` 的 `imm = 0xFFFFFFFF`。
///
/// # 移位量
///
/// `shamt` 为 5-bit 无符号移位量（0-31），仅用于 SLLI / SRLI / SRAI。
/// R-type 移位指令（SLL / SRL / SRA）使用 `rs2` 低 5 位作为移位量。
///
/// # 寄存器索引
///
/// `rd` / `rs1` / `rs2` 为 `u8`（0-31）。`x0`（zero 寄存器）的处理在
/// [`execute`] 中统一拦截：写 `x0` 丢弃，读 `x0` 返回 0。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    // ===== U-type：高位立即数 =====
    /// LUI rd, imm —— Load Upper Immediate（imm 已左移 12 位并符号扩展）
    Lui {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 立即数（已符号扩展，左移 12 位后的值）
        imm: u32,
    },
    /// AUIPC rd, imm —— Add Upper Immediate to PC（imm 已左移 12 位并符号扩展）
    Auipc {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 立即数（已符号扩展，左移 12 位后的值）
        imm: u32,
    },

    // ===== J-type / I-type 跳转 =====
    /// JAL rd, imm —— Jump and Link（imm 符号扩展，目标 = PC + imm）
    Jal {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 立即数（已符号扩展）
        imm: u32,
    },
    /// JALR rd, rs1, imm —— Jump and Link Register（目标 = (rs1 + imm) & !1）
    Jalr {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 立即数（已符号扩展）
        imm: u32,
    },

    // ===== B-type：条件分支 =====
    /// BEQ rs1, rs2, imm —— Branch if Equal
    Beq {
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
        /// 分支偏移（已符号扩展）
        imm: u32,
    },
    /// BNE rs1, rs2, imm —— Branch if Not Equal
    Bne {
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
        /// 分支偏移（已符号扩展）
        imm: u32,
    },
    /// BLT rs1, rs2, imm —— Branch if Less Than (signed)
    Blt {
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
        /// 分支偏移（已符号扩展）
        imm: u32,
    },
    /// BGE rs1, rs2, imm —— Branch if Greater or Equal (signed)
    Bge {
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
        /// 分支偏移（已符号扩展）
        imm: u32,
    },
    /// BLTU rs1, rs2, imm —— Branch if Less Than Unsigned
    Bltu {
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
        /// 分支偏移（已符号扩展）
        imm: u32,
    },
    /// BGEU rs1, rs2, imm —— Branch if Greater or Equal Unsigned
    Bgeu {
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
        /// 分支偏移（已符号扩展）
        imm: u32,
    },

    // ===== I-type Load =====
    /// LB rd, rs1, imm —— Load Byte (sign-extended)
    Lb {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 基址寄存器（0-31）
        rs1: u8,
        /// 地址偏移（已符号扩展）
        imm: u32,
    },
    /// LH rd, rs1, imm —— Load Halfword (sign-extended)
    Lh {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 基址寄存器（0-31）
        rs1: u8,
        /// 地址偏移（已符号扩展）
        imm: u32,
    },
    /// LW rd, rs1, imm —— Load Word
    Lw {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 基址寄存器（0-31）
        rs1: u8,
        /// 地址偏移（已符号扩展）
        imm: u32,
    },
    /// LBU rd, rs1, imm —— Load Byte Unsigned (zero-extended)
    Lbu {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 基址寄存器（0-31）
        rs1: u8,
        /// 地址偏移（已符号扩展）
        imm: u32,
    },
    /// LHU rd, rs1, imm —— Load Halfword Unsigned (zero-extended)
    Lhu {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 基址寄存器（0-31）
        rs1: u8,
        /// 地址偏移（已符号扩展）
        imm: u32,
    },

    // ===== S-type Store =====
    /// SB rs1, rs2, imm —— Store Byte
    Sb {
        /// 基址寄存器（0-31）
        rs1: u8,
        /// 数据寄存器（0-31）
        rs2: u8,
        /// 地址偏移（已符号扩展）
        imm: u32,
    },
    /// SH rs1, rs2, imm —— Store Halfword
    Sh {
        /// 基址寄存器（0-31）
        rs1: u8,
        /// 数据寄存器（0-31）
        rs2: u8,
        /// 地址偏移（已符号扩展）
        imm: u32,
    },
    /// SW rs1, rs2, imm —— Store Word
    Sw {
        /// 基址寄存器（0-31）
        rs1: u8,
        /// 数据寄存器（0-31）
        rs2: u8,
        /// 地址偏移（已符号扩展）
        imm: u32,
    },

    // ===== I-type OP-IMM =====
    /// ADDI rd, rs1, imm —— Add Immediate
    Addi {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 立即数（已符号扩展）
        imm: u32,
    },
    /// SLTI rd, rs1, imm —— Set Less Than Immediate (signed)
    Slti {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 立即数（已符号扩展）
        imm: u32,
    },
    /// SLTIU rd, rs1, imm —— Set Less Than Immediate Unsigned
    Sltiu {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 立即数（已符号扩展）
        imm: u32,
    },
    /// XORI rd, rs1, imm —— XOR Immediate
    Xori {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 立即数（已符号扩展）
        imm: u32,
    },
    /// ORI rd, rs1, imm —— OR Immediate
    Ori {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 立即数（已符号扩展）
        imm: u32,
    },
    /// ANDI rd, rs1, imm —— AND Immediate
    Andi {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 立即数（已符号扩展）
        imm: u32,
    },
    /// SLLI rd, rs1, shamt —— Shift Left Logical Immediate
    Slli {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 移位量（0-31）
        shamt: u8,
    },
    /// SRLI rd, rs1, shamt —— Shift Right Logical Immediate
    Srli {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 移位量（0-31）
        shamt: u8,
    },
    /// SRAI rd, rs1, shamt —— Shift Right Arithmetic Immediate
    Srai {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 移位量（0-31）
        shamt: u8,
    },

    // ===== R-type OP =====
    /// ADD rd, rs1, rs2
    Add {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// SUB rd, rs1, rs2
    Sub {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// SLL rd, rs1, rs2 —— Shift Left Logical
    Sll {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31，低 5 位为移位量）
        rs2: u8,
    },
    /// SLT rd, rs1, rs2 —— Set Less Than (signed)
    Slt {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// SLTU rd, rs1, rs2 —— Set Less Than Unsigned
    Sltu {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// XOR rd, rs1, rs2
    Xor {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// SRL rd, rs1, rs2 —— Shift Right Logical
    Srl {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31，低 5 位为移位量）
        rs2: u8,
    },
    /// SRA rd, rs1, rs2 —— Shift Right Arithmetic
    Sra {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31，低 5 位为移位量）
        rs2: u8,
    },
    /// OR rd, rs1, rs2
    Or {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// AND rd, rs1, rs2
    And {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },

    // ===== R-type M 扩展（funct7=0x01）=====
    /// MUL rd, rs1, rs2 —— 低 32 位乘法
    Mul {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// MULH rd, rs1, rs2 —— 有符号×有符号高 32 位
    Mulh {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// MULHSU rd, rs1, rs2 —— 有符号×无符号高 32 位
    Mulhsu {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// MULHU rd, rs1, rs2 —— 无符号×无符号高 32 位
    Mulhu {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// DIV rd, rs1, rs2 —— 有符号除法
    Div {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// DIVU rd, rs1, rs2 —— 无符号除法
    Divu {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// REM rd, rs1, rs2 —— 有符号取余
    Rem {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },
    /// REMU rd, rs1, rs2 —— 无符号取余
    Remu {
        /// 目标寄存器（0-31）
        rd: u8,
        /// 源寄存器 1（0-31）
        rs1: u8,
        /// 源寄存器 2（0-31）
        rs2: u8,
    },

    // ===== SYSTEM / MISC =====
    /// FENCE —— 内存屏障（ZKVM 中作为 NOP，无副作用）
    Fence,
    /// ECALL —— 触发 syscall 分派（基于 a7 寄存器）
    Ecall,
    /// EBREAK —— 断点（ZKVM 中终止执行，视为 halt）
    Ebreak,
}

// ===========================================================================
// decode / execute（SubTask 3.1.2-3.1.4 — Step D 实现）
// ===========================================================================

/// 12-bit 立即数符号扩展到 u32。
fn sign_extend_12(imm12: u32) -> u32 {
    if imm12 & 0x800 != 0 {
        imm12 | 0xFFFFF000
    } else {
        imm12
    }
}

/// 13-bit 立即数符号扩展到 u32（B-type：bit[12] 是符号位，bit[0]=0）。
fn sign_extend_13(imm13: u32) -> u32 {
    if imm13 & 0x1000 != 0 {
        imm13 | 0xFFFFE000
    } else {
        imm13
    }
}

/// 解码 I-type 立即数（bits[31:20]，12-bit 符号扩展）。
fn decode_i_imm(word: u32) -> u32 {
    sign_extend_12((word >> 20) & 0xFFF)
}

/// 解码 S-type 立即数（bits[31:25] + bits[11:7]，12-bit 符号扩展）。
fn decode_s_imm(word: u32) -> u32 {
    let imm = (((word >> 25) & 0x7F) << 5) | ((word >> 7) & 0x1F);
    sign_extend_12(imm)
}

/// 解码 B-type 立即数（13-bit，bit[0]=0，bit[12] 是符号位）。
///
/// B-type 立即数为 13 位有符号值（imm[12:0]，imm[0]=0）。
/// 符号位是 imm[12]（bit 12），**不是** imm[11]（bit 11）。
/// 使用 `sign_extend_13` 而非 `sign_extend_12`，否则正偏移 ≥ 2048
/// （bit 11 set）会被错误地当作负数。
fn decode_b_imm(word: u32) -> u32 {
    let imm = (((word >> 31) & 0x1) << 12)
        | (((word >> 7) & 0x1) << 11)
        | (((word >> 25) & 0x3F) << 5)
        | (((word >> 8) & 0xF) << 1);
    sign_extend_13(imm)
}

/// 解码 U-type 立即数（bits[31:12]，已左移 12 位）。
fn decode_u_imm(word: u32) -> u32 {
    word & 0xFFFFF000
}

/// 解码 J-type 立即数（21-bit，bit[0]=0，20-bit 符号扩展）。
fn decode_j_imm(word: u32) -> u32 {
    let imm = (((word >> 31) & 0x1) << 20)
        | (((word >> 12) & 0xFF) << 12)
        | (((word >> 20) & 0x1) << 11)
        | (((word >> 21) & 0x3FF) << 1);
    if imm & 0x100000 != 0 {
        imm | 0xFFE00000
    } else {
        imm
    }
}

/// RV32I 指令解码器（SubTask 3.1.2）。
///
/// 将 32-bit 指令 word 解码为 [`Instruction`]。拒绝 compressed 指令
/// （bits[1:0] != 0b11）和非 RV32I opcode（浮点 / atomics / SIMD）。
///
/// # Errors
/// - `ZkvmError::UnsupportedInstruction` — compressed 指令或非法 opcode/funct3/funct7
#[allow(clippy::missing_errors_doc)]
pub fn decode(word: u32) -> Result<Instruction, ZkvmError> {
    // 拒绝 compressed 指令
    if word & 0x3 != 0b11 {
        return Err(ZkvmError::UnsupportedInstruction(format!(
            "compressed instruction: 0x{word:08x} (bits[1:0] != 0b11)"
        )));
    }

    let opcode = word & 0x7F;
    let rd = ((word >> 7) & 0x1F) as u8;
    let rs1 = ((word >> 15) & 0x1F) as u8;
    let rs2 = ((word >> 20) & 0x1F) as u8;
    let funct3 = ((word >> 12) & 0x7) as u8;
    let funct7 = ((word >> 25) & 0x7F) as u8;

    match opcode {
        // ===== U-type =====
        0x37 => Ok(Instruction::Lui {
            rd,
            imm: decode_u_imm(word),
        }),
        0x17 => Ok(Instruction::Auipc {
            rd,
            imm: decode_u_imm(word),
        }),

        // ===== J-type =====
        0x6F => Ok(Instruction::Jal {
            rd,
            imm: decode_j_imm(word),
        }),

        // ===== I-type 跳转 =====
        0x67 => {
            if funct3 != 0 {
                return Err(ZkvmError::UnsupportedInstruction(format!(
                    "JALR funct3={funct3} (expected 0)"
                )));
            }
            Ok(Instruction::Jalr {
                rd,
                rs1,
                imm: decode_i_imm(word),
            })
        }

        // ===== B-type 条件分支 =====
        0x63 => {
            let imm = decode_b_imm(word);
            match funct3 {
                0 => Ok(Instruction::Beq { rs1, rs2, imm }),
                1 => Ok(Instruction::Bne { rs1, rs2, imm }),
                4 => Ok(Instruction::Blt { rs1, rs2, imm }),
                5 => Ok(Instruction::Bge { rs1, rs2, imm }),
                6 => Ok(Instruction::Bltu { rs1, rs2, imm }),
                7 => Ok(Instruction::Bgeu { rs1, rs2, imm }),
                _ => Err(ZkvmError::UnsupportedInstruction(format!(
                    "branch funct3={funct3}"
                ))),
            }
        }

        // ===== I-type Load =====
        0x03 => {
            let imm = decode_i_imm(word);
            match funct3 {
                0 => Ok(Instruction::Lb { rd, rs1, imm }),
                1 => Ok(Instruction::Lh { rd, rs1, imm }),
                2 => Ok(Instruction::Lw { rd, rs1, imm }),
                4 => Ok(Instruction::Lbu { rd, rs1, imm }),
                5 => Ok(Instruction::Lhu { rd, rs1, imm }),
                _ => Err(ZkvmError::UnsupportedInstruction(format!(
                    "load funct3={funct3}"
                ))),
            }
        }

        // ===== S-type Store =====
        0x23 => {
            let imm = decode_s_imm(word);
            match funct3 {
                0 => Ok(Instruction::Sb { rs1, rs2, imm }),
                1 => Ok(Instruction::Sh { rs1, rs2, imm }),
                2 => Ok(Instruction::Sw { rs1, rs2, imm }),
                _ => Err(ZkvmError::UnsupportedInstruction(format!(
                    "store funct3={funct3}"
                ))),
            }
        }

        // ===== I-type OP-IMM =====
        0x13 => {
            let imm = decode_i_imm(word);
            match funct3 {
                0 => Ok(Instruction::Addi { rd, rs1, imm }),
                2 => Ok(Instruction::Slti { rd, rs1, imm }),
                3 => Ok(Instruction::Sltiu { rd, rs1, imm }),
                4 => Ok(Instruction::Xori { rd, rs1, imm }),
                6 => Ok(Instruction::Ori { rd, rs1, imm }),
                7 => Ok(Instruction::Andi { rd, rs1, imm }),
                1 => {
                    // SLLI：funct7 必须为 0，shamt = rs2 字段
                    if funct7 != 0 {
                        return Err(ZkvmError::UnsupportedInstruction(format!(
                            "SLLI funct7={funct7} (expected 0)"
                        )));
                    }
                    Ok(Instruction::Slli {
                        rd,
                        rs1,
                        shamt: rs2,
                    })
                }
                5 => {
                    // SRLI（funct7=0）/ SRAI（funct7=0x20）
                    match funct7 {
                        0 => Ok(Instruction::Srli {
                            rd,
                            rs1,
                            shamt: rs2,
                        }),
                        0x20 => Ok(Instruction::Srai {
                            rd,
                            rs1,
                            shamt: rs2,
                        }),
                        _ => Err(ZkvmError::UnsupportedInstruction(format!(
                            "SRLI/SRAI funct7={funct7}"
                        ))),
                    }
                }
                _ => unreachable!(),
            }
        }

        // ===== R-type OP =====
        0x33 => match (funct3, funct7) {
            (0, 0x00) => Ok(Instruction::Add { rd, rs1, rs2 }),
            (0, 0x20) => Ok(Instruction::Sub { rd, rs1, rs2 }),
            (1, 0x00) => Ok(Instruction::Sll { rd, rs1, rs2 }),
            (2, 0x00) => Ok(Instruction::Slt { rd, rs1, rs2 }),
            (3, 0x00) => Ok(Instruction::Sltu { rd, rs1, rs2 }),
            (4, 0x00) => Ok(Instruction::Xor { rd, rs1, rs2 }),
            (5, 0x00) => Ok(Instruction::Srl { rd, rs1, rs2 }),
            (5, 0x20) => Ok(Instruction::Sra { rd, rs1, rs2 }),
            (6, 0x00) => Ok(Instruction::Or { rd, rs1, rs2 }),
            (7, 0x00) => Ok(Instruction::And { rd, rs1, rs2 }),
            // M 扩展（funct7=0x01）
            (0, 0x01) => Ok(Instruction::Mul { rd, rs1, rs2 }),
            (1, 0x01) => Ok(Instruction::Mulh { rd, rs1, rs2 }),
            (2, 0x01) => Ok(Instruction::Mulhsu { rd, rs1, rs2 }),
            (3, 0x01) => Ok(Instruction::Mulhu { rd, rs1, rs2 }),
            (4, 0x01) => Ok(Instruction::Div { rd, rs1, rs2 }),
            (5, 0x01) => Ok(Instruction::Divu { rd, rs1, rs2 }),
            (6, 0x01) => Ok(Instruction::Rem { rd, rs1, rs2 }),
            (7, 0x01) => Ok(Instruction::Remu { rd, rs1, rs2 }),
            _ => Err(ZkvmError::UnsupportedInstruction(format!(
                "R-type funct3={funct3} funct7={funct7}"
            ))),
        },

        // ===== FENCE =====
        0x0F => {
            if funct3 != 0 {
                return Err(ZkvmError::UnsupportedInstruction(format!(
                    "FENCE funct3={funct3} (expected 0; fence.i not supported)"
                )));
            }
            Ok(Instruction::Fence)
        }

        // ===== SYSTEM（ECALL / EBREAK）=====
        0x73 => {
            if funct3 != 0 {
                return Err(ZkvmError::UnsupportedInstruction(format!(
                    "SYSTEM funct3={funct3} (CSR not supported)"
                )));
            }
            // imm[11:0] = bits[31:20]：0x000 = ECALL, 0x001 = EBREAK
            let imm12 = (word >> 20) & 0xFFF;
            match imm12 {
                0x000 => Ok(Instruction::Ecall),
                0x001 => Ok(Instruction::Ebreak),
                _ => Err(ZkvmError::UnsupportedInstruction(format!(
                    "SYSTEM imm12=0x{imm12:03x} (only ECALL/EBREAK supported)"
                ))),
            }
        }

        _ => Err(ZkvmError::UnsupportedInstruction(format!(
            "unknown opcode=0x{opcode:02x} (word=0x{word:08x})"
        ))),
    }
}

/// 单步执行指令（SubTask 3.1.3）。
///
/// 执行 `insn`，修改 `state`（寄存器 / PC / 内存），返回 [`crate::trace::StepLog`]。
///
/// # Errors
/// - `ZkvmError::UnalignedAccess` — 内存访问未对齐
/// - `ZkvmError::UninitializedRead` — 读取未初始化内存
/// - `ZkvmError::OutOfMemory` — 内存分配超 16MB
#[allow(clippy::missing_errors_doc)]
pub fn execute(
    state: &mut state::VmState,
    insn: Instruction,
) -> Result<crate::trace::StepLog, ZkvmError> {
    use crate::trace::{MemAccess, MemOp};

    let pc = state.pc;
    let mut mem_access: alloc::vec::Vec<MemAccess> = alloc::vec![];

    match insn {
        // ===== U-type =====
        Instruction::Lui { rd, imm } => {
            state.write_register(rd, imm);
        }
        Instruction::Auipc { rd, imm } => {
            state.write_register(rd, pc.wrapping_add(imm));
        }

        // ===== J-type =====
        Instruction::Jal { rd, imm } => {
            state.write_register(rd, pc.wrapping_add(4));
            state.pc = pc.wrapping_add(imm);
            return finalize_steplog(pc, insn, state, mem_access);
        }

        // ===== I-type 跳转 =====
        Instruction::Jalr { rd, rs1, imm } => {
            let target = (state.read_register(rs1).wrapping_add(imm)) & !1;
            state.write_register(rd, pc.wrapping_add(4));
            state.pc = target;
            return finalize_steplog(pc, insn, state, mem_access);
        }

        // ===== B-type 条件分支 =====
        Instruction::Beq { rs1, rs2, imm } => {
            if state.read_register(rs1) == state.read_register(rs2) {
                state.pc = pc.wrapping_add(imm);
                return finalize_steplog(pc, insn, state, mem_access);
            }
        }
        Instruction::Bne { rs1, rs2, imm } => {
            if state.read_register(rs1) != state.read_register(rs2) {
                state.pc = pc.wrapping_add(imm);
                return finalize_steplog(pc, insn, state, mem_access);
            }
        }
        Instruction::Blt { rs1, rs2, imm } => {
            let a = state.read_register(rs1) as i32;
            let b = state.read_register(rs2) as i32;
            if a < b {
                state.pc = pc.wrapping_add(imm);
                return finalize_steplog(pc, insn, state, mem_access);
            }
        }
        Instruction::Bge { rs1, rs2, imm } => {
            let a = state.read_register(rs1) as i32;
            let b = state.read_register(rs2) as i32;
            if a >= b {
                state.pc = pc.wrapping_add(imm);
                return finalize_steplog(pc, insn, state, mem_access);
            }
        }
        Instruction::Bltu { rs1, rs2, imm } => {
            if state.read_register(rs1) < state.read_register(rs2) {
                state.pc = pc.wrapping_add(imm);
                return finalize_steplog(pc, insn, state, mem_access);
            }
        }
        Instruction::Bgeu { rs1, rs2, imm } => {
            if state.read_register(rs1) >= state.read_register(rs2) {
                state.pc = pc.wrapping_add(imm);
                return finalize_steplog(pc, insn, state, mem_access);
            }
        }

        // ===== I-type Load =====
        // V7 修复：MemAccess.value 存储**原始值**（raw byte/halfword），而非扩展后值。
        // 扩展值仍写入寄存器；原始值经 Memory AIR logup 验证后，由 CPU AIR 约束推导扩展。
        // 详见 `.trae/documents/poker_zkvm_v7v8_bytelevel_fix_plan.md` §3.2。
        Instruction::Lb { rd, rs1, imm } => {
            let addr = state.read_register(rs1).wrapping_add(imm);
            let raw = state.read_memory_byte(addr)? as u32; // 原始字节（未扩展）
            let val = raw as i8 as i32 as u32; // 符号扩展值（写入 rd）
            state.write_register(rd, val);
            mem_access.push(MemAccess {
                addr,
                op: MemOp::Read,
                value: raw, // V7：存原始值，扩展由 AIR 约束推导
                size: 1,
            });
        }
        Instruction::Lh { rd, rs1, imm } => {
            let addr = state.read_register(rs1).wrapping_add(imm);
            let raw = state.read_memory_halfword(addr)? as u32; // 原始半字（未扩展）
            let val = raw as i16 as i32 as u32; // 符号扩展值（写入 rd）
            state.write_register(rd, val);
            mem_access.push(MemAccess {
                addr,
                op: MemOp::Read,
                value: raw, // V7：存原始值，扩展由 AIR 约束推导
                size: 2,
            });
        }
        Instruction::Lw { rd, rs1, imm } => {
            let addr = state.read_register(rs1).wrapping_add(imm);
            let val = state.read_memory_word(addr)?;
            state.write_register(rd, val);
            mem_access.push(MemAccess {
                addr,
                op: MemOp::Read,
                value: val,
                size: 4,
            });
        }
        Instruction::Lbu { rd, rs1, imm } => {
            let addr = state.read_register(rs1).wrapping_add(imm);
            let val = state.read_memory_byte(addr)? as u32;
            state.write_register(rd, val);
            mem_access.push(MemAccess {
                addr,
                op: MemOp::Read,
                value: val,
                size: 1,
            });
        }
        Instruction::Lhu { rd, rs1, imm } => {
            let addr = state.read_register(rs1).wrapping_add(imm);
            let val = state.read_memory_halfword(addr)? as u32;
            state.write_register(rd, val);
            mem_access.push(MemAccess {
                addr,
                op: MemOp::Read,
                value: val,
                size: 2,
            });
        }

        // ===== S-type Store =====
        Instruction::Sb { rs1, rs2, imm } => {
            let addr = state.read_register(rs1).wrapping_add(imm);
            let val = state.read_register(rs2);
            state.write_memory_byte(addr, val as u8)?;
            mem_access.push(MemAccess {
                addr,
                op: MemOp::Write,
                value: val,
                size: 1,
            });
        }
        Instruction::Sh { rs1, rs2, imm } => {
            let addr = state.read_register(rs1).wrapping_add(imm);
            let val = state.read_register(rs2);
            state.write_memory_halfword(addr, val as u16)?;
            mem_access.push(MemAccess {
                addr,
                op: MemOp::Write,
                value: val,
                size: 2,
            });
        }
        Instruction::Sw { rs1, rs2, imm } => {
            let addr = state.read_register(rs1).wrapping_add(imm);
            let val = state.read_register(rs2);
            state.write_memory_word(addr, val)?;
            mem_access.push(MemAccess {
                addr,
                op: MemOp::Write,
                value: val,
                size: 4,
            });
        }

        // ===== I-type OP-IMM =====
        Instruction::Addi { rd, rs1, imm } => {
            let result = state.read_register(rs1).wrapping_add(imm);
            state.write_register(rd, result);
        }
        Instruction::Slti { rd, rs1, imm } => {
            let a = state.read_register(rs1) as i32;
            let b = imm as i32;
            state.write_register(rd, if a < b { 1 } else { 0 });
        }
        Instruction::Sltiu { rd, rs1, imm } => {
            let a = state.read_register(rs1);
            let b = imm;
            state.write_register(rd, if a < b { 1 } else { 0 });
        }
        Instruction::Xori { rd, rs1, imm } => {
            state.write_register(rd, state.read_register(rs1) ^ imm);
        }
        Instruction::Ori { rd, rs1, imm } => {
            state.write_register(rd, state.read_register(rs1) | imm);
        }
        Instruction::Andi { rd, rs1, imm } => {
            state.write_register(rd, state.read_register(rs1) & imm);
        }
        Instruction::Slli { rd, rs1, shamt } => {
            state.write_register(rd, state.read_register(rs1) << shamt);
        }
        Instruction::Srli { rd, rs1, shamt } => {
            state.write_register(rd, state.read_register(rs1) >> shamt);
        }
        Instruction::Srai { rd, rs1, shamt } => {
            let val = state.read_register(rs1) as i32;
            state.write_register(rd, (val >> shamt) as u32);
        }

        // ===== R-type OP =====
        Instruction::Add { rd, rs1, rs2 } => {
            let result = state
                .read_register(rs1)
                .wrapping_add(state.read_register(rs2));
            state.write_register(rd, result);
        }
        Instruction::Sub { rd, rs1, rs2 } => {
            let result = state
                .read_register(rs1)
                .wrapping_sub(state.read_register(rs2));
            state.write_register(rd, result);
        }
        Instruction::Sll { rd, rs1, rs2 } => {
            let shamt = state.read_register(rs2) & 0x1F;
            state.write_register(rd, state.read_register(rs1) << shamt);
        }
        Instruction::Slt { rd, rs1, rs2 } => {
            let a = state.read_register(rs1) as i32;
            let b = state.read_register(rs2) as i32;
            state.write_register(rd, if a < b { 1 } else { 0 });
        }
        Instruction::Sltu { rd, rs1, rs2 } => {
            let a = state.read_register(rs1);
            let b = state.read_register(rs2);
            state.write_register(rd, if a < b { 1 } else { 0 });
        }
        Instruction::Xor { rd, rs1, rs2 } => {
            state.write_register(rd, state.read_register(rs1) ^ state.read_register(rs2));
        }
        Instruction::Srl { rd, rs1, rs2 } => {
            let shamt = state.read_register(rs2) & 0x1F;
            state.write_register(rd, state.read_register(rs1) >> shamt);
        }
        Instruction::Sra { rd, rs1, rs2 } => {
            let shamt = state.read_register(rs2) & 0x1F;
            let val = state.read_register(rs1) as i32;
            state.write_register(rd, (val >> shamt) as u32);
        }
        Instruction::Or { rd, rs1, rs2 } => {
            state.write_register(rd, state.read_register(rs1) | state.read_register(rs2));
        }
        Instruction::And { rd, rs1, rs2 } => {
            state.write_register(rd, state.read_register(rs1) & state.read_register(rs2));
        }

        // ===== R-type M 扩展 =====
        Instruction::Mul { rd, rs1, rs2 } => {
            let a = state.read_register(rs1) as u64;
            let b = state.read_register(rs2) as u64;
            state.write_register(rd, (a * b) as u32);
        }
        Instruction::Mulh { rd, rs1, rs2 } => {
            let a = state.read_register(rs1) as i32 as i64;
            let b = state.read_register(rs2) as i32 as i64;
            state.write_register(rd, ((a * b) >> 32) as u32);
        }
        Instruction::Mulhsu { rd, rs1, rs2 } => {
            let a = state.read_register(rs1) as i32 as i64;
            let b = state.read_register(rs2) as u64 as i64;
            state.write_register(rd, ((a * b) >> 32) as u32);
        }
        Instruction::Mulhu { rd, rs1, rs2 } => {
            let a = state.read_register(rs1) as u64;
            let b = state.read_register(rs2) as u64;
            state.write_register(rd, ((a * b) >> 32) as u32);
        }
        Instruction::Div { rd, rs1, rs2 } => {
            let a = state.read_register(rs1) as i32;
            let b = state.read_register(rs2) as i32;
            let result = if b == 0 {
                -1i32
            } else if a == i32::MIN && b == -1 {
                i32::MIN
            } else {
                a / b
            };
            state.write_register(rd, result as u32);
        }
        Instruction::Divu { rd, rs1, rs2 } => {
            let a = state.read_register(rs1);
            let b = state.read_register(rs2);
            let result = a.checked_div(b).unwrap_or(u32::MAX);
            state.write_register(rd, result);
        }
        Instruction::Rem { rd, rs1, rs2 } => {
            let a = state.read_register(rs1) as i32;
            let b = state.read_register(rs2) as i32;
            let result = if b == 0 {
                a
            } else if a == i32::MIN && b == -1 {
                0
            } else {
                a % b
            };
            state.write_register(rd, result as u32);
        }
        Instruction::Remu { rd, rs1, rs2 } => {
            let a = state.read_register(rs1);
            let b = state.read_register(rs2);
            let result = if b == 0 { a } else { a % b };
            state.write_register(rd, result);
        }

        // ===== SYSTEM / MISC =====
        Instruction::Fence => {
            // NOP — 无副作用
        }
        Instruction::Ecall => {
            // 仅 PC+4，syscall 分派由 executor 循环处理
        }
        Instruction::Ebreak => {
            // 仅 PC+4，视为 halt 信号由 executor 处理
        }
    }

    // 非 branch/jump 指令：PC += 4
    state.pc = pc.wrapping_add(4);
    finalize_steplog(pc, insn, state, mem_access)
}

/// 组装 StepLog 返回值。
fn finalize_steplog(
    pc: u32,
    insn: Instruction,
    state: &state::VmState,
    mem_access: alloc::vec::Vec<crate::trace::MemAccess>,
) -> Result<crate::trace::StepLog, ZkvmError> {
    Ok(crate::trace::StepLog {
        pc,
        instruction: insn,
        registers: state.registers,
        mem_access,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_lui_constructible() {
        let insn = Instruction::Lui { rd: 1, imm: 0x1000 };
        let debug = format!("{insn:?}");
        assert!(debug.contains("Lui"));
        assert!(debug.contains("rd: 1"));
    }

    #[test]
    fn test_instruction_clone_eq() {
        let a = Instruction::Add {
            rd: 1,
            rs1: 2,
            rs2: 3,
        };
        let b = a.clone();
        assert_eq!(a, b);
        let c = Instruction::Add {
            rd: 1,
            rs1: 2,
            rs2: 4,
        };
        assert_ne!(a, c);
    }

    #[test]
    fn test_instruction_ecall_ebreak_fence_constructible() {
        let _ = Instruction::Ecall;
        let _ = Instruction::Ebreak;
        let _ = Instruction::Fence;
        assert_eq!(Instruction::Ecall, Instruction::Ecall);
        assert_eq!(Instruction::Ebreak, Instruction::Ebreak);
        assert_eq!(Instruction::Fence, Instruction::Fence);
    }

    #[test]
    fn test_instruction_variant_count() {
        // 确保覆盖全部 RV32I + ECALL + EBREAK + FENCE = 40 variants
        // U-type(2) + J-type/I-type跳转(2) + B-type(6) + Load(5) + Store(3)
        // + OP-IMM(9) + OP(10) + SYSTEM/MISC(3) = 40
        let variants: Vec<Instruction> = vec![
            // U-type (2)
            Instruction::Lui { rd: 0, imm: 0 },
            Instruction::Auipc { rd: 0, imm: 0 },
            // J-type / I-type 跳转 (2)
            Instruction::Jal { rd: 0, imm: 0 },
            Instruction::Jalr {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            // B-type (6)
            Instruction::Beq {
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            Instruction::Bne {
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            Instruction::Blt {
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            Instruction::Bge {
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            Instruction::Bltu {
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            Instruction::Bgeu {
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            // Load (5)
            Instruction::Lb {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            Instruction::Lh {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            Instruction::Lw {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            Instruction::Lbu {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            Instruction::Lhu {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            // Store (3)
            Instruction::Sb {
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            Instruction::Sh {
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            Instruction::Sw {
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            // OP-IMM (9)
            Instruction::Addi {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            Instruction::Slti {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            Instruction::Sltiu {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            Instruction::Xori {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            Instruction::Ori {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            Instruction::Andi {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            Instruction::Slli {
                rd: 0,
                rs1: 0,
                shamt: 0,
            },
            Instruction::Srli {
                rd: 0,
                rs1: 0,
                shamt: 0,
            },
            Instruction::Srai {
                rd: 0,
                rs1: 0,
                shamt: 0,
            },
            // OP (10)
            Instruction::Add {
                rd: 0,
                rs1: 0,
                rs2: 0,
            },
            Instruction::Sub {
                rd: 0,
                rs1: 0,
                rs2: 0,
            },
            Instruction::Sll {
                rd: 0,
                rs1: 0,
                rs2: 0,
            },
            Instruction::Slt {
                rd: 0,
                rs1: 0,
                rs2: 0,
            },
            Instruction::Sltu {
                rd: 0,
                rs1: 0,
                rs2: 0,
            },
            Instruction::Xor {
                rd: 0,
                rs1: 0,
                rs2: 0,
            },
            Instruction::Srl {
                rd: 0,
                rs1: 0,
                rs2: 0,
            },
            Instruction::Sra {
                rd: 0,
                rs1: 0,
                rs2: 0,
            },
            Instruction::Or {
                rd: 0,
                rs1: 0,
                rs2: 0,
            },
            Instruction::And {
                rd: 0,
                rs1: 0,
                rs2: 0,
            },
            // SYSTEM / MISC (3)
            Instruction::Fence,
            Instruction::Ecall,
            Instruction::Ebreak,
            // M 扩展（8）
            Instruction::Mul { rd: 0, rs1: 0, rs2: 0 },
            Instruction::Mulh { rd: 0, rs1: 0, rs2: 0 },
            Instruction::Mulhsu { rd: 0, rs1: 0, rs2: 0 },
            Instruction::Mulhu { rd: 0, rs1: 0, rs2: 0 },
            Instruction::Div { rd: 0, rs1: 0, rs2: 0 },
            Instruction::Divu { rd: 0, rs1: 0, rs2: 0 },
            Instruction::Rem { rd: 0, rs1: 0, rs2: 0 },
            Instruction::Remu { rd: 0, rs1: 0, rs2: 0 },
        ];
        assert_eq!(
            variants.len(),
            48,
            "RV32I + ECALL/EBREAK/FENCE + M 扩展 = 48 variants"
        );
    }

    // ===== Step D: decode 测试 =====

    /// 辅助：编码 U-type 指令
    fn encode_u(opcode: u32, rd: u8, imm20: u32) -> u32 {
        ((imm20 & 0xFFFFF) << 12) | ((rd as u32) << 7) | opcode
    }

    /// 辅助：编码 I-type 指令
    fn encode_i(opcode: u32, funct3: u8, rd: u8, rs1: u8, imm12: u32) -> u32 {
        ((imm12 & 0xFFF) << 20)
            | ((rs1 as u32) << 15)
            | ((funct3 as u32) << 12)
            | ((rd as u32) << 7)
            | opcode
    }

    /// 辅助：编码 S-type 指令
    fn encode_s(opcode: u32, funct3: u8, rs1: u8, rs2: u8, imm12: u32) -> u32 {
        let imm_hi = (imm12 >> 5) & 0x7F;
        let imm_lo = imm12 & 0x1F;
        (imm_hi << 25)
            | ((rs2 as u32) << 20)
            | ((rs1 as u32) << 15)
            | ((funct3 as u32) << 12)
            | (imm_lo << 7)
            | opcode
    }

    /// 辅助：编码 B-type 指令
    fn encode_b(opcode: u32, funct3: u8, rs1: u8, rs2: u8, imm13: u32) -> u32 {
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

    /// 辅助：编码 J-type 指令
    fn encode_j(opcode: u32, rd: u8, imm21: u32) -> u32 {
        let b20 = (imm21 >> 20) & 0x1;
        let b10_1 = (imm21 >> 1) & 0x3FF;
        let b11 = (imm21 >> 11) & 0x1;
        let b19_12 = (imm21 >> 12) & 0xFF;
        (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | ((rd as u32) << 7) | opcode
    }

    /// 辅助：编码 R-type 指令
    fn encode_r(opcode: u32, funct3: u8, funct7: u8, rd: u8, rs1: u8, rs2: u8) -> u32 {
        ((funct7 as u32) << 25)
            | ((rs2 as u32) << 20)
            | ((rs1 as u32) << 15)
            | ((funct3 as u32) << 12)
            | ((rd as u32) << 7)
            | opcode
    }

    #[test]
    fn test_decode_lui() {
        // LUI x1, 0x1000 → imm = 0x1000 << 12 = 0x01000000
        let word = encode_u(0x37, 1, 0x1000);
        let insn = decode(word).unwrap();
        assert_eq!(
            insn,
            Instruction::Lui {
                rd: 1,
                imm: 0x01000000
            }
        );
    }

    #[test]
    fn test_decode_auipc() {
        let word = encode_u(0x17, 2, 0x1000);
        let insn = decode(word).unwrap();
        assert_eq!(
            insn,
            Instruction::Auipc {
                rd: 2,
                imm: 0x01000000
            }
        );
    }

    #[test]
    fn test_decode_jal() {
        // JAL x1, 8
        let word = encode_j(0x6F, 1, 8);
        let insn = decode(word).unwrap();
        assert_eq!(insn, Instruction::Jal { rd: 1, imm: 8 });
    }

    #[test]
    fn test_decode_jalr() {
        // JALR x1, x2, 4
        let word = encode_i(0x67, 0, 1, 2, 4);
        let insn = decode(word).unwrap();
        assert_eq!(
            insn,
            Instruction::Jalr {
                rd: 1,
                rs1: 2,
                imm: 4
            }
        );
    }

    #[test]
    fn test_decode_beq() {
        // BEQ x1, x2, 8
        let word = encode_b(0x63, 0, 1, 2, 8);
        let insn = decode(word).unwrap();
        assert_eq!(
            insn,
            Instruction::Beq {
                rs1: 1,
                rs2: 2,
                imm: 8
            }
        );
    }

    #[test]
    fn test_decode_branch_all_types() {
        let cases = [
            (
                0u8,
                Instruction::Beq {
                    rs1: 1,
                    rs2: 2,
                    imm: 8,
                },
            ),
            (
                1,
                Instruction::Bne {
                    rs1: 1,
                    rs2: 2,
                    imm: 8,
                },
            ),
            (
                4,
                Instruction::Blt {
                    rs1: 1,
                    rs2: 2,
                    imm: 8,
                },
            ),
            (
                5,
                Instruction::Bge {
                    rs1: 1,
                    rs2: 2,
                    imm: 8,
                },
            ),
            (
                6,
                Instruction::Bltu {
                    rs1: 1,
                    rs2: 2,
                    imm: 8,
                },
            ),
            (
                7,
                Instruction::Bgeu {
                    rs1: 1,
                    rs2: 2,
                    imm: 8,
                },
            ),
        ];
        for (funct3, expected) in cases {
            let word = encode_b(0x63, funct3, 1, 2, 8);
            let insn = decode(word).unwrap();
            assert_eq!(insn, expected, "funct3={funct3}");
        }
    }

    #[test]
    fn test_decode_b_imm_large_positive() {
        // B-type 立即数为 13-bit 有符号值（imm[12:0]，imm[0]=0）。
        // 符号位是 imm[12]（bit 12），**不是** imm[11]（bit 11）。
        // 当正偏移 ≥ 2048（bit 11 set，bit 12 clear）时，sign_extend_12
        // 会错误地将其当作负数。sign_extend_13 检查 bit 12 才正确。
        //
        // B-type 范围：-4096..=+4094（偶数）
        //   正：imm[12]=0, 范围 0..=0xFFE（0..=4094）
        //   负：imm[12]=1, 范围 0x1000..=0x1FFE（-4096..=-2）

        // 0x8C8: bit12=0, bit11=1 → 正偏移 +2248（实际崩溃用例）
        let word = encode_b(0x63, 0, 10, 0, 0x8C8);
        let insn = decode(word).unwrap();
        assert_eq!(
            insn,
            Instruction::Beq {
                rs1: 10,
                rs2: 0,
                imm: 0x8C8,
            },
            "large positive B-type offset (bit11 set, bit12 clear) must be positive"
        );

        // 0x0FFE: 最大正偏移 +4094（bit12=0, all lower bits set）
        let word2 = encode_b(0x63, 0, 10, 0, 0x0FFE);
        let insn2 = decode(word2).unwrap();
        assert_eq!(
            insn2,
            Instruction::Beq {
                rs1: 10,
                rs2: 0,
                imm: 0x0FFE,
            },
            "max positive offset +0xFFE must be positive"
        );

        // 0x1000: 最小负偏移 -4096（bit12=1, rest=0）
        let word3 = encode_b(0x63, 0, 10, 0, 0x1000);
        let insn3 = decode(word3).unwrap();
        assert_eq!(
            insn3,
            Instruction::Beq {
                rs1: 10,
                rs2: 0,
                imm: (-4096i32 as u32),
            },
            "offset 0x1000 (bit12 set) must be -4096"
        );

        // 0x1FFE: 最大负偏移 -2（bit12=1, all lower bits set）
        let word4 = encode_b(0x63, 0, 10, 0, 0x1FFE);
        let insn4 = decode(word4).unwrap();
        assert_eq!(
            insn4,
            Instruction::Beq {
                rs1: 10,
                rs2: 0,
                imm: (-2i32 as u32),
            },
            "offset 0x1FFE must be -2"
        );

        // -2048: 常见负偏移
        let word5 = encode_b(0x63, 0, 10, 0, (-2048i32 as u32) & 0x1FFF);
        let insn5 = decode(word5).unwrap();
        assert_eq!(
            insn5,
            Instruction::Beq {
                rs1: 10,
                rs2: 0,
                imm: (-2048i32 as u32),
            },
            "offset -2048 must be negative"
        );

        // -4: 小负偏移
        let word6 = encode_b(0x63, 0, 10, 0, (-4i32 as u32) & 0x1FFF);
        let insn6 = decode(word6).unwrap();
        assert_eq!(
            insn6,
            Instruction::Beq {
                rs1: 10,
                rs2: 0,
                imm: (-4i32 as u32),
            },
            "offset -4 must be negative"
        );
    }

    #[test]
    fn test_decode_lw_lb_lbu() {
        // LW x1, 0(x2)
        assert_eq!(
            decode(encode_i(0x03, 2, 1, 2, 0)).unwrap(),
            Instruction::Lw {
                rd: 1,
                rs1: 2,
                imm: 0
            }
        );
        // LB x1, 0(x2)
        assert_eq!(
            decode(encode_i(0x03, 0, 1, 2, 0)).unwrap(),
            Instruction::Lb {
                rd: 1,
                rs1: 2,
                imm: 0
            }
        );
        // LBU x1, 0(x2)
        assert_eq!(
            decode(encode_i(0x03, 4, 1, 2, 0)).unwrap(),
            Instruction::Lbu {
                rd: 1,
                rs1: 2,
                imm: 0
            }
        );
    }

    #[test]
    fn test_decode_sw_sb() {
        // SW x2, 0(x1)
        assert_eq!(
            decode(encode_s(0x23, 2, 1, 2, 0)).unwrap(),
            Instruction::Sw {
                rs1: 1,
                rs2: 2,
                imm: 0
            }
        );
        // SB x2, 0(x1)
        assert_eq!(
            decode(encode_s(0x23, 0, 1, 2, 0)).unwrap(),
            Instruction::Sb {
                rs1: 1,
                rs2: 2,
                imm: 0
            }
        );
    }

    #[test]
    fn test_decode_addi_negative_imm() {
        // ADDI x1, x0, -1 → imm = 0xFFFFFFFF
        let word = encode_i(0x13, 0, 1, 0, 0xFFF);
        let insn = decode(word).unwrap();
        assert_eq!(
            insn,
            Instruction::Addi {
                rd: 1,
                rs1: 0,
                imm: 0xFFFFFFFF
            }
        );
    }

    #[test]
    fn test_decode_slli_shamt() {
        // SLLI x1, x2, 5
        let word = encode_i(0x13, 1, 1, 2, 5); // shamt in imm field
        let insn = decode(word).unwrap();
        assert_eq!(
            insn,
            Instruction::Slli {
                rd: 1,
                rs1: 2,
                shamt: 5
            }
        );
    }

    #[test]
    fn test_decode_srai_funct7() {
        // SRAI x1, x2, 5 → funct7=0x20, shamt=5
        let word = encode_r(0x13, 5, 0x20, 1, 2, 5);
        let insn = decode(word).unwrap();
        assert_eq!(
            insn,
            Instruction::Srai {
                rd: 1,
                rs1: 2,
                shamt: 5
            }
        );
    }

    #[test]
    fn test_decode_srli() {
        // SRLI x1, x2, 5 → funct7=0x00
        let word = encode_r(0x13, 5, 0x00, 1, 2, 5);
        let insn = decode(word).unwrap();
        assert_eq!(
            insn,
            Instruction::Srli {
                rd: 1,
                rs1: 2,
                shamt: 5
            }
        );
    }

    #[test]
    fn test_decode_add_sub() {
        // ADD x1, x2, x3 → funct7=0x00
        let word = encode_r(0x33, 0, 0x00, 1, 2, 3);
        assert_eq!(
            decode(word).unwrap(),
            Instruction::Add {
                rd: 1,
                rs1: 2,
                rs2: 3
            }
        );
        // SUB x1, x2, x3 → funct7=0x20
        let word = encode_r(0x33, 0, 0x20, 1, 2, 3);
        assert_eq!(
            decode(word).unwrap(),
            Instruction::Sub {
                rd: 1,
                rs1: 2,
                rs2: 3
            }
        );
    }

    #[test]
    fn test_decode_m_extension() {
        let cases = [
            (
                0u8,
                Instruction::Mul {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
            ),
            (
                1,
                Instruction::Mulh {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
            ),
            (
                2,
                Instruction::Mulhsu {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
            ),
            (
                3,
                Instruction::Mulhu {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
            ),
            (
                4,
                Instruction::Div {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
            ),
            (
                5,
                Instruction::Divu {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
            ),
            (
                6,
                Instruction::Rem {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
            ),
            (
                7,
                Instruction::Remu {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
            ),
        ];
        for (funct3, expected) in cases {
            let word = encode_r(0x33, funct3, 0x01, 1, 2, 3);
            assert_eq!(decode(word).unwrap(), expected, "funct3={funct3}");
        }
    }

    #[test]
    fn test_decode_ecall_ebreak() {
        // ECALL = 0x00000073
        assert_eq!(decode(0x00000073).unwrap(), Instruction::Ecall);
        // EBREAK = 0x00100073
        assert_eq!(decode(0x00100073).unwrap(), Instruction::Ebreak);
    }

    #[test]
    fn test_decode_fence() {
        // FENCE = 0x0000000F
        assert_eq!(decode(0x0000000F).unwrap(), Instruction::Fence);
    }

    #[test]
    fn test_decode_reject_compressed() {
        // bits[1:0] = 0b01 → compressed
        let err = decode(0x00000001).unwrap_err();
        assert!(matches!(err, ZkvmError::UnsupportedInstruction(_)));
    }

    #[test]
    fn test_decode_reject_float_opcode() {
        // FLW (opcode=0x07, funct3=2)
        let word = encode_i(0x07, 2, 1, 2, 0);
        let err = decode(word).unwrap_err();
        assert!(matches!(err, ZkvmError::UnsupportedInstruction(_)));
    }

    #[test]
    fn test_decode_reject_csr() {
        // CSR instruction (opcode=0x73, funct3=1 = CSRRW)
        let word = encode_i(0x73, 1, 1, 2, 0);
        let err = decode(word).unwrap_err();
        assert!(matches!(err, ZkvmError::UnsupportedInstruction(_)));
    }

    // ===== Step D: execute 测试 =====

    #[test]
    fn test_execute_addi() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        let log = execute(
            &mut state,
            Instruction::Addi {
                rd: 1,
                rs1: 0,
                imm: 42,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 42);
        assert_eq!(state.pc, 0x1004);
        assert_eq!(log.pc, 0x1000);
    }

    #[test]
    fn test_execute_addi_overflow_wraps() {
        let mut state = state::VmState::new();
        state.write_register(2, 0xFFFF_FFFF);
        execute(
            &mut state,
            Instruction::Addi {
                rd: 1,
                rs1: 2,
                imm: 1,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0, "0xFFFFFFFF + 1 wraps to 0");
    }

    #[test]
    fn test_execute_add() {
        let mut state = state::VmState::new();
        state.write_register(2, 10);
        state.write_register(3, 20);
        execute(
            &mut state,
            Instruction::Add {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 30);
    }

    #[test]
    fn test_execute_sub() {
        let mut state = state::VmState::new();
        state.write_register(2, 10);
        state.write_register(3, 3);
        execute(
            &mut state,
            Instruction::Sub {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 7);
    }

    #[test]
    fn test_execute_slt_signed() {
        let mut state = state::VmState::new();
        state.write_register(2, 0xFFFF_FFFF); // -1
        state.write_register(3, 1);
        execute(
            &mut state,
            Instruction::Slt {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 1, "-1 < 1");
    }

    #[test]
    fn test_execute_sltu_unsigned() {
        let mut state = state::VmState::new();
        state.write_register(2, 0xFFFF_FFFF);
        state.write_register(3, 1);
        execute(
            &mut state,
            Instruction::Sltu {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0, "0xFFFFFFFF > 1 unsigned");
    }

    #[test]
    fn test_execute_sra_sign_extend() {
        let mut state = state::VmState::new();
        state.write_register(2, 0x8000_0000);
        state.write_register(3, 4);
        execute(
            &mut state,
            Instruction::Sra {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(
            state.read_register(1),
            0xF800_0000,
            "arithmetic right shift"
        );
    }

    #[test]
    fn test_execute_srl_logical() {
        let mut state = state::VmState::new();
        state.write_register(2, 0x8000_0000);
        state.write_register(3, 4);
        execute(
            &mut state,
            Instruction::Srl {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0x0800_0000, "logical right shift");
    }

    #[test]
    fn test_execute_sll() {
        let mut state = state::VmState::new();
        state.write_register(2, 1);
        state.write_register(3, 4);
        execute(
            &mut state,
            Instruction::Sll {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0x10, "1 << 4 = 16");
    }

    // ===== M 扩展 execute 测试 =====

    #[test]
    fn test_execute_mul() {
        let mut state = state::VmState::new();
        state.write_register(2, 6);
        state.write_register(3, 7);
        execute(
            &mut state,
            Instruction::Mul {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 42, "6 * 7 = 42");

        // 0xFFFFFFFF * 2 = 0x1_FFFFFFFE, 低 32 位 = 0xFFFFFFFE
        state.write_register(2, 0xFFFF_FFFF);
        state.write_register(3, 2);
        execute(
            &mut state,
            Instruction::Mul {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0xFFFF_FFFE, "低 32 位");
    }

    #[test]
    fn test_execute_mulh() {
        let mut state = state::VmState::new();
        // (-1) * (-1) = 1, 高 32 位 = 0
        state.write_register(2, 0xFFFF_FFFF); // -1
        state.write_register(3, 0xFFFF_FFFF); // -1
        execute(
            &mut state,
            Instruction::Mulh {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0, "(-1)*(-1) 高 32 位 = 0");

        // 0x7FFFFFFF * 0x7FFFFFFF = 0x3FFFFFFF_00000001, 高 32 位 = 0x3FFFFFFF
        state.write_register(2, 0x7FFF_FFFF);
        state.write_register(3, 0x7FFF_FFFF);
        execute(
            &mut state,
            Instruction::Mulh {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0x3FFF_FFFF, "有符号高 32 位");
    }

    #[test]
    fn test_execute_mulhu() {
        let mut state = state::VmState::new();
        // 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE_00000001, 高 32 位 = 0xFFFFFFFE
        state.write_register(2, 0xFFFF_FFFF);
        state.write_register(3, 0xFFFF_FFFF);
        execute(
            &mut state,
            Instruction::Mulhu {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0xFFFF_FFFE, "无符号高 32 位");
    }

    #[test]
    fn test_execute_mulhsu() {
        let mut state = state::VmState::new();
        // (-1 as i64) * 0xFFFFFFFF = -0xFFFFFFFF = 0xFFFFFFFF_00000001 (as u64)
        // 高 32 位 = 0xFFFFFFFF
        state.write_register(2, 0xFFFF_FFFF); // -1 signed
        state.write_register(3, 0xFFFF_FFFF); // unsigned
        execute(
            &mut state,
            Instruction::Mulhsu {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0xFFFF_FFFF, "有符号×无符号高 32 位");
    }

    #[test]
    fn test_execute_div() {
        let mut state = state::VmState::new();
        state.write_register(2, 100);
        state.write_register(3, 7);
        execute(
            &mut state,
            Instruction::Div {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 14, "100 / 7 = 14");

        // -100 / 7 = -14
        state.write_register(2, (-100i32) as u32);
        state.write_register(3, 7);
        execute(
            &mut state,
            Instruction::Div {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), (-14i32) as u32, "-100 / 7 = -14");

        // DIV by 0 → -1
        state.write_register(2, 100);
        state.write_register(3, 0);
        execute(
            &mut state,
            Instruction::Div {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0xFFFF_FFFF, "DIV by 0 → -1");

        // INT_MIN / -1 → INT_MIN (overflow)
        state.write_register(2, i32::MIN as u32);
        state.write_register(3, (-1i32) as u32);
        execute(
            &mut state,
            Instruction::Div {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(
            state.read_register(1),
            i32::MIN as u32,
            "overflow → INT_MIN"
        );
    }

    #[test]
    fn test_execute_divu() {
        let mut state = state::VmState::new();
        state.write_register(2, 0xFFFF_FFFF);
        state.write_register(3, 2);
        execute(
            &mut state,
            Instruction::Divu {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0x7FFF_FFFF, "0xFFFFFFFF / 2");

        // DIVU by 0 → 0xFFFFFFFF
        state.write_register(2, 100);
        state.write_register(3, 0);
        execute(
            &mut state,
            Instruction::Divu {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(
            state.read_register(1),
            0xFFFF_FFFF,
            "DIVU by 0 → 0xFFFFFFFF"
        );
    }

    #[test]
    fn test_execute_rem() {
        let mut state = state::VmState::new();
        state.write_register(2, 100);
        state.write_register(3, 7);
        execute(
            &mut state,
            Instruction::Rem {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 2, "100 % 7 = 2");

        // -100 % 7 = -2
        state.write_register(2, (-100i32) as u32);
        state.write_register(3, 7);
        execute(
            &mut state,
            Instruction::Rem {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), (-2i32) as u32, "-100 % 7 = -2");

        // REM by 0 → rs1
        state.write_register(2, 42);
        state.write_register(3, 0);
        execute(
            &mut state,
            Instruction::Rem {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 42, "REM by 0 → rs1");

        // INT_MIN % -1 → 0 (overflow)
        state.write_register(2, i32::MIN as u32);
        state.write_register(3, (-1i32) as u32);
        execute(
            &mut state,
            Instruction::Rem {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0, "overflow → 0");
    }

    #[test]
    fn test_execute_remu() {
        let mut state = state::VmState::new();
        state.write_register(2, 0xFFFF_FFFF);
        state.write_register(3, 2);
        execute(
            &mut state,
            Instruction::Remu {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 1, "0xFFFFFFFF % 2 = 1");

        // REMU by 0 → rs1
        state.write_register(2, 42);
        state.write_register(3, 0);
        execute(
            &mut state,
            Instruction::Remu {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 42, "REMU by 0 → rs1");
    }

    #[test]
    fn test_execute_lui() {
        let mut state = state::VmState::new();
        execute(
            &mut state,
            Instruction::Lui {
                rd: 1,
                imm: 0x01000000,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0x01000000);
    }

    #[test]
    fn test_execute_auipc() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        execute(
            &mut state,
            Instruction::Auipc {
                rd: 1,
                imm: 0x01000000,
            },
        )
        .unwrap();
        assert_eq!(
            state.read_register(1),
            0x01001000,
            "pc + imm = 0x1000 + 0x01000000"
        );
    }

    #[test]
    fn test_execute_jal_link() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        let log = execute(&mut state, Instruction::Jal { rd: 1, imm: 8 }).unwrap();
        assert_eq!(state.read_register(1), 0x1004, "link = pc + 4");
        assert_eq!(state.pc, 0x1008, "jump target = pc + imm");
        assert_eq!(log.pc, 0x1000);
    }

    #[test]
    fn test_execute_jalr_target() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        state.write_register(2, 0x2000);
        execute(
            &mut state,
            Instruction::Jalr {
                rd: 1,
                rs1: 2,
                imm: 4,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0x1004, "link = pc + 4");
        assert_eq!(state.pc, 0x2004, "target = (rs1 + imm) & !1");
    }

    #[test]
    fn test_execute_jalr_clear_low_bit() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        state.write_register(2, 0x2000);
        execute(
            &mut state,
            Instruction::Jalr {
                rd: 1,
                rs1: 2,
                imm: 5,
            },
        )
        .unwrap();
        assert_eq!(state.pc, 0x2004, "target = (0x2000 + 5) & !1 = 0x2004");
    }

    #[test]
    fn test_execute_beq_taken() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        state.write_register(1, 42);
        state.write_register(2, 42);
        execute(
            &mut state,
            Instruction::Beq {
                rs1: 1,
                rs2: 2,
                imm: 8,
            },
        )
        .unwrap();
        assert_eq!(state.pc, 0x1008, "branch taken: pc + imm");
    }

    #[test]
    fn test_execute_beq_not_taken() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        state.write_register(1, 42);
        state.write_register(2, 43);
        execute(
            &mut state,
            Instruction::Beq {
                rs1: 1,
                rs2: 2,
                imm: 8,
            },
        )
        .unwrap();
        assert_eq!(state.pc, 0x1004, "branch not taken: pc + 4");
    }

    #[test]
    fn test_execute_blt_signed() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        state.write_register(1, 0xFFFF_FFFF); // -1
        state.write_register(2, 1);
        execute(
            &mut state,
            Instruction::Blt {
                rs1: 1,
                rs2: 2,
                imm: 8,
            },
        )
        .unwrap();
        assert_eq!(state.pc, 0x1008, "-1 < 1 signed → taken");
    }

    #[test]
    fn test_execute_bgeu_unsigned() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        state.write_register(1, 2);
        state.write_register(2, 1);
        execute(
            &mut state,
            Instruction::Bgeu {
                rs1: 1,
                rs2: 2,
                imm: 8,
            },
        )
        .unwrap();
        assert_eq!(state.pc, 0x1008, "2 >= 1 unsigned → taken");
    }

    #[test]
    fn test_execute_lw() {
        let mut state = state::VmState::new();
        state.write_register(2, 0x1000);
        state.write_memory_word(0x1000, 0xDEAD_BEEF).unwrap();
        let log = execute(
            &mut state,
            Instruction::Lw {
                rd: 1,
                rs1: 2,
                imm: 0,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0xDEAD_BEEF);
        assert_eq!(log.mem_access.len(), 1);
        assert_eq!(log.mem_access[0].op, crate::trace::MemOp::Read);
        assert_eq!(log.mem_access[0].size, 4);
    }

    #[test]
    fn test_execute_lb_sign_extend() {
        let mut state = state::VmState::new();
        state.write_register(2, 0x1000);
        state.write_memory_byte(0x1000, 0xFF).unwrap();
        execute(
            &mut state,
            Instruction::Lb {
                rd: 1,
                rs1: 2,
                imm: 0,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0xFFFF_FFFF, "0xFF sign-extended");
    }

    #[test]
    fn test_execute_lbu_zero_extend() {
        let mut state = state::VmState::new();
        state.write_register(2, 0x1000);
        state.write_memory_byte(0x1000, 0xFF).unwrap();
        execute(
            &mut state,
            Instruction::Lbu {
                rd: 1,
                rs1: 2,
                imm: 0,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0x0000_00FF, "0xFF zero-extended");
    }

    #[test]
    fn test_execute_sw() {
        let mut state = state::VmState::new();
        state.write_register(1, 0xDEAD_BEEF);
        state.write_register(2, 0x1000);
        let log = execute(
            &mut state,
            Instruction::Sw {
                rs1: 2,
                rs2: 1,
                imm: 0,
            },
        )
        .unwrap();
        assert_eq!(state.read_memory_word(0x1000).unwrap(), 0xDEAD_BEEF);
        assert_eq!(log.mem_access.len(), 1);
        assert_eq!(log.mem_access[0].op, crate::trace::MemOp::Write);
        assert_eq!(log.mem_access[0].size, 4);
    }

    #[test]
    fn test_execute_sb() {
        let mut state = state::VmState::new();
        state.write_register(1, 0xDEAD_BEEF);
        state.write_register(2, 0x1000);
        execute(
            &mut state,
            Instruction::Sb {
                rs1: 2,
                rs2: 1,
                imm: 0,
            },
        )
        .unwrap();
        assert_eq!(state.read_memory_byte(0x1000).unwrap(), 0xEF, "low byte");
    }

    #[test]
    fn test_execute_lh_lhu() {
        let mut state = state::VmState::new();
        state.write_register(2, 0x1000);
        state.write_memory_halfword(0x1000, 0xFFFF).unwrap();
        // LH sign-extend
        execute(
            &mut state,
            Instruction::Lh {
                rd: 1,
                rs1: 2,
                imm: 0,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(1), 0xFFFF_FFFF, "0xFFFF sign-extended");
        // LHU zero-extend
        execute(
            &mut state,
            Instruction::Lhu {
                rd: 3,
                rs1: 2,
                imm: 0,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(3), 0x0000_FFFF, "0xFFFF zero-extended");
    }

    #[test]
    fn test_execute_unaligned_lw() {
        let mut state = state::VmState::new();
        state.write_register(2, 0x1001); // unaligned
        let err = execute(
            &mut state,
            Instruction::Lw {
                rd: 1,
                rs1: 2,
                imm: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ZkvmError::UnalignedAccess { addr: 0x1001 }));
    }

    #[test]
    fn test_execute_uninitialized_lw() {
        let mut state = state::VmState::new();
        state.write_register(2, 0x2000); // uninitialized
        let err = execute(
            &mut state,
            Instruction::Lw {
                rd: 1,
                rs1: 2,
                imm: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ZkvmError::UninitializedRead { addr: 0x2000 }));
    }

    #[test]
    fn test_execute_fence_nop() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        state.write_register(1, 42);
        execute(&mut state, Instruction::Fence).unwrap();
        assert_eq!(state.read_register(1), 42, "FENCE is NOP");
        assert_eq!(state.pc, 0x1004);
    }

    #[test]
    fn test_execute_ecall_pc_advance() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        execute(&mut state, Instruction::Ecall).unwrap();
        assert_eq!(state.pc, 0x1004, "ECALL advances PC by 4");
    }

    #[test]
    fn test_execute_ebreak_pc_advance() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        execute(&mut state, Instruction::Ebreak).unwrap();
        assert_eq!(state.pc, 0x1004, "EBREAK advances PC by 4");
    }

    #[test]
    fn test_execute_write_x0_discarded() {
        let mut state = state::VmState::new();
        state.write_register(1, 99);
        execute(
            &mut state,
            Instruction::Addi {
                rd: 0,
                rs1: 1,
                imm: 42,
            },
        )
        .unwrap();
        assert_eq!(state.read_register(0), 0, "x0 must remain 0");
    }

    #[test]
    fn test_execute_steplog_contents() {
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        let insn = Instruction::Addi {
            rd: 1,
            rs1: 0,
            imm: 42,
        };
        let log = execute(&mut state, insn.clone()).unwrap();
        assert_eq!(log.pc, 0x1000, "StepLog.pc = execution PC");
        assert_eq!(log.instruction, insn, "StepLog.instruction = executed insn");
        assert_eq!(log.registers[1], 42, "StepLog.registers = post-state");
        assert!(log.mem_access.is_empty(), "ADDI has no memory access");
    }

    #[test]
    fn test_decode_execute_roundtrip_addi() {
        // 编码 ADDI x1, x0, 42 → 解码 → 执行
        let word = encode_i(0x13, 0, 1, 0, 42);
        let insn = decode(word).unwrap();
        let mut state = state::VmState::new();
        state.pc = 0x1000;
        execute(&mut state, insn).unwrap();
        assert_eq!(state.read_register(1), 42);
        assert_eq!(state.pc, 0x1004);
    }
}
