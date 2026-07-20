//! # Sha256 AIR — M31-native SHA-256 compression function AIR（Phase 4 — Tier 2）
//!
//! 详见 `.trae/documents/stwo_phase4_tier2_sha256_air_design.md`（v2.1 详细设计）。
//!
//! ## v2.1 Hard Constraint
//!
//! 所有约束 degree ≤ 2，强制 Stwo 使用 `EvaluationMode::SubDomain`（与 Poseidon AIR v2.1 一致）。
//!
//! ## 核心设计
//!
//! - **每行 = 1 轮**（64 行/compression block）
//! - **位分解策略**：对需要 ROTR/SHR 的字（a, e, W[t-15], W[t-2]）完全位分解为 32 boolean 列
//! - **XOR via AND**：`x ^ y = x + y - 2*(x & y)`，AND 在 bit 层面 degree 2
//! - **ROTR/SHR**：bit 层面列重排（degree 1）
//! - **ADD mod 2^32**：4×8-bit limb 加法 + carry（复用 CPU AIR 模式）
//!
//! ## 列布局（338 列，v2.1 详细版）
//!
//! 详见 [`SHA256_AIR_NUM_COLUMNS`] 常量定义和设计文档 §3。
//!
//! ## 状态
//!
//! - ⬅️ **CURRENT**：Step 5.1 — 基础结构 + 列布局常量（本文件）
//! - ⬜ **TODO**：Step 5.2 — 完整 compression function 约束
//! - ⬜ **TODO**：Step 5.3 — 多块 hash + 4 组件 logup 集成
//!
//! ## 参考
//!
//! - `poker_zkvm::stwo_backend::poseidon_air` — FrameworkEval 参考实现（v2.1 中间列降度）
//! - `poker_zkvm::stwo_backend::memory_air` — SubDomain 模式参考
//! - `.trae/documents/stwo_phase4_tier2_sha256_air_design.md` — v2.1 详细设计文档
//! - FIPS 180-4 — SHA-256 标准

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, RelationEntry};

use super::lookups::Sha256Lookup;

// ===========================================================================
// Sha256 AIR 列布局常量（338 列，v2.1 详细版）
// ===========================================================================

/// Message schedule: W[t] 当前轮（4×8-bit limb）。
pub const SHA256_AIR_COL_W_CUR_BASE: usize = 0;
/// Message schedule: W[t+1] 下一轮（4×8-bit limb，避免 prev-row 读取）。
pub const SHA256_AIR_COL_W_NEXT_BASE: usize = 4;
/// Message schedule: W[t-15]（4×8-bit limb，用于 σ0）。
pub const SHA256_AIR_COL_W_T15_BASE: usize = 8;
/// Message schedule: W[t-2]（4×8-bit limb，用于 σ1）。
pub const SHA256_AIR_COL_W_T2_BASE: usize = 12;
/// Message schedule: W[t-7]（4×8-bit limb，用于 message schedule update）。
pub const SHA256_AIR_COL_W_T7_BASE: usize = 16;
/// Message schedule: W[t-16]（4×8-bit limb，用于 message schedule update）。
pub const SHA256_AIR_COL_W_T16_BASE: usize = 20;

/// Working variable A 当前轮（4×8-bit limb）。
pub const SHA256_AIR_COL_A_BASE: usize = 24;
/// Working variable B 当前轮（4×8-bit limb）。
pub const SHA256_AIR_COL_B_BASE: usize = 28;
/// Working variable C 当前轮（4×8-bit limb）。
pub const SHA256_AIR_COL_C_BASE: usize = 32;
/// Working variable D 当前轮（4×8-bit limb）。
pub const SHA256_AIR_COL_D_BASE: usize = 36;
/// Working variable E 当前轮（4×8-bit limb）。
pub const SHA256_AIR_COL_E_BASE: usize = 40;
/// Working variable F 当前轮（4×8-bit limb）。
pub const SHA256_AIR_COL_F_BASE: usize = 44;
/// Working variable G 当前轮（4×8-bit limb）。
pub const SHA256_AIR_COL_G_BASE: usize = 48;
/// Working variable H 当前轮（4×8-bit limb）。
pub const SHA256_AIR_COL_H_BASE: usize = 52;

/// Working variable A 下一轮（4×8-bit limb）。
pub const SHA256_AIR_COL_A_NEXT_BASE: usize = 56;
/// Working variable B 下一轮（4×8-bit limb）。
pub const SHA256_AIR_COL_B_NEXT_BASE: usize = 60;
/// Working variable C 下一轮（4×8-bit limb）。
pub const SHA256_AIR_COL_C_NEXT_BASE: usize = 64;
/// Working variable D 下一轮（4×8-bit limb）。
pub const SHA256_AIR_COL_D_NEXT_BASE: usize = 68;
/// Working variable E 下一轮（4×8-bit limb）。
pub const SHA256_AIR_COL_E_NEXT_BASE: usize = 72;
/// Working variable F 下一轮（4×8-bit limb）。
pub const SHA256_AIR_COL_F_NEXT_BASE: usize = 76;
/// Working variable G 下一轮（4×8-bit limb）。
pub const SHA256_AIR_COL_G_NEXT_BASE: usize = 80;
/// Working variable H 下一轮（4×8-bit limb）。
pub const SHA256_AIR_COL_H_NEXT_BASE: usize = 84;

/// Flag: IsPadding（1=padding 行）。
pub const SHA256_AIR_COL_IS_PADDING: usize = 88;
/// Flag: IsFirstBlock（多块 hash 时第 0 块）。
pub const SHA256_AIR_COL_IS_FIRST_BLOCK: usize = 89;
/// Flag: IsLastBlock（多块 hash 时最后一块）。
pub const SHA256_AIR_COL_IS_LAST_BLOCK: usize = 90;
/// Flag: IsFirstRound（该 block 的第 0 轮）。
pub const SHA256_AIR_COL_IS_FIRST_ROUND: usize = 91;
/// Flag: IsLastRound（该 block 的最后一轮，第 63 轮）。
pub const SHA256_AIR_COL_IS_LAST_ROUND: usize = 92;
/// Round counter（0-63）。
pub const SHA256_AIR_COL_ROUND_COUNTER: usize = 93;

/// 初始 hash H0[0..7]（8 words × 4 limbs = 32 列）。
pub const SHA256_AIR_COL_H0_BASE: usize = 94;
/// 输出 hash H_out[0..7]（8 words × 4 limbs = 32 列）。
pub const SHA256_AIR_COL_H_OUT_BASE: usize = 126;

/// Bit decomposition of `a`（32 bits）。
pub const SHA256_AIR_COL_BIT_A_BASE: usize = 158;
/// Bit decomposition of `e`（32 bits）。
pub const SHA256_AIR_COL_BIT_E_BASE: usize = 190;
/// Bit decomposition of `W[t-15]`（32 bits）。
pub const SHA256_AIR_COL_BIT_W15_BASE: usize = 222;
/// Bit decomposition of `W[t-2]`（32 bits）。
pub const SHA256_AIR_COL_BIT_W2_BASE: usize = 254;

/// Σ0(a) 结果（4×8-bit limb）。
pub const SHA256_AIR_COL_SIGMA0_BASE: usize = 286;
/// Σ1(e) 结果（4×8-bit limb）。
pub const SHA256_AIR_COL_SIGMA1_BASE: usize = 290;
/// σ0(W[t-15]) 结果（4×8-bit limb）。
pub const SHA256_AIR_COL_SIGMA0_W_BASE: usize = 294;
/// σ1(W[t-2]) 结果（4×8-bit limb）。
pub const SHA256_AIR_COL_SIGMA1_W_BASE: usize = 298;

/// Ch(e,f,g) 结果（4×8-bit limb）。
pub const SHA256_AIR_COL_CH_BASE: usize = 302;
/// Maj(a,b,c) 结果（4×8-bit limb）。
pub const SHA256_AIR_COL_MAJ_BASE: usize = 306;

/// T1 = h + Σ1(e) + Ch + K[t] + W[t]（4×8-bit limb）。
pub const SHA256_AIR_COL_T1_BASE: usize = 310;
/// T2 = Σ0(a) + Maj(a,b,c)（4×8-bit limb）。
pub const SHA256_AIR_COL_T2_BASE: usize = 314;

/// Carry columns for T1 addition（4×8-bit limb carry）。
pub const SHA256_AIR_COL_CARRY_T1_BASE: usize = 318;
/// Carry columns for T2 addition（4×8-bit limb carry）。
pub const SHA256_AIR_COL_CARRY_T2_BASE: usize = 322;
/// Carry columns for W[t+1] message schedule addition（4×8-bit limb carry）。
pub const SHA256_AIR_COL_CARRY_W_BASE: usize = 326;
/// Carry columns for e_next = d + T1 addition（4×8-bit limb carry）。
pub const SHA256_AIR_COL_CARRY_E_BASE: usize = 330;
/// Carry columns for a_next = T1 + T2 addition（4×8-bit limb carry）。
pub const SHA256_AIR_COL_CARRY_A_BASE: usize = 334;

/// Sha256 AIR 总列数（v2.1 详细版）。
pub const SHA256_AIR_NUM_COLUMNS: usize = 338;

/// Sha256 syscall ID（= 0x04，与 `poker_zkvm::syscalls::SyscallId::Sha256` 一致）。
pub const SHA256_SYSCALL_ID: u32 = 0x04;

/// Sha256 compression function 总轮数。
pub const SHA256_AIR_TOTAL_ROUNDS: usize = 64;

// ===========================================================================
// Sha256 Air 结构
// ===========================================================================

/// Sha256 AIR 组件 — M31-native SHA-256 compression function FrameworkEval。
///
/// # 设计（v2.1）
/// - 每行表示一个 round（0-63）
/// - 每次 compression block 占 64 行
/// - 通过位分解处理 ROTR/SHR/XOR/AND（所有约束 degree ≤ 2）
/// - `max_constraint_log_degree_bound = log_size + 1`（约束度 ≤ 2，强制 SubDomain 模式）
/// - 通过 logup yield 与 CPU AIR 交互（Sha256Lookup 9 元组）
///
/// # 状态
///
/// **Step 5.1：基础结构已搭建，约束实现待完成。**
///
/// 当前仅实现 FrameworkEval 的骨架（log_size + max_constraint_log_degree_bound）。
/// 完整约束（binality + 位分解 + ROTR/SHR + working variable update + message schedule）
/// 将在 Step 5.2 实施。
///
/// # 用法
/// ```ignore
/// use poker_zkvm::stwo_backend::sha256_air::Sha256Air;
/// use poker_zkvm::stwo_backend::lookups::Sha256Lookup;
/// use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};
/// use stwo::core::fields::qm31::SecureField;
///
/// let air = Sha256Air::new(log_size, Sha256Lookup::dummy());
/// let component = FrameworkComponent::new(
///     &mut TraceLocationAllocator::default(),
///     air,
///     SecureField::from(0u32),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct Sha256Air {
    /// log2(trace 行数)
    log_size: u32,
    /// Sha256Lookup relation（用于 logup yield）
    sha256_lookup: Sha256Lookup,
}

impl Sha256Air {
    /// 创建指定 log_size 的 Sha256 AIR。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 6（至少 64 行 = 1 compression block）
    /// - `sha256_lookup` — Sha256Lookup relation 实例（从 channel draw 或 dummy）
    #[must_use]
    pub const fn new(log_size: u32, sha256_lookup: Sha256Lookup) -> Self {
        Self {
            log_size,
            sha256_lookup,
        }
    }

    /// 获取 log_size。
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.log_size
    }
}

impl FrameworkEval for Sha256Air {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    /// v2.1：所有约束的最大总度 = 2（binality: x*(x-1), AND: x*y）。
    /// log2(2) = 1，所以 max_constraint_log_degree_bound = log_size + 1。
    ///
    /// 这强制 Stwo 使用 `EvaluationMode::SubDomain`（与 Poseidon AIR v2.1 一致）。
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = BaseField::from(1u32).into();

        // ----- 读取全部 338 列 -----
        // Step 5.1: 仅读取列，不添加约束（骨架实现）
        // Step 5.2 将添加完整约束
        let mut cols: Vec<E::F> = Vec::with_capacity(SHA256_AIR_NUM_COLUMNS);
        for _ in 0..SHA256_AIR_NUM_COLUMNS {
            cols.push(eval.next_trace_mask());
        }
        let col = |idx: usize| -> E::F { cols[idx].clone() };

        // ----- 读取 flag 列 -----
        let is_padding = col(SHA256_AIR_COL_IS_PADDING);
        let _is_first_block = col(SHA256_AIR_COL_IS_FIRST_BLOCK);
        let is_last_block = col(SHA256_AIR_COL_IS_LAST_BLOCK);
        let _is_first_round = col(SHA256_AIR_COL_IS_FIRST_ROUND);
        let _is_last_round = col(SHA256_AIR_COL_IS_LAST_ROUND);

        // ===== Step 5.1: 基础 binality 约束 =====

        // IsPadding binality
        let padding_bin = is_padding.clone() * (is_padding.clone() - one.clone());
        eval.add_constraint(padding_bin);

        // IsFirstBlock binality
        let first_block_bin =
            _is_first_block.clone() * (_is_first_block.clone() - one.clone());
        eval.add_constraint(first_block_bin);

        // IsLastBlock binality
        let last_block_bin =
            is_last_block.clone() * (is_last_block.clone() - one.clone());
        eval.add_constraint(last_block_bin);

        // IsFirstRound binality
        let first_round_bin =
            _is_first_round.clone() * (_is_first_round.clone() - one.clone());
        eval.add_constraint(first_round_bin);

        // IsLastRound binality
        let last_round_bin =
            _is_last_round.clone() * (_is_last_round.clone() - one.clone());
        eval.add_constraint(last_round_bin);

        // ===== Step 5.2: 位分解 binality（128 条约束）=====
        // 每个 boolean bit 必须 ∈ {0, 1}：bit * (bit - 1) == 0 (degree 2)
        for i in 0..32 {
            // BitA[0..31] binality
            let bit_a = col(SHA256_AIR_COL_BIT_A_BASE + i);
            eval.add_constraint(bit_a.clone() * (bit_a - one.clone()));

            // BitE[0..31] binality
            let bit_e = col(SHA256_AIR_COL_BIT_E_BASE + i);
            eval.add_constraint(bit_e.clone() * (bit_e - one.clone()));

            // BitW15[0..31] binality
            let bit_w15 = col(SHA256_AIR_COL_BIT_W15_BASE + i);
            eval.add_constraint(bit_w15.clone() * (bit_w15 - one.clone()));

            // BitW2[0..31] binality
            let bit_w2 = col(SHA256_AIR_COL_BIT_W2_BASE + i);
            eval.add_constraint(bit_w2.clone() * (bit_w2 - one.clone()));
        }

        // ===== Step 5.2: 位分解重建（16 条约束，degree 1）=====
        // 每个 8-bit limb L = sum(bit_i * 2^i) for i in 0..7
        // 约束: L - sum(bit_i * 2^i) == 0 (degree 1)
        let powers_of_2: [u32; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
        for limb_idx in 0..4 {
            // BitA → A[0..3] 重建
            let a_limb = col(SHA256_AIR_COL_A_BASE + limb_idx);
            let mut reconstruction: E::F = BaseField::from(0u32).into();
            for bit_idx in 0..8 {
                let bit = col(SHA256_AIR_COL_BIT_A_BASE + limb_idx * 8 + bit_idx);
                let weight: E::F = BaseField::from(powers_of_2[bit_idx]).into();
                reconstruction = reconstruction + bit * weight;
            }
            eval.add_constraint(a_limb - reconstruction);

            // BitE → E[0..3] 重建
            let e_limb = col(SHA256_AIR_COL_E_BASE + limb_idx);
            let mut reconstruction: E::F = BaseField::from(0u32).into();
            for bit_idx in 0..8 {
                let bit = col(SHA256_AIR_COL_BIT_E_BASE + limb_idx * 8 + bit_idx);
                let weight: E::F = BaseField::from(powers_of_2[bit_idx]).into();
                reconstruction = reconstruction + bit * weight;
            }
            eval.add_constraint(e_limb - reconstruction);

            // BitW15 → W_t15[0..3] 重建
            let w15_limb = col(SHA256_AIR_COL_W_T15_BASE + limb_idx);
            let mut reconstruction: E::F = BaseField::from(0u32).into();
            for bit_idx in 0..8 {
                let bit = col(SHA256_AIR_COL_BIT_W15_BASE + limb_idx * 8 + bit_idx);
                let weight: E::F = BaseField::from(powers_of_2[bit_idx]).into();
                reconstruction = reconstruction + bit * weight;
            }
            eval.add_constraint(w15_limb - reconstruction);

            // BitW2 → W_t2[0..3] 重建
            let w2_limb = col(SHA256_AIR_COL_W_T2_BASE + limb_idx);
            let mut reconstruction: E::F = BaseField::from(0u32).into();
            for bit_idx in 0..8 {
                let bit = col(SHA256_AIR_COL_BIT_W2_BASE + limb_idx * 8 + bit_idx);
                let weight: E::F = BaseField::from(powers_of_2[bit_idx]).into();
                reconstruction = reconstruction + bit * weight;
            }
            eval.add_constraint(w2_limb - reconstruction);
        }

        // ===== Step 5.2 TODO: 完整约束（待实施）=====
        // 以下约束待 Step 5.2 后续实施：
        // - ROTR/SHR 列重排约束（degree 1）
        //   Σ0(a) = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22)
        //   Σ1(e) = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25)
        //   σ0(W[t-15]) = ROTR(W,7) ^ ROTR(W,18) ^ SHR(W,3)
        //   σ1(W[t-2]) = ROTR(W,17) ^ ROTR(W,19) ^ SHR(W,10)
        // - XOR via AND（degree 2，需中间列）
        //   x ^ y = x + y - 2*(x & y)
        //   对 3-way XOR 需分两步：tmp = x^y, result = tmp^z
        //   **设计决策待定**：可能需要独立 BitwiseAir 组件处理 XOR/AND
        // - Working variable update（degree 2，含 carry）
        //   T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
        //   T2 = Σ0(a) + Maj(a,b,c)
        //   a_next = T1 + T2, e_next = d + T1
        //   b_next=a, c_next=b, d_next=c, f_next=e, g_next=f, h_next=g
        // - Message schedule update（degree 2，含 carry）
        //   W[t+1] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16] (t >= 16)

        // ===== Step 5.2: Working variable shift 约束（degree 1，无 gating）=====
        // SHA-256 round: b_next = a, c_next = b, d_next = c, f_next = e, g_next = f, h_next = g
        // 这 6 个是直接复制，无运算，约束为 degree 1
        // padding 行也满足（全 0）
        for limb_idx in 0..4 {
            // b_next = a
            eval.add_constraint(
                col(SHA256_AIR_COL_B_NEXT_BASE + limb_idx) - col(SHA256_AIR_COL_A_BASE + limb_idx),
            );
            // c_next = b
            eval.add_constraint(
                col(SHA256_AIR_COL_C_NEXT_BASE + limb_idx) - col(SHA256_AIR_COL_B_BASE + limb_idx),
            );
            // d_next = c
            eval.add_constraint(
                col(SHA256_AIR_COL_D_NEXT_BASE + limb_idx) - col(SHA256_AIR_COL_C_BASE + limb_idx),
            );
            // f_next = e
            eval.add_constraint(
                col(SHA256_AIR_COL_F_NEXT_BASE + limb_idx) - col(SHA256_AIR_COL_E_BASE + limb_idx),
            );
            // g_next = f
            eval.add_constraint(
                col(SHA256_AIR_COL_G_NEXT_BASE + limb_idx) - col(SHA256_AIR_COL_F_BASE + limb_idx),
            );
            // h_next = g
            eval.add_constraint(
                col(SHA256_AIR_COL_H_NEXT_BASE + limb_idx) - col(SHA256_AIR_COL_G_BASE + limb_idx),
            );
        }

        // ===== Step 5.2 TODO: First round boundary（gated by IsFirstRound）=====
        // 待实施：IsFirstRound=1 时，A-H = H0[0..7]
        // 约束: IsFirstRound * (A[i] - H0[i]) == 0 (degree 2)

        // ===== Step 5.2 TODO: Last round boundary（gated by IsLastRound）=====
        // 待实施：IsLastRound=1 时，H_out[0..7] = A-H（next）
        // 约束: IsLastRound * (H_out[i] - A_next[i]) == 0 (degree 2)

        // ===== Step 5.2 TODO: Round counter 递增 =====
        // 待实施：非 last round 行，RoundCounter_next = RoundCounter + 1
        // 需读取 RoundCounter 列并约束

        // ===== Logup yield =====
        // Sha256 AIR 在 IsLastBlock=1 行发送 yield：
        //   values = (SHA256=0x04, Input[0..3], Output[0..3], 1, 0)
        //   multiplicity = -1 * IsLastBlock * (1 - IsPadding)
        //
        // Step 5.1 骨架：使用 H0[0..3] 作为 Input，H_out[0..3] 作为 Output
        // Step 5.3 将完善：Input 应为该 hash 的原始输入摘要
        let mut lookup_values: Vec<E::F> = Vec::with_capacity(9);
        lookup_values.push(BaseField::from(SHA256_SYSCALL_ID).into());
        // Input[0..3] = H0[0..3]（初始 hash 前 3 个 word 的第 0 个 limb）
        for i in 0..3 {
            lookup_values.push(col(SHA256_AIR_COL_H0_BASE + i * 4));
        }
        // Output[0..3] = H_out[0..3]（输出 hash 前 3 个 word 的第 0 个 limb）
        for i in 0..3 {
            lookup_values.push(col(SHA256_AIR_COL_H_OUT_BASE + i * 4));
        }
        lookup_values.push(is_last_block.clone());
        lookup_values.push(is_padding.clone());

        let neg_one: E::EF = SecureField::from(-1i32).into();
        let is_non_padding: E::F = one.clone() - is_padding.clone();
        let multiplicity: E::EF = neg_one * is_last_block.clone() * is_non_padding;
        eval.add_to_relation(RelationEntry::new(
            &self.sha256_lookup,
            multiplicity,
            &lookup_values,
        ));
        eval.finalize_logup();

        eval
    }
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_air_num_columns() {
        // 验证总列数 = 338
        assert_eq!(SHA256_AIR_NUM_COLUMNS, 338);
    }

    #[test]
    fn test_sha256_air_column_layout_no_overlap() {
        // 验证列布局无重叠：每个 base + size 不超过下一个 base
        // W columns: 0-23 (6 words × 4 limbs)
        assert!(SHA256_AIR_COL_W_CUR_BASE < SHA256_AIR_COL_W_NEXT_BASE);
        assert!(SHA256_AIR_COL_W_NEXT_BASE < SHA256_AIR_COL_W_T15_BASE);
        assert!(SHA256_AIR_COL_W_T15_BASE < SHA256_AIR_COL_W_T2_BASE);
        assert!(SHA256_AIR_COL_W_T2_BASE < SHA256_AIR_COL_W_T7_BASE);
        assert!(SHA256_AIR_COL_W_T7_BASE < SHA256_AIR_COL_W_T16_BASE);
        assert!(SHA256_AIR_COL_W_T16_BASE < SHA256_AIR_COL_A_BASE);

        // Working variables: 24-87 (8 words × 4 limbs × 2 = 64)
        assert!(SHA256_AIR_COL_A_BASE < SHA256_AIR_COL_B_BASE);
        assert!(SHA256_AIR_COL_H_BASE < SHA256_AIR_COL_A_NEXT_BASE);
        assert!(SHA256_AIR_COL_A_NEXT_BASE < SHA256_AIR_COL_H_NEXT_BASE);
        assert!(SHA256_AIR_COL_H_NEXT_BASE < SHA256_AIR_COL_IS_PADDING);

        // Flags: 88-93
        assert!(SHA256_AIR_COL_IS_PADDING < SHA256_AIR_COL_IS_FIRST_BLOCK);
        assert!(SHA256_AIR_COL_IS_FIRST_BLOCK < SHA256_AIR_COL_IS_LAST_BLOCK);
        assert!(SHA256_AIR_COL_IS_LAST_BLOCK < SHA256_AIR_COL_IS_FIRST_ROUND);
        assert!(SHA256_AIR_COL_IS_FIRST_ROUND < SHA256_AIR_COL_IS_LAST_ROUND);
        assert!(SHA256_AIR_COL_IS_LAST_ROUND < SHA256_AIR_COL_ROUND_COUNTER);
        assert!(SHA256_AIR_COL_ROUND_COUNTER < SHA256_AIR_COL_H0_BASE);

        // H0/H_out: 94-157 (2 × 32 = 64)
        assert!(SHA256_AIR_COL_H0_BASE < SHA256_AIR_COL_H_OUT_BASE);
        assert!(SHA256_AIR_COL_H_OUT_BASE < SHA256_AIR_COL_BIT_A_BASE);

        // Bit decompositions: 158-285 (4 × 32 = 128)
        assert!(SHA256_AIR_COL_BIT_A_BASE < SHA256_AIR_COL_BIT_E_BASE);
        assert!(SHA256_AIR_COL_BIT_E_BASE < SHA256_AIR_COL_BIT_W15_BASE);
        assert!(SHA256_AIR_COL_BIT_W15_BASE < SHA256_AIR_COL_BIT_W2_BASE);
        assert!(SHA256_AIR_COL_BIT_W2_BASE < SHA256_AIR_COL_SIGMA0_BASE);

        // Helper results: 286-317 (8 × 4 = 32)
        assert!(SHA256_AIR_COL_SIGMA0_BASE < SHA256_AIR_COL_SIGMA1_BASE);
        assert!(SHA256_AIR_COL_SIGMA1_BASE < SHA256_AIR_COL_SIGMA0_W_BASE);
        assert!(SHA256_AIR_COL_SIGMA0_W_BASE < SHA256_AIR_COL_SIGMA1_W_BASE);
        assert!(SHA256_AIR_COL_SIGMA1_W_BASE < SHA256_AIR_COL_CH_BASE);
        assert!(SHA256_AIR_COL_CH_BASE < SHA256_AIR_COL_MAJ_BASE);
        assert!(SHA256_AIR_COL_MAJ_BASE < SHA256_AIR_COL_T1_BASE);
        assert!(SHA256_AIR_COL_T1_BASE < SHA256_AIR_COL_T2_BASE);
        assert!(SHA256_AIR_COL_T2_BASE < SHA256_AIR_COL_CARRY_T1_BASE);

        // Carry: 318-337 (5 × 4 = 20)
        assert!(SHA256_AIR_COL_CARRY_T1_BASE < SHA256_AIR_COL_CARRY_T2_BASE);
        assert!(SHA256_AIR_COL_CARRY_T2_BASE < SHA256_AIR_COL_CARRY_W_BASE);
        assert!(SHA256_AIR_COL_CARRY_W_BASE < SHA256_AIR_COL_CARRY_E_BASE);
        assert!(SHA256_AIR_COL_CARRY_E_BASE < SHA256_AIR_COL_CARRY_A_BASE);
        assert_eq!(SHA256_AIR_COL_CARRY_A_BASE + 4, SHA256_AIR_NUM_COLUMNS);
    }

    #[test]
    fn test_sha256_syscall_id() {
        // 验证 SHA256 syscall ID = 0x04
        assert_eq!(SHA256_SYSCALL_ID, 0x04);
    }

    #[test]
    fn test_sha256_air_total_rounds() {
        // 验证 SHA-256 compression 总轮数 = 64
        assert_eq!(SHA256_AIR_TOTAL_ROUNDS, 64);
    }

    #[test]
    fn test_sha256_air_new() {
        // 验证 Sha256Air 可以创建
        let air = Sha256Air::new(10, Sha256Lookup::dummy());
        assert_eq!(air.log_size(), 10);
    }

    #[test]
    fn test_sha256_air_max_constraint_log_degree_bound() {
        // 验证 max_constraint_log_degree_bound = log_size + 1（强制 SubDomain 模式）
        let air = Sha256Air::new(10, Sha256Lookup::dummy());
        assert_eq!(air.max_constraint_log_degree_bound(), 11);
    }
}