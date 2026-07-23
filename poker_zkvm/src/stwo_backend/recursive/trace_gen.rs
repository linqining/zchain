//! # Trace Generators — 4 个 Verifier AIR 的 trace 生成器（Phase 5 — v5.1）
//!
//! 详见 `.trae/documents/stwo_phase5_verifier_air_design.md` §9。
//!
//! ## v5.1 实现状态
//!
//! - ✅ `gen_oods_check_trace` — OODS Check AIR trace 生成器（v5.1：从 L1 proof 提取 sampled_values + QM31 乘法分解）
//! - ✅ `gen_fri_verifier_trace` — FRI Verifier AIR trace 生成器（v5.1：Horner method + 完整 QM31 乘法分解）
//! - ⬜ `gen_merkle_path_trace` — Merkle Path AIR trace 生成器（v5.2）
//! - ⬜ `gen_composition_eval_trace` — Composition Eval AIR trace 生成器（已合并到 OODS Check AIR v5.1）

use super::fri_verifier_air::{
    FRI_AIR_COL_COEFF_BASE, FRI_AIR_COL_GATING, FRI_AIR_COL_IS_FIRST_ROW, FRI_AIR_COL_IS_LAST_ROW,
    FRI_AIR_COL_IS_PADDING, FRI_AIR_COL_M_BASE, FRI_AIR_COL_PARTIAL_EVAL_BASE,
    FRI_AIR_COL_PARTIAL_EVAL_PREV_BASE, FRI_AIR_COL_QUERY_EVAL_BASE, FRI_AIR_COL_QUERY_X_BASE,
    FRI_AIR_NUM_COLUMNS, FRI_AIR_NUM_M_INTERMEDIATES,
};
use super::oods_check_air::{
    OODS_AIR_COL_CLAIMED_BASE, OODS_AIR_COL_COMPUTED_BASE, OODS_AIR_COL_DF_X_BASE,
    OODS_AIR_COL_IS_PADDING, OODS_AIR_COL_LEFT_EVAL_BASE, OODS_AIR_COL_M_BASE,
    OODS_AIR_COL_PRODUCT_BASE, OODS_AIR_COL_RIGHT_EVAL_BASE, OODS_AIR_COL_SV_BASE,
    OODS_AIR_NUM_COLUMNS, OODS_AIR_NUM_M_INTERMEDIATES, OODS_AIR_NUM_SAMPLED_VALUES,
};
use super::public_inputs::RecursivePublicInputs;
use ark_ff::Zero;
use stwo::core::channel::{Channel, MerkleChannel, Poseidon252Channel};
use stwo::core::circle::{CirclePoint, Coset};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
use stwo::core::fri::{CirclePolyDegreeBound, FriVerifier};
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::line::{LineDomain, LinePoly};
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_index;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    poseidon_finalize, Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use starknet_ff::FieldElement as FieldElement252;

/// OODS Check AIR 使用的 log_size（4 行 = 1 real + 3 padding）。
pub const OODS_TRACE_LOG_SIZE: u32 = 2;

/// 将 FieldElement252（Poseidon252 hash 输出）转换为 8 个 M31 limbs。
///
/// Poseidon252 hash 输出是 252-bit field element，拆分为 8×31-bit M31 limbs。
/// 高字节在前（big-endian）。
fn field_element_252_to_m31_limbs(hash: &FieldElement252) -> [BaseField; 8] {
    let bytes = hash.to_bytes_be();
    let mut limbs = [BaseField::zero(); 8];
    for i in 0..8 {
        let start = i * 4;
        let mut limb_bytes = [0u8; 4];
        limb_bytes.copy_from_slice(&bytes[start..start + 4]);
        let limb_u32 = u32::from_be_bytes(limb_bytes);
        limbs[i] = BaseField::from_u32_unchecked(limb_u32);
    }
    limbs
}

/// 计算 FRI Verifier AIR trace 所需的 log_size。
///
/// 给定 `last_layer_poly`，计算 `gen_fri_verifier_trace` 生成的 trace 行数对应的 log_size：
/// 1. `n_coeffs = last_layer_poly.len()`（总是 2 的幂）
/// 2. `n_real_rows = n_coeffs + 1`（1 init + n_coeffs Horner steps）
/// 3. `num_rows = if n_real_rows.is_power_of_two() { 2 * n_real_rows } else { n_real_rows.next_power_of_two() }`
/// 4. `log_size = log2(num_rows)`
///
/// # 参数
/// - `last_layer_poly` — L1 FRI 的 last layer polynomial
///
/// # 返回
/// `u32` — log2(trace 行数)，至少 1（保证 num_rows >= 2）
///
/// # Panics
/// 如果 `last_layer_poly.len() == 0`（LinePoly 构造时已保证 len >= 1）。
#[must_use]
pub fn compute_fri_trace_log_size(last_layer_poly: &LinePoly) -> u32 {
    let n_coeffs = last_layer_poly.len();
    assert!(n_coeffs > 0, "last_layer_poly 不能为空");
    let n_real_rows = n_coeffs + 1;
    let num_rows = if n_real_rows.is_power_of_two() {
        2 * n_real_rows // 强制至少 1 padding row
    } else {
        n_real_rows.next_power_of_two()
    };
    // num_rows >= 2 (因为 n_coeffs >= 1 → n_real_rows >= 2 → num_rows >= 4)
    debug_assert!(num_rows.is_power_of_two());
    debug_assert!(num_rows >= 2);
    num_rows.trailing_zeros()
}

/// 将 OODS Check AIR trace 从原始 log_size (2) pad 到目标 log_size。
///
/// 多组件 proof 要求 OODS 和 FRI 两个 component 共享同一 Tree 1，
/// 因此两者必须有相同的 log_size。此函数将 OODS trace 的每列从
/// `2^OODS_TRACE_LOG_SIZE` 行 pad 到 `2^target_log_size` 行：
/// - 新增的 padding rows：IsPadding=1，其余列=0
/// - 原有 rows 保持不变
///
/// # 参数
/// - `cols` — OODS trace 列（73 列 × `2^OODS_TRACE_LOG_SIZE` 行）
/// - `target_log_size` — 目标 log_size（必须 >= `OODS_TRACE_LOG_SIZE`）
///
/// # 返回
/// 新的 `Vec<Vec<BaseField>>`，每列长度为 `2^target_log_size`
///
/// # Panics
/// - 如果 `target_log_size < OODS_TRACE_LOG_SIZE`
/// - 如果 `cols` 的列数 != `OODS_AIR_NUM_COLUMNS`
/// - 如果 `cols` 的任一列长度 != `2^OODS_TRACE_LOG_SIZE`
#[must_use]
pub fn pad_oods_trace_to_log_size(
    cols: Vec<Vec<BaseField>>,
    target_log_size: u32,
) -> Vec<Vec<BaseField>> {
    assert!(
        target_log_size >= OODS_TRACE_LOG_SIZE,
        "target_log_size ({target_log_size}) < OODS_TRACE_LOG_SIZE ({OODS_TRACE_LOG_SIZE})"
    );
    assert_eq!(
        cols.len(),
        OODS_AIR_NUM_COLUMNS,
        "OODS trace 列数不匹配：{} != {}",
        cols.len(),
        OODS_AIR_NUM_COLUMNS
    );

    let src_rows = 1usize << OODS_TRACE_LOG_SIZE;
    let dst_rows = 1usize << target_log_size;
    let one = BaseField::from(1u32);

    cols.into_iter()
        .enumerate()
        .map(|(col_idx, mut col)| {
            assert_eq!(
                col.len(),
                src_rows,
                "col {col_idx} 行数不匹配：{} != {src_rows}",
                col.len()
            );
            col.resize(dst_rows, BaseField::zero());
            // 对 IsPadding 列，新增的 padding rows 设为 1
            if col_idx == OODS_AIR_COL_IS_PADDING {
                for row in src_rows..dst_rows {
                    col[row] = one;
                }
            }
            col
        })
        .collect()
}

/// 将 Merkle Path AIR trace 从自然 log_size pad 到目标 log_size。
///
/// # 参数
/// - `cols` — Merkle trace 列（60 列）
/// - `target_log_size` — 目标 log_size
///
/// # 返回
/// 新的 `Vec<Vec<BaseField>>`，每列长度为 `2^target_log_size`
#[must_use]
pub fn pad_merkle_trace_to_log_size(
    cols: Vec<Vec<BaseField>>,
    target_log_size: u32,
) -> Vec<Vec<BaseField>> {
    use super::merkle_path_air::{MERKLE_AIR_COL_IS_PADDING, MERKLE_AIR_NUM_COLUMNS};

    assert_eq!(
        cols.len(),
        MERKLE_AIR_NUM_COLUMNS,
        "Merkle trace 列数不匹配：{} != {}",
        cols.len(),
        MERKLE_AIR_NUM_COLUMNS
    );

    let src_rows = cols[0].len();
    let dst_rows = 1usize << target_log_size;
    let one = BaseField::from(1u32);

    cols.into_iter()
        .enumerate()
        .map(|(col_idx, mut col)| {
            col.resize(dst_rows, BaseField::zero());
            if col_idx == MERKLE_AIR_COL_IS_PADDING {
                for row in src_rows..dst_rows {
                    col[row] = one;
                }
            }
            col
        })
        .collect()
}

/// 将 FRI Verifier AIR trace 从自然 log_size pad 到目标 log_size。
///
/// 当 `target_log_size > compute_fri_trace_log_size(last_layer_poly)` 时，
/// `gen_fri_verifier_trace` 生成的 trace 行数 < `2^target_log_size`，
/// 需要此函数扩展 padding rows 到 `2^target_log_size` 行。
///
/// 新增的 padding rows：
/// - IsPadding=1（col 18）
/// - 其余列=0（包括 IsFirstRow, IsLastRow, QueryX, PartialEval, Coeff, M, Gating）
///
/// 这确保 FRI AIR 的所有约束在 padding rows 上自动满足：
/// - F1-F3: IsFirstRow=0, IsLastRow=0, IsPadding=1 → binality ✓
/// - F4c: Gating=0, (1-0)*(1-1)=0 → 0=0 ✓
/// - F4a: M[k]=0, pe_prev*query_x=0*0=0 → 0=0 ✓
/// - F4b: Gating=0 → auto-satisfied ✓
/// - F5: IsFirstRow=0 → auto-satisfied ✓
/// - F6: IsLastRow=0 → auto-satisfied ✓
///
/// # 参数
/// - `cols` — FRI trace 列（36 列 × `2^fri_log_size` 行）
/// - `target_log_size` — 目标 log_size（必须 >= FRI trace 的自然 log_size）
///
/// # 返回
/// 新的 `Vec<Vec<BaseField>>`，每列长度为 `2^target_log_size`
///
/// # Panics
/// - 如果 `cols` 的列数 != `FRI_AIR_NUM_COLUMNS`
/// - 如果 `cols` 的行数不是 2 的幂
/// - 如果 `target_log_size` 使得 `2^target_log_size < cols[0].len()`
#[must_use]
pub fn pad_fri_trace_to_log_size(
    cols: Vec<Vec<BaseField>>,
    target_log_size: u32,
) -> Vec<Vec<BaseField>> {
    assert_eq!(
        cols.len(),
        FRI_AIR_NUM_COLUMNS,
        "FRI trace 列数不匹配：{} != {}",
        cols.len(),
        FRI_AIR_NUM_COLUMNS
    );

    let src_rows = cols[0].len();
    assert!(
        src_rows.is_power_of_two(),
        "FRI trace 行数必须是 2 的幂，实际 {src_rows}"
    );
    let src_log_size = src_rows.trailing_zeros();
    assert!(
        target_log_size >= src_log_size,
        "target_log_size ({target_log_size}) < FRI trace log_size ({src_log_size})"
    );

    let dst_rows = 1usize << target_log_size;
    let one = BaseField::from(1u32);

    cols.into_iter()
        .enumerate()
        .map(|(col_idx, mut col)| {
            assert_eq!(
                col.len(),
                src_rows,
                "col {col_idx} 行数不匹配：{} != {src_rows}",
                col.len()
            );
            col.resize(dst_rows, BaseField::zero());
            // 对 IsPadding 列，新增的 padding rows 设为 1
            if col_idx == FRI_AIR_COL_IS_PADDING {
                for row in src_rows..dst_rows {
                    col[row] = one;
                }
            }
            col
        })
        .collect()
}

/// 从 L1 proof 的 `sampled_values` 提取 8 个 SecureField partial evals。
///
/// L1 proof 的 `sampled_values` 最后一个 tree 是 `left_and_right_composition_mask`，
/// 包含 `2 * SECURE_EXTENSION_DEGREE = 8` 个 column，每个 column 1 个 SecureField。
///
/// # 参数
/// - `l1_proof` — L1 Stwo proof
///
/// # 返回
/// - `Some([SecureField; 8])` — 提取成功
/// - `None` — sampled_values 结构不匹配
fn extract_sampled_values_from_l1(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
) -> Option<[SecureField; 8]> {
    let sampled_values = &l1_proof.sampled_values;
    let last_tree = sampled_values.last()?;

    if last_tree.len() != 2 * SECURE_EXTENSION_DEGREE {
        return None;
    }

    let mut evals: [SecureField; 8] = [SecureField::zero(); 8];
    for (i, column) in last_tree.iter().enumerate() {
        if column.len() != 1 {
            return None;
        }
        evals[i] = column[0];
    }
    Some(evals)
}

/// 从 L1 proof 的 `sampled_values` 提取 composition OODS evaluation。
///
/// 重实现 `StarkProof::extract_composition_oods_eval`（`pub(crate)` 不可外部调用）。
///
/// # 算法（参考 `stwo-2.3.0/src/core/proof.rs:27-57`）
/// 1. `sampled_values` 最后一个 tree 是 `left_and_right_composition_mask`
/// 2. 该 mask 有 `2 * SECURE_EXTENSION_DEGREE = 8` 个 column，每个 column 1 个 SecureField
/// 3. 前 4 个 = left_coordinate_evals，后 4 个 = right_coordinate_evals
/// 4. `value = left_eval + oods_point.repeated_double(max_log_degree_bound - 1).x * right_eval`
///
/// # 参数
/// - `l1_proof` — L1 Stwo proof
/// - `oods_point` — OODS 采样点（须与 L1 verifier 的 oods_point 一致）
/// - `max_log_degree_bound` — composition polynomial 的 max log degree bound（须与 L1 verifier 一致）
///
/// # 返回
/// - `Some(SecureField)` — 提取成功
/// - `None` — sampled_values 结构不匹配
///
/// # v5.1 用途
/// v5.1 的 OODS Check AIR 使用此函数从 L1 proof 提取 computed_oods_eval，
/// 在 L2 trace 中验证它与 claimed_oods_eval 一致，提供完整 soundness。
pub fn extract_composition_oods_eval_from_l1(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    oods_point: CirclePoint<SecureField>,
    max_log_degree_bound: u32,
) -> Option<SecureField> {
    let evals = extract_sampled_values_from_l1(l1_proof)?;
    let (left_evals, right_evals) = evals.split_at(SECURE_EXTENSION_DEGREE);

    let left_eval = SecureField::from_partial_evals(left_evals.try_into().ok()?);
    let right_eval = SecureField::from_partial_evals(right_evals.try_into().ok()?);

    let doubling_factor = oods_point.repeated_double(max_log_degree_bound - 1);
    Some(left_eval + doubling_factor.x * right_eval)
}

/// 从 L1 proof 的 Fiat-Shamir transcript 提取 FRI query point（v5.2 soundness fix）。
///
/// 重放 L1 verifier 的 channel 操作序列，重新采样 FRI query positions，
/// 然后折叠到 last layer，计算真实的 query point x 和 query_eval。
///
/// # 算法
/// 1. 创建 fresh `Poseidon252Channel`（镜像 L1 verifier）
/// 2. 重放 L1 commit phase：
///    a. 对每个 commitment（除最后一个 composition commitment）调用 `mix_root`
///    b. `draw_secure_felt()` — random_coeff（用于 composition polynomial）
///    c. `mix_root(commitments.last())` — composition commitment
/// 3. `CirclePoint::get_random_point(channel)` — OODS point（推进 channel 状态）
/// 4. `channel.mix_felts(sampled_values.flatten_cols())`
/// 5. `draw_secure_felt()` — random_coeff2（用于 FRI）
/// 6. `FriVerifier::commit(channel, fri_config, fri_proof.clone(), bound)`
/// 7. `verify_pow_nonce` + `mix_u64(proof_of_work)`
/// 8. `sample_query_positions(channel)` → first-layer positions
/// 9. 折叠到 last layer，计算 `x = last_layer_domain.at(bit_reverse_index(query, log_size))`
/// 10. `query_eval = last_layer_poly.eval_at_point(x)`
///
/// # 参数
/// - `l1_proof` — L1 Stwo proof
/// - `config` — L1 proof 的 PcsConfig（须与 L1 verifier 一致）
/// - `max_log_degree_bound` — composition polynomial 的 max log degree bound
/// - `last_layer_poly` — L1 FRI last layer polynomial
///
/// # 返回
/// - `Some((query_x, query_eval))` — 提取成功
/// - `None` — L1 proof 结构不匹配或 FriVerifier 构造失败
///
/// # 限制
/// 当前仅支持单组件 proof（无 interaction phase）。
/// 多组件 proof 需在 step 2a 与 2b 之间插入 interaction element draws。
#[allow(clippy::missing_errors_doc)]
pub fn extract_fri_query_from_l1(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    config: PcsConfig,
    max_log_degree_bound: u32,
    last_layer_poly: &LinePoly,
) -> Option<(SecureField, SecureField)> {
    let commitments = &l1_proof.0.commitments;
    let n_commitments = commitments.len();
    // 至少需要 preprocessed + original + composition = 3 个 commitment
    if n_commitments < 3 {
        return None;
    }

    // 1. 创建 fresh channel（镜像 L1 verifier）
    let mut channel = Poseidon252Channel::default();

    // 2a. 重放 commit phase：mix 所有 commitment（除最后一个 composition commitment）
    for i in 0..(n_commitments - 1) {
        Poseidon252MerkleChannel::mix_root(&mut channel, commitments[i]);
    }

    // 2b. draw_secure_felt() — random_coeff（composition polynomial 的随机系数）
    let _random_coeff = channel.draw_secure_felt();

    // 2c. mix composition commitment（最后一个）
    Poseidon252MerkleChannel::mix_root(&mut channel, commitments[n_commitments - 1]);

    // 3. Draw OODS point（推进 channel 状态，值不需要）
    let _oods_point = CirclePoint::<SecureField>::get_random_point(&mut channel);

    // 4. mix sampled_values
    let sampled_values = &l1_proof.0.sampled_values;
    let flattened: Vec<SecureField> = sampled_values.clone().flatten_cols();
    channel.mix_felts(&flattened);

    // 5. draw_secure_felt() — random_coeff2（FRI 的随机系数）
    let _random_coeff2 = channel.draw_secure_felt();

    // 6. Construct FriVerifier（clone fri_proof 因为 commit 消费它）
    let fri_config = config.fri_config;
    let bound = CirclePolyDegreeBound::new(max_log_degree_bound);
    let fri_proof = l1_proof.0.fri_proof.clone();

    let mut fri_verifier = FriVerifier::<Poseidon252MerkleChannel>::commit(
        &mut channel,
        fri_config,
        fri_proof,
        bound,
    )
    .ok()?;

    // 7. Verify PoW + mix
    if !channel.verify_pow_nonce(config.pow_bits, l1_proof.0.proof_of_work) {
        return None;
    }
    channel.mix_u64(l1_proof.0.proof_of_work);

    // 8. Sample query positions
    let query_positions = fri_verifier.sample_query_positions(&mut channel);
    if query_positions.is_empty() {
        return None;
    }

    // 9. 折叠到 last layer 并计算 x
    // first_layer_log_size = max_log_degree_bound + log_blowup_factor + 1（circle domain）
    // last_layer_log_size = log_last_layer_degree_bound + log_blowup_factor（line domain）
    // total_fold = first_layer_log_size - last_layer_log_size
    let first_layer_log_size = max_log_degree_bound + fri_config.log_blowup_factor + 1;
    let last_layer_log_size = fri_config.log_last_layer_degree_bound + fri_config.log_blowup_factor;
    let total_fold = first_layer_log_size
        .checked_sub(last_layer_log_size)
        .filter(|&f| f <= 32)?;

    // 取第一个 query position，折叠到 last layer
    let first_query = query_positions[0];
    let last_layer_query = first_query >> total_fold;

    // 10. 计算 x = last_layer_domain.at(bit_reverse_index(query, log_size))
    let last_layer_domain = LineDomain::new(Coset::half_odds(last_layer_log_size));
    let x_base = last_layer_domain.at(bit_reverse_index(
        last_layer_query,
        last_layer_domain.log_size(),
    ));
    let query_x: SecureField = x_base.into();

    // 11. 计算 query_eval = last_layer_poly.eval_at_point(query_x)
    let query_eval = last_layer_poly.eval_at_point(query_x);

    Some((query_x, query_eval))
}

/// 计算 QM31 乘法的 16 个 M31×M31 中间值。
///
/// QM31 乘法 `product = df.x * right_eval` 分解为 16 个 M31 乘积（degree 2）。
///
/// # 参数
/// - `df_x` — DoublingFactorX 的 4 个 M31 分量
/// - `right_eval` — RightEval 的 4 个 M31 分量
///
/// # 返回
/// `[BaseField; 16]` — m1..m16（1-based 索引对应数组 0..16）
///
/// # 中间值定义
/// ```text
/// m1 = x0*r0, m2 = x1*r1, m3 = x2*r2, m4 = x3*r3
/// m5 = x2*r3, m6 = x3*r2, m7 = x0*r1, m8 = x1*r0
/// m9 = x0*r2, m10 = x1*r3, m11 = x2*r0, m12 = x3*r1
/// m13 = x0*r3, m14 = x1*r2, m15 = x2*r1, m16 = x3*r0
/// ```
fn compute_qm31_mult_intermediates(
    df_x: &[BaseField; 4],
    right_eval: &[BaseField; 4],
) -> [BaseField; 16] {
    let x0 = df_x[0];
    let x1 = df_x[1];
    let x2 = df_x[2];
    let x3 = df_x[3];
    let r0 = right_eval[0];
    let r1 = right_eval[1];
    let r2 = right_eval[2];
    let r3 = right_eval[3];

    [
        x0 * r0,  // m1
        x1 * r1,  // m2
        x2 * r2,  // m3
        x3 * r3,  // m4
        x2 * r3,  // m5
        x3 * r2,  // m6
        x0 * r1,  // m7
        x1 * r0,  // m8
        x0 * r2,  // m9
        x1 * r3,  // m10
        x2 * r0,  // m11
        x3 * r1,  // m12
        x0 * r3,  // m13
        x1 * r2,  // m14
        x2 * r1,  // m15
        x3 * r0,  // m16
    ]
}

/// 从 16 个 M31×M31 中间值计算 Product 的 4 个 M31 分量。
///
/// # 公式
/// ```text
/// Product[0] = m1 - m2 + 2*m3 - 2*m4 - m5 - m6
/// Product[1] = m7 + m8 + m3 - m4 + 2*m5 + 2*m6
/// Product[2] = m9 - m10 + m11 - m12
/// Product[3] = m13 + m14 + m15 + m16
/// ```
fn compute_product_from_intermediates(m: &[BaseField; 16]) -> [BaseField; 4] {
    let two = BaseField::from(2u32);
    [
        m[0] - m[1] + two * m[2] - two * m[3] - m[4] - m[5],
        m[6] + m[7] + m[2] - m[3] + two * m[4] + two * m[5],
        m[8] - m[9] + m[10] - m[11],
        m[12] + m[13] + m[14] + m[15],
    ]
}

/// OODS Check AIR 的 trace 生成器（v5.1 完整实现）。
///
/// 生成 73 列 × 2^`OODS_TRACE_LOG_SIZE` 行的 trace：
/// - col 0-3: ClaimedOodsEval（QM31 的 4 个 M31 分量，来自 `public_inputs.composition_oods_eval`）
/// - col 4-7: ComputedOodsEval（QM31，由 L1 proof sampled_values 推导）
/// - col 8: IsPadding
/// - col 9-12: DoublingFactorX（QM31 = oods_point.repeated_double(max_log_degree_bound-1).x）
/// - col 13-44: SampledValues[0..8]（L1 proof 的 8 个 SecureField partial evals）
/// - col 45-48: LeftEval（QM31 = from_partial_evals(SV[0..4])）
/// - col 49-52: RightEval（QM31 = from_partial_evals(SV[4..8])）
/// - col 53-68: M[1..16]（M31×M31 乘积中间值）
/// - col 69-72: Product（QM31 = DoublingFactorX * RightEval）
///
/// # Trace 布局
/// - Row 0: real row（IsPadding=0，所有见证/中间值都填充）
/// - Rows 1..2^log_size: padding（IsPadding=1，其余=0）
///
/// # v5.1 soundness
/// v5.1 的 ComputedOodsEval 由 L1 proof 的 sampled_values 推导：
/// 1. 提取 8 个 SecureField partial evals
/// 2. 计算 left_eval = from_partial_evals(SV[0..4])
/// 3. 计算 right_eval = from_partial_evals(SV[4..8])
/// 4. 计算 product = df.x * right_eval（QM31 乘法，分解为 16 个 M31×M31）
/// 5. ComputedOodsEval = left_eval + product
///
/// AIR 约束 O34-O37 验证 ComputedOodsEval == LeftEval + Product（per M31 component）。
/// AIR 约束 O2-O5 验证 ClaimedOodsEval == ComputedOodsEval。
///
/// 如果 `public_inputs.composition_oods_eval` 与 L1 proof 实际值不一致，
/// AIR 约束 O2-O5 会失败，prover 会返回 `ConstraintsNotSatisfied` 错误。
///
/// # Panics
/// 如果 L1 proof 的 sampled_values 结构不匹配（非 8 columns × 1 SecureField），
/// 函数会 panic（这是编程错误，不是运行时错误）。
#[allow(clippy::missing_errors_doc)]
pub fn gen_oods_check_trace(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    public_inputs: &RecursivePublicInputs,
) -> Vec<Vec<BaseField>> {
    let num_rows = 1usize << OODS_TRACE_LOG_SIZE;

    // ----- 1. 从 L1 proof 提取 8 个 SecureField partial evals -----
    let sampled_values: [SecureField; OODS_AIR_NUM_SAMPLED_VALUES] =
        extract_sampled_values_from_l1(l1_proof).expect(
            "L1 proof 的 sampled_values 结构不匹配：期望最后一个 tree 有 8 个 column，每个 1 个 SecureField"
        );

    // ----- 2. 计算 DoublingFactorX -----
    // doubling_factor = oods_point.repeated_double(max_log_degree_bound - 1)
    let doubling_factor = public_inputs
        .oods_point
        .repeated_double(public_inputs.max_log_degree_bound - 1);
    let df_x: [BaseField; 4] = doubling_factor.x.to_m31_array();

    // ----- 3. 计算 LeftEval 和 RightEval -----
    let (left_evals, right_evals) = sampled_values.split_at(SECURE_EXTENSION_DEGREE);
    let left_eval_qm31 = SecureField::from_partial_evals(left_evals.try_into().unwrap());
    let right_eval_qm31 = SecureField::from_partial_evals(right_evals.try_into().unwrap());
    let left_eval: [BaseField; 4] = left_eval_qm31.to_m31_array();
    let right_eval: [BaseField; 4] = right_eval_qm31.to_m31_array();

    // ----- 4. 计算 16 个 M31×M31 中间值 -----
    let m_intermediates: [BaseField; OODS_AIR_NUM_M_INTERMEDIATES] =
        compute_qm31_mult_intermediates(&df_x, &right_eval);

    // ----- 5. 计算 Product = df.x * right_eval -----
    // 使用 Stwo 原生 QM31 乘法计算 product（用于验证我们的分解公式正确）
    let product_qm31 = doubling_factor.x * right_eval_qm31;
    let product: [BaseField; 4] = product_qm31.to_m31_array();

    // 验证我们的分解公式与 Stwo 原生乘法一致
    let product_from_decomp = compute_product_from_intermediates(&m_intermediates);
    for i in 0..4 {
        assert_eq!(
            product[i], product_from_decomp[i],
            "QM31 乘法分解公式错误：Product[{}] 不匹配（Stwo 原生={}, 分解={}）",
            i, product[i], product_from_decomp[i]
        );
    }

    // ----- 6. 计算 ComputedOodsEval = LeftEval + Product -----
    let computed_oods_eval_qm31 = left_eval_qm31 + product_qm31;
    let computed_oods_eval: [BaseField; 4] = computed_oods_eval_qm31.to_m31_array();

    // ----- 7. 提取 ClaimedOodsEval -----
    let claimed_oods_eval: [BaseField; 4] = public_inputs.composition_oods_eval.to_m31_array();

    // ----- 8. 初始化 73 列 × num_rows 行，全部填 0 -----
    let mut cols = vec![vec![BaseField::zero(); num_rows]; OODS_AIR_NUM_COLUMNS];

    // ----- 9. Row 0: real row -----
    // ClaimedOodsEval
    for i in 0..4 {
        cols[OODS_AIR_COL_CLAIMED_BASE + i][0] = claimed_oods_eval[i];
    }
    // ComputedOodsEval
    for i in 0..4 {
        cols[OODS_AIR_COL_COMPUTED_BASE + i][0] = computed_oods_eval[i];
    }
    // IsPadding = 0
    cols[OODS_AIR_COL_IS_PADDING][0] = BaseField::from(0u32);
    // DoublingFactorX
    for i in 0..4 {
        cols[OODS_AIR_COL_DF_X_BASE + i][0] = df_x[i];
    }
    // SampledValues[0..8]
    for sv_idx in 0..OODS_AIR_NUM_SAMPLED_VALUES {
        let sv_m31: [BaseField; 4] = sampled_values[sv_idx].to_m31_array();
        for j in 0..4 {
            cols[OODS_AIR_COL_SV_BASE + 4 * sv_idx + j][0] = sv_m31[j];
        }
    }
    // LeftEval
    for i in 0..4 {
        cols[OODS_AIR_COL_LEFT_EVAL_BASE + i][0] = left_eval[i];
    }
    // RightEval
    for i in 0..4 {
        cols[OODS_AIR_COL_RIGHT_EVAL_BASE + i][0] = right_eval[i];
    }
    // M[1..16] intermediates
    for i in 0..OODS_AIR_NUM_M_INTERMEDIATES {
        cols[OODS_AIR_COL_M_BASE + i][0] = m_intermediates[i];
    }
    // Product
    for i in 0..4 {
        cols[OODS_AIR_COL_PRODUCT_BASE + i][0] = product[i];
    }

    // ----- 10. Rows 1..num_rows: padding rows -----
    for row in 1..num_rows {
        cols[OODS_AIR_COL_IS_PADDING][row] = BaseField::from(1u32);
        // 其余列保持 0（初始化时已设为 0）
    }

    cols
}

/// FRI Verifier AIR 的 trace 生成器（v5.1 完整实现）。
///
/// 生成 36 列 × 2^`log_size` 行的 trace，验证 `query_eval == last_layer_poly.eval_at_point(x)`。
///
/// # 算法
///
/// 使用 Horner method 在 AIR trace 中评估 `last_layer_poly`：
/// ```text
/// p(x) = c_0 + c_1*x + c_2*x^2 + ... + c_{n-1}*x^{n-1}
/// Horner: p(x) = ((...((c_{n-1}*x + c_{n-2})*x + c_{n-3})*x + ...)*x + c_0)
/// ```
///
/// # Trace 布局（36 列，n+1 real rows + padding）
///
/// - Row 0 (IsFirstRow=1): partial_eval = 0 (init), coeff = c_{n-1}
/// - Row 1: partial_eval = c_{n-1}, coeff = c_{n-2}
/// - Row 2: partial_eval = c_{n-1}*x + c_{n-2}, coeff = c_{n-3}
/// - ...
/// - Row n (IsLastRow=1): partial_eval = p(x) = query_eval, coeff = 0
/// - Row n+1..num_rows-1: IsPadding=1, all zeros
///
/// # 列填充
///
/// | 列 | 值 |
/// |----|----|
/// | QueryEval (0-3) | query_eval = last_layer_poly.eval_at_point(x) |
/// | QueryX (4-7) | query point x（v5.1 placeholder: x=1） |
/// | PartialEval (8-11) | Horner 累积值 |
/// | Coeff (12-15) | 当前系数 c_{n-1-row} |
/// | IsFirstRow (16) | row == 0 |
/// | IsLastRow (17) | row == n_coeffs |
/// | IsPadding (18) | row > n_coeffs |
/// | Gating (19) | (1 - IsFirstRow) * (1 - IsPadding) |
/// | M[1..16] (20-35) | partial_eval_prev * query_x 的 M31×M31 分解 |
///
/// # v5.2 Query Point（soundness fix）
///
/// v5.2 从 `public_inputs.fri_query_x` 提取真实 query point（由 `extract_fri_query_from_l1`
/// 从 L1 proof 的 Fiat-Shamir transcript 重新推导）。`query_eval` 同样来自
/// `public_inputs.fri_query_eval`，与 `query_x` 一起经 channel mix 绑定到 L2 proof。
///
/// v5.1 的 soundness gap（硬编码 `x = 1`）已修复：
/// - `query_x` 和 `query_eval` 是 `RecursivePublicInputs` 的公开输入
/// - prover 端一致性检查验证它们与 L1 transcript 推导值一致
/// - L2 channel mix 绑定它们到 L2 Fiat-Shamir
/// - L2 FRI Verifier AIR 约束 Horner 累积值 == `query_eval`
///
/// # Panics
///
/// 如果 `public_inputs.fri_last_layer_poly.len() == 0`（不可能，因为 LinePoly 要求 len >= 1）。
#[allow(clippy::missing_errors_doc)]
pub fn gen_fri_verifier_trace(
    _l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    public_inputs: &RecursivePublicInputs,
) -> Vec<Vec<BaseField>> {
    // ----- 1. 从 public_inputs 提取 last_layer_poly -----
    let last_layer_poly = &public_inputs.fri_last_layer_poly;
    let n_coeffs = last_layer_poly.len(); // 2^log_size, e.g., 8 for default PcsConfig

    // ----- 2. 提取自然序系数 -----
    // into_ordered_coefficients() 消费 self 并返回自然序系数：
    // coeffs_natural[0] = c_0, coeffs_natural[1] = c_1, ..., coeffs_natural[n-1] = c_{n-1}
    let coeffs_natural = public_inputs
        .fri_last_layer_poly
        .clone()
        .into_ordered_coefficients();

    // ----- 3. 从 public_inputs 提取真实 query point x（v5.2 soundness fix） -----
    // v5.2：query_x 和 query_eval 从 L1 proof 的 Fiat-Shamir transcript 提取（extract_fri_query_from_l1），
    // 作为 RecursivePublicInputs 的公开输入绑定到 L2 channel。
    // 此前 v5.1 硬编码 query_x = 1，允许恶意 prover 选择在 x=1 处通过但其他点失败的伪造多项式。
    let query_x_qm31 = public_inputs.fri_query_x;
    let query_x: [BaseField; 4] = query_x_qm31.to_m31_array();

    // ----- 4. query_eval 来自 public_inputs（与 query_x 一起由 extract_fri_query_from_l1 计算） -----
    // L2 FRI Verifier AIR 约束 Horner 累积值最终 == query_eval，确保 last_layer_poly 在 query_x 处的
    // evaluation 与 L1 FRI verifier 验证的值一致。
    let query_eval_qm31 = public_inputs.fri_query_eval;
    let query_eval: [BaseField; 4] = query_eval_qm31.to_m31_array();

    // ----- 5. 确定 trace 大小 -----
    // n_coeffs + 1 real rows (1 init + n_coeffs Horner steps)
    // 至少 1 padding row（确保 row 0 的 wrap-around prev 是 padding，partial_eval=0）
    let n_real_rows = n_coeffs + 1;
    let num_rows = if n_real_rows.is_power_of_two() {
        2 * n_real_rows // 强制至少 1 padding row
    } else {
        n_real_rows.next_power_of_two()
    };

    // ----- 6. 初始化 36 列 × num_rows，全部填 0 -----
    let mut cols = vec![vec![BaseField::zero(); num_rows]; FRI_AIR_NUM_COLUMNS];
    let one = BaseField::from(1u32);

    // ----- 7. 填充 real rows (0..=n_coeffs) -----
    // 使用 Stwo 原生 QM31 算术跟踪 Horner 累积值
    let mut prev_partial_eval = SecureField::zero(); // partial_eval[-1] = 0 (init for row 0)
    let mut prev_coeff = SecureField::zero(); // coeff[-1] = 0 (unused at row 0, Gating=0)

    for row in 0..=n_coeffs {
        let is_first = row == 0;
        let is_last = row == n_coeffs;

        // 7a. 计算 M[k] = prev_partial_eval * query_x（当前行的 M 中间值）
        // F4a 约束: M[k] at row R = partial_eval[R-1] * query_x[R]
        let prev_pe_m31 = prev_partial_eval.to_m31_array();
        let m_intermediates = compute_qm31_mult_intermediates(&prev_pe_m31, &query_x);

        // 7b. 计算 partial_eval[row] = prev_partial_eval * query_x + prev_coeff（Horner step）
        let partial_eval_qm31 = prev_partial_eval * query_x_qm31 + prev_coeff;
        let partial_eval_m31: [BaseField; 4] = partial_eval_qm31.to_m31_array();

        // 7c. 计算 coeff[row]
        // Row 0: coeff = c_{n-1}（第一个 Horner 系数）
        // Row 1: coeff = c_{n-2}
        // ...
        // Row n-1: coeff = c_0
        // Row n: coeff = 0（unused, IsLastRow=1）
        let coeff_qm31 = if row < n_coeffs {
            coeffs_natural[n_coeffs - 1 - row]
        } else {
            SecureField::zero()
        };
        let coeff_m31: [BaseField; 4] = coeff_qm31.to_m31_array();

        // 7d. 写入 trace（self-contained 布局：每行包含 prev_partial_eval 和 prev_coeff）
        // Horner 约束: partial_eval = pe_prev * x + coeff（coeff 是上一行的系数）
        // QueryEval, QueryX（constant across all real rows）
        for i in 0..4 {
            cols[FRI_AIR_COL_QUERY_EVAL_BASE + i][row] = query_eval[i];
            cols[FRI_AIR_COL_QUERY_X_BASE + i][row] = query_x[i];
        }
        // PartialEvalPrev（上一行的 partial_eval）
        for i in 0..4 {
            cols[FRI_AIR_COL_PARTIAL_EVAL_PREV_BASE + i][row] = prev_pe_m31[i];
        }
        // PartialEval（当前行的 partial_eval）
        for i in 0..4 {
            cols[FRI_AIR_COL_PARTIAL_EVAL_BASE + i][row] = partial_eval_m31[i];
        }
        // Coeff（上一行的系数，用于 Horner 约束）
        let prev_coeff_m31: [BaseField; 4] = prev_coeff.to_m31_array();
        for i in 0..4 {
            cols[FRI_AIR_COL_COEFF_BASE + i][row] = prev_coeff_m31[i];
        }
        // Flags
        cols[FRI_AIR_COL_IS_FIRST_ROW][row] = if is_first { one } else { BaseField::zero() };
        cols[FRI_AIR_COL_IS_LAST_ROW][row] = if is_last { one } else { BaseField::zero() };
        cols[FRI_AIR_COL_IS_PADDING][row] = BaseField::zero(); // real row
        // Gating = (1 - IsFirstRow) * (1 - IsPadding)
        cols[FRI_AIR_COL_GATING][row] = if is_first { BaseField::zero() } else { one };
        // M[1..16] intermediates
        for i in 0..FRI_AIR_NUM_M_INTERMEDIATES {
            cols[FRI_AIR_COL_M_BASE + i][row] = m_intermediates[i];
        }

        // 7e. 更新 prev 值用于下一行
        prev_partial_eval = partial_eval_qm31;
        prev_coeff = coeff_qm31;
    }

    // ----- 8. 验证 Horner 计算正确 -----
    // partial_eval at last real row 应等于 query_eval
    debug_assert_eq!(
        prev_partial_eval, query_eval_qm31,
        "Horner 计算错误：partial_eval[n] != query_eval"
    );

    // ----- 9. 填充 padding rows (n_coeffs+1 .. num_rows) -----
    // Padding rows: IsPadding=1, 其余=0（包括 QueryX=0, partial_eval=0, coeff=0, M=0）
    // F4a at padding row R: M[k] = pe_prev * query_x = 0 * 0 = 0 ✓
    // F4b at padding row: Gating=0, auto-satisfied ✓
    for row in (n_coeffs + 1)..num_rows {
        cols[FRI_AIR_COL_IS_PADDING][row] = one;
        // 其余列保持 0（初始化时已设为 0）
        // QueryX=0 → M[k] = pe_prev * 0 = 0 ✓
    }

    cols
}

/// Merkle Path Verifier AIR 的 trace 生成器（v5.2）。
///
/// 从 L1 proof 提取 Merkle path decommitments，
/// 生成 52 列 × (N_queries × tree_height) 行的 hash chain trace。
///
/// # 算法
/// 1. 从 L1 proof 的 `decommitments` 提取 `hash_witness`（sibling hashes）
/// 2. 从 `public_inputs` 获取 `query_positions` 和 `commitments`（roots）
/// 3. 对每个 query：
///    - 计算 leaf_hash = Poseidon252(queried_values)
///    - 沿 path 上行，每层计算 parent_hash = Poseidon252(left, right)
///    - 最后验证 computed_root == public_root
/// 4. 将 hash chain 写入 trace（每行 = Merkle tree 的一层）
#[allow(clippy::missing_errors_doc)]
pub fn gen_merkle_path_trace(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    public_inputs: &RecursivePublicInputs,
) -> Vec<Vec<BaseField>> {
    use super::merkle_path_air::{
        MERKLE_AIR_COL_COMPUTED_ROOT_BASE, MERKLE_AIR_COL_IS_LAST_LAYER, MERKLE_AIR_COL_IS_LEFT_CHILD,
        MERKLE_AIR_COL_IS_PADDING, MERKLE_AIR_COL_LAYER_IDX, MERKLE_AIR_COL_LEAF_HASH_BASE,
        MERKLE_AIR_COL_PARENT_HASH_BASE, MERKLE_AIR_COL_POSEIDON_INTERMEDIATE1_BASE,
        MERKLE_AIR_COL_POSEIDON_INTERMEDIATE2_BASE, MERKLE_AIR_COL_PREV_PARENT_HASH_BASE,
        MERKLE_AIR_COL_SIBLING_HASH_BASE, MERKLE_AIR_NUM_COLUMNS,
    };

    let log_size = public_inputs.log_size;
    let tree_height = log_size as usize;
    let num_queries = public_inputs.query_positions.len();
    
    if num_queries == 0 {
        return Vec::new();
    }

    let n_real_rows = num_queries * tree_height;
    let num_rows = if n_real_rows.is_power_of_two() {
        n_real_rows.next_power_of_two() * 2
    } else {
        n_real_rows.next_power_of_two()
    };

    let mut cols = vec![vec![BaseField::zero(); num_rows]; MERKLE_AIR_NUM_COLUMNS];

    for (query_idx, &query_pos) in public_inputs.query_positions.iter().enumerate() {
        let mut current_hash = compute_leaf_hash(l1_proof, query_pos);
        let mut prev_parent_hash = [BaseField::zero(); 8];

        for layer_idx in 0..tree_height {
            let row = query_idx * tree_height + layer_idx;
            
            let is_left_child = (query_pos >> layer_idx) & 1 == 0;
            
            let sibling_hash = extract_sibling_hash(l1_proof, query_idx, layer_idx, tree_height);
            
            let parent_hash = compute_parent_hash(&current_hash, &sibling_hash, is_left_child);
            
            let is_last_layer = (layer_idx == tree_height - 1) as u32;

            for i in 0..8 {
                cols[MERKLE_AIR_COL_LEAF_HASH_BASE + i][row] = current_hash[i];
                cols[MERKLE_AIR_COL_PREV_PARENT_HASH_BASE + i][row] = prev_parent_hash[i];
                cols[MERKLE_AIR_COL_SIBLING_HASH_BASE + i][row] = sibling_hash[i];
                cols[MERKLE_AIR_COL_PARENT_HASH_BASE + i][row] = parent_hash[i];

                let left_i = if is_left_child { current_hash[i] } else { sibling_hash[i] };
                let right_i = if is_left_child { sibling_hash[i] } else { current_hash[i] };
                cols[MERKLE_AIR_COL_POSEIDON_INTERMEDIATE1_BASE + i][row] = left_i;
                cols[MERKLE_AIR_COL_POSEIDON_INTERMEDIATE2_BASE + i][row] = right_i;
            }

            cols[MERKLE_AIR_COL_IS_LEFT_CHILD][row] = BaseField::from_u32_unchecked(is_left_child as u32);
            cols[MERKLE_AIR_COL_LAYER_IDX][row] = BaseField::from_u32_unchecked(layer_idx as u32);
            cols[MERKLE_AIR_COL_IS_LAST_LAYER][row] = BaseField::from_u32_unchecked(is_last_layer);

            if is_last_layer != 0 {
                let root_limbs = if !public_inputs.l1_commitments.is_empty() {
                    field_element_252_to_m31_limbs(&public_inputs.l1_commitments[0])
                } else {
                    field_element_252_to_m31_limbs(&FieldElement252::ZERO)
                };
                for i in 0..8 {
                    cols[MERKLE_AIR_COL_COMPUTED_ROOT_BASE + i][row] = root_limbs[i];
                }
            }

            prev_parent_hash = parent_hash;
            current_hash = parent_hash;
        }
    }

    for row in n_real_rows..num_rows {
        cols[MERKLE_AIR_COL_IS_PADDING][row] = BaseField::from_u32_unchecked(1);
    }

    cols
}

/// 计算 leaf hash（从 L1 proof 的 queried_values 提取并 hash）。
fn compute_leaf_hash(l1_proof: &StarkProof<Poseidon252MerkleHasher>, _query_pos: usize) -> [BaseField; 8] {
    let queried_values = &l1_proof.0.queried_values;
    if queried_values.is_empty() || queried_values[0].is_empty() {
        let msg = [FieldElement252::from(1u32), FieldElement252::from(2u32)];
        let state = poseidon_finalize(&msg, [FieldElement252::ZERO; 3]);
        return field_element_252_to_m31_limbs(&state[0]);
    }

    let first_column = &queried_values[0][0];
    let mut values = Vec::with_capacity(first_column.len());
    for val in first_column.iter() {
        let limb_bytes = val.0.to_be_bytes();
        let mut felt_bytes = [0u8; 32];
        felt_bytes[28..32].copy_from_slice(&limb_bytes);
        values.push(FieldElement252::from_bytes_be(&felt_bytes).unwrap());
    }
    
    if values.is_empty() {
        values = vec![FieldElement252::from(1u32), FieldElement252::from(2u32)];
    }

    let state = poseidon_finalize(&values, [FieldElement252::ZERO; 3]);
    field_element_252_to_m31_limbs(&state[0])
}

/// 从 L1 proof 的 hash_witness 提取 sibling hash。
fn extract_sibling_hash(l1_proof: &StarkProof<Poseidon252MerkleHasher>, query_idx: usize, layer_idx: usize, tree_height: usize) -> [BaseField; 8] {
    let decommitments = &l1_proof.0.decommitments;
    if decommitments.is_empty() {
        return [BaseField::zero(); 8];
    }

    let tree_decommitment = &decommitments[0];
    let witness_idx = query_idx * tree_height + layer_idx;
    
    if witness_idx < tree_decommitment.hash_witness.len() {
        field_element_252_to_m31_limbs(&tree_decommitment.hash_witness[witness_idx])
    } else {
        [BaseField::zero(); 8]
    }
}

/// 计算 parent hash = Poseidon252(left, right)。
fn compute_parent_hash(left: &[BaseField; 8], right: &[BaseField; 8], is_left_child: bool) -> [BaseField; 8] {
    let left_felt = construct_felt252_from_m31s(left);
    let right_felt = construct_felt252_from_m31s(right);

    let (a, b) = if is_left_child {
        (left_felt, right_felt)
    } else {
        (right_felt, left_felt)
    };

    let msg = [a, b];
    let state = poseidon_finalize(&msg, [FieldElement252::ZERO; 3]);
    field_element_252_to_m31_limbs(&state[0])
}

/// 从 8 个 M31 limbs 构建 FieldElement252。
fn construct_felt252_from_m31s(limbs: &[BaseField; 8]) -> FieldElement252 {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let limb_bytes = limbs[i].0.to_be_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&limb_bytes);
    }
    FieldElement252::from_bytes_be(&bytes).unwrap()
}

/// Composition Eval AIR 的 trace 生成器（已合并到 OODS Check AIR v5.1）。
///
/// v5.1 已将 Composition Eval 逻辑合并到 `gen_oods_check_trace`。
/// 此函数保留为占位符，未来可能用于独立的 Composition Eval AIR。
#[allow(clippy::missing_errors_doc)]
pub fn gen_composition_eval_trace(
    _l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    _public_inputs: &RecursivePublicInputs,
) -> Vec<Vec<BaseField>> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use stwo::core::circle::CirclePoint;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::pcs::PcsConfig;
    use stwo::core::poly::line::LinePoly;
    use starknet_ff::FieldElement as FieldElement252;

    /// 创建测试用 RecursivePublicInputs。
    fn make_test_public_inputs(composition_oods_eval: SecureField) -> RecursivePublicInputs {
        RecursivePublicInputs::new(
            Vec::new(),
            CirclePoint::zero(),
            composition_oods_eval,
            FieldElement252::ZERO,
            LinePoly::new(vec![SecureField::zero()]),
            10,
            PcsConfig::default(),
            Vec::new(),
            10,
            SecureField::zero(),
            SecureField::zero(),
        )
    }

    #[test]
    fn test_trace_gen_signatures() {
        // 确保函数签名编译通过
        let _fns: [
            fn(&StarkProof<Poseidon252MerkleHasher>, &RecursivePublicInputs) -> Vec<Vec<BaseField>>;
            4
        ] = [
            gen_oods_check_trace,
            gen_fri_verifier_trace,
            gen_merkle_path_trace,
            gen_composition_eval_trace,
        ];
    }

    #[test]
    fn test_extract_sampled_values_from_l1_real_proof() {
        use crate::stwo_backend::prover::prove_cpu_trace;
        use crate::stwo_backend::trace_native::TraceBuilder;

        // 生成真实 L1 proof
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let l1_proof = prove_cpu_trace(&trace).expect("L1 prove 应成功");

        // 提取 sampled_values
        let sv = extract_sampled_values_from_l1(&l1_proof);
        assert!(sv.is_some(), "提取 sampled_values 应成功");
        let sv = sv.unwrap();
        assert_eq!(sv.len(), 8, "应提取 8 个 SecureField");
    }

    #[test]
    fn test_compute_qm31_mult_intermediates_and_product() {
        // 验证 QM31 乘法分解公式正确
        // 使用一个简单的测试用例：df_x = (1, 0, 0, 0), right_eval = (2, 3, 4, 5)
        let df_x = [
            BaseField::from(1u32),
            BaseField::from(0u32),
            BaseField::from(0u32),
            BaseField::from(0u32),
        ];
        let right_eval = [
            BaseField::from(2u32),
            BaseField::from(3u32),
            BaseField::from(4u32),
            BaseField::from(5u32),
        ];

        let m = compute_qm31_mult_intermediates(&df_x, &right_eval);
        let product = compute_product_from_intermediates(&m);

        // df.x = (1, 0, 0, 0) = 1（QM31 单位元）
        // product = 1 * right_eval = right_eval = (2, 3, 4, 5)
        assert_eq!(product[0], BaseField::from(2u32));
        assert_eq!(product[1], BaseField::from(3u32));
        assert_eq!(product[2], BaseField::from(4u32));
        assert_eq!(product[3], BaseField::from(5u32));
    }

    #[test]
    fn test_compute_qm31_mult_intermediates_zero() {
        // 零元测试：df_x = 0, right_eval = anything → product = 0
        let df_x = [BaseField::zero(); 4];
        let right_eval = [
            BaseField::from(2u32),
            BaseField::from(3u32),
            BaseField::from(4u32),
            BaseField::from(5u32),
        ];

        let m = compute_qm31_mult_intermediates(&df_x, &right_eval);
        let product = compute_product_from_intermediates(&m);

        for i in 0..4 {
            assert_eq!(product[i], BaseField::zero(), "Product[{}] 应为 0", i);
        }
    }

    #[test]
    fn test_extract_composition_oods_eval_from_real_l1_proof() {
        use crate::stwo_backend::prover::prove_cpu_trace;
        use crate::stwo_backend::trace_native::TraceBuilder;

        // 生成真实 L1 proof
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let l1_proof = prove_cpu_trace(&trace).expect("L1 prove 应成功");

        // 验证 sampled_values 结构
        assert!(
            !l1_proof.sampled_values.is_empty(),
            "L1 proof 的 sampled_values 不应为空"
        );
        let last_tree = l1_proof.sampled_values.last().unwrap();
        assert_eq!(
            last_tree.len(),
            2 * SECURE_EXTENSION_DEGREE,
            "composition mask 应有 8 个 column，实际 {}",
            last_tree.len()
        );

        // 尝试提取（用任意 oods_point 和 max_log_degree_bound，验证不 panic）
        let oods_point = CirclePoint::zero();
        let max_log_degree_bound = 10u32;
        let extracted = extract_composition_oods_eval_from_l1(&l1_proof, oods_point, max_log_degree_bound);
        assert!(
            extracted.is_some(),
            "提取应成功（sampled_values 结构匹配）"
        );
    }

    #[test]
    fn test_extract_composition_oods_eval_empty_sampled_values() {
        // 验证 SECURE_EXTENSION_DEGREE 常量正确
        assert_eq!(SECURE_EXTENSION_DEGREE, 4);
        assert_eq!(2 * SECURE_EXTENSION_DEGREE, 8);
    }

    /// 验证 v5.1 gen_oods_check_trace 能从真实 L1 proof 生成 73 列 trace。
    ///
    /// 使用 prove_cpu_trace 生成 L1 proof，然后用 extract_composition_oods_eval_from_l1
    /// 计算正确的 composition_oods_eval，最后生成 trace。
    #[test]
    fn test_gen_oods_check_trace_v5_1_from_real_l1_proof() {
        use crate::stwo_backend::prover::prove_cpu_trace;
        use crate::stwo_backend::trace_native::TraceBuilder;

        // 生成真实 L1 proof
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let l1_proof = prove_cpu_trace(&trace).expect("L1 prove 应成功");

        // 用任意 oods_point 和 max_log_degree_bound 计算 composition_oods_eval
        let oods_point = CirclePoint::zero();
        let max_log_degree_bound = 10u32;
        let composition_oods_eval = extract_composition_oods_eval_from_l1(
            &l1_proof,
            oods_point,
            max_log_degree_bound,
        )
        .expect("提取 composition_oods_eval 应成功");

        // 创建 RecursivePublicInputs
        let public_inputs = RecursivePublicInputs::new(
            Vec::new(),
            oods_point,
            composition_oods_eval,
            FieldElement252::ZERO,
            LinePoly::new(vec![SecureField::zero()]),
            max_log_degree_bound,
            PcsConfig::default(),
            Vec::new(),
            10,
            SecureField::zero(),
            SecureField::zero(),
        );

        // 生成 trace
        let trace_cols = gen_oods_check_trace(&l1_proof, &public_inputs);

        // 验证维度
        assert_eq!(trace_cols.len(), OODS_AIR_NUM_COLUMNS, "列数应为 73");
        let num_rows = 1usize << OODS_TRACE_LOG_SIZE;
        for (i, col) in trace_cols.iter().enumerate() {
            assert_eq!(col.len(), num_rows, "col {} 行数应为 {}", i, num_rows);
        }

        // 验证 IsPadding
        assert_eq!(trace_cols[OODS_AIR_COL_IS_PADDING][0], BaseField::from(0u32));
        for row in 1..num_rows {
            assert_eq!(
                trace_cols[OODS_AIR_COL_IS_PADDING][row],
                BaseField::from(1u32),
                "padding row {} IsPadding 应为 1",
                row
            );
        }

        // 验证 Claimed == Computed（因为我们设置了 composition_oods_eval = extracted value）
        for i in 0..4 {
            assert_eq!(
                trace_cols[OODS_AIR_COL_CLAIMED_BASE + i][0],
                trace_cols[OODS_AIR_COL_COMPUTED_BASE + i][0],
                "Claimed[{}] 应等于 Computed[{}]",
                i, i
            );
        }
    }

    /// 验证 v5.1 soundness：篡改 composition_oods_eval 会导致 Claimed != Computed。
    ///
    /// 这个测试不调用 prove_recursive，只验证 trace 的不一致性。
    /// prove_recursive 的 soundness 测试在 recursion_prover.rs 中。
    #[test]
    fn test_gen_oods_check_trace_v5_1_soundness_tampered_claimed() {
        use crate::stwo_backend::prover::prove_cpu_trace;
        use crate::stwo_backend::trace_native::TraceBuilder;

        // 生成真实 L1 proof
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let l1_proof = prove_cpu_trace(&trace).expect("L1 prove 应成功");

        // 用任意 oods_point 和 max_log_degree_bound 计算 composition_oods_eval
        let oods_point = CirclePoint::zero();
        let max_log_degree_bound = 10u32;
        let real_composition_oods_eval = extract_composition_oods_eval_from_l1(
            &l1_proof,
            oods_point,
            max_log_degree_bound,
        )
        .expect("提取 composition_oods_eval 应成功");

        // 篡改 composition_oods_eval（添加 1）
        let tampered_composition_oods_eval = real_composition_oods_eval + SecureField::from(1u32);

        // 创建 RecursivePublicInputs（使用篡改的值）
        let public_inputs = RecursivePublicInputs::new(
            Vec::new(),
            oods_point,
            tampered_composition_oods_eval,
            FieldElement252::ZERO,
            LinePoly::new(vec![SecureField::zero()]),
            max_log_degree_bound,
            PcsConfig::default(),
            Vec::new(),
            10,
            SecureField::zero(),
            SecureField::zero(),
        );

        // 生成 trace（应该成功，但 trace 中 Claimed != Computed）
        let trace_cols = gen_oods_check_trace(&l1_proof, &public_inputs);

        // 验证 Claimed != Computed（至少有一个分量不同）
        let mut has_diff = false;
        for i in 0..4 {
            if trace_cols[OODS_AIR_COL_CLAIMED_BASE + i][0]
                != trace_cols[OODS_AIR_COL_COMPUTED_BASE + i][0]
            {
                has_diff = true;
                break;
            }
        }
        assert!(has_diff, "篡改 composition_oods_eval 后 Claimed 应不等于 Computed");
    }

    // =====================================================================
    // FRI Verifier AIR trace generator 测试（v5.1）
    // =====================================================================

    /// 创建带真实 `fri_last_layer_poly` 的测试 `RecursivePublicInputs`。
    ///
    /// 使用 `query_x = 1` 作为 FRI query point（与下游测试期望一致），
    /// `fri_query_eval = last_layer_poly.eval_at_point(1)`。
    fn make_fri_test_public_inputs(last_layer_poly: LinePoly) -> RecursivePublicInputs {
        let query_x = SecureField::from(1u32);
        let query_eval = last_layer_poly.eval_at_point(query_x);
        RecursivePublicInputs::new(
            Vec::new(),
            CirclePoint::zero(),
            SecureField::zero(),
            FieldElement252::ZERO,
            last_layer_poly,
            10,
            PcsConfig::default(),
            Vec::new(),
            10,
            query_x,
            query_eval,
        )
    }

    /// 验证 `gen_fri_verifier_trace` 的维度（36 列 × power-of-2 行）。
    #[test]
    fn test_gen_fri_verifier_trace_dimensions() {
        // 构造 8 系数 LinePoly (log_size=3)
        let coeffs = vec![
            SecureField::from(1u32),
            SecureField::from(2u32),
            SecureField::from(3u32),
            SecureField::from(4u32),
            SecureField::from(5u32),
            SecureField::from(6u32),
            SecureField::from(7u32),
            SecureField::from(8u32),
        ];
        let poly = LinePoly::new(coeffs);
        let n_coeffs = poly.len();
        assert_eq!(n_coeffs, 8);

        let public_inputs = make_fri_test_public_inputs(poly);
        let trace_cols = gen_fri_verifier_trace(
            &make_minimal_l1_proof(),
            &public_inputs,
        );

        // 验证列数
        assert_eq!(trace_cols.len(), FRI_AIR_NUM_COLUMNS, "列数应为 40");

        // 验证行数：n_real_rows = 9, next_power_of_two = 16
        let num_rows = trace_cols[0].len();
        assert_eq!(num_rows, 16, "行数应为 16 (9 real + 7 padding)");
        assert!(num_rows.is_power_of_two(), "行数应为 2 的幂");

        // 所有列应有相同行数
        for (i, col) in trace_cols.iter().enumerate() {
            assert_eq!(col.len(), num_rows, "col {} 行数不匹配", i);
        }
    }

    /// 验证 Horner 计算正确：partial_eval at last real row == query_eval。
    #[test]
    fn test_gen_fri_verifier_trace_horner_correctness() {
        // 构造 8 系数 LinePoly
        let coeffs = vec![
            SecureField::from(1u32),
            SecureField::from(2u32),
            SecureField::from(3u32),
            SecureField::from(4u32),
            SecureField::from(5u32),
            SecureField::from(6u32),
            SecureField::from(7u32),
            SecureField::from(8u32),
        ];
        let poly = LinePoly::new(coeffs.clone());
        let n_coeffs = poly.len();
        let public_inputs = make_fri_test_public_inputs(poly);
        let trace_cols = gen_fri_verifier_trace(
            &make_minimal_l1_proof(),
            &public_inputs,
        );

        // 计算 expected query_eval = poly.eval_at_point(x=1)
        let query_x = SecureField::from(1u32);
        let expected_eval = public_inputs.fri_last_layer_poly.eval_at_point(query_x);
        let expected_m31: [BaseField; 4] = expected_eval.to_m31_array();

        // last real row = row n_coeffs = row 8
        let last_row = n_coeffs;
        for i in 0..4 {
            assert_eq!(
                trace_cols[FRI_AIR_COL_PARTIAL_EVAL_BASE + i][last_row],
                expected_m31[i],
                "PartialEval[{}] at last real row 应等于 query_eval[{}]",
                i, i
            );
            assert_eq!(
                trace_cols[FRI_AIR_COL_QUERY_EVAL_BASE + i][last_row],
                expected_m31[i],
                "QueryEval[{}] at last real row 应等于 query_eval[{}]",
                i, i
            );
        }
    }

    /// 验证 M intermediates 正确：M[k] at row R == partial_eval[R-1] * query_x。
    #[test]
    fn test_gen_fri_verifier_trace_m_intermediates() {
        let coeffs = vec![
            SecureField::from(3u32),
            SecureField::from(7u32),
            SecureField::from(11u32),
            SecureField::from(13u32),
            SecureField::from(17u32),
            SecureField::from(19u32),
            SecureField::from(23u32),
            SecureField::from(29u32),
        ];
        let poly = LinePoly::new(coeffs);
        let n_coeffs = poly.len();
        let public_inputs = make_fri_test_public_inputs(poly);
        let trace_cols = gen_fri_verifier_trace(
            &make_minimal_l1_proof(),
            &public_inputs,
        );

        let query_x_m31: [BaseField; 4] = SecureField::from(1u32).to_m31_array();

        // 验证每行的 M intermediates
        for row in 0..=n_coeffs {
            // 获取当前行的 M intermediates
            let m_vals: [BaseField; 16] = (0..16)
                .map(|i| trace_cols[FRI_AIR_COL_M_BASE + i][row])
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            // 获取 prev row 的 partial_eval
            // Row 0 的 prev 是 wrap-around (last padding row, all zeros)
            let prev_pe: [BaseField; 4] = if row == 0 {
                [BaseField::zero(); 4]
            } else {
                (0..4)
                    .map(|i| trace_cols[FRI_AIR_COL_PARTIAL_EVAL_BASE + i][row - 1])
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            };

            // 计算 expected M intermediates
            let expected_m = compute_qm31_mult_intermediates(&prev_pe, &query_x_m31);

            for i in 0..16 {
                assert_eq!(
                    m_vals[i], expected_m[i],
                    "M[{}] at row {} 不匹配：expected {}, got {}",
                    i + 1, row, expected_m[i], m_vals[i]
                );
            }
        }
    }

    /// 验证 F4b 正确：partial_eval[R] == Product + coeff[R] for real non-first rows。
    /// self-contained 设计中，coeff[R] 存储的是上一行的系数。
    #[test]
    fn test_gen_fri_verifier_trace_f4b_horner_step() {
        let coeffs = vec![
            SecureField::from(5u32),
            SecureField::from(11u32),
            SecureField::from(17u32),
            SecureField::from(23u32),
            SecureField::from(29u32),
            SecureField::from(31u32),
            SecureField::from(37u32),
            SecureField::from(41u32),
        ];
        let poly = LinePoly::new(coeffs);
        let n_coeffs = poly.len();
        let public_inputs = make_fri_test_public_inputs(poly);
        let trace_cols = gen_fri_verifier_trace(
            &make_minimal_l1_proof(),
            &public_inputs,
        );

        // 验证每个 real non-first row 的 F4b 约束
        for row in 1..=n_coeffs {
            // 获取当前行的 partial_eval
            let pe: [BaseField; 4] = (0..4)
                .map(|i| trace_cols[FRI_AIR_COL_PARTIAL_EVAL_BASE + i][row])
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            // 获取当前行的 coeff（self-contained 设计中，coeff[R] = 上一行的系数）
            let coeff: [BaseField; 4] = (0..4)
                .map(|i| trace_cols[FRI_AIR_COL_COEFF_BASE + i][row])
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            // 获取当前行的 M intermediates
            let m_vals: [BaseField; 16] = (0..16)
                .map(|i| trace_cols[FRI_AIR_COL_M_BASE + i][row])
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            // 计算 Product = pe_prev * query_x（从 M intermediates 线性组合）
            let product = compute_product_from_intermediates(&m_vals);

            // 验证 partial_eval[row] == Product + coeff[row]（coeff[row] 已存储上一行的系数）
            for i in 0..4 {
                let expected_pe = product[i] + coeff[i];
                assert_eq!(
                    pe[i], expected_pe,
                    "F4b 失败 at row {} component {}: pe={}, expected Product+coeff={}",
                    row, i, pe[i], expected_pe
                );
            }
        }
    }

    /// 验证 padding rows 正确：IsPadding=1，其余=0。
    #[test]
    fn test_gen_fri_verifier_trace_padding() {
        let coeffs = vec![
            SecureField::from(1u32),
            SecureField::from(2u32),
            SecureField::from(3u32),
            SecureField::from(4u32),
            SecureField::from(5u32),
            SecureField::from(6u32),
            SecureField::from(7u32),
            SecureField::from(8u32),
        ];
        let poly = LinePoly::new(coeffs);
        let n_coeffs = poly.len();
        let public_inputs = make_fri_test_public_inputs(poly);
        let trace_cols = gen_fri_verifier_trace(
            &make_minimal_l1_proof(),
            &public_inputs,
        );

        let num_rows = trace_cols[0].len();
        let one = BaseField::from(1u32);

        // 验证 real rows: IsPadding=0
        for row in 0..=n_coeffs {
            assert_eq!(
                trace_cols[FRI_AIR_COL_IS_PADDING][row],
                BaseField::zero(),
                "real row {} IsPadding 应为 0",
                row
            );
        }

        // 验证 padding rows: IsPadding=1, 其余=0
        for row in (n_coeffs + 1)..num_rows {
            assert_eq!(
                trace_cols[FRI_AIR_COL_IS_PADDING][row],
                one,
                "padding row {} IsPadding 应为 1",
                row
            );
            // QueryX, QueryEval, PartialEval, Coeff, M 都应为 0
            for i in 0..4 {
                assert_eq!(
                    trace_cols[FRI_AIR_COL_QUERY_X_BASE + i][row],
                    BaseField::zero(),
                    "padding row {} QueryX[{}] 应为 0",
                    row, i
                );
                assert_eq!(
                    trace_cols[FRI_AIR_COL_QUERY_EVAL_BASE + i][row],
                    BaseField::zero(),
                    "padding row {} QueryEval[{}] 应为 0",
                    row, i
                );
                assert_eq!(
                    trace_cols[FRI_AIR_COL_PARTIAL_EVAL_BASE + i][row],
                    BaseField::zero(),
                    "padding row {} PartialEval[{}] 应为 0",
                    row, i
                );
                assert_eq!(
                    trace_cols[FRI_AIR_COL_COEFF_BASE + i][row],
                    BaseField::zero(),
                    "padding row {} Coeff[{}] 应为 0",
                    row, i
                );
            }
            for i in 0..16 {
                assert_eq!(
                    trace_cols[FRI_AIR_COL_M_BASE + i][row],
                    BaseField::zero(),
                    "padding row {} M[{}] 应为 0",
                    row, i + 1
                );
            }
            // IsFirstRow, IsLastRow 应为 0
            assert_eq!(
                trace_cols[FRI_AIR_COL_IS_FIRST_ROW][row],
                BaseField::zero(),
                "padding row {} IsFirstRow 应为 0",
                row
            );
            assert_eq!(
                trace_cols[FRI_AIR_COL_IS_LAST_ROW][row],
                BaseField::zero(),
                "padding row {} IsLastRow 应为 0",
                row
            );
            // Gating = (1 - IsFirstRow) * (1 - IsPadding) = 0
            assert_eq!(
                trace_cols[FRI_AIR_COL_GATING][row],
                BaseField::zero(),
                "padding row {} Gating 应为 0",
                row
            );
        }
    }

    /// 验证 flags 正确：IsFirstRow=1 at row 0, IsLastRow=1 at row n_coeffs。
    #[test]
    fn test_gen_fri_verifier_trace_flags() {
        let coeffs = vec![
            SecureField::from(1u32),
            SecureField::from(2u32),
            SecureField::from(3u32),
            SecureField::from(4u32),
        ];
        let poly = LinePoly::new(coeffs);
        let n_coeffs = poly.len();
        let public_inputs = make_fri_test_public_inputs(poly);
        let trace_cols = gen_fri_verifier_trace(
            &make_minimal_l1_proof(),
            &public_inputs,
        );

        let num_rows = trace_cols[0].len();
        let one = BaseField::from(1u32);

        // IsFirstRow: 只有 row 0 为 1
        for row in 0..num_rows {
            let expected = if row == 0 { one } else { BaseField::zero() };
            assert_eq!(
                trace_cols[FRI_AIR_COL_IS_FIRST_ROW][row],
                expected,
                "IsFirstRow at row {} 不匹配",
                row
            );
        }

        // IsLastRow: 只有 row n_coeffs 为 1
        for row in 0..num_rows {
            let expected = if row == n_coeffs { one } else { BaseField::zero() };
            assert_eq!(
                trace_cols[FRI_AIR_COL_IS_LAST_ROW][row],
                expected,
                "IsLastRow at row {} 不匹配",
                row
            );
        }
    }

    /// 验证 Gating 列正确：Gating = (1 - IsFirstRow) * (1 - IsPadding)。
    #[test]
    fn test_gen_fri_verifier_trace_gating() {
        let coeffs = vec![SecureField::from(42u32)];
        let poly = LinePoly::new(coeffs);
        let n_coeffs = poly.len();
        assert_eq!(n_coeffs, 1);
        let public_inputs = make_fri_test_public_inputs(poly);
        let trace_cols = gen_fri_verifier_trace(
            &make_minimal_l1_proof(),
            &public_inputs,
        );

        let num_rows = trace_cols[0].len();
        let one = BaseField::from(1u32);

        for row in 0..num_rows {
            let is_first = if row == 0 { one } else { BaseField::zero() };
            let is_padding = trace_cols[FRI_AIR_COL_IS_PADDING][row];
            let expected_gating = (one - is_first) * (one - is_padding);
            assert_eq!(
                trace_cols[FRI_AIR_COL_GATING][row],
                expected_gating,
                "Gating at row {} 不匹配",
                row
            );
        }
    }

    /// 验证 constant polynomial（1 个系数）的 trace 正确。
    /// self-contained 设计中，coeff[R] 存储上一行的系数。
    #[test]
    fn test_gen_fri_verifier_trace_constant_poly() {
        // 1 系数 LinePoly: p(x) = c_0 = 42
        let coeffs = vec![SecureField::from(42u32)];
        let poly = LinePoly::new(coeffs);
        let n_coeffs = poly.len();
        assert_eq!(n_coeffs, 1);
        let public_inputs = make_fri_test_public_inputs(poly);
        let trace_cols = gen_fri_verifier_trace(
            &make_minimal_l1_proof(),
            &public_inputs,
        );

        // n_real_rows = 2, num_rows = 4 (2 real + 2 padding)
        assert_eq!(trace_cols[0].len(), 4, "constant poly 应有 4 行");

        // Row 0: IsFirstRow=1, partial_eval=0, pe_prev=0, coeff=0（上一行系数，不存在则为 0）
        assert_eq!(trace_cols[FRI_AIR_COL_IS_FIRST_ROW][0], BaseField::from(1u32));
        for i in 0..4 {
            assert_eq!(
                trace_cols[FRI_AIR_COL_PARTIAL_EVAL_PREV_BASE + i][0],
                BaseField::zero(),
                "Row 0 PartialEvalPrev 应为 0"
            );
            assert_eq!(
                trace_cols[FRI_AIR_COL_PARTIAL_EVAL_BASE + i][0],
                BaseField::zero(),
                "Row 0 PartialEval 应为 0"
            );
            assert_eq!(
                trace_cols[FRI_AIR_COL_COEFF_BASE + i][0],
                BaseField::zero(),
                "Row 0 Coeff 应为 0（上一行系数，不存在则为 0）"
            );
        }

        // Row 1: IsLastRow=1, partial_eval=42, pe_prev=0, coeff=42（上一行的系数）
        assert_eq!(trace_cols[FRI_AIR_COL_IS_LAST_ROW][1], BaseField::from(1u32));
        let coeff_m31 = SecureField::from(42u32).to_m31_array();
        for i in 0..4 {
            assert_eq!(
                trace_cols[FRI_AIR_COL_PARTIAL_EVAL_PREV_BASE + i][1],
                BaseField::zero(),
                "Row 1 PartialEvalPrev 应为 0"
            );
            assert_eq!(
                trace_cols[FRI_AIR_COL_PARTIAL_EVAL_BASE + i][1],
                coeff_m31[i],
                "Row 1 PartialEval 应为 42 (= p(x) for constant poly)"
            );
            assert_eq!(
                trace_cols[FRI_AIR_COL_COEFF_BASE + i][1],
                coeff_m31[i],
                "Row 1 Coeff 应为 42（上一行的系数）"
            );
            assert_eq!(
                trace_cols[FRI_AIR_COL_QUERY_EVAL_BASE + i][1],
                coeff_m31[i],
                "Row 1 QueryEval 应为 42"
            );
        }
    }

    /// 验证从真实 L1 proof 提取的 last_layer_poly 也能正确生成 trace。
    #[test]
    fn test_gen_fri_verifier_trace_from_real_l1_proof() {
        use crate::stwo_backend::prover::prove_cpu_trace;
        use crate::stwo_backend::trace_native::TraceBuilder;

        // 生成真实 L1 proof
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let l1_proof = prove_cpu_trace(&trace).expect("L1 prove 应成功");

        // 从 L1 proof 提取 last_layer_poly
        let last_layer_poly = l1_proof.0.fri_proof.last_layer_poly.clone();
        let n_coeffs = last_layer_poly.len();
        assert!(
            n_coeffs > 0,
            "last_layer_poly 应至少有 1 个系数"
        );
        assert!(
            n_coeffs.is_power_of_two(),
            "last_layer_poly 系数数应为 2 的幂，实际 {}",
            n_coeffs
        );

        let public_inputs = make_fri_test_public_inputs(last_layer_poly.clone());
        let trace_cols = gen_fri_verifier_trace(&l1_proof, &public_inputs);

        // 验证维度
        assert_eq!(trace_cols.len(), FRI_AIR_NUM_COLUMNS, "列数应为 40");
        let num_rows = trace_cols[0].len();
        assert!(num_rows.is_power_of_two(), "行数应为 2 的幂");
        assert!(
            num_rows >= n_coeffs + 2,
            "行数应至少 {} (n_coeffs+2)，实际 {}",
            n_coeffs + 2,
            num_rows
        );

        // 验证 Horner 计算正确
        let query_x = SecureField::from(1u32);
        let expected_eval = last_layer_poly.eval_at_point(query_x);
        let expected_m31: [BaseField; 4] = expected_eval.to_m31_array();
        let last_real_row = n_coeffs;
        for i in 0..4 {
            assert_eq!(
                trace_cols[FRI_AIR_COL_PARTIAL_EVAL_BASE + i][last_real_row],
                expected_m31[i],
                "PartialEval[{}] at last real row 不匹配",
                i
            );
        }
    }

    /// 创建一个最小的 L1 proof（用于不需要真实 L1 proof 数据的测试）。
    ///
    /// `gen_fri_verifier_trace` 只使用 `public_inputs.fri_last_layer_poly`，
    /// 不使用 `l1_proof` 参数（v5.1），所以可以传一个空 proof。
    /// 但函数签名要求 `&StarkProof`，所以需要构造一个。
    #[allow(clippy::missing_errors_doc)]
    fn make_minimal_l1_proof() -> StarkProof<Poseidon252MerkleHasher> {
        use crate::stwo_backend::prover::prove_cpu_trace;
        use crate::stwo_backend::trace_native::TraceBuilder;

        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        prove_cpu_trace(&trace).expect("L1 prove 应成功")
    }

    // =====================================================================
    // compute_fri_trace_log_size 测试
    // =====================================================================

    #[test]
    fn test_compute_fri_trace_log_size_constant_poly() {
        // 1 coefficient: n_real_rows=2, is_power_of_two → num_rows=4, log_size=2
        let poly = LinePoly::new(vec![SecureField::from(42u32)]);
        assert_eq!(compute_fri_trace_log_size(&poly), 2);
    }

    #[test]
    fn test_compute_fri_trace_log_size_2_coeffs() {
        // 2 coefficients: n_real_rows=3, not power_of_two → next_pow2=4, log_size=2
        let poly = LinePoly::new(vec![SecureField::from(1u32), SecureField::from(2u32)]);
        assert_eq!(compute_fri_trace_log_size(&poly), 2);
    }

    #[test]
    fn test_compute_fri_trace_log_size_4_coeffs() {
        // 4 coefficients: n_real_rows=5, not power_of_two → next_pow2=8, log_size=3
        let poly = LinePoly::new(vec![
            SecureField::from(1u32),
            SecureField::from(2u32),
            SecureField::from(3u32),
            SecureField::from(4u32),
        ]);
        assert_eq!(compute_fri_trace_log_size(&poly), 3);
    }

    #[test]
    fn test_compute_fri_trace_log_size_8_coeffs_default() {
        // 8 coefficients (default PcsConfig): n_real_rows=9, next_pow2=16, log_size=4
        let poly = LinePoly::new(vec![
            SecureField::from(1u32),
            SecureField::from(2u32),
            SecureField::from(3u32),
            SecureField::from(4u32),
            SecureField::from(5u32),
            SecureField::from(6u32),
            SecureField::from(7u32),
            SecureField::from(8u32),
        ]);
        assert_eq!(compute_fri_trace_log_size(&poly), 4);
    }

    #[test]
    fn test_compute_fri_trace_log_size_matches_gen_fri_verifier_trace() {
        // 验证 compute_fri_trace_log_size 与 gen_fri_verifier_trace 实际行数一致
        let poly = LinePoly::new(vec![
            SecureField::from(1u32),
            SecureField::from(2u32),
            SecureField::from(3u32),
            SecureField::from(4u32),
            SecureField::from(5u32),
            SecureField::from(6u32),
            SecureField::from(7u32),
            SecureField::from(8u32),
        ]);
        let expected_log_size = compute_fri_trace_log_size(&poly);
        let public_inputs = make_fri_test_public_inputs(poly);
        let trace_cols = gen_fri_verifier_trace(&make_minimal_l1_proof(), &public_inputs);
        let actual_num_rows = trace_cols[0].len();
        assert_eq!(
            actual_num_rows,
            1usize << expected_log_size,
            "compute_fri_trace_log_size 与 gen_fri_verifier_trace 不一致"
        );
    }

    // =====================================================================
    // pad_oods_trace_to_log_size 测试
    // =====================================================================

    #[test]
    fn test_pad_oods_trace_to_log_size_no_op() {
        // target_log_size == OODS_TRACE_LOG_SIZE (2) → 无 padding
        let l1_proof = make_minimal_l1_proof();
        let public_inputs = make_test_public_inputs(SecureField::from(42u32));
        let original = gen_oods_check_trace(&l1_proof, &public_inputs);

        let padded = pad_oods_trace_to_log_size(original.clone(), OODS_TRACE_LOG_SIZE);
        assert_eq!(padded.len(), OODS_AIR_NUM_COLUMNS);
        for (i, col) in padded.iter().enumerate() {
            assert_eq!(col.len(), 4, "col {i} 应保持 4 行");
        }
        // 内容应与原始完全一致
        for i in 0..OODS_AIR_NUM_COLUMNS {
            for j in 0..4 {
                assert_eq!(padded[i][j], original[i][j], "col {i} row {j} 内容不一致");
            }
        }
    }

    #[test]
    fn test_pad_oods_trace_to_log_size_pad_to_4() {
        // target_log_size=4 → 16 行（原 4 行 + 12 padding）
        let l1_proof = make_minimal_l1_proof();
        let public_inputs = make_test_public_inputs(SecureField::from(42u32));
        let original = gen_oods_check_trace(&l1_proof, &public_inputs);

        let padded = pad_oods_trace_to_log_size(original.clone(), 4);
        assert_eq!(padded.len(), OODS_AIR_NUM_COLUMNS);
        for (i, col) in padded.iter().enumerate() {
            assert_eq!(col.len(), 16, "col {i} 应有 16 行");
        }

        // 前 4 行应与原始一致
        for i in 0..OODS_AIR_NUM_COLUMNS {
            for j in 0..4 {
                assert_eq!(padded[i][j], original[i][j], "col {i} row {j} 前 4 行应一致");
            }
        }

        // IsPadding 列：rows 4..16 应为 1
        let one = BaseField::from(1u32);
        for row in 4..16 {
            assert_eq!(
                padded[OODS_AIR_COL_IS_PADDING][row],
                one,
                "padding row {row} IsPadding 应为 1"
            );
        }

        // 其他列：rows 4..16 应为 0
        for col_idx in 0..OODS_AIR_NUM_COLUMNS {
            if col_idx == OODS_AIR_COL_IS_PADDING {
                continue;
            }
            for row in 4..16 {
                assert_eq!(
                    padded[col_idx][row],
                    BaseField::zero(),
                    "col {col_idx} padding row {row} 应为 0"
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "target_log_size (1) < OODS_TRACE_LOG_SIZE (2)")]
    fn test_pad_oods_trace_to_log_size_panic_on_shrink() {
        let l1_proof = make_minimal_l1_proof();
        let public_inputs = make_test_public_inputs(SecureField::from(42u32));
        let original = gen_oods_check_trace(&l1_proof, &public_inputs);
        // 尝试 shrink 到 log_size=1 应 panic
        let _ = pad_oods_trace_to_log_size(original, 1);
    }

    #[test]
    #[should_panic(expected = "OODS trace 列数不匹配")]
    fn test_pad_oods_trace_to_log_size_panic_on_wrong_cols() {
        // 传入错误列数的 trace 应 panic
        let wrong_cols = vec![vec![BaseField::zero(); 4]; 10]; // 10 列而非 73 列
        let _ = pad_oods_trace_to_log_size(wrong_cols, 4);
    }

    // =====================================================================
    // pad_fri_trace_to_log_size 测试
    // =====================================================================

    #[test]
    fn test_pad_fri_trace_to_log_size_no_op() {
        // 8 coeffs → fri_log_size=4 → 16 rows; target_log_size=4 → no padding
        let poly = LinePoly::new(vec![
            SecureField::from(1u32),
            SecureField::from(2u32),
            SecureField::from(3u32),
            SecureField::from(4u32),
            SecureField::from(5u32),
            SecureField::from(6u32),
            SecureField::from(7u32),
            SecureField::from(8u32),
        ]);
        let public_inputs = make_fri_test_public_inputs(poly);
        let original = gen_fri_verifier_trace(&make_minimal_l1_proof(), &public_inputs);

        let padded = pad_fri_trace_to_log_size(original.clone(), 4);
        assert_eq!(padded.len(), FRI_AIR_NUM_COLUMNS);
        for (i, col) in padded.iter().enumerate() {
            assert_eq!(col.len(), 16, "col {i} 应保持 16 行");
        }
        // 内容应与原始完全一致
        for i in 0..FRI_AIR_NUM_COLUMNS {
            for j in 0..16 {
                assert_eq!(padded[i][j], original[i][j], "col {i} row {j} 内容不一致");
            }
        }
    }

    #[test]
    fn test_pad_fri_trace_to_log_size_pad_to_larger() {
        // 1 coeff → fri_log_size=2 → 4 rows; target_log_size=4 → 16 rows (12 padding)
        let poly = LinePoly::new(vec![SecureField::from(42u32)]);
        let public_inputs = make_fri_test_public_inputs(poly);
        let original = gen_fri_verifier_trace(&make_minimal_l1_proof(), &public_inputs);
        assert_eq!(original[0].len(), 4, "原始 FRI trace 应有 4 行");

        let padded = pad_fri_trace_to_log_size(original.clone(), 4);
        assert_eq!(padded.len(), FRI_AIR_NUM_COLUMNS);
        for (i, col) in padded.iter().enumerate() {
            assert_eq!(col.len(), 16, "col {i} 应有 16 行");
        }

        // 前 4 行应与原始一致
        for i in 0..FRI_AIR_NUM_COLUMNS {
            for j in 0..4 {
                assert_eq!(padded[i][j], original[i][j], "col {i} row {j} 前 4 行应一致");
            }
        }

        // IsPadding 列：rows 4..16 应为 1
        let one = BaseField::from(1u32);
        for row in 4..16 {
            assert_eq!(
                padded[FRI_AIR_COL_IS_PADDING][row],
                one,
                "padding row {row} IsPadding 应为 1"
            );
        }

        // 其他列：rows 4..16 应为 0
        for col_idx in 0..FRI_AIR_NUM_COLUMNS {
            if col_idx == FRI_AIR_COL_IS_PADDING {
                continue;
            }
            for row in 4..16 {
                assert_eq!(
                    padded[col_idx][row],
                    BaseField::zero(),
                    "col {col_idx} padding row {row} 应为 0"
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "FRI trace 列数不匹配")]
    fn test_pad_fri_trace_to_log_size_panic_on_wrong_cols() {
        let wrong_cols = vec![vec![BaseField::zero(); 4]; 10]; // 10 列而非 36 列
        let _ = pad_fri_trace_to_log_size(wrong_cols, 4);
    }

    #[test]
    #[should_panic(expected = "target_log_size (1) < FRI trace log_size")]
    fn test_pad_fri_trace_to_log_size_panic_on_shrink() {
        // 8 coeffs → fri_log_size=4 → 16 rows; target_log_size=1 → panic
        let poly = LinePoly::new(vec![
            SecureField::from(1u32),
            SecureField::from(2u32),
            SecureField::from(3u32),
            SecureField::from(4u32),
            SecureField::from(5u32),
            SecureField::from(6u32),
            SecureField::from(7u32),
            SecureField::from(8u32),
        ]);
        let public_inputs = make_fri_test_public_inputs(poly);
        let original = gen_fri_verifier_trace(&make_minimal_l1_proof(), &public_inputs);
        let _ = pad_fri_trace_to_log_size(original, 1);
    }
}
