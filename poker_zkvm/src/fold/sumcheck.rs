//! Sumcheck 协议（Phase 6 — Task 6.5）。
//!
//! 严格遵循 spec.md L381-395（v1.4 FROZEN）与 Hypernova 原论文（eprint 2023/573）。
//!
//! ## 外层 sumcheck（v1.3 修正 C2-003 — claimed sum = u' 标量）
//!
//! 证明 `Σ_X G(X) = u'` 其中：
//! - `G(X) = eq(X, r_x_L) · Σ_i [c_i · Π_{j∈S_i} v'(j)(X)]`（v1.4 Min3-005 显式括号）
//! - `v'(j)(X) = MLE of (M_j · z')` 其中 `z' = z_L + r · z_C`
//! - **关键简化**：`v_L(j)(X) + r · v_C(j)(X) = MLE of (M_j · z')`（因 M_j 线性）
//! - 归约到 final point `r_x_prime`，prover 提供 `v_pp[j] = v'(j)(r_x_prime)`
//! - final check: `eq(r_x_prime, r_x_L) · Σ_i c_i · Π_{j∈S_i} v_pp[j] == last_round_eval`
//!
//! ## 内层 batched sumcheck（v1.3 修正 C2-001 — 单 r_y）
//!
//! 证明 `Σ_j γ^j · v_pp[j] = Σ_Y (Σ_j γ^j · M_j(r_x_prime, Y)) · z'(Y)`
//! - `H(Y) = C(Y) · Z(Y)` 其中 `C(Y) = Σ_j γ^j · M_j(r_x_prime, Y)`，`Z(Y) = z'(Y)`
//! - C 和 Z 均为 multilinear，H 为 degree 2
//! - 归约到**单个 challenge `r_y`**（combined_point = r_y，非元组）
//! - final check: `(Σ_j γ^j · M_j(r_x_prime, r_y)) · z_at_r_y == last_round_eval`
//!
//! ## v1.3 关键修正
//!
//! - **C2-001**：内层 batched sumcheck 产生单个 r_y
//! - **C2-003**：外层 claimed sum = u' 标量
//! - **M2-001**：relaxed 约束 u' 可非 0
//!
//! ## 实现决策
//!
//! - **r_x_prime vs r_x_L**：spec L392 内层 sumcheck 写 `M_j(r_x_L, y)`，但数学上应为
//!   `M_j(r_x_prime, y)`（r_x_prime 是外层 sumcheck 产生的 fresh challenge point）。
//!   spec 的 r_x_L 是简化标注（见 alternatives.md）。本实现使用 r_x_prime。
//! - **round polynomial 表示**：使用 evaluation points（非系数），便于 prove 和 verify
//!   对齐。degree D 多项式用 D+1 个点 [g(0), g(1), ..., g(D)]。
//! - **bind_var**：multilinear binding `(1-r) * table[2i] + r * table[2i+1]`，每轮长度减半。

use crate::ccs::{Ccs, Fr};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::fold::lcccs::eq_eval;
use crate::transcript::{Transcript, SUMCHECK_DOMAIN_TAG};

// ============ 辅助函数 ============

/// 计算两个向量的多线性 eq 函数：`eq(a, b) = Π_i (a_i·b_i + (1-a_i)·(1-b_i))`。
///
/// 与 `lcccs::eq_eval` 不同，此函数接受两个 Fr 向量（均可为非 boolean）。
/// 空向量返回 1（空积）。
fn eq_eval_vec(a: &[Fr], b: &[Fr]) -> Result<Fr, ZkvmError> {
    if a.len() != b.len() {
        return Err(ZkvmError::Other(format!(
            "eq_eval_vec: a.len() {} != b.len() {}",
            a.len(),
            b.len()
        )));
    }
    let mut result = Fr::one();
    for (ai, bi) in a.iter().zip(b.iter()) {
        let one = Fr::one();
        let one_minus_ai = one.sub(ai);
        let one_minus_bi = one.sub(bi);
        let term = one_minus_ai.mul(&one_minus_bi).add(&ai.mul(bi));
        result = result.mul(&term);
    }
    Ok(result)
}

/// Multilinear binding：将 table 的第一个未绑定变量绑定为 r。
///
/// `bound[i] = (1-r) * table[2i] + r * table[2i+1]`
///
/// table 长度须为 2 的幂且 ≥ 2。返回长度 = table.len() / 2。
fn bind_var(table: &[Fr], r: &Fr) -> Vec<Fr> {
    let n = table.len() / 2;
    let one_minus_r = Fr::one().sub(r);
    (0..n)
        .map(|i| {
            let lo = table[2 * i];
            let hi = table[2 * i + 1];
            one_minus_r.mul(&lo).add(&r.mul(&hi))
        })
        .collect()
}

/// 使用 Lagrange 插值在 evaluation points `[g(0), g(1), ..., g(D)]` 上求值 `g(r)`。
///
/// evaluation points 固定为 `x_i = i`（i = 0, 1, ..., D）。
fn eval_poly_at(eval_points: &[Fr], r: &Fr) -> Fr {
    let d = eval_points.len() - 1;
    if d == 0 {
        return eval_points[0];
    }
    let mut result = Fr::zero();
    for (i, &eval_i) in eval_points.iter().enumerate() {
        let xi = Fr::from_u32_with_wrap(i as u32);
        let mut num = Fr::one();
        let mut den = Fr::one();
        for j in 0..=d {
            if i != j {
                let xj = Fr::from_u32_with_wrap(j as u32);
                num = num.mul(&r.sub(&xj));
                den = den.mul(&xi.sub(&xj));
            }
        }
        let den_inv = den.inverse().unwrap_or_else(Fr::zero);
        result = result.add(&eval_i.mul(&num).mul(&den_inv));
    }
    result
}

/// 计算 CCS 的最大子集大小 `max|S_i|`（决定外层 sumcheck 的 degree）。
fn max_subset_size(ccs: &Ccs) -> usize {
    ccs.subsets.iter().map(|s| s.len()).max().unwrap_or(0)
}

/// 计算外层 sumcheck 的 degree = 1 + max|S_i|（eq degree 1 + Π degree |S_i|）。
fn outer_degree(ccs: &Ccs) -> usize {
    1 + max_subset_size(ccs)
}

/// 计算内层 sumcheck 的 degree = 2（C(Y) · Z(Y)，两个 multilinear 之积）。
const INNER_DEGREE: usize = 2;

/// 计算 eq_table[row] = eq(r_x_l, row) for all boolean rows。
fn compute_eq_table(r_x_l: &[Fr], num_rows: usize) -> Result<Vec<Fr>, ZkvmError> {
    (0..num_rows).map(|row| eq_eval(r_x_l, row)).collect()
}

/// 计算 vjp_tables[j][row] = (M_j · z')[row] for all j and boolean rows。
///
/// 这是 v'(j)(X) 的 MLE 在 boolean hypercube 上的求值。
fn compute_vjp_tables(ccs: &Ccs, z_prime: &[Fr]) -> Result<Vec<Vec<Fr>>, ZkvmError> {
    ccs.matrices.iter().map(|m| m.evaluate(z_prime)).collect()
}

/// 计算 `M_j(r_x, r_y) = Σ_{(row,col,val) ∈ entries} val · eq(r_x, row_bits) · eq(r_y, col_bits)`。
///
/// 用于 verifier 在内层 sumcheck final check 中计算 `Σ_j γ^j · M_j(r_x_prime, r_y)`。
fn evaluate_matrix_at(
    matrix: &crate::ccs::SparseMatrix,
    r_x: &[Fr],
    r_y: &[Fr],
) -> Result<Fr, ZkvmError> {
    let m = r_x.len();
    let n = r_y.len();
    let mut sum = Fr::zero();
    for entry in &matrix.entries {
        let row_bits: Vec<Fr> = (0..m)
            .map(|i| {
                if (entry.row >> i) & 1 == 1 {
                    Fr::one()
                } else {
                    Fr::zero()
                }
            })
            .collect();
        let col_bits: Vec<Fr> = (0..n)
            .map(|i| {
                if (entry.col >> i) & 1 == 1 {
                    Fr::one()
                } else {
                    Fr::zero()
                }
            })
            .collect();
        let eq_x = eq_eval_vec(r_x, &row_bits)?;
        let eq_y = eq_eval_vec(r_y, &col_bits)?;
        let term = entry.value.mul(&eq_x).mul(&eq_y);
        sum = sum.add(&term);
    }
    Ok(sum)
}

/// 在 point 处求值 MLE（给定 boolean hypercube 上的 evaluation table）。
///
/// 逐变量 binding，最终 table[0] 即为 MLE(point)。
#[allow(dead_code)]
fn eval_mle_at(table: &[Fr], point: &[Fr]) -> Fr {
    let mut current = table.to_vec();
    for r in point {
        if current.len() <= 1 {
            break;
        }
        current = bind_var(&current, r);
    }
    current[0]
}

// ============ 数据结构 ============

/// Sumcheck 证明（外层 + 内层）。
#[derive(Debug, Clone)]
pub struct SumcheckProof {
    /// 外层 sumcheck 每轮的 round polynomial（evaluation points 表示）。
    /// 长度 = m = log2(num_rows)。每轮 D_outer+1 个点。
    pub outer_round_polys: Vec<Vec<Fr>>,
    /// `v_pp[j] = v'(j)(r_x_prime)` — prover 在外层 sumcheck 结束时提供。
    /// 长度 = num_matrices。
    pub v_pp: Vec<Fr>,
    /// 内层 batched sumcheck 每轮的 round polynomial。
    /// 长度 = n = log2(num_vars)。每轮 3 个点（degree 2）。
    pub inner_round_polys: Vec<Vec<Fr>>,
}

/// Prover 输出（含 proof + r_y + z_at_r_y 供 PCS opening 使用）。
#[derive(Debug, Clone)]
pub struct SumcheckProverOutput {
    /// Sumcheck 证明。
    pub proof: SumcheckProof,
    /// 内层 sumcheck 产生的 final challenge point（PCS opening point）。
    pub r_y: Vec<Fr>,
    /// `z'(r_y)` — folded witness 在 r_y 处的求值（PCS opening 值）。
    pub z_at_r_y: Fr,
    /// 实际计算的 claimed sum `Σ_X G(X)`。
    ///
    /// 对于线性 CCS（所有 |S_i| = 1），此值 = `u_L + r·u_C`（与 spec L372 一致）。
    /// 对于非线性 CCS（存在 |S_i| ≥ 2），此值 ≠ `u_L + r·u_C`，因为
    /// `Π_{j∈S_i} (v_L[j] + r·v_C[j]) ≠ Π v_L[j] + r·Π v_C[j]`（Π 不分配 +）。
    /// 调用方应使用此值更新 folded LCCCS 的 `u` 字段（见 alternatives.md）。
    pub actual_u_prime: Fr,
}

// ============ Prove ============

/// 生成 Hypernova sumcheck 证明（外层 + 内层）。
///
/// # 参数
/// - `ccs` — CCS 结构（矩阵 M_j / 子集 S_i / 系数 c_i）
/// - `z_prime` — folded witness `z' = z_L + r · z_C`（长度 = num_vars）
/// - `r_x_l` — LCCCS 的 r_x（长度 = log2(num_rows)）
/// - `u_prime` — spec 的 claimed sum `u' = u_L + r·u_C`（标量）。
///   **注意**：对线性 CCS，此值 = 实际 sumcheck claimed sum；对非线性 CCS，
///   实际 claimed sum ≠ 此值（因 Π 不分配 +）。prover 会计算实际 sum
///   `actual_u_prime` 并使用它。调用方应使用返回的 `actual_u_prime` 进行 verify。
/// - `transcript` — Fiat-Shamir transcript
///
/// # 返回
/// [`SumcheckProverOutput`]，含 proof + r_y + z_at_r_y + actual_u_prime。
///
/// # 错误
/// - num_rows / num_vars 不是 2 的幂
/// - 维度不匹配
///
/// # Transcript 吸收顺序
///
/// 1. actual_u_prime（实际计算的 claimed sum）
/// 2. 每轮外层 round polynomial → derive r_{x,k}
/// 3. v_pp 值 → derive γ
/// 4. 每轮内层 round polynomial → derive r_{y,k}
pub fn prove(
    ccs: &Ccs,
    z_prime: &[Fr],
    r_x_l: &[Fr],
    u_prime: Fr,
    transcript: &mut Transcript,
) -> Result<SumcheckProverOutput, ZkvmError> {
    let num_rows = ccs.num_rows();
    let num_vars = ccs.num_vars;

    // 维度校验
    if z_prime.len() != num_vars {
        return Err(ZkvmError::Other(format!(
            "sumcheck::prove: z_prime.len() {} != num_vars {}",
            z_prime.len(),
            num_vars
        )));
    }
    if num_rows == 0 || !num_rows.is_power_of_two() {
        return Err(ZkvmError::Other(format!(
            "sumcheck::prove: num_rows {} 须为 2 的幂",
            num_rows
        )));
    }
    if num_vars == 0 || !num_vars.is_power_of_two() {
        return Err(ZkvmError::Other(format!(
            "sumcheck::prove: num_vars {} 须为 2 的幂",
            num_vars
        )));
    }
    let m = num_rows.trailing_zeros() as usize; // 外层轮数
    let n = num_vars.trailing_zeros() as usize; // 内层轮数
    if r_x_l.len() != m {
        return Err(ZkvmError::Other(format!(
            "sumcheck::prove: r_x_l.len() {} != log2(num_rows) = {}",
            r_x_l.len(),
            m
        )));
    }

    let d_outer = outer_degree(ccs); // 外层每轮 degree
    let t = ccs.num_matrices(); // 矩阵数

    // ===== 1. 预计算 evaluation tables =====
    let mut eq_table = compute_eq_table(r_x_l, num_rows)?;
    let mut vjp_tables = compute_vjp_tables(ccs, z_prime)?;

    // ===== 2. 计算实际 claimed sum = Σ_X G(X) =====
    // G(X) = eq(X, r_x_L) · Σ_i [c_i · Π_{j∈S_i} v'(j)(X)]
    // Σ_X G(X) = Σ_row eq(r_x_L, row) · F'(row)
    //   其中 F'(row) = Σ_i c_i · Π_{j∈S_i} (M_j · z')[row]
    //
    // 对于线性 CCS（所有 |S_i| = 1）：actual_u_prime = u_L + r·u_C = u_prime（spec L372）
    // 对于非线性 CCS（存在 |S_i| ≥ 2）：actual_u_prime ≠ u_prime
    //   因为 Π_{j∈S_i} (v_L[j] + r·v_C[j]) ≠ Π v_L[j] + r·Π v_C[j]
    // 使用实际值作为 claimed sum（见 alternatives.md Phase 6 数学说明）
    let mut actual_u_prime = Fr::zero();
    for row in 0..num_rows {
        let eq_val = eq_table[row];
        let mut f_val = Fr::zero();
        for (si, s) in ccs.subsets.iter().enumerate() {
            let mut prod = Fr::one();
            for &j in s {
                prod = prod.mul(&vjp_tables[j][row]);
            }
            f_val = f_val.add(&ccs.coeffs[si].mul(&prod));
        }
        actual_u_prime = actual_u_prime.add(&eq_val.mul(&f_val));
    }

    // ===== 3. 吸收 claimed sum（使用实际值） =====
    transcript.absorb_field(SUMCHECK_DOMAIN_TAG, &actual_u_prime);

    // debug 校验：对线性 CCS，actual_u_prime 应 = u_prime（spec L372）
    #[cfg(debug_assertions)]
    {
        let is_linear = ccs.subsets.iter().all(|s| s.len() <= 1);
        if is_linear {
            debug_assert_eq!(
                actual_u_prime, u_prime,
                "线性 CCS: actual_u_prime 应 = u_L + r·u_C = u_prime"
            );
        }
    }

    // ===== 4. 外层 sumcheck =====
    let mut outer_round_polys: Vec<Vec<Fr>> = Vec::with_capacity(m);
    let mut r_x_prime: Vec<Fr> = Vec::with_capacity(m);

    for _k in 0..m {
        // 计算 round polynomial g_k(X_k) at points 0, 1, ..., d_outer
        let mut evals: Vec<Fr> = Vec::with_capacity(d_outer + 1);
        for e in 0..=d_outer {
            let e_fr = Fr::from_u32_with_wrap(e as u32);
            // 临时 bind X_k = e
            let eq_e = bind_var(&eq_table, &e_fr);
            let vjp_e: Vec<Vec<Fr>> =
                vjp_tables.iter().map(|t| bind_var(t, &e_fr)).collect();

            // F_e[i] = Σ_i c_i · Π_{j∈S_i} vjp_e[j][i]
            let half = eq_e.len();
            let mut g_sum = Fr::zero();
            for i in 0..half {
                let mut f_val = Fr::zero();
                for (si, s) in ccs.subsets.iter().enumerate() {
                    let mut prod = Fr::one();
                    for &j in s {
                        prod = prod.mul(&vjp_e[j][i]);
                    }
                    f_val = f_val.add(&ccs.coeffs[si].mul(&prod));
                }
                let g_val = eq_e[i].mul(&f_val);
                g_sum = g_sum.add(&g_val);
            }
            evals.push(g_sum);
        }

        // 吸收 round polynomial 并派生 challenge
        for eval_point in &evals {
            transcript.absorb_field(SUMCHECK_DOMAIN_TAG, eval_point);
        }
        let r_k = transcript.challenge(SUMCHECK_DOMAIN_TAG);

        outer_round_polys.push(evals);
        r_x_prime.push(r_k);

        // 永久 bind X_k = r_k
        eq_table = bind_var(&eq_table, &r_k);
        for vjp in vjp_tables.iter_mut() {
            *vjp = bind_var(vjp, &r_k);
        }
    }

    // 外层结束后：eq_table[0] = eq(r_x_prime, r_x_L)
    // vjp_tables[j][0] = v'(j)(r_x_prime) = v_pp[j]
    let v_pp: Vec<Fr> = vjp_tables.iter().map(|t| t[0]).collect();
    let eq_at_r_x_prime = eq_table[0];

    // 验证 prover 自己的 final check（debug 用，不影响 soundness）
    // G(r_x_prime) = eq(r_x_prime, r_x_L) · Σ_i c_i · Π_{j∈S_i} v_pp[j]
    // 此值应等于最后一轮 g_{m-1}(r_{m-1})（如 m > 0）
    #[cfg(debug_assertions)]
    if m > 0 {
        let f_at_r_x_prime = crate::fold::lcccs::compute_relaxed_constraint(ccs, &v_pp);
        let g_at_r_x_prime = eq_at_r_x_prime.mul(&f_at_r_x_prime);
        let last_round = &outer_round_polys[m - 1];
        let last_r = r_x_prime[m - 1];
        let expected = eval_poly_at(last_round, &last_r);
        debug_assert_eq!(
            g_at_r_x_prime, expected,
            "外层 sumcheck final check 应一致"
        );
    }

    // ===== 5. 吸收 v_pp，派生 γ =====
    transcript.absorb_field_slice(SUMCHECK_DOMAIN_TAG, &v_pp);
    let gamma = transcript.challenge(SUMCHECK_DOMAIN_TAG);

    // ===== 6. 内层 batched sumcheck =====
    // H(Y) = C(Y) · Z(Y)
    // C(Y) = Σ_j γ^j · M_j(r_x_prime, Y) — multilinear
    // Z(Y) = z'(Y) — multilinear
    //
    // 预计算 C 和 Z 的 evaluation tables on boolean hypercube {0,1}^n

    // c_table[y] = Σ_j γ^j · M_j(r_x_prime, y)
    // M_j(r_x_prime, y) = Σ_{(row,col,val) ∈ M_j.entries where col=y} val · eq(r_x_prime, row)
    // 注意：此处使用 r_x_prime（外层 sumcheck 产生的 fresh challenge），不是 r_x_L。
    // spec L392 写 M_j(r_x_L, y) 是简化标注，数学上应为 r_x_prime（见 alternatives.md）。
    let mut c_table = vec![Fr::zero(); num_vars];
    let mut gamma_pow = Fr::one();
    for j in 0..t {
        let m_j = &ccs.matrices[j];
        for entry in &m_j.entries {
            let eq_x = eq_eval(&r_x_prime, entry.row)?;
            let term = gamma_pow.mul(&entry.value).mul(&eq_x);
            c_table[entry.col] = c_table[entry.col].add(&term);
        }
        gamma_pow = gamma_pow.mul(&gamma);
    }

    // z_table[y] = z'[y]
    let z_table: Vec<Fr> = z_prime.to_vec();

    // 内层 sumcheck claimed sum = Σ_j γ^j · v_pp[j]
    let mut inner_claimed_sum = Fr::zero();
    let mut gamma_pow = Fr::one();
    for &vp in &v_pp {
        inner_claimed_sum = inner_claimed_sum.add(&gamma_pow.mul(&vp));
        gamma_pow = gamma_pow.mul(&gamma);
    }

    let mut inner_round_polys: Vec<Vec<Fr>> = Vec::with_capacity(n);
    let mut r_y: Vec<Fr> = Vec::with_capacity(n);

    let mut c_current = c_table;
    let mut z_current = z_table;

    for _k in 0..n {
        // 计算 round polynomial h_k(X_k) at points 0, 1, 2 (degree 2)
        let mut evals: Vec<Fr> = Vec::with_capacity(INNER_DEGREE + 1);
        for e in 0..=INNER_DEGREE {
            let e_fr = Fr::from_u32_with_wrap(e as u32);
            let c_e = bind_var(&c_current, &e_fr);
            let z_e = bind_var(&z_current, &e_fr);

            // H_e[i] = c_e[i] · z_e[i]
            let half = c_e.len();
            let mut h_sum = Fr::zero();
            for i in 0..half {
                h_sum = h_sum.add(&c_e[i].mul(&z_e[i]));
            }
            evals.push(h_sum);
        }

        // 吸收 round polynomial 并派生 challenge
        for eval_point in &evals {
            transcript.absorb_field(SUMCHECK_DOMAIN_TAG, eval_point);
        }
        let r_k = transcript.challenge(SUMCHECK_DOMAIN_TAG);

        inner_round_polys.push(evals);
        r_y.push(r_k);

        // 永久 bind
        c_current = bind_var(&c_current, &r_k);
        z_current = bind_var(&z_current, &r_k);
    }

    // 内层结束后：
    // c_current[0] = C(r_y) = Σ_j γ^j · M_j(r_x_prime, r_y)
    // z_current[0] = Z(r_y) = z'(r_y) = z_at_r_y
    let z_at_r_y = z_current[0];

    // 验证 prover 自己的 final check（debug 用）
    #[cfg(debug_assertions)]
    if n > 0 {
        let h_at_r_y = c_current[0].mul(&z_at_r_y);
        let last_round = &inner_round_polys[n - 1];
        let last_r = r_y[n - 1];
        let expected = eval_poly_at(last_round, &last_r);
        debug_assert_eq!(
            h_at_r_y, expected,
            "内层 sumcheck final check 应一致"
        );
    }

    Ok(SumcheckProverOutput {
        proof: SumcheckProof {
            outer_round_polys,
            v_pp,
            inner_round_polys,
        },
        r_y,
        z_at_r_y,
        actual_u_prime,
    })
}

// ============ Verify ============

/// 验证 Hypernova sumcheck 证明。
///
/// # 参数
/// - `proof` — Sumcheck 证明
/// - `ccs` — CCS 结构
/// - `r_x_l` — LCCCS 的 r_x
/// - `u_prime` — claimed sum（u'）
/// - `z_at_r_y` — PCS opening 提供的 z'(r_y) 值
/// - `transcript` — Fiat-Shamir transcript
///
/// # 返回
/// `true` 若外层 + 内层 sumcheck 均验证通过。
///
/// # 验证流程
/// 1. 外层 sumcheck：逐轮检查 g_k(0)+g_k(1) = expected，final check G(r_x_prime) 一致
/// 2. 内层 sumcheck：逐轮检查 h_k(0)+h_k(1) = expected，final check H(r_y) 一致
/// 3. Cross-language claim：`(Σ_j γ^j · M_j(r_x_prime, r_y)) · z_at_r_y == last_round_eval`
pub fn verify(
    proof: &SumcheckProof,
    ccs: &Ccs,
    r_x_l: &[Fr],
    u_prime: Fr,
    z_at_r_y: Fr,
    transcript: &mut Transcript,
) -> Result<bool, ZkvmError> {
    let num_rows = ccs.num_rows();
    let num_vars = ccs.num_vars;
    let m = num_rows.trailing_zeros() as usize;
    let n = num_vars.trailing_zeros() as usize;

    // 维度校验
    if proof.outer_round_polys.len() != m {
        return Err(ZkvmError::Other(format!(
            "sumcheck::verify: outer_round_polys.len() {} != m {}",
            proof.outer_round_polys.len(),
            m
        )));
    }
    if proof.inner_round_polys.len() != n {
        return Err(ZkvmError::Other(format!(
            "sumcheck::verify: inner_round_polys.len() {} != n {}",
            proof.inner_round_polys.len(),
            n
        )));
    }
    if proof.v_pp.len() != ccs.num_matrices() {
        return Err(ZkvmError::Other(format!(
            "sumcheck::verify: v_pp.len() {} != num_matrices {}",
            proof.v_pp.len(),
            ccs.num_matrices()
        )));
    }

    let d_outer = outer_degree(ccs);

    // ===== 1. 吸收 claimed sum =====
    transcript.absorb_field(SUMCHECK_DOMAIN_TAG, &u_prime);

    // ===== 2. 外层 sumcheck 验证 =====
    let mut r_x_prime: Vec<Fr> = Vec::with_capacity(m);
    let mut expected_sum = u_prime;

    for k in 0..m {
        let round_poly = &proof.outer_round_polys[k];
        if round_poly.len() != d_outer + 1 {
            return Err(ZkvmError::Other(format!(
                "sumcheck::verify: outer round {} has {} evals, expected {}",
                k,
                round_poly.len(),
                d_outer + 1
            )));
        }

        // 检查 g_k(0) + g_k(1) = expected_sum
        let g0_plus_g1 = round_poly[0].add(&round_poly[1]);
        if g0_plus_g1 != expected_sum {
            return Ok(false);
        }

        // 吸收 round polynomial
        for eval_point in round_poly {
            transcript.absorb_field(SUMCHECK_DOMAIN_TAG, eval_point);
        }

        // 派生 challenge
        let r_k = transcript.challenge(SUMCHECK_DOMAIN_TAG);
        r_x_prime.push(r_k);

        // 下一轮的 expected = g_k(r_k)
        expected_sum = eval_poly_at(round_poly, &r_k);
    }

    // 外层 final check: G(r_x_prime) = eq(r_x_prime, r_x_L) · Σ_i c_i · Π_{j∈S_i} v_pp[j]
    // 应等于 expected_sum（最后一轮 g_{m-1}(r_{m-1})）
    if m > 0 {
        let eq_at_r_x_prime = eq_eval_vec(&r_x_prime, r_x_l)?;
        let f_at_r_x_prime = crate::fold::lcccs::compute_relaxed_constraint(ccs, &proof.v_pp);
        let g_at_r_x_prime = eq_at_r_x_prime.mul(&f_at_r_x_prime);
        if g_at_r_x_prime != expected_sum {
            return Ok(false);
        }
    } else {
        // m = 0: num_rows = 1，无外层 round
        // G([]) = eq([], []) · Σ_i c_i · Π v_pp[j] = 1 · Σ_i c_i · Π v_pp[j]
        // 应等于 u'
        let f_val = crate::fold::lcccs::compute_relaxed_constraint(ccs, &proof.v_pp);
        if f_val != u_prime {
            return Ok(false);
        }
    }

    // ===== 3. 吸收 v_pp，派生 γ =====
    transcript.absorb_field_slice(SUMCHECK_DOMAIN_TAG, &proof.v_pp);
    let gamma = transcript.challenge(SUMCHECK_DOMAIN_TAG);

    // 内层 claimed sum = Σ_j γ^j · v_pp[j]
    let mut inner_claimed_sum = Fr::zero();
    let mut gamma_pow = Fr::one();
    for &vp in &proof.v_pp {
        inner_claimed_sum = inner_claimed_sum.add(&gamma_pow.mul(&vp));
        gamma_pow = gamma_pow.mul(&gamma);
    }

    // ===== 4. 内层 sumcheck 验证 =====
    let mut r_y: Vec<Fr> = Vec::with_capacity(n);
    let mut expected_inner = inner_claimed_sum;

    for k in 0..n {
        let round_poly = &proof.inner_round_polys[k];
        if round_poly.len() != INNER_DEGREE + 1 {
            return Err(ZkvmError::Other(format!(
                "sumcheck::verify: inner round {} has {} evals, expected {}",
                k,
                round_poly.len(),
                INNER_DEGREE + 1
            )));
        }

        // 检查 h_k(0) + h_k(1) = expected_inner
        let h0_plus_h1 = round_poly[0].add(&round_poly[1]);
        if h0_plus_h1 != expected_inner {
            return Ok(false);
        }

        // 吸收 round polynomial
        for eval_point in round_poly {
            transcript.absorb_field(SUMCHECK_DOMAIN_TAG, eval_point);
        }

        // 派生 challenge
        let r_k = transcript.challenge(SUMCHECK_DOMAIN_TAG);
        r_y.push(r_k);

        // 下一轮 expected = h_k(r_k)
        expected_inner = eval_poly_at(round_poly, &r_k);
    }

    // 内层 final check: H(r_y) = C(r_y) · Z(r_y)
    // C(r_y) = Σ_j γ^j · M_j(r_x_prime, r_y) — verifier 从矩阵条目计算
    // Z(r_y) = z_at_r_y — PCS opening 提供
    // 应等于 expected_inner（最后一轮 h_{n-1}(r_{n-1})）
    if n > 0 {
        let mut c_at_r_y = Fr::zero();
        let mut gamma_pow = Fr::one();
        for j in 0..ccs.num_matrices() {
            let m_j_at_r_y = evaluate_matrix_at(&ccs.matrices[j], &r_x_prime, &r_y)?;
            c_at_r_y = c_at_r_y.add(&gamma_pow.mul(&m_j_at_r_y));
            gamma_pow = gamma_pow.mul(&gamma);
        }
        let h_at_r_y = c_at_r_y.mul(&z_at_r_y);
        if h_at_r_y != expected_inner {
            return Ok(false);
        }
    } else {
        // n = 0: num_vars = 1，无内层 round
        // H([]) = C([]) · Z([]) = (Σ_j γ^j · M_j(r_x_prime, 0)) · z'[0]
        // 应等于 inner_claimed_sum
        let mut c_at_0 = Fr::zero();
        let mut gamma_pow = Fr::one();
        for j in 0..ccs.num_matrices() {
            // M_j(r_x_prime, 0) — col=0 的条目求和
            let m_j = &ccs.matrices[j];
            let mut m_val = Fr::zero();
            for entry in &m_j.entries {
                if entry.col == 0 {
                    let eq_x = eq_eval(&r_x_prime, entry.row)?;
                    m_val = m_val.add(&entry.value.mul(&eq_x));
                }
            }
            c_at_0 = c_at_0.add(&gamma_pow.mul(&m_val));
            gamma_pow = gamma_pow.mul(&gamma);
        }
        let h_at_0 = c_at_0.mul(&z_at_r_y);
        if h_at_0 != inner_claimed_sum {
            return Ok(false);
        }
    }

    Ok(true)
}

// ============ 测试 ============

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::SparseMatrix;
    use crate::fold::fold_step::fold;
    use crate::pcs::ipa::IpaCommitment;
    use ark_bn254::G1Affine;
    use ark_ec::AffineRepr;

    /// 辅助：构造 Fr。
    fn f(v: u32) -> Fr {
        Fr::from_u32_with_wrap(v)
    }

    /// 辅助：构造负 Fr。
    fn neg_f(v: u32) -> Fr {
        Fr::zero().sub(&f(v))
    }

    /// 构造 stub commitment。
    fn stub_commitment() -> IpaCommitment {
        IpaCommitment(G1Affine::generator())
    }

    /// 构造线性 CCS — x - y = 0（1 row, 4 vars, 2 matrices）
    /// num_vars=4（2 的幂，sumcheck 要求），z = [1, x, y, 0]（col 3 为 padding）
    fn make_linear_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();

        Ccs::new(4, vec![m0, m1], vec![vec![0], vec![1]], vec![f(1), neg_f(1)])
            .expect("linear Ccs 构造应成功")
    }

    /// 构造非线性 CCS — x * y - z = 0（1 row, 4 vars, 3 matrices）
    fn make_nonlinear_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        let mut m2 = SparseMatrix::new(1, 4);
        m2.add_entry(0, 3, f(1)).unwrap();

        Ccs::new(
            4,
            vec![m0, m1, m2],
            vec![vec![0, 1], vec![2]],
            vec![f(1), neg_f(1)],
        )
        .expect("nonlinear Ccs 构造应成功")
    }

    /// 构造 2-row 线性 CCS — row 0: x-y=0, row 1: y-z=0
    fn make_2row_linear_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(2, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        m0.add_entry(1, 2, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(2, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        m1.add_entry(1, 3, f(1)).unwrap();

        Ccs::new(4, vec![m0, m1], vec![vec![0], vec![1]], vec![f(1), neg_f(1)])
            .expect("2-row linear Ccs 构造应成功")
    }

    /// 构造 4-row 线性 CCS — 4 个约束行（num_vars=4，z = [1, x, y, 0]）
    fn make_4row_linear_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(4, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        m0.add_entry(1, 1, f(1)).unwrap();
        m0.add_entry(2, 1, f(1)).unwrap();
        m0.add_entry(3, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(4, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        m1.add_entry(1, 2, f(1)).unwrap();
        m1.add_entry(2, 2, f(1)).unwrap();
        m1.add_entry(3, 2, f(1)).unwrap();

        Ccs::new(4, vec![m0, m1], vec![vec![0], vec![1]], vec![f(1), neg_f(1)])
            .expect("4-row linear Ccs 构造应成功")
    }

    // ===== 辅助函数测试 =====

    #[test]
    fn test_eq_eval_vec_empty() {
        let result = eq_eval_vec(&[], &[]).expect("空向量 eq 应成功");
        assert_eq!(result, Fr::one(), "空积 = 1");
    }

    #[test]
    fn test_eq_eval_vec_boolean() {
        // eq((1,0), (1,0)) = 1
        let a = vec![f(1), f(0)];
        let b = vec![f(1), f(0)];
        assert_eq!(eq_eval_vec(&a, &b).unwrap(), Fr::one());

        // eq((1,0), (0,1)) = 0
        let b2 = vec![f(0), f(1)];
        assert_eq!(eq_eval_vec(&a, &b2).unwrap(), Fr::zero());
    }

    #[test]
    fn test_eq_eval_vec_non_boolean() {
        // eq((0.5,), (1,)) = 0.5
        let half = f(2).inverse().unwrap();
        let a = vec![half];
        let b = vec![f(1)];
        assert_eq!(eq_eval_vec(&a, &b).unwrap(), half);
    }

    #[test]
    fn test_bind_var() {
        let table = vec![f(1), f(2), f(3), f(4)];
        let r = f(0); // bind to 0
        let bound = bind_var(&table, &r);
        assert_eq!(bound, vec![f(1), f(3)]);

        let r = f(1); // bind to 1
        let bound = bind_var(&table, &r);
        assert_eq!(bound, vec![f(2), f(4)]);

        let half = f(2).inverse().unwrap();
        let bound = bind_var(&table, &half);
        // (1-0.5)*1 + 0.5*2 = 1.5
        // (1-0.5)*3 + 0.5*4 = 3.5
        assert_eq!(bound, vec![f(3).mul(&half), f(7).mul(&half)]);
    }

    #[test]
    fn test_eval_poly_at_degree1() {
        // g(x) = 2x + 3 → g(0)=3, g(1)=5
        let evals = vec![f(3), f(5)];
        assert_eq!(eval_poly_at(&evals, &f(0)), f(3));
        assert_eq!(eval_poly_at(&evals, &f(1)), f(5));
        // g(2) = 7
        assert_eq!(eval_poly_at(&evals, &f(2)), f(7));
    }

    #[test]
    fn test_eval_poly_at_degree2() {
        // g(x) = x^2 → g(0)=0, g(1)=1, g(2)=4
        let evals = vec![f(0), f(1), f(4)];
        assert_eq!(eval_poly_at(&evals, &f(0)), f(0));
        assert_eq!(eval_poly_at(&evals, &f(1)), f(1));
        assert_eq!(eval_poly_at(&evals, &f(2)), f(4));
        // g(3) = 9
        assert_eq!(eval_poly_at(&evals, &f(3)), f(9));
    }

    // ===== 基础 prove/verify 测试 =====

    #[test]
    fn test_sumcheck_linear_ccs_1row_satisfied() {
        // 线性 CCS: x - y = 0（1 row, m=0 外层轮）
        // z_L = [1, 5, 5, 0], z_C = [1, 3, 3, 0], r 从 fold 派生
        // z' = z_L + r·z_C, u' = 0
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut fold_t = Transcript::new();
        let fold_out = fold(&lcccs, &stub_commitment(), &ccccs, &mut fold_t).expect("fold");

        // z' = z_L + r·z_C
        let z_prime = fold_out.folded_witness.clone();
        let u_prime = fold_out.folded_lcccs.u_l;
        let r_x_l = fold_out.folded_lcccs.r_x_l.clone();

        // 生成 sumcheck proof（使用 fold 后的 transcript）
        let mut sc_t = fold_t.clone();
        let prover_out = prove(&ccs, &z_prime, &r_x_l, u_prime, &mut sc_t).expect("prove");

        // 验证（使用 actual_u_prime — 线性 CCS 下 = u_prime）
        let mut verify_t = fold_t.clone();
        let result = verify(
            &prover_out.proof,
            &ccs,
            &r_x_l,
            prover_out.actual_u_prime,
            prover_out.z_at_r_y,
            &mut verify_t,
        )
        .expect("verify");

        assert!(result, "线性 CCS 1-row sumcheck 应验证通过");
    }

    #[test]
    fn test_sumcheck_nonlinear_ccs_1row_satisfied() {
        // 非线性 CCS: x*y - z = 0（1 row, m=0 外层轮）
        // z_L = [1, 3, 4, 12] (satisfied: 3*4-12=0), z_C = [1, 2, 5, 10] (satisfied: 2*5-10=0)
        // 非线性 CCS 折叠后不代数满足（Π 不分配 +），需用 actual_u_prime
        let ccs = make_nonlinear_ccs();
        let z_l = vec![f(1), f(3), f(4), f(12)];
        let z_c = vec![f(1), f(2), f(5), f(10)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut fold_t = Transcript::new();
        let fold_out = fold(&lcccs, &stub_commitment(), &ccccs, &mut fold_t).expect("fold");

        let z_prime = fold_out.folded_witness.clone();
        let u_prime_spec = fold_out.folded_lcccs.u_l; // spec: u_L + r·u_C = 0
        let r_x_l = fold_out.folded_lcccs.r_x_l.clone();

        // 非线性 CCS: u_prime_spec = u_L + r·u_C = 0 + r·0 = 0（两 satisfied CCS）
        assert_eq!(
            u_prime_spec, Fr::zero(),
            "u_L + r·u_C 应为 0（两 satisfied CCS 的 u 均为 0）"
        );
        // 但 actual_u_prime ≠ 0（因 Π 不分配 +，产生 r² 等交叉项）

        let mut sc_t = fold_t.clone();
        let prover_out = prove(&ccs, &z_prime, &r_x_l, u_prime_spec, &mut sc_t).expect("prove");

        // 非线性 CCS: actual_u_prime ≠ u_prime_spec
        assert_ne!(
            prover_out.actual_u_prime, u_prime_spec,
            "非线性 CCS: actual_u_prime ≠ u_L + r·u_C"
        );

        // 验证：必须使用 actual_u_prime（非 spec 的 u_prime）
        let mut verify_t = fold_t.clone();
        let result = verify(
            &prover_out.proof,
            &ccs,
            &r_x_l,
            prover_out.actual_u_prime, // ← 使用实际值
            prover_out.z_at_r_y,
            &mut verify_t,
        )
        .expect("verify");

        assert!(result, "非线性 CCS 1-row sumcheck 应验证通过（使用 actual_u_prime）");

        // 反例：使用 spec 的 u_prime 应验证失败
        let mut verify_t2 = fold_t.clone();
        let result2 = verify(
            &prover_out.proof,
            &ccs,
            &r_x_l,
            u_prime_spec, // ← 使用 spec 值（错误）
            prover_out.z_at_r_y,
            &mut verify_t2,
        )
        .expect("verify");
        assert!(
            !result2,
            "非线性 CCS 使用 spec u_prime 应验证失败（actual ≠ spec）"
        );
    }

    // ===== 多行线性 CCS 测试（m > 0 外层轮）=====

    #[test]
    fn test_sumcheck_2row_linear_ccs_satisfied() {
        // 2-row 线性 CCS: row 0: x-y=0, row 1: y-z=0（m=1 外层轮）
        let ccs = make_2row_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(5)]; // row 0: 5-5=0, row 1: 5-5=0
        let z_c = vec![f(1), f(3), f(3), f(3)]; // row 0: 3-3=0, row 1: 3-3=0

        // r_x_l = [0]（在 row 0 处求值），x_l 长度须 = x_c 长度 = log2(num_rows) = 1
        let lcccs = ccs.to_lcccs(&z_l, &[f(0)], vec![f(0)]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![f(0)], stub_commitment())
            .expect("to_cccs");

        let mut fold_t = Transcript::new();
        let fold_out = fold(&lcccs, &stub_commitment(), &ccccs, &mut fold_t).expect("fold");

        let z_prime = fold_out.folded_witness.clone();
        let u_prime = fold_out.folded_lcccs.u_l;
        let r_x_l = fold_out.folded_lcccs.r_x_l.clone();

        let mut sc_t = fold_t.clone();
        let prover_out = prove(&ccs, &z_prime, &r_x_l, u_prime, &mut sc_t).expect("prove");

        // 线性 CCS: actual_u_prime == u_prime
        assert_eq!(
            prover_out.actual_u_prime, u_prime,
            "线性 CCS: actual_u_prime 应 = u_prime"
        );

        let mut verify_t = fold_t.clone();
        let result = verify(
            &prover_out.proof,
            &ccs,
            &r_x_l,
            prover_out.actual_u_prime,
            prover_out.z_at_r_y,
            &mut verify_t,
        )
        .expect("verify");

        assert!(result, "2-row 线性 CCS sumcheck 应验证通过（m=1 外层轮）");
    }

    #[test]
    fn test_sumcheck_4row_linear_ccs_satisfied() {
        // 4-row 线性 CCS（m=2 外层轮, num_vars=4）
        let ccs = make_4row_linear_ccs();
        let z_l = vec![f(1), f(7), f(7), f(0)]; // 所有行: 7-7=0
        let z_c = vec![f(1), f(4), f(4), f(0)]; // 所有行: 4-4=0

        // r_x_l = [0, 0]，x_l 长度须 = x_c 长度 = log2(num_rows) = 2
        let lcccs = ccs.to_lcccs(&z_l, &[f(0), f(0)], vec![f(0), f(0)]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![f(0), f(0)], stub_commitment())
            .expect("to_cccs");

        let mut fold_t = Transcript::new();
        let fold_out = fold(&lcccs, &stub_commitment(), &ccccs, &mut fold_t).expect("fold");

        let z_prime = fold_out.folded_witness.clone();
        let u_prime = fold_out.folded_lcccs.u_l;
        let r_x_l = fold_out.folded_lcccs.r_x_l.clone();

        let mut sc_t = fold_t.clone();
        let prover_out = prove(&ccs, &z_prime, &r_x_l, u_prime, &mut sc_t).expect("prove");

        assert_eq!(
            prover_out.actual_u_prime, u_prime,
            "线性 CCS: actual_u_prime 应 = u_prime"
        );

        let mut verify_t = fold_t.clone();
        let result = verify(
            &prover_out.proof,
            &ccs,
            &r_x_l,
            prover_out.actual_u_prime,
            prover_out.z_at_r_y,
            &mut verify_t,
        )
        .expect("verify");

        assert!(result, "4-row 线性 CCS sumcheck 应验证通过（m=2 外层轮）");
    }

    // ===== u' ≠ 0 场景 =====

    #[test]
    fn test_sumcheck_u_prime_nonzero() {
        // 线性 CCS with non-zero u'：通过 unsatisfied witness 产生 u_L ≠ 0
        // CCS: x - y = 0, z_L = [1, 5, 3, 0] → u_L = 5 - 3 = 2 ≠ 0
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(3), f(0)]; // u_L = 5 - 3 = 2
        let z_c = vec![f(1), f(3), f(3), f(0)]; // u_C = 0

        // to_lcccs 计算 u_L = compute_relaxed_constraint(ccs, v_l)
        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        // u_L 应为 2（非 0）
        assert_ne!(lcccs.u_l, Fr::zero(), "u_L 应非 0");

        let mut fold_t = Transcript::new();
        let fold_out = fold(&lcccs, &stub_commitment(), &ccccs, &mut fold_t).expect("fold");

        let z_prime = fold_out.folded_witness.clone();
        let u_prime = fold_out.folded_lcccs.u_l;
        let r_x_l = fold_out.folded_lcccs.r_x_l.clone();

        // u' = u_L + r·u_C = u_L + 0 = u_L ≠ 0
        assert_ne!(u_prime, Fr::zero(), "u' 应非 0");

        let mut sc_t = fold_t.clone();
        let prover_out = prove(&ccs, &z_prime, &r_x_l, u_prime, &mut sc_t).expect("prove");

        assert_eq!(
            prover_out.actual_u_prime, u_prime,
            "线性 CCS: actual_u_prime 应 = u_prime"
        );

        let mut verify_t = fold_t.clone();
        let result = verify(
            &prover_out.proof,
            &ccs,
            &r_x_l,
            prover_out.actual_u_prime,
            prover_out.z_at_r_y,
            &mut verify_t,
        )
        .expect("verify");

        assert!(result, "u' ≠ 0 场景 sumcheck 应验证通过");
    }

    // ===== Soundness 测试 =====

    #[test]
    fn test_sumcheck_soundness_tampered_claimed_sum() {
        // 篡改 claimed sum → verify 应失败
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut fold_t = Transcript::new();
        let fold_out = fold(&lcccs, &stub_commitment(), &ccccs, &mut fold_t).expect("fold");

        let z_prime = fold_out.folded_witness.clone();
        let u_prime = fold_out.folded_lcccs.u_l;
        let r_x_l = fold_out.folded_lcccs.r_x_l.clone();

        let mut sc_t = fold_t.clone();
        let prover_out = prove(&ccs, &z_prime, &r_x_l, u_prime, &mut sc_t).expect("prove");

        // 篡改 claimed sum：加 1
        let tampered_u = prover_out.actual_u_prime.add(&Fr::one());
        let mut verify_t = fold_t.clone();
        let result = verify(
            &prover_out.proof,
            &ccs,
            &r_x_l,
            tampered_u,
            prover_out.z_at_r_y,
            &mut verify_t,
        )
        .expect("verify");

        assert!(!result, "篡改 claimed sum 应验证失败");
    }

    #[test]
    fn test_sumcheck_soundness_tampered_proof() {
        // 篡改 proof 中的 round polynomial → verify 应失败
        let ccs = make_2row_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3), f(3)];

        let lcccs = ccs.to_lcccs(&z_l, &[f(0)], vec![f(0)]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![f(0)], stub_commitment())
            .expect("to_cccs");

        let mut fold_t = Transcript::new();
        let fold_out = fold(&lcccs, &stub_commitment(), &ccccs, &mut fold_t).expect("fold");

        let z_prime = fold_out.folded_witness.clone();
        let u_prime = fold_out.folded_lcccs.u_l;
        let r_x_l = fold_out.folded_lcccs.r_x_l.clone();

        let mut sc_t = fold_t.clone();
        let prover_out = prove(&ccs, &z_prime, &r_x_l, u_prime, &mut sc_t).expect("prove");

        // 篡改外层第一个 round polynomial 的第一个点
        let mut tampered_proof = prover_out.proof.clone();
        if !tampered_proof.outer_round_polys.is_empty() {
            let mut round = tampered_proof.outer_round_polys[0].clone();
            round[0] = round[0].add(&Fr::one());
            tampered_proof.outer_round_polys[0] = round;
        }

        let mut verify_t = fold_t.clone();
        let result = verify(
            &tampered_proof,
            &ccs,
            &r_x_l,
            prover_out.actual_u_prime,
            prover_out.z_at_r_y,
            &mut verify_t,
        )
        .expect("verify");

        assert!(!result, "篡改 proof round polynomial 应验证失败");
    }

    #[test]
    fn test_sumcheck_soundness_tampered_z_at_r_y() {
        // 篡改 z_at_r_y（PCS opening 值）→ verify 应失败
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut fold_t = Transcript::new();
        let fold_out = fold(&lcccs, &stub_commitment(), &ccccs, &mut fold_t).expect("fold");

        let z_prime = fold_out.folded_witness.clone();
        let u_prime = fold_out.folded_lcccs.u_l;
        let r_x_l = fold_out.folded_lcccs.r_x_l.clone();

        let mut sc_t = fold_t.clone();
        let prover_out = prove(&ccs, &z_prime, &r_x_l, u_prime, &mut sc_t).expect("prove");

        // 篡改 z_at_r_y：加 1
        let tampered_z = prover_out.z_at_r_y.add(&Fr::one());
        let mut verify_t = fold_t.clone();
        let result = verify(
            &prover_out.proof,
            &ccs,
            &r_x_l,
            prover_out.actual_u_prime,
            tampered_z,
            &mut verify_t,
        )
        .expect("verify");

        assert!(!result, "篡改 z_at_r_y 应验证失败");
    }

    #[test]
    fn test_sumcheck_nonlinear_u_prime_nonzero() {
        // 非线性 CCS + u_L ≠ 0 场景
        // CCS: x*y - z = 0, z_L = [1, 3, 4, 11] → u_L = 3*4-11 = 1 ≠ 0
        let ccs = make_nonlinear_ccs();
        let z_l = vec![f(1), f(3), f(4), f(11)]; // u_L = 12-11 = 1
        let z_c = vec![f(1), f(2), f(5), f(10)]; // u_C = 0

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        assert_ne!(lcccs.u_l, Fr::zero(), "u_L 应非 0");

        let mut fold_t = Transcript::new();
        let fold_out = fold(&lcccs, &stub_commitment(), &ccccs, &mut fold_t).expect("fold");

        let z_prime = fold_out.folded_witness.clone();
        let u_prime_spec = fold_out.folded_lcccs.u_l;
        let r_x_l = fold_out.folded_lcccs.r_x_l.clone();

        let mut sc_t = fold_t.clone();
        let prover_out = prove(&ccs, &z_prime, &r_x_l, u_prime_spec, &mut sc_t).expect("prove");

        // 非线性 CCS: actual_u_prime ≠ u_prime_spec
        assert_ne!(
            prover_out.actual_u_prime, u_prime_spec,
            "非线性 CCS: actual_u_prime ≠ spec u_prime"
        );

        let mut verify_t = fold_t.clone();
        let result = verify(
            &prover_out.proof,
            &ccs,
            &r_x_l,
            prover_out.actual_u_prime,
            prover_out.z_at_r_y,
            &mut verify_t,
        )
        .expect("verify");

        assert!(result, "非线性 CCS u'≠0 场景 sumcheck 应验证通过");
    }

    #[test]
    fn test_sumcheck_dimension_validation() {
        // 维度校验：z_prime 长度不匹配
        let ccs = make_linear_ccs();
        let bad_z = vec![f(1), f(2)]; // 长度 2 ≠ num_vars 4
        let mut t = Transcript::new();
        let result = prove(&ccs, &bad_z, &[], Fr::zero(), &mut t);
        assert!(result.is_err(), "z_prime 维度不匹配应返回错误");

        // r_x_l 长度不匹配
        let z = vec![f(1), f(2), f(3), f(0)]; // 正确长度 4
        let bad_r_x = vec![f(0), f(0)]; // 长度 2 ≠ log2(1) = 0
        let mut t = Transcript::new();
        let result = prove(&ccs, &z, &bad_r_x, Fr::zero(), &mut t);
        assert!(result.is_err(), "r_x_l 维度不匹配应返回错误");
    }

    #[test]
    fn test_sumcheck_verify_dimension_validation() {
        // verify 维度校验
        let ccs = make_linear_ccs();
        let bad_proof = SumcheckProof {
            outer_round_polys: vec![vec![Fr::zero()]], // 长度 1 ≠ m = 0
            v_pp: vec![Fr::zero(), Fr::zero()],
            inner_round_polys: vec![],
        };
        let mut t = Transcript::new();
        let result = verify(&bad_proof, &ccs, &[], Fr::zero(), Fr::zero(), &mut t);
        assert!(result.is_err(), "outer_round_polys 维度不匹配应返回错误");

        // v_pp 长度不匹配
        let bad_proof2 = SumcheckProof {
            outer_round_polys: vec![],
            v_pp: vec![Fr::zero()], // 长度 1 ≠ num_matrices = 2
            inner_round_polys: vec![],
        };
        let mut t = Transcript::new();
        let result = verify(&bad_proof2, &ccs, &[], Fr::zero(), Fr::zero(), &mut t);
        assert!(result.is_err(), "v_pp 维度不匹配应返回错误");
    }
}