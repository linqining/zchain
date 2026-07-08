//! 单步折叠（Phase 6 — Task 6.4）。
//!
//! 严格遵循 spec.md L366-379（v1.4 FROZEN）与 Hypernova 原论文。
//!
//! ## 折叠核心等式
//!
//! ```text
//! r       ← FS challenge（标量，absorb ccs_commitment + commitments + u/x/v）
//! u'      = u_L + r · u_C                                  (标量)
//! x'      = x_L + r · x_C                                  (向量)
//! trace'  = trace_L + r · trace_C                          (向量)
//! r_x'    = r_x_L                                          (沿用 LCCCS_L)
//! v'[j]   = v_L[j] + r · v_C[j](r_x_L)                    (分量级)
//! z'      = z_L + r · z_C                                  (folded witness)
//! C'      = C_L + r · C_C                                  (folded commitment)
//! ```
//!
//! 其中 `v_C[j](r_x_L) = Σ_y M_j(r_x_L, y) · z_C(y)` 通过 [`Ccs::compute_v_at`] 计算。
//!
//! ## v1.3 关键修正
//!
//! - **C2-002**：v_C[j] 不存储在 CCCCS 中，折叠时在 r_x_L 处即时求值
//! - **C2-003**：u' 为标量（外层 sumcheck claimed sum）
//! - **M2-001**：folded LCCCS relaxed 约束 `Σ c_i · Π v'[j] = u'`（u' 可非 0）
//!
//! ## 实现决策
//!
//! - **witness_commitment_l 参数**：spec L353 的 LCCCS 结构不含 witness_commitment 字段，
//!   但 spec L432 的 absorb 序列含 `lcccs_witness_commitment`。本实现将 witness_commitment_l
//!   作为 fold 函数的独立参数传入（不修改 Lcccs 结构），见 alternatives.md。
//! - **sumcheck 子证明**：Step 4 暂不生成完整 sumcheck proof（待 Step 5 实现 sumcheck.rs），
//!   仅计算 v_C[j](r_x_L) 并构造 folded LCCCS。Step 5 将扩展 FoldStepOutput 加入 sumcheck_proof。
//!
//! ## 代数满足性说明
//!
//! 对**线性 CCS**（所有 |S_i| = 1），folded LCCCS 代数满足 `Σ c_i · Π v'[j] = u'`。
//! 对**非线性 CCS**（存在 |S_i| ≥ 2），代数等式一般不成立（因 Π 展开产生交叉项 r² 等），
//! 需通过外层 sumcheck 密码学证明。本模块的 `fold()` 仅计算实例，不验证代数等式。

use ark_bn254::G1Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;

use crate::ccs::Fr;
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::fold::ccccs::Ccccs;
use crate::fold::lcccs::Lcccs;
use crate::pcs::ipa::IpaCommitment;
use crate::transcript::{Transcript, HYPERNOVA_FOLD_DOMAIN_TAG};

/// 将 G1Affine 点序列化为 compressed bytes（用于 transcript absorb）。
fn point_to_bytes(p: &G1Affine) -> Vec<u8> {
    let mut bytes = Vec::new();
    p.serialize_compressed(&mut bytes)
        .expect("G1Affine serialize_compressed 不应失败");
    bytes
}

/// 单步折叠输出（prover 视角，含 verifier 所需的 folded LCCCS）。
#[derive(Debug, Clone)]
pub struct FoldStepOutput {
    /// 折叠后的 LCCCS 实例（verifier view）。
    pub folded_lcccs: Lcccs,
    /// 折叠后的 witness `z' = z_L + r · z_C`（prover view，用于 PCS opening）。
    pub folded_witness: Vec<Fr>,
    /// 折叠后的 witness commitment `C' = C_L + r · C_C`（prover view，用于下一轮 fold 或 PCS verify）。
    pub folded_commitment: IpaCommitment,
    /// fold challenge `r`（FS 派生的标量）。
    pub fold_challenge: Fr,
    /// `v_C[j](r_x_L)` 求值向量（长度 = num_matrices），用于调试与测试。
    /// `v_C[j](r_x_L) = Σ_y M_j(r_x_L, y) · z_C(y)`。
    pub v_c_at_r_x_l: Vec<Fr>,
}

/// Hypernova 单步折叠（spec L366-379）。
///
/// # 参数
/// - `lcccs` — LCCCS_L 实例（running instance）
/// - `witness_commitment_l` — LCCCS_L 的 witness commitment `C_L`
/// - `ccccs` — CCCCS_C 实例（incoming instance，含 `witness_commitment_c`）
/// - `transcript` — Fiat-Shamir transcript（用于派生 fold challenge `r`）
///
/// # 返回
/// [`FoldStepOutput`]，含 folded LCCCS + folded witness + folded commitment + challenge。
///
/// # 错误
/// - `CcsCommitmentMismatch` — LCCCS 与 CCCCS 引用不同 CCS 结构
/// - `FieldDimensionMismatch` — x_L / x_C / trace_L / trace_C 维度不一致
/// - `Lcccs::new` 失败（folded 字段维度校验）
///
/// # 吸收顺序（spec L432，v1.4 FROZEN）
///
/// 1. `ccs_commitment`（32 bytes Blake2b）
/// 2. `lcccs_witness_commitment`（compressed G1 point）
/// 3. `lcccs_u_l` / `lcccs_x_l` / `lcccs_r_x_l` / `lcccs_v_l`
/// 4. `ccccs_witness_commitment`（compressed G1 point）
/// 5. `ccccs_u_c` / `ccccs_x_c`
///
/// **注**：spec L432 列出 `ccccs_v`，但 v1.3 修正 C2-002 后 CCCCS 不存储 v_C，
/// 故此处省略（v_C 在 r_x_L 处的求值由 fold 内部计算，非实例字段）。
pub fn fold(
    lcccs: &Lcccs,
    witness_commitment_l: &IpaCommitment,
    ccccs: &Ccccs,
    transcript: &mut Transcript,
) -> Result<FoldStepOutput, ZkvmError> {
    // 1. 校验 CCS 引用一致（防 CCS 结构替换攻击）
    let ccs_commit_l = lcccs.ccs_ref.ccs_commitment();
    let ccs_commit_c = ccccs.ccs_ref.ccs_commitment();
    if ccs_commit_l != ccs_commit_c {
        return Err(ZkvmError::Other(
            "fold: CCS commitment mismatch — lcccs.ccs_ref != ccccs.ccs_ref".to_string(),
        ));
    }

    // 2. 校验维度一致（x_L 与 x_C 长度应相同，trace_L 与 trace_C 长度应相同）
    if lcccs.x_l.len() != ccccs.x_c.len() {
        return Err(ZkvmError::Other(format!(
            "fold: x_l.len() {} != x_c.len() {}",
            lcccs.x_l.len(),
            ccccs.x_c.len()
        )));
    }
    if lcccs.trace_l.len() != ccccs.trace_c.len() {
        return Err(ZkvmError::Other(format!(
            "fold: trace_l.len() {} != trace_c.len() {}",
            lcccs.trace_l.len(),
            ccccs.trace_c.len()
        )));
    }

    // 3. absorb fold 输入到 transcript（spec L432 顺序）
    // (a) ccs_commitment
    transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &ccs_commit_l);

    // (b) lcccs_witness_commitment
    transcript.absorb(
        HYPERNOVA_FOLD_DOMAIN_TAG,
        &point_to_bytes(&witness_commitment_l.0),
    );

    // (c) lcccs_u_l / x_l / r_x_l / v_l
    transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, &lcccs.u_l);
    transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &lcccs.x_l);
    transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &lcccs.r_x_l);
    transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &lcccs.v_l);

    // (d) ccccs_witness_commitment
    transcript.absorb(
        HYPERNOVA_FOLD_DOMAIN_TAG,
        &point_to_bytes(&ccccs.witness_commitment_c.0),
    );

    // (e) ccccs_u_c / x_c（注：不 absorb v_c，因 CCCCS 不存储 v_C — v1.3 C2-002）
    transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, &ccccs.u_c);
    transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &ccccs.x_c);

    // 4. 派生 fold challenge r（标量）
    let r = transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG);

    // 5. 计算折叠后的字段
    // (a) u' = u_L + r · u_C
    let folded_u = lcccs.u_l.add(&r.mul(&ccccs.u_c));

    // (b) x' = x_L + r · x_C（向量）
    let folded_x: Vec<Fr> = lcccs
        .x_l
        .iter()
        .zip(ccccs.x_c.iter())
        .map(|(xl, xc)| xl.add(&r.mul(xc)))
        .collect();

    // (c) trace' = trace_L + r · trace_C（向量）
    let folded_trace: Vec<Fr> = lcccs
        .trace_l
        .iter()
        .zip(ccccs.trace_c.iter())
        .map(|(tl, tc)| tl.add(&r.mul(tc)))
        .collect();

    // (d) r_x' = r_x_L（沿用 LCCCS_L 的 r_x）
    let folded_r_x_l = lcccs.r_x_l.clone();

    // (e) v_C[j](r_x_L) = Σ_y M_j(r_x_L, y) · z_C(y)
    //     使用 Ccs::compute_v_at（共享工具方法）
    let v_c_at_r_x_l = ccccs.ccs_ref.compute_v_at(&ccccs.trace_c, &lcccs.r_x_l)?;

    // (f) v'[j] = v_L[j] + r · v_C[j](r_x_L)（分量级）
    if lcccs.v_l.len() != v_c_at_r_x_l.len() {
        return Err(ZkvmError::Other(format!(
            "fold: v_l.len() {} != v_c_at_r_x_l.len() {}",
            lcccs.v_l.len(),
            v_c_at_r_x_l.len()
        )));
    }
    let folded_v: Vec<Fr> = lcccs
        .v_l
        .iter()
        .zip(v_c_at_r_x_l.iter())
        .map(|(vl, vc)| vl.add(&r.mul(vc)))
        .collect();

    // (g) z' = z_L + r · z_C（folded witness — prover view，用于 PCS opening）
    //     z_L = trace_L, z_C = trace_C
    let folded_witness: Vec<Fr> = lcccs
        .trace_l
        .iter()
        .zip(ccccs.trace_c.iter())
        .map(|(zl, zc)| zl.add(&r.mul(zc)))
        .collect();

    // (h) C' = C_L + r · C_C（folded commitment — EC 点加法）
    let c_l_group = witness_commitment_l.0.into_group();
    let c_c_group = ccccs.witness_commitment_c.0.into_group();
    let r_ark = r.into_fr();
    let folded_commitment_group = c_l_group + c_c_group * r_ark;
    let folded_commitment = IpaCommitment(folded_commitment_group.into_affine());

    // 6. 构造 folded LCCCS 实例
    let folded_lcccs = Lcccs::new(
        lcccs.ccs_ref.clone(),
        folded_u,
        folded_x,
        folded_trace,
        folded_r_x_l,
        folded_v,
    )?;

    Ok(FoldStepOutput {
        folded_lcccs,
        folded_witness,
        folded_commitment,
        fold_challenge: r,
        v_c_at_r_x_l,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::{Ccs, SparseMatrix};
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

    /// 构造不同的 stub commitment（用于测试 commitment 绑定）。
    fn stub_commitment_2() -> IpaCommitment {
        IpaCommitment((G1Affine::generator().into_group() * ark_bn254::Fr::from(2u64)).into_affine())
    }

    /// 构造线性 CCS（所有 |S_i| = 1）— 约束：x - y = 0
    /// z = [1, x, y]
    /// M_0 = [[0,1,0]] → M_0·z = x
    /// M_1 = [[0,0,1]] → M_1·z = y
    /// S_0={0}, c_0=1; S_1={1}, c_1=-1
    /// 约束：x - y = 0
    fn make_linear_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(1, 3);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 3);
        m1.add_entry(0, 2, f(1)).unwrap();

        Ccs::new(
            3,
            vec![m0, m1],
            vec![vec![0], vec![1]],
            vec![f(1), neg_f(1)],
        )
        .expect("linear Ccs 构造应成功")
    }

    /// 构造非线性 CCS（|S_0| = 2）— 约束：x * y - z = 0
    /// z = [1, x, y, z_val]
    /// M_0 = [[0,1,0,0]] → x
    /// M_1 = [[0,0,1,0]] → y
    /// M_2 = [[0,0,0,1]] → z_val
    /// S_0={0,1}, c_0=1; S_1={2}, c_1=-1
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

    /// 构造 2-row 线性 CCS — 单约束 M_0·z - M_1·z = 0 应用于所有行
    /// z = [1, x, y, z_val]
    /// M_0: row 0 → x (col 1), row 1 → y (col 2)
    /// M_1: row 0 → y (col 2), row 1 → z_val (col 3)
    /// S_0={0}, c_0=1; S_1={1}, c_1=-1
    /// 约束：row 0: x - y = 0, row 1: y - z_val = 0
    fn make_multi_row_linear_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(2, 4);
        m0.add_entry(0, 1, f(1)).unwrap(); // row 0: x
        m0.add_entry(1, 2, f(1)).unwrap(); // row 1: y

        let mut m1 = SparseMatrix::new(2, 4);
        m1.add_entry(0, 2, f(1)).unwrap(); // row 0: y
        m1.add_entry(1, 3, f(1)).unwrap(); // row 1: z_val

        Ccs::new(
            4,
            vec![m0, m1],
            vec![vec![0], vec![1]],
            vec![f(1), neg_f(1)],
        )
        .expect("multi-row linear Ccs 构造应成功")
    }

    // ===== 正例：线性 CCS 折叠后代数满足 =====

    #[test]
    fn test_fold_linear_ccs_satisfied() {
        // 线性 CCS: x - y = 0
        // z_L = [1, 5, 5] (satisfied: 5 - 5 = 0)
        // z_C = [1, 3, 3] (satisfied: 3 - 3 = 0)
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut transcript = Transcript::new();
        let output = fold(&lcccs, &stub_commitment(), &ccccs, &mut transcript).expect("fold 应成功");

        // 线性 CCS: u' = u_L + r·u_C = 0 + r·0 = 0
        assert_eq!(output.folded_lcccs.u_l, Fr::zero());

        // folded LCCCS 代数满足（线性 CCS 特性）
        assert!(
            output.folded_lcccs.satisfied().unwrap(),
            "线性 CCS 折叠后应代数满足 relaxed 约束"
        );

        // v' 长度 = num_matrices = 2
        assert_eq!(output.folded_lcccs.v_l.len(), 2);
        // v_C[j](r_x_L) 长度 = 2
        assert_eq!(output.v_c_at_r_x_l.len(), 2);
    }

    #[test]
    fn test_fold_linear_ccs_multi_row_satisfied() {
        // 2-row 线性 CCS, r_x_l = [0]（在 row 0 处求值）
        // z_L = [1, 5, 5, 5] (row 0: 5-5=0, row 1: 5-5=0)
        // 注：x_l 和 x_c 必须同长度（fold 方程 x' = x_L + r·x_C 要求）
        let ccs = make_multi_row_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3), f(3)];

        let lcccs = ccs.to_lcccs(&z_l, &[f(0)], vec![f(0)]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![f(0)], stub_commitment())
            .expect("to_cccs");

        let mut transcript = Transcript::new();
        let output = fold(&lcccs, &stub_commitment(), &ccccs, &mut transcript).expect("fold");

        // u' = 0（两个 satisfied CCS 在 boolean 点 r_x_l=[0] 处 u 均为 0）
        assert_eq!(output.folded_lcccs.u_l, Fr::zero());
        assert!(
            output.folded_lcccs.satisfied().unwrap(),
            "多行线性 CCS 在 boolean r_x_l 处折叠后应代数满足"
        );
    }

    #[test]
    fn test_fold_linear_ccs_folded_witness_correct() {
        // 验证 z' = z_L + r·z_C
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut transcript = Transcript::new();
        let output = fold(&lcccs, &stub_commitment(), &ccccs, &mut transcript).expect("fold");

        let r = output.fold_challenge;
        // z' = z_L + r·z_C
        let expected_z: Vec<Fr> = z_l
            .iter()
            .zip(z_c.iter())
            .map(|(zl, zc)| zl.add(&r.mul(zc)))
            .collect();
        assert_eq!(output.folded_witness, expected_z);
    }

    #[test]
    fn test_fold_folded_commitment_correct() {
        // 验证 C' = C_L + r·C_C
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let cmt_l = stub_commitment();
        let cmt_c = stub_commitment_2();
        let ccccs = ccs
            .to_cccs(&z_c, vec![], cmt_c.clone())
            .expect("to_cccs");

        let mut transcript = Transcript::new();
        let output = fold(&lcccs, &cmt_l, &ccccs, &mut transcript).expect("fold");

        let r = output.fold_challenge;
        // C' = C_L + r·C_C
        let c_l_group = cmt_l.0.into_group();
        let c_c_group = cmt_c.0.into_group();
        let r_ark = r.into_fr();
        let expected_group = c_l_group + c_c_group * r_ark;
        let expected = IpaCommitment(expected_group.into_affine());
        assert_eq!(output.folded_commitment.0, expected.0);
    }

    #[test]
    fn test_fold_v_c_at_r_x_l_correct() {
        // 验证 v_C[j](r_x_L) 计算正确
        // 线性 CCS: M_0·z = x, M_1·z = y
        // z_C = [1, 3, 3] → v_C = [3, 3]（在 r_x_l=[] 即 row 0 处）
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut transcript = Transcript::new();
        let output = fold(&lcccs, &stub_commitment(), &ccccs, &mut transcript).expect("fold");

        // v_C[0](r_x_L) = M_0·z_C = x = 3
        assert_eq!(output.v_c_at_r_x_l[0], f(3));
        // v_C[1](r_x_L) = M_1·z_C = y = 3
        assert_eq!(output.v_c_at_r_x_l[1], f(3));

        // v'[0] = v_L[0] + r·v_C[0] = 5 + r·3
        let r = output.fold_challenge;
        let expected_v0 = f(5).add(&r.mul(&f(3)));
        assert_eq!(output.folded_lcccs.v_l[0], expected_v0);
    }

    // ===== 负例：非线性 CCS 折叠后代数不满足（需 sumcheck）=====

    #[test]
    fn test_fold_nonlinear_ccs_not_algebraically_satisfied() {
        // 非线性 CCS: x*y - z = 0
        // z_L = [1, 3, 4, 12] (satisfied: 3*4 - 12 = 0)
        // z_C = [1, 2, 5, 10] (satisfied: 2*5 - 10 = 0)
        let ccs = make_nonlinear_ccs();
        let z_l = vec![f(1), f(3), f(4), f(12)];
        let z_c = vec![f(1), f(2), f(5), f(10)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut transcript = Transcript::new();
        let output = fold(&lcccs, &stub_commitment(), &ccccs, &mut transcript).expect("fold");

        // u' = u_L + r·u_C = 0 + r·0 = 0（两个 satisfied CCS）
        assert_eq!(output.folded_lcccs.u_l, Fr::zero());

        // 非线性 CCS: 代数等式 Σ c_i · Π v'[j] 一般不等于 u'
        // v'[0]·v'[1] - v'[2] = (v_L[0]+r·v_C[0])·(v_L[1]+r·v_C[1]) - (v_L[2]+r·v_C[2])
        //   = v_L[0]·v_L[1] - v_L[2]  +  r·(v_L[0]·v_C[1] + v_C[0]·v_L[1] - v_C[2])  +  r²·(v_C[0]·v_C[1])
        //   = 0  +  r·(3·5 + 2·4 - 10)  +  r²·(2·5)
        //   = r·(15 + 8 - 10) + r²·10
        //   = 13r + 10r²  ≠  0 = u'
        let r = output.fold_challenge;
        let r_squared = r.square();
        let expected_algebraic = f(13).mul(&r).add(&f(10).mul(&r_squared));
        let computed = crate::fold::lcccs::compute_relaxed_constraint(
            &output.folded_lcccs.ccs_ref,
            &output.folded_lcccs.v_l,
        );
        assert_eq!(
            computed, expected_algebraic,
            "非线性 CCS 折叠后代数值应匹配手算"
        );
        assert_ne!(
            computed, output.folded_lcccs.u_l,
            "非线性 CCS 折叠后不应代数满足（需 sumcheck 证明）"
        );
        assert!(
            !output.folded_lcccs.satisfied().unwrap(),
            "非线性 CCS 折叠后 satisfied() 应返回 false（代数不满足）"
        );
    }

    // ===== 错误处理 =====

    #[test]
    fn test_fold_ccs_mismatch() {
        // LCCCS 和 CCCCS 引用不同 CCS 结构
        let ccs1 = make_linear_ccs();
        let ccs2 = make_nonlinear_ccs();

        let z_l = vec![f(1), f(5), f(5)];
        let z_c = vec![f(1), f(2), f(5), f(10)]; // 4 vars for nonlinear

        let lcccs = ccs1.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs2
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut transcript = Transcript::new();
        let result = fold(&lcccs, &stub_commitment(), &ccccs, &mut transcript);
        assert!(result.is_err(), "CCS 不匹配应返回错误");
    }

    #[test]
    fn test_fold_dimension_mismatch_x() {
        // x_L 与 x_C 长度不一致
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3)];

        let lcccs = ccs
            .to_lcccs(&z_l, &[], vec![f(1)])
            .expect("to_lcccs with x_l=[1]");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs with x_c=[]");

        let mut transcript = Transcript::new();
        let result = fold(&lcccs, &stub_commitment(), &ccccs, &mut transcript);
        assert!(result.is_err(), "x 维度不匹配应返回错误");
    }

    // ===== 确定性与绑定测试 =====

    #[test]
    fn test_fold_challenge_deterministic() {
        // 相同输入 + 相同 transcript → 相同 fold challenge r
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        let out1 = fold(&lcccs, &stub_commitment(), &ccccs, &mut t1).expect("fold 1");
        let out2 = fold(&lcccs, &stub_commitment(), &ccccs, &mut t2).expect("fold 2");

        assert_eq!(
            out1.fold_challenge, out2.fold_challenge,
            "相同输入应产生相同 fold challenge"
        );
        assert_eq!(out1.folded_lcccs.u_l, out2.folded_lcccs.u_l);
    }

    #[test]
    fn test_fold_challenge_binds_to_witness_commitment_l() {
        // 篡改 witness_commitment_l 应改变 fold challenge
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        let out1 = fold(&lcccs, &stub_commitment(), &ccccs, &mut t1).expect("fold 1");
        let out2 = fold(&lcccs, &stub_commitment_2(), &ccccs, &mut t2).expect("fold 2");

        assert_ne!(
            out1.fold_challenge, out2.fold_challenge,
            "不同 witness_commitment_l 应产生不同 fold challenge（防 witness 替换）"
        );
    }

    #[test]
    fn test_fold_challenge_binds_to_ccccs_witness_commitment() {
        // 篡改 ccccs.witness_commitment_c 应改变 fold challenge
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs1 = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs 1");
        let ccccs2 = ccs
            .to_cccs(&z_c, vec![], stub_commitment_2())
            .expect("to_cccs 2");

        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        let out1 = fold(&lcccs, &stub_commitment(), &ccccs1, &mut t1).expect("fold 1");
        let out2 = fold(&lcccs, &stub_commitment(), &ccccs2, &mut t2).expect("fold 2");

        assert_ne!(
            out1.fold_challenge, out2.fold_challenge,
            "不同 ccccs.witness_commitment_c 应产生不同 fold challenge"
        );
    }

    #[test]
    fn test_fold_challenge_binds_to_u_l() {
        // 篡改 u_l 应改变 fold challenge
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3)];

        let lcccs1 = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");

        // 构造 u_l ≠ 0 的 LCCCS（手动修改）
        let lcccs2 = Lcccs::new(
            ccs.clone(),
            f(99), // 篡改 u_l
            vec![],
            z_l.clone(),
            vec![],
            lcccs1.v_l.clone(),
        )
        .expect("Lcccs 构造");

        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        let out1 = fold(&lcccs1, &stub_commitment(), &ccccs, &mut t1).expect("fold 1");
        let out2 = fold(&lcccs2, &stub_commitment(), &ccccs, &mut t2).expect("fold 2");

        assert_ne!(
            out1.fold_challenge, out2.fold_challenge,
            "不同 u_l 应产生不同 fold challenge"
        );
    }

    #[test]
    fn test_fold_challenge_binds_to_v_l() {
        // 篡改 v_l 应改变 fold challenge
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)];

        let lcccs1 = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");

        // 构造 v_l 被篡改的 LCCCS
        let mut tampered_v = lcccs1.v_l.clone();
        tampered_v[0] = f(99);
        let lcccs2 = Lcccs::new(
            ccs.clone(),
            lcccs1.u_l,
            vec![],
            z_l,
            vec![],
            tampered_v,
        )
        .expect("Lcccs 构造");

        let z_c = vec![f(1), f(3), f(3)];
        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        let out1 = fold(&lcccs1, &stub_commitment(), &ccccs, &mut t1).expect("fold 1");
        let out2 = fold(&lcccs2, &stub_commitment(), &ccccs, &mut t2).expect("fold 2");

        assert_ne!(
            out1.fold_challenge, out2.fold_challenge,
            "不同 v_l 应产生不同 fold challenge"
        );
    }

    // ===== Soundness: 篡改输入导致 folded 不满足 =====

    #[test]
    fn test_fold_soundness_tampered_u_l() {
        // 篡改 lcccs.u_l（使其与 v_l 不一致）
        // 线性 CCS 折叠后: u' = u_L + r·u_C
        // 若 u_L 被篡改为非 0，则 u' ≠ 0，但 v' 不变 → folded 不满足
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)];
        let z_c = vec![f(1), f(3), f(3)];

        let lcccs_valid = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        // 篡改 u_l: 原值 0 → 99
        let lcccs_tampered = Lcccs::new(
            ccs.clone(),
            f(99), // 篡改 u_l
            vec![],
            z_l,
            vec![],
            lcccs_valid.v_l.clone(),
        )
        .expect("Lcccs 构造");

        let ccccs = ccs
            .to_cccs(&z_c, vec![], stub_commitment())
            .expect("to_cccs");

        let mut transcript = Transcript::new();
        let output = fold(
            &lcccs_tampered,
            &stub_commitment(),
            &ccccs,
            &mut transcript,
        )
        .expect("fold");

        // u' = 99 + r·0 = 99 ≠ 0（代数约束结果）
        assert_eq!(output.folded_lcccs.u_l, f(99));
        // folded LCCCS 不满足（u' ≠ Σ c_i · Π v'[j]）
        assert!(
            !output.folded_lcccs.satisfied().unwrap(),
            "篡改 u_l 后 folded LCCCS 不应 satisfied"
        );
    }

    #[test]
    fn test_fold_soundness_tampered_trace_c() {
        // 篡改 ccccs.trace_c 使 CCCCS 不满足 CCS 约束
        // 这会使 v_C[j](r_x_L) 改变，进而改变 v'[j]，使 folded 不满足
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5)]; // satisfied: 5 - 5 = 0
        let z_c_tampered = vec![f(1), f(3), f(7)]; // 不满足: 3 - 7 = -4

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c_tampered, vec![], stub_commitment())
            .expect("to_cccs");

        let mut transcript = Transcript::new();
        let output = fold(&lcccs, &stub_commitment(), &ccccs, &mut transcript).expect("fold");

        // ccccs 不满足 CCS（u_c = 0 但实际约束 = -4）
        // to_cccs 设 u_c = 0，但实际 v_C 求值后约束 ≠ 0
        // v'[j] = v_L[j] + r·v_C[j](r_x_L)
        //   v_L = [5, 5], v_C = [3, 7] (tampered)
        //   v'[0] = 5 + r·3, v'[1] = 5 + r·7
        // folded 约束 = v'[0] - v'[1] = (5 + 3r) - (5 + 7r) = -4r
        // u' = 0 + r·0 = 0
        // 故 folded 不满足（-4r ≠ 0，除非 r = 0）
        let r = output.fold_challenge;
        let expected_constraint = neg_f(4).mul(&r);
        let computed = crate::fold::lcccs::compute_relaxed_constraint(
            &output.folded_lcccs.ccs_ref,
            &output.folded_lcccs.v_l,
        );
        assert_eq!(
            computed, expected_constraint,
            "篡改 trace_c 后 folded 约束应 = -4r"
        );
        assert_ne!(computed, output.folded_lcccs.u_l);
        assert!(
            !output.folded_lcccs.satisfied().unwrap(),
            "篡改 trace_c 后 folded LCCCS 不应 satisfied"
        );
    }

    // ===== 多步折叠链测试 =====

    #[test]
    fn test_fold_chain_two_steps() {
        // 链式折叠：fold(fold(L1, C2), C3) — 验证 FoldStepOutput 可链式使用
        let ccs = make_linear_ccs();
        let z1 = vec![f(1), f(5), f(5)];
        let z2 = vec![f(1), f(3), f(3)];
        let z3 = vec![f(1), f(7), f(7)];

        let lcccs1 = ccs.to_lcccs(&z1, &[], vec![]).expect("to_lcccs 1");
        let ccccs2 = ccs.to_cccs(&z2, vec![], stub_commitment()).expect("to_cccs 2");
        let ccccs3 = ccs.to_cccs(&z3, vec![], stub_commitment()).expect("to_cccs 3");

        // 第一步：fold(lcccs1, ccccs2)
        let mut transcript = Transcript::new();
        let out1 = fold(&lcccs1, &stub_commitment(), &ccccs2, &mut transcript).expect("fold 1");

        // 线性 CCS: 第一步后 u' = 0，folded satisfied
        assert_eq!(out1.folded_lcccs.u_l, Fr::zero());
        assert!(out1.folded_lcccs.satisfied().unwrap());

        // 第二步：fold(out1.folded_lcccs, ccccs3) 使用 out1.folded_commitment
        let out2 = fold(
            &out1.folded_lcccs,
            &out1.folded_commitment,
            &ccccs3,
            &mut transcript,
        )
        .expect("fold 2");

        // 两个 satisfied CCS 链式折叠后 u'' = 0
        assert_eq!(out2.folded_lcccs.u_l, Fr::zero());
        assert!(
            out2.folded_lcccs.satisfied().unwrap(),
            "线性 CCS 两步链式折叠后应 satisfied"
        );
    }
}
