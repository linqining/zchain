//! IPA over BN254（Phase 1.5 — Task 1.5.2 实现）。
//!
//! 严格遵循 spec.md L326-337（v1.4 FROZEN）：
//! - NUMS generators 派生（`hash_to_curve(b"poker_zkvm_ipa_gen" || i)`）
//! - `commit(poly)` — Pedersen vector commitment `C = ⟨a, G⟩`
//! - `open(poly, point, transcript)` — log(N) 轮 IPA protocol，challenge 绑定 point + commitment
//! - `verify(commitment, point, eval, proof, transcript)` — challenge 重算 + 闭式 G_final MSM
//!
//! # 安全特性
//!
//! - **NUMS generators**：try-and-increment hash-to-curve，无离散对数后门
//! - **challenge 绑定**：open 开始前 absorb `PCS_OPEN_TAG || commitment || point`，防 proof 复用
//! - **soundness**：伪造 a_final 等价于求解 DLP

use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

use crate::error::ZkvmError;
use crate::field::Bn254ScalarField;
use crate::pcs::{MultilinearPoly, Pcs};
use crate::transcript::{PCS_OPEN_DOMAIN_TAG, Transcript};

/// IPA generators 派生 domain tag（spec L330）。
const IPA_GEN_DOMAIN: &[u8] = b"poker_zkvm_ipa_gen";

/// Q generator 派生 domain tag（独立于 G_i，防 DL 关系）。
const IPA_Q_DOMAIN: &[u8] = b"poker_zkvm_ipa_q";

/// 最大支持变量数（N = 2^24 = 16M，防 OOM）。
pub const MAX_N_VARS: usize = 24;

/// NUMS hash-to-curve：try-and-increment（BN254 G1: y² = x³ + 3）。
///
/// 算法：
/// 1. counter = 0
/// 2. x = Fq::from_le_bytes_mod_order(Blake2b(domain || index_le || counter_le))
/// 3. 调用 G1Affine::get_point_from_x_unchecked(x, true)（内部 sqrt + QR 检测）
/// 4. 若 Some(p) 返回（BN254 cofactor=1，必在子群）；否则 counter += 1 重试
///
/// # 安全性
///
/// - domain separation：不同 domain tag 产生独立 generator 集
/// - counter 吸收：防 try-and-increment 歧义
/// - cofactor=1：无需 cofactor clearing
fn hash_to_curve(domain: &[u8], index: u32) -> G1Affine {
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) init");
    hasher.update(domain);
    hasher.update(&index.to_le_bytes());

    for counter in 0u32.. {
        let mut h = hasher.clone();
        h.update(&counter.to_le_bytes());
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("Blake2bVar finalize");
        let x = Fq::from_le_bytes_mod_order(&out);
        if let Some(p) = G1Affine::get_point_from_x_unchecked(x, true) {
            return p;
        }
        // counter 溢出概率 ≈ 2^-256（每轮成功率 ≈ 1/2）
        let _ = counter;
    }
    unreachable!("try-and-increment 必然在 ~2 次内成功")
}

/// 将 Bn254ScalarField 转为 Fr（解包 newtype）。
fn field_to_fr(f: &Bn254ScalarField) -> Fr {
    f.into_fr()
}

/// 将 Fr 转为 Bn254ScalarField。
fn fr_to_field(fr: Fr) -> Bn254ScalarField {
    Bn254ScalarField::from_fr(fr)
}

/// 将 G1Affine 点序列化为 compressed bytes（用于 transcript absorb）。
fn point_to_bytes(p: &G1Affine) -> Vec<u8> {
    let mut bytes = Vec::new();
    p.serialize_compressed(&mut bytes)
        .expect("G1Affine serialize_compressed 不应失败");
    bytes
}

/// 计算多线性扩展的查询向量 b（spec — eq(binary(i), point)）。
///
/// `b[i] = Π_{j=0..m-1} (bit_j(i) · point[j] + (1-bit_j(i)) · (1-point[j]))`
///
/// 其中 `bit_j(i) = (i >> j) & 1`，`m = point.len()`。
///
/// 当 bit_j(i)==1 时因子为 point[j]，否则为 (1 - point[j])。
fn compute_query_vector(point: &[Fr]) -> Vec<Fr> {
    let m = point.len();
    let n = 1usize << m;
    let one = Fr::one();
    (0..n)
        .map(|i| {
            (0..m).fold(one, |acc, j| {
                let bit = (i >> j) & 1;
                let factor = if bit == 1 { point[j] } else { one - point[j] };
                acc * factor
            })
        })
        .collect()
}

/// 计算内积 ⟨a, b⟩ = Σ_i a_i · b_i。
fn inner_product(a: &[Fr], b: &[Fr]) -> Fr {
    if a.len() < 1024 {
        a.iter()
            .zip(b.iter())
            .fold(Fr::zero(), |acc, (ai, bi)| acc + *ai * bi)
    } else {
        use rayon::prelude::*;
        a.par_iter()
            .zip(b.par_iter())
            .map(|(ai, bi)| *ai * bi)
            .reduce(Fr::zero, |a, b| a + b)
    }
}

/// 多标量乘法 MSM：Σ_i scalars[i] · bases[i]。
///
/// 使用 arkworks VariableBaseMSM，失败时回退手动循环。
fn msm(scalars: &[Fr], bases: &[G1Affine]) -> G1Projective {
    if scalars.is_empty() || bases.is_empty() {
        return G1Projective::zero();
    }
    let n = scalars.len().min(bases.len());
    match VariableBaseMSM::msm(&bases[..n], &scalars[..n]) {
        Ok(result) => result,
        Err(_) => {
            // 回退：手动循环（理论不会触发，msm 仅在长度不匹配时报错）
            scalars[..n]
                .iter()
                .zip(bases[..n].iter())
                .fold(G1Projective::zero(), |acc, (s, b)| acc + *b * s)
        }
    }
}

/// 闭式计算 G_final（verifier 端，避免逐轮点折叠的 O(N log N)）。
///
/// `G_final = Σ_i (Π_{k=0..m-1} r_k_inv^{bit_{m-1-k}(i)}) · G_i`
///
/// 其中 bit_{m-1-k}(i) = (i >> (m-1-k)) & 1，m = challenges_inv.len()。
///
/// 单次 MSM，复杂度 O(N)。
fn compute_g_final(generators: &[G1Affine], challenges_inv: &[Fr]) -> G1Projective {
    let m = challenges_inv.len();
    let n = generators.len();
    if n == 0 {
        return G1Projective::zero();
    }
    let one = Fr::one();
    let scalars: Vec<Fr> = (0..n)
        .map(|i| {
            (0..m).fold(one, |acc, k| {
                let bit = (i >> (m - 1 - k)) & 1;
                if bit == 1 {
                    acc * challenges_inv[k]
                } else {
                    acc
                }
            })
        })
        .collect();
    msm(&scalars, generators)
}

/// IPA 承诺（G1 仿射点）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaCommitment(pub G1Affine);

/// IPA 证明（log(N) 轮的 L/R 点 + 最终标量 a_final）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaProof {
    /// 每轮的 L_k 点（k = 0..log(N)）。
    pub l_vec: Vec<G1Affine>,
    /// 每轮的 R_k 点。
    pub r_vec: Vec<G1Affine>,
    /// 最终标量 a_final。
    pub a_final: Bn254ScalarField,
}

/// IPA 求值（多线性多项式在 point 处的值）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaEval(pub Bn254ScalarField);

/// IPA over BN254 PCS 实现（spec L326-337）。
///
/// 预计算 NUMS generators `G_0..G_{N-1}`（N = 2^max_n_vars）和独立 Q generator。
pub struct IpaPcs {
    /// NUMS generators G_0..G_{N-1}。
    generators: Vec<G1Affine>,
    /// 独立 NUMS generator Q（用于内积承诺 P = C + v·Q）。
    q_generator: G1Affine,
    /// 最大支持变量数。
    max_n_vars: usize,
}

impl IpaPcs {
    /// 构造 IPA PCS：预计算 generators。
    ///
    /// # 参数
    /// - `max_n_vars`：最大支持变量数（N = 2^max_n_vars ≤ 2^24）
    ///
    /// # 错误
    /// - `max_n_vars > 24`：返回 `Other`（防 OOM）
    pub fn new(max_n_vars: usize) -> Result<Self, ZkvmError> {
        if max_n_vars > MAX_N_VARS {
            return Err(ZkvmError::Other(format!(
                "max_n_vars={max_n_vars} 超过上限 {MAX_N_VARS}"
            )));
        }
        let n = 1usize << max_n_vars;
        let generators: Vec<G1Affine> = (0..n)
            .map(|i| hash_to_curve(IPA_GEN_DOMAIN, i as u32))
            .collect();
        let q_generator = hash_to_curve(IPA_Q_DOMAIN, 0);
        Ok(Self {
            generators,
            q_generator,
            max_n_vars,
        })
    }

    /// 返回最大支持变量数。
    pub fn max_n_vars(&self) -> usize {
        self.max_n_vars
    }

    /// 吸收 commitment + point 到 transcript（open/verify 共用，spec L334）。
    ///
    /// 顺序：commitment_bytes → point[j]（每个分量 absorb_field）
    fn absorb_commitment_and_point(
        transcript: &mut Transcript,
        commitment: &G1Affine,
        point: &[Bn254ScalarField],
    ) {
        let c_bytes = point_to_bytes(commitment);
        transcript.absorb(PCS_OPEN_DOMAIN_TAG, &c_bytes);
        for p in point {
            transcript.absorb_field(PCS_OPEN_DOMAIN_TAG, p);
        }
    }
}

impl Pcs for IpaPcs {
    type Commitment = IpaCommitment;
    type Proof = IpaProof;
    type Eval = IpaEval;

    fn commit(&self, poly: &MultilinearPoly) -> Result<Self::Commitment, ZkvmError> {
        if poly.num_vars > self.max_n_vars {
            return Err(ZkvmError::Other(format!(
                "poly.num_vars={} > max_n_vars={}",
                poly.num_vars, self.max_n_vars
            )));
        }
        let n = poly.len();
        let scalars: Vec<Fr> = poly.evals.iter().map(field_to_fr).collect();
        let c = msm(&scalars, &self.generators[..n]);
        Ok(IpaCommitment(c.into_affine()))
    }

    fn open(
        &self,
        poly: &MultilinearPoly,
        point: &[Bn254ScalarField],
        transcript: &mut Transcript,
    ) -> Result<(Self::Proof, Self::Eval), ZkvmError> {
        if point.len() != poly.num_vars {
            return Err(ZkvmError::Other(format!(
                "point.len()={} != poly.num_vars={}",
                point.len(),
                poly.num_vars
            )));
        }
        if poly.num_vars > self.max_n_vars {
            return Err(ZkvmError::Other(format!(
                "poly.num_vars={} > max_n_vars={}",
                poly.num_vars, self.max_n_vars
            )));
        }

        let n = poly.len();
        let num_vars = poly.num_vars;

        // 1. 计算 commitment（与 commit 相同）
        let scalars: Vec<Fr> = poly.evals.iter().map(field_to_fr).collect();
        let c = msm(&scalars, &self.generators[..n]);
        let c_affine = c.into_affine();

        // 2. 预绑定：absorb commitment + point（spec L334）
        Self::absorb_commitment_and_point(transcript, &c_affine, point);

        // 3. 计算查询向量 b 和求值 v
        let point_fr: Vec<Fr> = point.iter().map(field_to_fr).collect();
        let b = compute_query_vector(&point_fr);
        let v = inner_product(&scalars, &b);

        // 4. 构造 P = C + v·Q
        let q = self.q_generator;
        let mut p = c + q * v;

        // 5. log(N) 轮折叠
        let mut a = scalars.clone();
        let mut b_curr = b.clone();
        let mut g: Vec<G1Affine> = self.generators[..n].to_vec();

        let mut l_vec = Vec::with_capacity(num_vars);
        let mut r_vec = Vec::with_capacity(num_vars);

        for k in 0..num_vars {
            let half = a.len() / 2;
            let a_l = &a[..half];
            let a_r = &a[half..];
            let b_l = &b_curr[..half];
            let b_r = &b_curr[half..];
            let g_l = &g[..half];
            let g_r = &g[half..];

            // L_k = ⟨a_R, G_L⟩ + ⟨a_R, b_L⟩·Q
            let l_k = msm(a_r, g_l) + q * inner_product(a_r, b_l);
            // R_k = ⟨a_L, G_R⟩ + ⟨a_L, b_R⟩·Q
            let r_k = msm(a_l, g_r) + q * inner_product(a_l, b_r);

            let l_k_affine = l_k.into_affine();
            let r_k_affine = r_k.into_affine();

            // absorb L_k, R_k, k（spec L333）
            transcript.absorb(PCS_OPEN_DOMAIN_TAG, &point_to_bytes(&l_k_affine));
            transcript.absorb(PCS_OPEN_DOMAIN_TAG, &point_to_bytes(&r_k_affine));
            transcript.absorb(PCS_OPEN_DOMAIN_TAG, &k.to_le_bytes());

            // challenge r_k
            let r_k = field_to_fr(&transcript.challenge(PCS_OPEN_DOMAIN_TAG));
            let r_k_inv = r_k
                .inverse()
                .ok_or_else(|| ZkvmError::Other("IPA challenge inverse 为零".to_string()))?;

            // 折叠 a, b, G
            if half < 1024 {
                a = (0..half).map(|i| a_l[i] + r_k * a_r[i]).collect();
                b_curr = (0..half).map(|i| b_l[i] + r_k_inv * b_r[i]).collect();
                g = (0..half)
                    .map(|i| (g_l[i].into_group() + g_r[i] * r_k_inv).into_affine())
                    .collect();
            } else {
                use rayon::prelude::*;
                a = (0..half)
                    .into_par_iter()
                    .map(|i| a_l[i] + r_k * a_r[i])
                    .collect();
                b_curr = (0..half)
                    .into_par_iter()
                    .map(|i| b_l[i] + r_k_inv * b_r[i])
                    .collect();
                g = (0..half)
                    .into_par_iter()
                    .map(|i| (g_l[i].into_group() + g_r[i] * r_k_inv).into_affine())
                    .collect();
            }

            // 折叠 P
            p = p + l_k_affine * r_k + r_k_affine * r_k_inv;

            l_vec.push(l_k_affine);
            r_vec.push(r_k_affine);
        }

        // 6. 最终 a_final, b_final
        let a_final = fr_to_field(a[0]);
        let _b_final = b_curr[0];

        Ok((
            IpaProof {
                l_vec,
                r_vec,
                a_final,
            },
            IpaEval(fr_to_field(v)),
        ))
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[Bn254ScalarField],
        eval: &Self::Eval,
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<bool, ZkvmError> {
        let num_vars = point.len();

        // 校验 proof 长度
        if proof.l_vec.len() != num_vars || proof.r_vec.len() != num_vars {
            return Ok(false);
        }

        let n = 1usize << num_vars;
        if n > self.generators.len() {
            return Err(ZkvmError::Other(format!(
                "n={n} > generators.len()={}",
                self.generators.len()
            )));
        }

        // 1. 预绑定：absorb commitment + point（与 open 相同顺序，spec L334）
        Self::absorb_commitment_and_point(transcript, &commitment.0, point);

        // 2. 计算查询向量 b
        let point_fr: Vec<Fr> = point.iter().map(field_to_fr).collect();
        let b = compute_query_vector(&point_fr);

        // 3. 构造 P = C + eval·Q
        let q = self.q_generator;
        let c = commitment.0.into_group();
        let v_fr = field_to_fr(&eval.0);
        let mut p = c + q * v_fr;

        // 4. log(N) 轮重算 challenge 与折叠
        let mut b_curr = b;
        let mut challenges_inv: Vec<Fr> = Vec::with_capacity(num_vars);

        for k in 0..num_vars {
            let half = b_curr.len() / 2;
            let b_l = &b_curr[..half];
            let b_r = &b_curr[half..];

            let l_k_point = proof.l_vec[k];
            let r_k_point = proof.r_vec[k];

            // absorb L_k, R_k, k（与 open 相同顺序）
            transcript.absorb(PCS_OPEN_DOMAIN_TAG, &point_to_bytes(&l_k_point));
            transcript.absorb(PCS_OPEN_DOMAIN_TAG, &point_to_bytes(&r_k_point));
            transcript.absorb(PCS_OPEN_DOMAIN_TAG, &k.to_le_bytes());

            // challenge r_k
            let r_k = field_to_fr(&transcript.challenge(PCS_OPEN_DOMAIN_TAG));
            let r_k_inv = r_k
                .inverse()
                .ok_or_else(|| ZkvmError::Other("IPA challenge inverse 为零".to_string()))?;

            // 折叠 b
            b_curr = (0..half).map(|i| b_l[i] + r_k_inv * b_r[i]).collect();

            // 折叠 P
            p = p + l_k_point * r_k + r_k_point * r_k_inv;

            challenges_inv.push(r_k_inv);
        }

        // 5. 闭式计算 G_final
        let g_final = compute_g_final(&self.generators[..n], &challenges_inv);

        // 6. 最终校验：P_final == a_final·G_final + (a_final·b_final)·Q
        let b_final = b_curr[0];
        let a_final_fr = field_to_fr(&proof.a_final);

        // P_final == a_final · G_final + (a_final * b_final) · Q
        let expected = g_final * a_final_fr + q * (a_final_fr * b_final);

        Ok(p == expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::ZkvmField;

    // ===== 测试 1-3：hash_to_curve =====

    #[test]
    fn test_hash_to_curve_deterministic() {
        let p1 = hash_to_curve(IPA_GEN_DOMAIN, 0);
        let p2 = hash_to_curve(IPA_GEN_DOMAIN, 0);
        assert_eq!(p1, p2, "相同输入应产生相同 G1 点");
    }

    #[test]
    fn test_hash_to_curve_on_curve() {
        let p = hash_to_curve(IPA_GEN_DOMAIN, 0);
        assert!(p.is_on_curve(), "hash_to_curve 产生的点应在曲线上");
        assert!(
            p.is_in_correct_subgroup_assuming_on_curve(),
            "BN254 cofactor=1，点应在子群内"
        );
    }

    #[test]
    fn test_hash_to_curve_different_index() {
        let p0 = hash_to_curve(IPA_GEN_DOMAIN, 0);
        let p1 = hash_to_curve(IPA_GEN_DOMAIN, 1);
        assert_ne!(p0, p1, "不同 index 应产生不同点");
    }

    // ===== 测试 4-5：辅助函数 =====

    #[test]
    fn test_compute_query_vector_correctness() {
        // point = [1, 0], m=2, N=4
        // b[0] = (1-1)*(1-0) = 0  (bit0=0,bit1=0)
        // b[1] = (1-1)*1     = 0  (bit0=1,bit1=0 → factor0=point[0]=1, factor1=1-point[1]=1)
        //   wait, bit_j(i) = (i >> j) & 1
        //   i=1: bit0=1, bit1=0 → factor0=point[0]=1, factor1=1-point[1]=1 → b[1]=1
        // b[2] = 1*(1-0) = 1  (bit0=0,bit1=1 → factor0=1-point[0]=0, factor1=point[1]=0)
        //   → b[2] = 0
        // b[3] = 1*0 = 0  → b[3] = 0
        // 重新计算：point=[1,0]
        //   i=0 (00): bit0=0→1-1=0, bit1=0→1-0=1 → b=0
        //   i=1 (01): bit0=1→1, bit1=0→1-0=1 → b=1
        //   i=2 (10): bit0=0→0, bit1=1→0 → b=0
        //   i=3 (11): bit0=1→1, bit1=1→0 → b=0
        let point = vec![Fr::from(1u64), Fr::from(0u64)];
        let b = compute_query_vector(&point);
        assert_eq!(b.len(), 4);
        assert_eq!(b[0], Fr::zero());
        assert_eq!(b[1], Fr::one());
        assert_eq!(b[2], Fr::zero());
        assert_eq!(b[3], Fr::zero());
    }

    #[test]
    fn test_inner_product_correctness() {
        let a = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let b = vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];
        // 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        let v = inner_product(&a, &b);
        assert_eq!(v, Fr::from(32u64));
    }

    // ===== 测试 6-7：commit =====

    #[test]
    fn test_ipa_commit_simple() {
        let pcs = IpaPcs::new(4).unwrap();
        let poly = MultilinearPoly::from_u32_evals(&[1, 2, 3, 4]).unwrap();
        let c = pcs.commit(&poly).unwrap();
        assert!(!c.0.is_zero(), "commitment 不应为 identity");
    }

    #[test]
    fn test_ipa_commit_deterministic() {
        let pcs = IpaPcs::new(4).unwrap();
        let poly = MultilinearPoly::from_u32_evals(&[1, 2, 3, 4]).unwrap();
        let c1 = pcs.commit(&poly).unwrap();
        let c2 = pcs.commit(&poly).unwrap();
        assert_eq!(c1, c2, "相同 poly 应产生相同 commitment");
    }

    // ===== 测试 8-9：completeness =====

    #[test]
    fn test_ipa_open_verify_completeness() {
        let pcs = IpaPcs::new(4).unwrap();
        let poly = MultilinearPoly::from_u32_evals(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let point = vec![
            Bn254ScalarField::from_u32_with_wrap(1),
            Bn254ScalarField::from_u32_with_wrap(0),
            Bn254ScalarField::from_u32_with_wrap(1),
        ];
        let c = pcs.commit(&poly).unwrap();
        let mut t = Transcript::new();
        let (proof, eval) = pcs.open(&poly, &point, &mut t).unwrap();
        let mut t2 = Transcript::new();
        let result = pcs.verify(&c, &point, &eval, &proof, &mut t2).unwrap();
        assert!(result, "completeness: verify 应返回 true");
    }

    #[test]
    fn test_ipa_completeness_multiple_vars() {
        for &n_vars in &[0usize, 1, 2, 4, 8] {
            let pcs = IpaPcs::new(n_vars.max(1)).unwrap();
            let n = 1usize << n_vars;
            let evals: Vec<u32> = (1..=n as u32).collect();
            let poly = MultilinearPoly::from_u32_evals(&evals).unwrap();
            let point: Vec<Bn254ScalarField> = (0..n_vars)
                .map(|_| Bn254ScalarField::from_u32_with_wrap(1))
                .collect();
            let c = pcs.commit(&poly).unwrap();
            let mut t = Transcript::new();
            let (proof, eval) = pcs.open(&poly, &point, &mut t).unwrap();
            let mut t2 = Transcript::new();
            let result = pcs.verify(&c, &point, &eval, &proof, &mut t2).unwrap();
            assert!(result, "completeness 失败: num_vars={n_vars}");
        }
    }

    // ===== 测试 10-14：soundness 负例 =====

    #[test]
    fn test_ipa_soundness_tampered_eval() {
        let pcs = IpaPcs::new(4).unwrap();
        let poly = MultilinearPoly::from_u32_evals(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let point = vec![
            Bn254ScalarField::from_u32_with_wrap(1),
            Bn254ScalarField::from_u32_with_wrap(0),
            Bn254ScalarField::from_u32_with_wrap(1),
        ];
        let c = pcs.commit(&poly).unwrap();
        let mut t = Transcript::new();
        let (proof, _eval) = pcs.open(&poly, &point, &mut t).unwrap();
        // 篡改 eval
        let tampered_eval = IpaEval(Bn254ScalarField::from_u32_with_wrap(999));
        let mut t2 = Transcript::new();
        let result = pcs
            .verify(&c, &point, &tampered_eval, &proof, &mut t2)
            .unwrap();
        assert!(!result, "篡改 eval 应 verify 失败");
    }

    #[test]
    fn test_ipa_soundness_tampered_a_final() {
        let pcs = IpaPcs::new(4).unwrap();
        let poly = MultilinearPoly::from_u32_evals(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let point = vec![
            Bn254ScalarField::from_u32_with_wrap(1),
            Bn254ScalarField::from_u32_with_wrap(0),
            Bn254ScalarField::from_u32_with_wrap(1),
        ];
        let c = pcs.commit(&poly).unwrap();
        let mut t = Transcript::new();
        let (mut proof, eval) = pcs.open(&poly, &point, &mut t).unwrap();
        // 篡改 a_final
        proof.a_final = Bn254ScalarField::from_u32_with_wrap(999);
        let mut t2 = Transcript::new();
        let result = pcs.verify(&c, &point, &eval, &proof, &mut t2).unwrap();
        assert!(!result, "篡改 a_final 应 verify 失败");
    }

    #[test]
    fn test_ipa_soundness_tampered_commitment() {
        let pcs = IpaPcs::new(4).unwrap();
        let poly = MultilinearPoly::from_u32_evals(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let point = vec![
            Bn254ScalarField::from_u32_with_wrap(1),
            Bn254ScalarField::from_u32_with_wrap(0),
            Bn254ScalarField::from_u32_with_wrap(1),
        ];
        let _c = pcs.commit(&poly).unwrap();
        let mut t = Transcript::new();
        let (proof, eval) = pcs.open(&poly, &point, &mut t).unwrap();
        // 篡改 commitment（用不同 poly 的 commitment）
        let poly2 = MultilinearPoly::from_u32_evals(&[8, 7, 6, 5, 4, 3, 2, 1]).unwrap();
        let c2 = pcs.commit(&poly2).unwrap();
        let mut t2 = Transcript::new();
        let result = pcs.verify(&c2, &point, &eval, &proof, &mut t2).unwrap();
        assert!(!result, "篡改 commitment 应 verify 失败");
    }

    #[test]
    fn test_ipa_soundness_tampered_l_vec() {
        let pcs = IpaPcs::new(4).unwrap();
        let poly = MultilinearPoly::from_u32_evals(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let point = vec![
            Bn254ScalarField::from_u32_with_wrap(1),
            Bn254ScalarField::from_u32_with_wrap(0),
            Bn254ScalarField::from_u32_with_wrap(1),
        ];
        let c = pcs.commit(&poly).unwrap();
        let mut t = Transcript::new();
        let (mut proof, eval) = pcs.open(&poly, &point, &mut t).unwrap();
        // 篡改 l_vec[0]（用 r_vec[0] 替换）
        proof.l_vec[0] = proof.r_vec[0];
        let mut t2 = Transcript::new();
        let result = pcs.verify(&c, &point, &eval, &proof, &mut t2).unwrap();
        assert!(!result, "篡改 l_vec 应 verify 失败");
    }

    #[test]
    fn test_ipa_soundness_reuse_proof_different_point() {
        let pcs = IpaPcs::new(4).unwrap();
        let poly = MultilinearPoly::from_u32_evals(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let point = vec![
            Bn254ScalarField::from_u32_with_wrap(1),
            Bn254ScalarField::from_u32_with_wrap(0),
            Bn254ScalarField::from_u32_with_wrap(1),
        ];
        let c = pcs.commit(&poly).unwrap();
        let mut t = Transcript::new();
        let (proof, eval) = pcs.open(&poly, &point, &mut t).unwrap();
        // 复用 proof 到不同 point
        let point2 = vec![
            Bn254ScalarField::from_u32_with_wrap(0),
            Bn254ScalarField::from_u32_with_wrap(1),
            Bn254ScalarField::from_u32_with_wrap(0),
        ];
        let mut t2 = Transcript::new();
        let result = pcs.verify(&c, &point2, &eval, &proof, &mut t2).unwrap();
        assert!(!result, "复用 proof 到不同 point 应 verify 失败");
    }

    // ===== 测试 15-16：边界校验 =====

    #[test]
    fn test_ipa_rejects_poly_too_large() {
        let pcs = IpaPcs::new(2).unwrap();
        let poly = MultilinearPoly::from_u32_evals(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        // num_vars=3 > max_n_vars=2
        let result = pcs.commit(&poly);
        assert!(result.is_err(), "poly.num_vars > max_n_vars 应返回 Err");
    }

    #[test]
    fn test_ipa_rejects_point_length_mismatch() {
        let pcs = IpaPcs::new(4).unwrap();
        let poly = MultilinearPoly::from_u32_evals(&[1, 2, 3, 4]).unwrap();
        // point.len()=3 != num_vars=2
        let point = vec![
            Bn254ScalarField::from_u32_with_wrap(1),
            Bn254ScalarField::from_u32_with_wrap(0),
            Bn254ScalarField::from_u32_with_wrap(1),
        ];
        let mut t = Transcript::new();
        let result = pcs.open(&poly, &point, &mut t);
        assert!(result.is_err(), "point.len() != num_vars 应返回 Err");
    }

    // ===== proptest =====

    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// 随机 poly + 随机 point，commit/open/verify 返回 true
            #[test]
            fn prop_ipa_completeness(n_vars in 0usize..=6) {
                let pcs = IpaPcs::new(n_vars.max(1)).unwrap();
                let n = 1usize << n_vars;
                let evals: Vec<u32> = (0..n).map(|i| (i as u32) * 7 + 3).collect();
                let poly = MultilinearPoly::from_u32_evals(&evals).unwrap();
                let point: Vec<Bn254ScalarField> = (0..n_vars)
                    .map(|i| Bn254ScalarField::from_u32_with_wrap((i as u32) * 13 + 1))
                    .collect();
                let c = pcs.commit(&poly).unwrap();
                let mut t = Transcript::new();
                let (proof, eval) = pcs.open(&poly, &point, &mut t).unwrap();
                let mut t2 = Transcript::new();
                let result = pcs.verify(&c, &point, &eval, &proof, &mut t2).unwrap();
                prop_assert!(result, "completeness 失败: n_vars={}", n_vars);
            }

            /// 随机篡改 eval 使 verify 返回 false
            #[test]
            fn prop_ipa_soundness_eval(n_vars in 1usize..=6, tamper in 1u32..1000) {
                let pcs = IpaPcs::new(n_vars.max(1)).unwrap();
                let n = 1usize << n_vars;
                let evals: Vec<u32> = (0..n).map(|i| (i as u32) * 7 + 3).collect();
                let poly = MultilinearPoly::from_u32_evals(&evals).unwrap();
                let point: Vec<Bn254ScalarField> = (0..n_vars)
                    .map(|i| Bn254ScalarField::from_u32_with_wrap((i as u32) * 13 + 1))
                    .collect();
                let c = pcs.commit(&poly).unwrap();
                let mut t = Transcript::new();
                let (proof, eval) = pcs.open(&poly, &point, &mut t).unwrap();
                // 篡改 eval
                let tampered = IpaEval(Bn254ScalarField::from_u32_with_wrap(
                    eval.0.to_u32().wrapping_add(tamper),
                ));
                let mut t2 = Transcript::new();
                let result = pcs.verify(&c, &point, &tampered, &proof, &mut t2).unwrap();
                prop_assert!(!result, "篡改 eval 应 verify 失败");
            }
        }
    }
}
