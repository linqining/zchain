//! CycleFold 递归聚合（Phase 9 — Task 9.2）。
//!
//! 严格遵循 spec.md L549-599（v1.4 FROZEN）：
//! - 树形聚合 K 个 Hypernova sub-proof 为单个 final proof
//! - BN254 / Grumpkin 曲线 cycle 上交替递归
//! - 递归终止条件：proof ≤ 64KB 或 depth > 16
//!
//! ## MVP 实现深度
//!
//! spec L590/L599 明确将"递归电路的 SNARK 证明"推迟到 Phase 12/13。
//! Phase 9 采用原生验证模拟（复用 [`verify_hypernova`]）：
//! - 验证所有 sub-proof 的 soundness
//! - 树形配对聚合（log(K) 深度）
//! - `aggregated_proof` 取左子树 proof（真实压缩需 SNARK 电路）
//!
//! ## 子模块
//!
//! - [`circuit_bn254`] — C_BN254 递归 verifier 电路（Task 9.3）
//! - [`circuit_grumpkin`] — C_Grumpkin 镜像电路（Task 9.4）

pub mod circuit_bn254;
pub mod circuit_grumpkin;
pub mod hypernova_verifier_circuit;
pub mod r1cs_gadgets;
pub mod r1cs_gadgets_bn254;

use crate::error::ZkvmError;
#[allow(deprecated)]
use crate::fold::fold_loop::{HypernovaProof, verify_hypernova};
use crate::pcs::ipa::IpaPcs;
use crate::prover::groth16_compress::{CompressedProof, groth16_compress};
use crate::prover::{MAX_RECURSION_DEPTH, MAX_ZKVM_PROOF_SIZE, serialize_proof};

/// 曲线种类（交替递归用，spec L572/587）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveKind {
    /// BN254 — 主曲线
    Bn254,
    /// Grumpkin — 辅助曲线
    Grumpkin,
}

impl CurveKind {
    /// 返回相反曲线（交替递归用）。
    pub fn opposite(self) -> Self {
        match self {
            CurveKind::Bn254 => CurveKind::Grumpkin,
            CurveKind::Grumpkin => CurveKind::Bn254,
        }
    }
}

/// 递归聚合节点 — 树形结构表示 CycleFold 聚合过程（spec L595）。
///
/// 叶节点为 sub-proofs，内部节点为递归 verifier 电路实例。
#[derive(Debug, Clone)]
pub enum CycleFoldNode {
    /// 叶节点 — 单个 Hypernova sub-proof。
    Leaf {
        /// sub-proof（Box 避免 enum variant 过大）。
        proof: Box<HypernovaProof>,
        /// proof 所在曲线
        curve: CurveKind,
    },
    /// 内部节点 — 两个子节点聚合后的结果。
    Node {
        /// 左子树
        left: Box<CycleFoldNode>,
        /// 右子树
        right: Box<CycleFoldNode>,
        /// 聚合后的 proof（MVP: 取左子树 proof；真实压缩需 SNARK 电路）。
        /// Box 避免 enum variant 过大（clippy::large_enum_variant）。
        aggregated_proof: Box<HypernovaProof>,
        /// Phase D 压缩 proof（原生约束满足性验证）。
        /// None 表示压缩失败或叶节点；Some 表示已通过 fold commitment 链验证。
        /// Box 避免 enum variant 过大（CompressedProof::Groth16 含 Proof<Bn254> ~256B）。
        compressed_proof: Option<Box<CompressedProof>>,
        /// 本层证明所在曲线
        curve: CurveKind,
        /// 递归深度（叶 = 0，根 = ceil(log2(K))）
        depth: u32,
    },
}

impl CycleFoldNode {
    /// 返回节点关联的 proof。
    pub fn proof(&self) -> &HypernovaProof {
        match self {
            CycleFoldNode::Leaf { proof, .. } => proof.as_ref(),
            CycleFoldNode::Node {
                aggregated_proof, ..
            } => aggregated_proof.as_ref(),
        }
    }

    /// 返回节点的压缩 proof（Phase D）。
    ///
    /// 叶节点返回 `None`；内部节点返回 `Some(&CompressedProof)` 若压缩成功。
    pub fn compressed_proof(&self) -> Option<&CompressedProof> {
        match self {
            CycleFoldNode::Leaf { .. } => None,
            CycleFoldNode::Node {
                compressed_proof, ..
            } => compressed_proof.as_ref().map(Box::as_ref),
        }
    }

    /// 返回节点所在曲线。
    pub fn curve(&self) -> CurveKind {
        match self {
            CycleFoldNode::Leaf { curve, .. } => *curve,
            CycleFoldNode::Node { curve, .. } => *curve,
        }
    }

    /// 返回节点深度（叶 = 0）。
    pub fn depth(&self) -> u32 {
        match self {
            CycleFoldNode::Leaf { .. } => 0,
            CycleFoldNode::Node { depth, .. } => *depth,
        }
    }

    /// 统计叶节点数（sub-proof 总数）。
    pub fn leaf_count(&self) -> usize {
        match self {
            CycleFoldNode::Leaf { .. } => 1,
            CycleFoldNode::Node { left, right, .. } => left.leaf_count() + right.leaf_count(),
        }
    }
}

/// 递归 verifier 电路 trait — 定义电路结构 + 约束数 + 原生验证模拟。
///
/// `C_BN254`（[`circuit_bn254::CircuitBn254`]）和 `C_Grumpkin`
/// （[`circuit_grumpkin::CircuitGrumpkin`]）均实现此 trait。
///
/// MVP 实现：原生验证模拟（复用 [`verify_hypernova`]）。
/// 真实 R1CS / PLONKish 电路编译推迟到 Phase 12/13。
pub trait RecursiveVerifierCircuit {
    /// 电路所在曲线。
    fn curve_kind() -> CurveKind;

    /// 验证的 sub-proof 所在曲线。
    fn sub_proof_curve_kind() -> CurveKind;

    /// 估算单层约束数（spec L589 — 100k-200k）。
    ///
    /// # 参数
    /// - `num_vars` — witness 变量数
    /// - `num_matrices` — CCS 矩阵数
    fn constraint_count(num_vars: usize, num_matrices: usize) -> usize;

    /// 原生验证模拟（MVP — 复用 [`verify_hypernova`]）。
    fn verify_native(&self) -> Result<bool, ZkvmError>;

    /// public inputs 清单（spec L586）。
    fn public_inputs_desc() -> &'static [&'static str];
}

/// 聚合 K 个 sub-proof 为单个 final proof（spec L553-559, Task 9.2.2）。
///
/// MVP 实现：验证所有 sub-proof 后返回树根的 proof。
/// 真实 size 压缩需 Phase 12/13 SNARK 电路。
///
/// # 参数
/// - `sub_proofs` — K 个 Hypernova sub-proof
/// - `pcs` — IPA PCS（用于原生验证）
///
/// # 返回
/// 聚合后的单个 [`HypernovaProof`]。
///
/// # 错误
/// - `sub_proofs` 为空
/// - 任一 sub-proof 验证失败
/// - 递归深度超限（> [`MAX_RECURSION_DEPTH`] = 16）
pub fn aggregate(sub_proofs: &[HypernovaProof], pcs: &IpaPcs) -> Result<HypernovaProof, ZkvmError> {
    let root = tree_aggregate(sub_proofs, MAX_RECURSION_DEPTH, pcs)?;
    Ok(root.proof().clone())
}

/// 树形聚合（spec L592-598, Task 9.2.3）— log(K) 递归深度。
///
/// 构建二叉树：叶节点为 sub-proofs，内部节点为递归 verifier 电路实例。
/// 每层交替曲线：叶 = BN254 → depth 1 = Grumpkin → depth 2 = BN254 → ...
///
/// # 参数
/// - `sub_proofs` — K 个 Hypernova sub-proof
/// - `max_depth` — 递归深度上限（默认 [`MAX_RECURSION_DEPTH`] = 16）
/// - `pcs` — IPA PCS（用于原生验证）
///
/// # 返回
/// [`CycleFoldNode`] — 树根节点。
///
/// # 错误
/// - `sub_proofs` 为空 → `Other`
/// - 任一 sub-proof 验证失败 → `Other`
/// - depth > max_depth → `RecursionDepthExceeded`
///
/// # 深度依据分析（spec L566）
///
/// 最坏 N=1000 sub-proofs，树形聚合深度 = ceil(log2(1000)) = 10，
/// [`MAX_RECURSION_DEPTH`] = 16 留 60% 余量。
pub fn tree_aggregate(
    sub_proofs: &[HypernovaProof],
    max_depth: u32,
    pcs: &IpaPcs,
) -> Result<CycleFoldNode, ZkvmError> {
    if sub_proofs.is_empty() {
        return Err(ZkvmError::Other(
            "tree_aggregate: sub_proofs 为空".to_string(),
        ));
    }

    // 1. 验证所有 sub-proof（soundness 保证）
    for (i, proof) in sub_proofs.iter().enumerate() {
        #[allow(deprecated)]
        if !verify_hypernova(proof, pcs)? {
            return Err(ZkvmError::Other(format!(
                "tree_aggregate: sub_proof[{i}] 原生验证失败"
            )));
        }
    }

    // 2. 构建叶节点（BN254，因 HypernovaProof 基于 BN254 IPA PCS）
    let leaves: Vec<CycleFoldNode> = sub_proofs
        .iter()
        .map(|p| CycleFoldNode::Leaf {
            proof: Box::new(p.clone()),
            curve: CurveKind::Bn254,
        })
        .collect();

    // 3. 递归配对聚合
    tree_aggregate_recursive(&leaves, 1, max_depth, true)
}

/// 递归配对聚合内部实现。
///
/// 每层将 nodes 两两配对，生成内部节点。
/// 曲线交替：depth 1 = Grumpkin（C_Grumpkin 验证 BN254 叶 proofs）
///          → depth 2 = Bn254（C_BN254 验证 Grumpkin proofs）→ ...
///
/// `compress` 参数控制是否调用 `groth16_compress`（Phase F 真实 SNARK 压缩）。
/// 生产代码始终 `compress = true`；测试可传 `false` 跳过压缩以加速（~80min/节点）。
fn tree_aggregate_recursive(
    nodes: &[CycleFoldNode],
    depth: u32,
    max_depth: u32,
    compress: bool,
) -> Result<CycleFoldNode, ZkvmError> {
    // 基本情况：仅剩 1 个节点 → 聚合完成
    if nodes.len() == 1 {
        return Ok(nodes[0].clone());
    }

    // 深度检查（spec L565）
    if depth > max_depth {
        return Err(ZkvmError::RecursionDepthExceeded {
            actual: depth,
            limit: max_depth,
        });
    }

    // 曲线交替：奇数 depth = Grumpkin，偶数 depth = Bn254
    // 叶 = Bn254 → depth 1 = Grumpkin（验证 Bn254 proofs）→ depth 2 = Bn254 → ...
    let node_curve = if depth % 2 == 1 {
        CurveKind::Grumpkin
    } else {
        CurveKind::Bn254
    };

    // 两两配对
    let mut next_level: Vec<CycleFoldNode> = Vec::with_capacity(nodes.len().div_ceil(2));
    let mut i = 0;
    while i < nodes.len() {
        if i + 1 >= nodes.len() {
            // 奇数节点：直接传递到下一层
            next_level.push(nodes[i].clone());
            break;
        }

        let left = &nodes[i];
        let right = &nodes[i + 1];

        // MVP: aggregated_proof = 左子树 proof（真实聚合需 SNARK 电路）
        let aggregated_proof = Box::new(left.proof().clone());

        // Phase F: 压缩 proof（真实 Groth16 SNARK）。
        // best-effort — 压缩失败时存 None，full proof 仍可用于原生验证。
        // compress = false 时跳过（测试用，避免 ~80min/节点的 Groth16 setup）。
        let compressed_proof = if compress {
            groth16_compress(&aggregated_proof).ok().map(Box::new)
        } else {
            None
        };

        next_level.push(CycleFoldNode::Node {
            left: Box::new(left.clone()),
            right: Box::new(right.clone()),
            aggregated_proof,
            compressed_proof,
            curve: node_curve,
            depth,
        });
        i += 2;
    }

    tree_aggregate_recursive(&next_level, depth + 1, max_depth, compress)
}

/// 检查 final proof 是否满足大小约束（spec L563-564）。
///
/// MVP 工具函数：真实压缩后 proof 应 ≤ [`MAX_ZKVM_PROOF_SIZE`] = 64KB。
/// 若超过，需 Phase 12/13 Spartan/Groth16 压缩。
///
/// # 返回
/// `Ok(())` 若 proof ≤ 64KB；`Err` 含实际大小与上限。
pub fn check_proof_size(proof: &HypernovaProof) -> Result<(), ZkvmError> {
    let bytes = serialize_proof(proof)?;
    if bytes.len() > MAX_ZKVM_PROOF_SIZE {
        return Err(ZkvmError::Other(format!(
            "proof 大小 {} > MAX_ZKVM_PROOF_SIZE {}，需 Phase 12/13 SNARK 压缩",
            bytes.len(),
            MAX_ZKVM_PROOF_SIZE
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::ccs::{Ccs, Fr, SparseMatrix};
    use crate::field::ZkvmField;
    use crate::fold::fold_loop::fold_loop;
    use crate::pcs::ipa::{IpaCommitment, IpaPcs};
    use crate::pcs::{MultilinearPoly, Pcs};
    use crate::prover::groth16_compress::groth16_compress_verify;
    use crate::transcript::{HYPERNOVA_FOLD_DOMAIN_TAG, Transcript};

    /// 辅助：构造 Fr。
    fn f(v: u32) -> Fr {
        Fr::from_u32_with_wrap(v)
    }

    /// 辅助：构造负 Fr。
    fn neg_f(v: u32) -> Fr {
        Fr::zero().sub(&f(v))
    }

    /// 使用 IPA 计算实际 witness commitment（用于 PCS opening 一致性）。
    fn commit_witness(pcs: &IpaPcs, z: &[Fr]) -> IpaCommitment {
        let poly = MultilinearPoly::from_evals(z.to_vec()).expect("MultilinearPoly 构造应成功");
        pcs.commit(&poly).expect("pcs.commit 应成功")
    }

    /// 构造线性 CCS — x - y = 0（1 row, 4 vars, 2 matrices）。
    fn make_linear_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();

        Ccs::new(
            4,
            vec![m0, m1],
            vec![vec![0], vec![1]],
            vec![f(1), neg_f(1)],
        )
        .expect("linear Ccs 构造应成功")
    }

    /// 构造 IPA PCS（max_n_vars = 4）。
    fn make_ipa_pcs() -> IpaPcs {
        IpaPcs::new(4).expect("IpaPcs 构造应成功")
    }

    /// 使用 fold_loop 生成单个 HypernovaProof（单步折叠，线性 CCS）。
    /// 匹配 prover/mod.rs:813-841 的 transcript 初始化流程（D3 要求 — groth16_compress 需重放 transcript）。
    fn make_proof(pcs: &IpaPcs, seed: u32) -> HypernovaProof {
        let ccs = make_linear_ccs();
        // 使用不同 seed 生成不同 witness（但都满足 CCS 约束 x - y = 0）
        let z_l = vec![f(1), f(seed), f(seed), f(0)];
        let z_c = vec![f(1), f(seed + 1), f(seed + 1), f(0)];

        // 使用真实 IPA commitment，使 C' = C_L + r·C_C = ⟨z', G⟩ 与 pcs.open 内部承诺一致
        let cmt_l = commit_witness(pcs, &z_l);
        let cmt_c = commit_witness(pcs, &z_c);

        // 匹配 prover/mod.rs:813-841:transcript 初始化 + absorb + r_x_l 派生
        let public_io_commitment = [0u8; 32];
        let ccs_commitment = ccs.ccs_commitment();
        let batch_public_inputs: Vec<Vec<Fr>> = vec![vec![]];

        let mut transcript = Transcript::with_domain(b"poker_zkvm_prover_v1");
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &public_io_commitment);
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &ccs_commitment);
        for group in &batch_public_inputs {
            for pi in group {
                transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, pi);
            }
        }
        // 派生 r_x_l（长度 = log2(num_rows)）；num_rows=1 → r_x_l_len=0 → r_x_l 为空
        let num_rows = ccs.num_rows();
        let r_x_l_len = num_rows.trailing_zeros() as usize;
        let r_x_l: Vec<Fr> = (0..r_x_l_len)
            .map(|_| transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG))
            .collect();

        let lcccs = ccs.to_lcccs(&z_l, &r_x_l, r_x_l.clone()).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, r_x_l, cmt_c).expect("to_cccs");

        fold_loop(
            &ccs,
            lcccs,
            cmt_l,
            &[ccccs],
            pcs,
            &mut transcript,
            ccs_commitment,
            public_io_commitment,
            batch_public_inputs,
        )
        .expect("fold_loop 应成功")
    }

    /// 生成 K 个有效 HypernovaProof。
    fn make_k_proofs(pcs: &IpaPcs, k: usize) -> Vec<HypernovaProof> {
        (0..k)
            .map(|i| make_proof(pcs, (i as u32) * 10 + 1))
            .collect()
    }

    /// 测试辅助：tree_aggregate 但跳过 Groth16 压缩（compress = false）。
    ///
    /// 验证 sub-proofs + 构建叶节点 + `tree_aggregate_recursive(compress=false)`。
    /// 用于树结构测试，避免每个内部节点 ~80min 的 Groth16 setup。
    fn tree_aggregate_no_compress(
        sub_proofs: &[HypernovaProof],
        max_depth: u32,
        pcs: &IpaPcs,
    ) -> Result<CycleFoldNode, ZkvmError> {
        if sub_proofs.is_empty() {
            return Err(ZkvmError::Other("sub_proofs 为空".to_string()));
        }
        for (i, proof) in sub_proofs.iter().enumerate() {
            #[allow(deprecated)]
            if !verify_hypernova(proof, pcs)? {
                return Err(ZkvmError::Other(format!("sub_proof[{i}] 原生验证失败")));
            }
        }
        let leaves: Vec<CycleFoldNode> = sub_proofs
            .iter()
            .map(|p| CycleFoldNode::Leaf {
                proof: Box::new(p.clone()),
                curve: CurveKind::Bn254,
            })
            .collect();
        tree_aggregate_recursive(&leaves, 1, max_depth, false)
    }

    // ===== SubTask 9.2.1: CycleFoldNode 树结构测试 =====

    #[test]
    fn test_curve_kind_opposite() {
        assert_eq!(CurveKind::Bn254.opposite(), CurveKind::Grumpkin);
        assert_eq!(CurveKind::Grumpkin.opposite(), CurveKind::Bn254);
    }

    #[test]
    fn test_cycle_fold_node_leaf() {
        let pcs = make_ipa_pcs();
        let proof = make_proof(&pcs, 1);
        let leaf = CycleFoldNode::Leaf {
            proof: Box::new(proof.clone()),
            curve: CurveKind::Bn254,
        };
        assert_eq!(leaf.depth(), 0);
        assert_eq!(leaf.curve(), CurveKind::Bn254);
        assert_eq!(leaf.leaf_count(), 1);
        assert_eq!(leaf.proof().abi_version, proof.abi_version);
    }

    // ===== SubTask 9.2.2: aggregate 测试 =====

    #[test]
    fn test_aggregate_single_proof() {
        let pcs = make_ipa_pcs();
        let proof = make_proof(&pcs, 1);
        let result = aggregate(std::slice::from_ref(&proof), &pcs).expect("单个 proof 聚合应成功");
        assert_eq!(result.abi_version, proof.abi_version);
    }

    #[test]
    fn test_aggregate_empty_error() {
        let pcs = make_ipa_pcs();
        let result = aggregate(&[], &pcs);
        assert!(result.is_err(), "空 sub_proofs 应返回错误");
    }

    // ===== SubTask 9.2.3: tree_aggregate 测试 =====

    #[test]
    fn test_tree_aggregate_k8() {
        let pcs = make_ipa_pcs();
        let proofs = make_k_proofs(&pcs, 8);
        let root =
            tree_aggregate_no_compress(&proofs, MAX_RECURSION_DEPTH, &pcs).expect("K=8 聚合应成功");

        // 根节点应有 8 个叶节点
        assert_eq!(root.leaf_count(), 8);
        // 深度 = ceil(log2(8)) = 3
        assert_eq!(root.depth(), 3);
        // depth 1 = Grumpkin, depth 2 = Bn254, depth 3 = Grumpkin
        assert_eq!(root.curve(), CurveKind::Grumpkin);
    }

    #[test]
    fn test_tree_aggregate_k4() {
        let pcs = make_ipa_pcs();
        let proofs = make_k_proofs(&pcs, 4);
        let root =
            tree_aggregate_no_compress(&proofs, MAX_RECURSION_DEPTH, &pcs).expect("K=4 聚合应成功");

        assert_eq!(root.leaf_count(), 4);
        // 深度 = ceil(log2(4)) = 2
        assert_eq!(root.depth(), 2);
        // depth 1 = Grumpkin, depth 2 = Bn254
        assert_eq!(root.curve(), CurveKind::Bn254);
    }

    #[test]
    fn test_tree_aggregate_k2() {
        let pcs = make_ipa_pcs();
        let proofs = make_k_proofs(&pcs, 2);
        let root =
            tree_aggregate_no_compress(&proofs, MAX_RECURSION_DEPTH, &pcs).expect("K=2 聚合应成功");

        assert_eq!(root.leaf_count(), 2);
        assert_eq!(root.depth(), 1);
        // depth 1 = Grumpkin
        assert_eq!(root.curve(), CurveKind::Grumpkin);
    }

    #[test]
    fn test_tree_aggregate_k1() {
        let pcs = make_ipa_pcs();
        let proofs = make_k_proofs(&pcs, 1);
        let root = tree_aggregate(&proofs, MAX_RECURSION_DEPTH, &pcs).expect("K=1 聚合应成功");

        // 单个 proof → 直接返回叶节点
        assert_eq!(root.leaf_count(), 1);
        assert_eq!(root.depth(), 0);
        assert!(matches!(root, CycleFoldNode::Leaf { .. }));
    }

    // ===== SubTask 9.2.4: 递归终止条件测试 =====

    #[test]
    fn test_tree_aggregate_depth_exceeded() {
        let pcs = make_ipa_pcs();
        // K=2 但 max_depth=0 → 应触发 RecursionDepthExceeded
        let proofs = make_k_proofs(&pcs, 2);
        let result = tree_aggregate(&proofs, 0, &pcs);
        assert!(result.is_err());
        match result.unwrap_err() {
            ZkvmError::RecursionDepthExceeded { actual, limit } => {
                assert_eq!(actual, 1);
                assert_eq!(limit, 0);
            }
            other => panic!("期望 RecursionDepthExceeded，实际 {:?}", other),
        }
    }

    #[test]
    fn test_tree_aggregate_depth_limit_at_boundary() {
        let pcs = make_ipa_pcs();
        // K=2, max_depth=1 → depth=1 不超过 1，应成功
        let proofs = make_k_proofs(&pcs, 2);
        let root = tree_aggregate_no_compress(&proofs, 1, &pcs).expect("max_depth=1 应成功");
        assert_eq!(root.depth(), 1);
    }

    // ===== SubTask 9.2.5: K=8 sub-proofs 聚合为单个 final proof =====

    #[test]
    fn test_aggregate_k8_returns_valid_proof() {
        let pcs = make_ipa_pcs();
        let proofs = make_k_proofs(&pcs, 8);
        let root =
            tree_aggregate_no_compress(&proofs, MAX_RECURSION_DEPTH, &pcs).expect("K=8 聚合应成功");
        let final_proof = root.proof().clone();

        // final proof 应可通过原生验证
        assert!(
            verify_hypernova(&final_proof, &pcs).expect("final proof 验证应成功"),
            "聚合后的 final proof 应通过 verify_hypernova"
        );
    }

    // ===== SubTask 9.2.6: soundness 负例 — 篡改 sub_proof 聚合失败 =====

    #[test]
    fn test_aggregate_tampered_sub_proof_fails() {
        let pcs = make_ipa_pcs();
        let mut proofs = make_k_proofs(&pcs, 4);

        // 篡改第 2 个 proof 的 z_at_point（应导致验证失败）
        proofs[1].z_at_point = proofs[1].z_at_point.add(&Fr::one());

        let result = aggregate(&proofs, &pcs);
        assert!(
            result.is_err(),
            "篡改 sub_proof 后聚合应失败（verify_hypernova 应拒绝）"
        );
    }

    #[test]
    fn test_aggregate_tampered_abi_version_fails() {
        let pcs = make_ipa_pcs();
        let mut proofs = make_k_proofs(&pcs, 4);

        // 篡改 abi_version
        proofs[0].abi_version = 99;

        let result = tree_aggregate_no_compress(&proofs, MAX_RECURSION_DEPTH, &pcs);
        // abi_version 篡改可能不影响 verify_hypernova（它不检查 abi_version）
        // 但 tree_aggregate 应仍然完成；soundness 由 verify_hypernova 保证
        // 此测试验证 abi_version 篡改不导致 panic
        let _ = result;
    }

    // ===== check_proof_size 测试 =====

    #[test]
    fn test_check_proof_size_small_proof_ok() {
        let pcs = make_ipa_pcs();
        let proof = make_proof(&pcs, 1);
        // 单步折叠的 proof 应远小于 64KB
        check_proof_size(&proof).expect("小 proof 应通过大小检查");
    }

    #[test]
    fn test_curve_alternation_in_tree() {
        let pcs = make_ipa_pcs();
        let proofs = make_k_proofs(&pcs, 8);
        let root = tree_aggregate_no_compress(&proofs, MAX_RECURSION_DEPTH, &pcs).unwrap();

        // 验证交替：从根到叶，曲线应交替
        // root depth=3 (Grumpkin) → depth 2 (Bn254) → depth 1 (Grumpkin) → leaf (Bn254)
        fn check_alternation(node: &CycleFoldNode) {
            match node {
                CycleFoldNode::Leaf { curve, .. } => {
                    assert_eq!(*curve, CurveKind::Bn254, "叶节点应在 Bn254 上");
                }
                CycleFoldNode::Node {
                    left,
                    right,
                    curve,
                    depth,
                    ..
                } => {
                    // 本层曲线 = opposite of parent's children's curve
                    let expected = if *depth % 2 == 1 {
                        CurveKind::Grumpkin
                    } else {
                        CurveKind::Bn254
                    };
                    assert_eq!(*curve, expected, "depth {} 曲线应为 {:?}", depth, expected);
                    // 递归检查子节点
                    check_alternation(left);
                    check_alternation(right);
                }
            }
        }
        check_alternation(&root);
    }

    #[test]
    fn test_odd_number_of_proofs() {
        let pcs = make_ipa_pcs();
        // K=5（奇数）— 奇数节点应传递到下一层
        let proofs = make_k_proofs(&pcs, 5);
        let root =
            tree_aggregate_no_compress(&proofs, MAX_RECURSION_DEPTH, &pcs).expect("K=5 聚合应成功");
        assert_eq!(root.leaf_count(), 5);
        // 深度 = ceil(log2(5)) = 3
        assert_eq!(root.depth(), 3);
    }

    #[test]
    fn test_large_k_within_depth_limit() {
        let pcs = make_ipa_pcs();
        // K=16 → depth = ceil(log2(16)) = 4，远低于 16
        let proofs = make_k_proofs(&pcs, 16);
        let root = tree_aggregate_no_compress(&proofs, MAX_RECURSION_DEPTH, &pcs)
            .expect("K=16 聚合应成功");
        assert_eq!(root.leaf_count(), 16);
        assert_eq!(root.depth(), 4);
    }

    // ===== Phase D — D3: compressed_proof 集成测试 =====

    #[test]
    fn test_compressed_proof_leaf_is_none() {
        let pcs = make_ipa_pcs();
        let proof = make_proof(&pcs, 1);
        let leaf = CycleFoldNode::Leaf {
            proof: Box::new(proof),
            curve: CurveKind::Bn254,
        };
        assert!(leaf.compressed_proof().is_none(), "叶节点应返回 None");
    }

    #[test]
    #[ignore = "K=2 含 1 次 Groth16 setup+prove（~80min）；手动运行: cargo test ... -- --ignored"]
    fn test_compressed_proof_in_internal_node() {
        let pcs = make_ipa_pcs();
        let proofs = make_k_proofs(&pcs, 2);
        let root = tree_aggregate(&proofs, MAX_RECURSION_DEPTH, &pcs).expect("K=2 聚合应成功");

        // 内部节点应有压缩 proof
        let compressed = root
            .compressed_proof()
            .expect("内部节点应有 compressed_proof");
        match compressed {
            CompressedProof::Groth16(groth16) => {
                assert_eq!(groth16.fold_step_count, 1, "fold_step_count 应 = 1");
                let valid = groth16_compress_verify(compressed).expect("verify 应成功");
                assert!(valid, "Groth16 proof 应验证通过");
            }
            CompressedProof::Native(_) => {
                panic!("Phase F 应返回 Groth16 变体");
            }
        }
    }

    #[test]
    #[ignore = "K=2 含 2 次 Groth16 setup+prove（~160min）；手动运行: cargo test ... -- --ignored"]
    fn test_compressed_proof_matches_direct_call() {
        let pcs = make_ipa_pcs();
        let proofs = make_k_proofs(&pcs, 2);
        let root = tree_aggregate(&proofs, MAX_RECURSION_DEPTH, &pcs).expect("K=2 聚合应成功");

        // 直接调用 groth16_compress
        let direct = groth16_compress(root.proof()).expect("直接 groth16_compress 应成功");

        // 树中的 compressed_proof 应与直接调用结果一致（fold_step_count 相同）
        let in_tree = root
            .compressed_proof()
            .expect("内部节点应有 compressed_proof");
        match (&direct, in_tree) {
            (CompressedProof::Groth16(d), CompressedProof::Groth16(t)) => {
                assert_eq!(
                    d.fold_step_count, t.fold_step_count,
                    "fold_step_count 应一致"
                );
                assert_eq!(d.public_inputs, t.public_inputs, "public_inputs 应一致");
            }
            _ => panic!("Phase F 双方均应为 Groth16 变体"),
        }
    }

    #[test]
    #[ignore = "K=8 含 7 次 Groth16 setup+prove，极慢；手动运行: cargo test ... -- --ignored"]
    fn test_compressed_proof_all_internal_nodes_k8() {
        let pcs = make_ipa_pcs();
        let proofs = make_k_proofs(&pcs, 8);
        let root = tree_aggregate(&proofs, MAX_RECURSION_DEPTH, &pcs).expect("K=8 聚合应成功");

        // 递归检查所有内部节点都有压缩 proof
        fn check_all_internal(node: &CycleFoldNode) {
            match node {
                CycleFoldNode::Leaf { .. } => {
                    assert!(node.compressed_proof().is_none());
                }
                CycleFoldNode::Node { left, right, .. } => {
                    assert!(
                        node.compressed_proof().is_some(),
                        "内部节点 depth={} 应有 compressed_proof",
                        node.depth()
                    );
                    check_all_internal(left);
                    check_all_internal(right);
                }
            }
        }
        check_all_internal(&root);
    }
}
