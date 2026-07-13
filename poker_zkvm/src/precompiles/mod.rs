//! 预编译电路（Phase 10 — Task 10.1）。
//!
//! 严格遵循 spec.md L637-669（v1.4 FROZEN）：
//! - [`PrecompileCircuit`] trait — 预编译电路接口（`build_ccs` + `assign_witness`）
//! - [`PrecompileRegistry`] — 预编译电路注册表（名称 → 电路映射）
//! - [`CcsCircuit`] trait — 通用 CCS 电路接口（从 poker_l1 迁移，Fr-based 新签名）
//!
//! ## 设计决策（D3/D4，已批准）
//!
//! - `CcsCircuit` trait 从 poker_l1 迁入此模块，签名基于 `Fr` + `CcsInstance`（非旧 hash-based）
//! - 预编译电路用 `PrecompileCircuit` trait（CCS 矩阵生成器），非 halo2/arkworks Circuit trait
//!
//! ## 子模块（Step 3-6 实现）
//!
//! - `poseidon` — Poseidon 哈希电路（Task 10.2）
//! - `sha256` — SHA-256 电路（Task 10.3）
//! - `ecdsa` — ECDSA 验签电路（Task 10.4）
//! - `zk_shuffle` — ZkShuffle CCS 电路迁移（Task 10.5）

pub mod bit_ops;
pub mod bn254_ops;
pub mod bn254_pairing;
pub mod ccs_builder;
pub mod chaum_pedersen;
pub mod dleq;
pub mod ecdsa;
pub mod ed25519;
pub mod elgamal;
pub mod generalized_schnorr;
pub mod keccak256;
pub mod merkle_verify;
pub mod modexp;
pub mod non_native;
pub mod poker_transcript;
pub mod poseidon;
pub mod reconstruction;
pub mod remask_leave;
pub mod reveal_token;
pub mod secp256k1_ops;
pub mod sha256;
pub mod shuffle_proof;
pub mod zk_shuffle;

use std::collections::HashMap;
use std::fmt::Debug;

use crate::ccs::{Ccs, CcsInstance, Fr};
use crate::error::ZkvmError;

/// 预编译电路 trait（Phase 10 — Task 10.1）。
///
/// 每个预编译电路（Poseidon / SHA-256 / ECDSA）实现此 trait，
/// 提供 CCS 约束结构生成 + witness 赋值 + gas 计费。
///
/// # 闭环验证
///
/// ```text
/// let ccs = circuit.build_ccs();
/// let witness = circuit.assign_witness(inputs)?;
/// assert!(ccs.satisfied_by(&witness)?);
/// ```
pub trait PrecompileCircuit: Debug + Send + Sync {
    /// 电路名称（用于注册表查找与日志）。
    fn name(&self) -> &str;

    /// 变量数（witness 向量长度）。
    fn num_variables(&self) -> usize;

    /// 生成 CCS 约束结构（矩阵 M_j / 子集 S_i / 系数 c_i）。
    fn build_ccs(&self) -> Ccs;

    /// 赋值 witness（从输入计算完整 witness 向量）。
    ///
    /// # 错误
    /// - 输入长度不符 / 输入非法返回 `ZkvmError`
    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError>;

    /// gas 计费（与 host syscall gas 对齐）。
    fn gas_cost(&self) -> u64;
}

/// 预编译电路注册表（Phase 10 — Task 10.1）。
///
/// 通过名称查找预编译电路，供 syscall 子电路（Task 5.5）分派使用。
///
/// # 用法
///
/// ```text
/// let mut registry = PrecompileRegistry::new();
/// registry.register(Box::new(PoseidonCircuit::new()));
/// let circuit = registry.get("poseidon").expect("应找到");
/// ```
#[derive(Debug, Default)]
pub struct PrecompileRegistry {
    /// 名称 → 电路映射。
    circuits: HashMap<String, Box<dyn PrecompileCircuit>>,
}

impl PrecompileRegistry {
    /// 创建空注册表。
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
        }
    }

    /// 注册预编译电路（同名覆盖）。
    ///
    /// # 参数
    /// - `circuit` — 预编译电路实例（Boxed trait object）
    pub fn register(&mut self, circuit: Box<dyn PrecompileCircuit>) {
        let name = circuit.name().to_string();
        self.circuits.insert(name, circuit);
    }

    /// 按名称查找预编译电路。
    ///
    /// # 返回
    /// - 找到返回 `Some(&dyn PrecompileCircuit)`
    /// - 未找到返回 `None`
    pub fn get(&self, name: &str) -> Option<&dyn PrecompileCircuit> {
        self.circuits.get(name).map(|c| c.as_ref())
    }

    /// 已注册的电路数量。
    pub fn len(&self) -> usize {
        self.circuits.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }
}

/// 通用 CCS 电路 trait（从 poker_l1 迁移，Fr-based 新签名）。
///
/// 任何能生成 CCS 实例的电路实现此 trait。
/// 与 [`PrecompileCircuit`] 的区别：`CcsCircuit` 侧重实例生成（witness → CcsInstance），
/// `PrecompileCircuit` 侧重约束结构 + witness 赋值（inputs → witness）。
///
/// # 迁移说明（D3）
///
/// 旧 `poker_l1::CcsCircuit` 基于 `Hash` 类型，新签名基于 `Fr` + [`CcsInstance`] 新类型。
/// poker_l1 通过 `pub use poker_zkvm::precompiles::CcsCircuit;` re-export（Phase 11 完成）。
pub trait CcsCircuit: Send + Sync {
    /// 电路名称。
    fn name(&self) -> &str;

    /// 约束矩阵数量。
    fn num_matrices(&self) -> usize;

    /// 生成 CCS 实例。
    ///
    /// # 参数
    /// - `witness` — 见证向量（域元素）
    /// - `public_inputs` — 公共输入（域元素）
    ///
    /// # 错误
    /// - witness 长度不符 / 约束不满足返回 `ZkvmError`
    fn to_ccs_instance(
        &self,
        witness: &[Fr],
        public_inputs: &[Fr],
    ) -> Result<CcsInstance, ZkvmError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::SparseMatrix;
    use crate::field::ZkvmField;

    /// Mock 预编译电路 — 简单乘法约束 x * y = z（用于测试注册表）。
    #[derive(Debug)]
    struct MockMulCircuit {
        name: String,
    }

    impl MockMulCircuit {
        fn new() -> Self {
            Self {
                name: "mock_mul".to_string(),
            }
        }
    }

    impl PrecompileCircuit for MockMulCircuit {
        fn name(&self) -> &str {
            &self.name
        }

        fn num_variables(&self) -> usize {
            4 // z = [1, x, y, result]
        }

        fn build_ccs(&self) -> Ccs {
            let mut m0 = SparseMatrix::new(1, 4);
            m0.add_entry(0, 1, Fr::one()).unwrap();
            let mut m1 = SparseMatrix::new(1, 4);
            m1.add_entry(0, 2, Fr::one()).unwrap();
            let mut m2 = SparseMatrix::new(1, 4);
            m2.add_entry(0, 3, Fr::one()).unwrap();

            Ccs::new(
                4,
                vec![m0, m1, m2],
                vec![vec![0, 1], vec![2]],
                vec![Fr::one(), Fr::zero().sub(&Fr::one())],
            )
            .expect("MockMulCircuit CCS 构造应成功")
        }

        fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
            if inputs.len() != 2 {
                return Err(ZkvmError::Other(format!(
                    "MockMulCircuit: inputs.len() {} != 2",
                    inputs.len()
                )));
            }
            // z = [1, x, y, x*y]
            let result = inputs[0].mul(&inputs[1]);
            Ok(vec![Fr::one(), inputs[0], inputs[1], result])
        }

        fn gas_cost(&self) -> u64 {
            100
        }
    }

    /// Mock CcsCircuit — 用于测试 trait object dispatch。
    struct MockCcsCircuit {
        name: String,
    }

    impl MockCcsCircuit {
        fn new() -> Self {
            Self {
                name: "mock_ccs".to_string(),
            }
        }
    }

    impl CcsCircuit for MockCcsCircuit {
        fn name(&self) -> &str {
            &self.name
        }

        fn num_matrices(&self) -> usize {
            3
        }

        fn to_ccs_instance(
            &self,
            witness: &[Fr],
            public_inputs: &[Fr],
        ) -> Result<CcsInstance, ZkvmError> {
            let mut m0 = SparseMatrix::new(1, 4);
            m0.add_entry(0, 1, Fr::one()).unwrap();
            let mut m1 = SparseMatrix::new(1, 4);
            m1.add_entry(0, 2, Fr::one()).unwrap();
            let mut m2 = SparseMatrix::new(1, 4);
            m2.add_entry(0, 3, Fr::one()).unwrap();

            let ccs = Ccs::new(
                4,
                vec![m0, m1, m2],
                vec![vec![0, 1], vec![2]],
                vec![Fr::one(), Fr::zero().sub(&Fr::one())],
            )?;

            CcsInstance::new(ccs, witness.to_vec(), public_inputs.to_vec())
        }
    }

    #[test]
    fn test_precompile_registry_register_and_get() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(MockMulCircuit::new()));

        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());

        let circuit = registry.get("mock_mul").expect("应找到 mock_mul");
        assert_eq!(circuit.name(), "mock_mul");
        assert_eq!(circuit.num_variables(), 4);
        assert_eq!(circuit.gas_cost(), 100);
    }

    #[test]
    fn test_precompile_registry_empty() {
        let registry = PrecompileRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_precompile_registry_overwrite() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(MockMulCircuit::new()));
        // 同名覆盖
        registry.register(Box::new(MockMulCircuit::new()));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_precompile_circuit_build_and_satisfy() {
        let circuit = MockMulCircuit::new();
        let ccs = circuit.build_ccs();
        let witness = circuit
            .assign_witness(&[Fr::from_u32_with_wrap(3), Fr::from_u32_with_wrap(4)])
            .expect("assign_witness 应成功");

        // 3 * 4 = 12
        assert_eq!(witness.len(), 4);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_precompile_circuit_assign_witness_wrong_input() {
        let circuit = MockMulCircuit::new();
        let result = circuit.assign_witness(&[Fr::one()]); // 长度 1 != 2
        assert!(result.is_err());
    }

    #[test]
    fn test_ccs_circuit_trait_object_dispatch() {
        let circuit = MockCcsCircuit::new();
        let witness = vec![
            Fr::one(),
            Fr::from_u32_with_wrap(3),
            Fr::from_u32_with_wrap(4),
            Fr::from_u32_with_wrap(12),
        ];
        let public_inputs = vec![Fr::one()];

        // 通过 trait object 调用
        let ccs_circuit: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs_circuit.name(), "mock_ccs");
        assert_eq!(ccs_circuit.num_matrices(), 3);

        let instance = ccs_circuit
            .to_ccs_instance(&witness, &public_inputs)
            .expect("to_ccs_instance 应成功");
        assert!(instance.is_satisfied().expect("is_satisfied 应成功"));
    }

    // ===== Phase 10 集成测试（Step 7）=====

    /// 注册全部 9 个预编译电路并验证名称 / gas / 变量数。
    #[test]
    fn test_phase10_registry_full() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(poseidon::PoseidonCircuit::new_mvp()));
        registry.register(Box::new(sha256::Sha256Circuit::new_mvp()));
        registry.register(Box::new(ecdsa::EcdsaVerifyCircuit::new_mvp()));
        registry.register(Box::new(zk_shuffle::ZkShuffleCcsCircuit::new_light()));
        registry.register(Box::new(keccak256::Keccak256Circuit::new_mvp()));
        registry.register(Box::new(modexp::ModexpCircuit::new_mvp()));
        registry.register(Box::new(merkle_verify::MerkleVerifyCircuit::new_mvp()));
        registry.register(Box::new(ed25519::Ed25519VerifyCircuit::new_mvp()));
        registry.register(Box::new(bn254_pairing::Bn254PairingCircuit::new_mvp()));

        assert_eq!(registry.len(), 9, "应有 9 个预编译电路");

        // Poseidon
        let poseidon = registry.get("poseidon").expect("应找到 poseidon");
        assert_eq!(poseidon.num_variables(), 5);
        assert_eq!(poseidon.gas_cost(), 200);

        // SHA-256
        let sha256 = registry.get("sha256").expect("应找到 sha256");
        assert_eq!(sha256.num_variables(), 6);
        assert_eq!(sha256.gas_cost(), 25_000);

        // ECDSA
        let ecdsa = registry.get("ecdsa_verify").expect("应找到 ecdsa_verify");
        assert_eq!(ecdsa.num_variables(), 6);
        assert_eq!(ecdsa.gas_cost(), 100_000);

        // ZkShuffle
        let zk_shuffle = registry.get("zk_shuffle").expect("应找到 zk_shuffle");
        assert!(zk_shuffle.num_variables() > 1000, "zk_shuffle 应有大量变量");
        assert_eq!(zk_shuffle.gas_cost(), 1_780_000); // Light mode

        // Keccak256 (MVP)
        let keccak = registry.get("keccak256").expect("应找到 keccak256");
        assert_eq!(keccak.gas_cost(), 10_000);

        // Modexp (MVP)
        let modexp = registry.get("modexp").expect("应找到 modexp");
        assert_eq!(modexp.gas_cost(), 50_000);

        // MerkleVerify (MVP)
        let merkle = registry.get("merkle_verify").expect("应找到 merkle_verify");
        assert_eq!(merkle.gas_cost(), 100);

        // Ed25519 (MVP)
        let ed25519_circuit = registry.get("ed25519").expect("应找到 ed25519");
        assert_eq!(ed25519_circuit.gas_cost(), 50_000);

        // BN254 Pairing (MVP)
        let bn254 = registry.get("bn254_pairing").expect("应找到 bn254_pairing");
        assert_eq!(bn254.gas_cost(), 30_000);
    }

    /// 验证所有预编译电路都实现 PrecompileCircuit + CcsCircuit 双 trait。
    #[test]
    fn test_phase10_all_implement_both_traits() {
        // Poseidon
        let poseidon = poseidon::PoseidonCircuit::new();
        let _: &dyn PrecompileCircuit = &poseidon;
        let _: &dyn CcsCircuit = &poseidon;

        // SHA-256
        let sha256 = sha256::Sha256Circuit::new();
        let _: &dyn PrecompileCircuit = &sha256;
        let _: &dyn CcsCircuit = &sha256;

        // ECDSA
        let ecdsa = ecdsa::EcdsaVerifyCircuit::new();
        let _: &dyn PrecompileCircuit = &ecdsa;
        let _: &dyn CcsCircuit = &ecdsa;

        // ZkShuffle
        let zk_shuffle = zk_shuffle::ZkShuffleCcsCircuit::new();
        let _: &dyn PrecompileCircuit = &zk_shuffle;
        let _: &dyn CcsCircuit = &zk_shuffle;

        // Keccak256
        let keccak_circuit = keccak256::Keccak256Circuit::new();
        let _: &dyn PrecompileCircuit = &keccak_circuit;
        let _: &dyn CcsCircuit = &keccak_circuit;

        // Modexp
        let modexp_circuit = modexp::ModexpCircuit::new();
        let _: &dyn PrecompileCircuit = &modexp_circuit;
        let _: &dyn CcsCircuit = &modexp_circuit;

        // MerkleVerify
        let merkle_circuit = merkle_verify::MerkleVerifyCircuit::new();
        let _: &dyn PrecompileCircuit = &merkle_circuit;
        let _: &dyn CcsCircuit = &merkle_circuit;

        // Ed25519
        let ed25519_circuit = ed25519::Ed25519VerifyCircuit::new();
        let _: &dyn PrecompileCircuit = &ed25519_circuit;
        let _: &dyn CcsCircuit = &ed25519_circuit;

        // BN254 Pairing
        let bn254_circuit = bn254_pairing::Bn254PairingCircuit::new();
        let _: &dyn PrecompileCircuit = &bn254_circuit;
        let _: &dyn CcsCircuit = &bn254_circuit;
    }

    /// 验证 gas 成本合理性（spec L637/L660 对齐）。
    #[test]
    fn test_phase10_gas_costs_reasonable() {
        let cases = [
            ("poseidon", 200u64, 1_000u64),       // ~200 gas/round
            ("sha256", 25_000, 100_000),          // ~25k gas/block
            ("ecdsa_verify", 100_000, 200_000),   // ~100k gas/verify
            ("zk_shuffle", 1_000_000, 5_000_000), // Light = 1_780_000
            ("keccak256", 5_000, 15_000),         // MVP = 10_000
            ("modexp", 10_000, 100_000),          // MVP = 50_000
            ("merkle_verify", 1, 1_000),          // MVP = 100
            ("ed25519", 5_000, 100_000),          // MVP = 50_000
            ("bn254_pairing", 1_000, 100_000),    // MVP = 30_000
        ];

        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(poseidon::PoseidonCircuit::new_mvp()));
        registry.register(Box::new(sha256::Sha256Circuit::new_mvp()));
        registry.register(Box::new(ecdsa::EcdsaVerifyCircuit::new_mvp()));
        registry.register(Box::new(zk_shuffle::ZkShuffleCcsCircuit::new_light()));
        registry.register(Box::new(keccak256::Keccak256Circuit::new_mvp()));
        registry.register(Box::new(modexp::ModexpCircuit::new_mvp()));
        registry.register(Box::new(merkle_verify::MerkleVerifyCircuit::new_mvp()));
        registry.register(Box::new(ed25519::Ed25519VerifyCircuit::new_mvp()));
        registry.register(Box::new(bn254_pairing::Bn254PairingCircuit::new_mvp()));

        for (name, min, max) in cases {
            let circuit = registry
                .get(name)
                .unwrap_or_else(|| panic!("应找到 {name}"));
            let gas = circuit.gas_cost();
            assert!(
                gas >= min && gas < max,
                "{name} gas_cost={gas} 不在合理范围 [{min}, {max})"
            );
        }
    }

    /// 验证完整模式电路可注册且 gas 正确（不调用 num_variables / build_ccs，避免慢测试）。
    #[test]
    fn test_phase10_registry_full_mode_smoke() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(poseidon::PoseidonCircuit::new()));
        registry.register(Box::new(sha256::Sha256Circuit::new()));
        registry.register(Box::new(ecdsa::EcdsaVerifyCircuit::new()));
        registry.register(Box::new(zk_shuffle::ZkShuffleCcsCircuit::new()));
        registry.register(Box::new(keccak256::Keccak256Circuit::new()));
        registry.register(Box::new(modexp::ModexpCircuit::new()));
        registry.register(Box::new(merkle_verify::MerkleVerifyCircuit::new()));
        registry.register(Box::new(ed25519::Ed25519VerifyCircuit::new()));
        registry.register(Box::new(bn254_pairing::Bn254PairingCircuit::new()));

        assert_eq!(registry.len(), 9, "应有 9 个预编译电路");

        // 仅验证 name() + gas_cost()（完整模式 gas 值）
        assert_eq!(registry.get("poseidon").unwrap().gas_cost(), 12_800);
        assert_eq!(registry.get("sha256").unwrap().gas_cost(), 25_000);
        assert_eq!(registry.get("ecdsa_verify").unwrap().gas_cost(), 19_376_000);
        assert_eq!(registry.get("zk_shuffle").unwrap().gas_cost(), 3_540_000);
        assert_eq!(registry.get("keccak256").unwrap().gas_cost(), 240_000);
        assert_eq!(registry.get("modexp").unwrap().gas_cost(), 69_200);
        assert_eq!(registry.get("merkle_verify").unwrap().gas_cost(), 100);
        assert_eq!(registry.get("ed25519").unwrap().gas_cost(), 2_066_000);
        assert_eq!(registry.get("bn254_pairing").unwrap().gas_cost(), 80_000);
    }

    /// 验证 Poseidon/SHA-256/ECDSA 三个真实电路的 CCS 闭环（build → assign → satisfied）。
    #[test]
    fn test_phase10_real_circuits_ccs_closed_loop() {
        // Poseidon: x=3 → x5=243
        let poseidon = poseidon::PoseidonCircuit::new_mvp();
        let ccs = poseidon.build_ccs();
        let witness = poseidon
            .assign_witness(&[Fr::from_u32_with_wrap(3)])
            .expect("poseidon assign_witness");
        assert!(ccs.satisfied_by(&witness).expect("poseidon satisfied_by"));

        // SHA-256: x=1, y=1, z=0 → Ch=1
        let sha256 = sha256::Sha256Circuit::new_mvp();
        let ccs = sha256.build_ccs();
        let witness = sha256
            .assign_witness(&[
                Fr::from_u32_with_wrap(1),
                Fr::from_u32_with_wrap(1),
                Fr::from_u32_with_wrap(0),
            ])
            .expect("sha256 assign_witness");
        assert!(ccs.satisfied_by(&witness).expect("sha256 satisfied_by"));

        // ECDSA: bit=1, R=42, P=100 → R_new=142
        let ecdsa = ecdsa::EcdsaVerifyCircuit::new_mvp();
        let ccs = ecdsa.build_ccs();
        let witness = ecdsa
            .assign_witness(&[
                Fr::one(),
                Fr::from_u32_with_wrap(42),
                Fr::from_u32_with_wrap(100),
            ])
            .expect("ecdsa assign_witness");
        assert!(ccs.satisfied_by(&witness).expect("ecdsa satisfied_by"));
    }
}
