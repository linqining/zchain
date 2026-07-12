//! Phase L — 形式化验证属性测试套件（Task L-3）。
//!
//! 覆盖核心数学不变量：
//! - CCS satisfied_by 一致性（AddCircuit/MulCircuit/MulhCircuit + 篡改测试）
//! - LogUp 等式一致性（create → verify 闭环）
//! - 域算术属性（交换律/结合律/分配律/单位元/零元）
//! - SparseMatrix 运算属性（row-isolated evaluate）

use proptest::prelude::*;

use poker_zkvm::ccs::{Fr, SparseMatrix};
use poker_zkvm::constraints::algebra::{AddCircuit, MulCircuit, MulhCircuit};
use poker_zkvm::constraints::lookup::LogUpProof;
use poker_zkvm::field::ZkvmField;

// ===========================================================================
// L-3.1：CCS satisfied_by 一致性
// ===========================================================================

proptest! {
    /// 属性：满足 CCS 约束的 witness 必须通过 satisfied_by 检查（AddCircuit）。
    #[test]
    fn prop_ccs_satisfied_by_consistent(a: u32, b: u32) {
        let instance = AddCircuit::to_instance(a, b).expect("to_instance");
        prop_assert!(instance.ccs.satisfied_by(&instance.witness).expect("satisfied_by"));
    }

    /// 属性：篡改 witness 后 satisfied_by 必须失败（idx > 0）。
    #[test]
    fn prop_ccs_satisfied_by_tampered(a: u32, b: u32, tamper_idx: u8) {
        let instance = AddCircuit::to_instance(a, b).expect("to_instance");
        let mut witness = instance.witness.clone();
        let idx = (tamper_idx as usize) % witness.len();
        if idx == 0 {
            return Ok(());
        }
        witness[idx] = witness[idx].add(&Fr::one());
        let result = instance.ccs.satisfied_by(&witness).expect("satisfied_by");
        prop_assert!(!result, "篡改 witness[{}] 后应失败", idx);
    }

    /// 属性：MUL 子电路对任意 a,b 满足约束。
    #[test]
    fn prop_mul_circuit_satisfied(a: u32, b: u32) {
        let instance = MulCircuit::to_instance(a, b).expect("to_instance");
        prop_assert!(instance.ccs.satisfied_by(&instance.witness).expect("satisfied_by"));
    }

    /// 属性：MULH 子电路对任意 a,b 满足约束。
    #[test]
    fn prop_mulh_circuit_satisfied(a: u32, b: u32) {
        let instance = MulhCircuit::to_instance(a, b).expect("to_instance");
        prop_assert!(instance.ccs.satisfied_by(&instance.witness).expect("satisfied_by"));
    }
}

// ===========================================================================
// L-3.2：LogUp 等式一致性
// ===========================================================================

proptest! {
    /// 属性：LogUp create → verify 闭环对合法 table/witness 成功。
    ///
    /// 构造方式：table = [0, 1, 2, ...]，mult 为随机非负整数，
    /// witness = 按 mult 展开 table（保证 table.len() == mult.len() 硬约束）。
    #[test]
    fn prop_logup_create_verify_consistent(
        mult in prop::collection::vec(0u32..5, 1..10)
    ) {
        let table: Vec<u32> = (0..mult.len() as u32).collect();
        let table_fr: Vec<Fr> = table.iter().map(|&v| Fr::from_u32_with_wrap(v)).collect();
        let mult_fr: Vec<Fr> = mult.iter().map(|&v| Fr::from_u32_with_wrap(v)).collect();

        let mut witness_fr = Vec::new();
        for (t, &m) in table.iter().zip(mult.iter()) {
            for _ in 0..m {
                witness_fr.push(Fr::from_u32_with_wrap(*t));
            }
        }

        if witness_fr.is_empty() {
            return Ok(());
        }

        let (proof, commits) = LogUpProof::create(table_fr, witness_fr, mult_fr).expect("create");
        prop_assert!(proof.verify(&commits).expect("verify"));
        prop_assert!(proof.verify_equation().expect("verify_equation"));
    }
}

// ===========================================================================
// L-3.3：域算术属性
// ===========================================================================

proptest! {
    /// 属性：a + b = b + a（交换律，64-bit）。
    #[test]
    fn prop_field_add_commutative_u64(a: u64, b: u64) {
        let fa = Fr::from_u64(a);
        let fb = Fr::from_u64(b);
        prop_assert_eq!(fa.add(&fb), fb.add(&fa));
    }

    /// 属性：a * b = b * a（交换律，64-bit）。
    #[test]
    fn prop_field_mul_commutative_u64(a: u64, b: u64) {
        let fa = Fr::from_u64(a);
        let fb = Fr::from_u64(b);
        prop_assert_eq!(fa.mul(&fb), fb.mul(&fa));
    }

    /// 属性：(a + b) + c = a + (b + c)（结合律）。
    #[test]
    fn prop_field_add_associative(a: u32, b: u32, c: u32) {
        let fa = Fr::from_u32_with_wrap(a);
        let fb = Fr::from_u32_with_wrap(b);
        let fc = Fr::from_u32_with_wrap(c);
        prop_assert_eq!(fa.add(&fb).add(&fc), fa.add(&fb.add(&fc)));
    }

    /// 属性：a * (b + c) = a*b + a*c（分配律）。
    #[test]
    fn prop_field_distributive(a: u32, b: u32, c: u32) {
        let fa = Fr::from_u32_with_wrap(a);
        let fb = Fr::from_u32_with_wrap(b);
        let fc = Fr::from_u32_with_wrap(c);
        prop_assert_eq!(
            fa.mul(&fb.add(&fc)),
            fa.mul(&fb).add(&fa.mul(&fc))
        );
    }

    /// 属性：a - a = 0。
    #[test]
    fn prop_field_sub_self(a: u64) {
        let fa = Fr::from_u64(a);
        prop_assert!(fa.sub(&fa).is_zero());
    }

    /// 属性：a * 0 = 0。
    #[test]
    fn prop_field_mul_zero(a: u64) {
        let fa = Fr::from_u64(a);
        prop_assert!(fa.mul(&Fr::zero()).is_zero());
    }

    /// 属性：a * 1 = a。
    #[test]
    fn prop_field_mul_one(a: u64) {
        let fa = Fr::from_u64(a);
        prop_assert_eq!(fa.mul(&Fr::one()), fa);
    }
}

// ===========================================================================
// L-3.4：SparseMatrix 运算属性
// ===========================================================================

proptest! {
    /// 属性：SparseMatrix evaluate 在 row-isolated（单 entry）下仅 row 处非零。
    ///
    /// 构造一个 10×z_len 的稀疏矩阵，仅含单个 entry (row, col, val)，
    /// 验证 `evaluate(z)` 结果长度为 10，且仅 row 处等于 `val * z[col]`，其余为 0。
    #[test]
    fn prop_sparse_matrix_row_isolated_evaluate(
        row in 0u32..10,
        col in 0u32..5,
        val in 0u64..1000,
        z_len in 5usize..10
    ) {
        let mut m = SparseMatrix::new(10, z_len);
        m.add_entry(row as usize, col as usize, Fr::from_u64(val))
            .expect("add_entry");
        let z: Vec<Fr> = (0..z_len)
            .map(|i| Fr::from_u32_with_wrap(i as u32))
            .collect();
        let result = m.evaluate(&z).expect("evaluate");
        prop_assert_eq!(result.len(), 10);
        for (i, &v) in result.iter().enumerate() {
            if i == row as usize {
                prop_assert_eq!(v, Fr::from_u64(val).mul(&z[col as usize]));
            } else {
                prop_assert!(v.is_zero(), "row {} 应为 0", i);
            }
        }
    }
}
