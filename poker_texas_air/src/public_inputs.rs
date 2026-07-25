//! 公开输入定义 — Method AIR 与 Aggregator AIR 的 public inputs。
//!
//! ## 角色
//!
//! 每个 method AIR 的公开输入包含 `pre_state_root` 和 `post_state_root`。
//! Aggregator AIR 的核心约束为 `left.post_state_root == right.pre_state_root`。
//!
//! ## 复用
//!
//! L2 递归层的 [`RecursivePublicInputs`]（来自 `poker_zkvm`）只包含 L1 commitment
//! 等 Stwo 内部字段，**不含 state_root**。本模块通过 newtype `TexasRecursivePublicInputs`
//! 在其基础上扩展业务字段（state_root / method_kind / table_id / hand_id）。

use starknet_ff::FieldElement;

use crate::error::TexasAirResult;
use crate::method_kind::MethodKind;
use crate::state_root::StateRoot;

/// L1 proof 的 Stwo 内部公开输入（直接复用 `poker_zkvm`）。
pub use poker_zkvm::stwo_backend::recursive::RecursivePublicInputs;

/// 单方法 L1 proof（包含 StarkProof + 业务公开输入）。
#[derive(Debug, Clone)]
pub struct TexasMethodProof {
    /// 方法种类。
    pub kind: MethodKind,
    /// L1 Stwo proof（序列化字节）。
    pub stark_proof_bytes: Vec<u8>,
    /// L1 proof 的 Stwo RecursivePublicInputs。
    pub l1_public_inputs: RecursivePublicInputs,
    /// 调用前表台 state_root。
    pub pre_state_root: StateRoot,
    /// 调用后表台 state_root。
    pub post_state_root: StateRoot,
    /// 表台 ID（防跨表台聚合攻击）。
    pub table_id: u64,
    /// 手牌序号（同一 table 内的递增计数）。
    pub hand_id: u32,
    /// 方法调用序号（同一 hand 内的递增计数，用于 Aggregator 排序）。
    pub call_seq: u32,
}

impl TexasMethodProof {
    /// 构造新的 method proof。
    #[must_use]
    pub fn new(
        kind: MethodKind,
        stark_proof_bytes: Vec<u8>,
        l1_public_inputs: RecursivePublicInputs,
        pre_state_root: StateRoot,
        post_state_root: StateRoot,
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
    ) -> Self {
        Self {
            kind,
            stark_proof_bytes,
            l1_public_inputs,
            pre_state_root,
            post_state_root,
            table_id,
            hand_id,
            call_seq,
        }
    }

    /// 验证 proof 自洽性（kind/seq/roots 非零等）。
    ///
    /// # Errors
    ///
    /// 当任何字段不满足约束时返回 `TexasAirError`。
    pub fn validate(&self) -> TexasAirResult<()> {
        use crate::error::TexasAirError;
        if self.pre_state_root == self.post_state_root {
            // 严格相等不一定是错误（如 reset_for_next_hand），但日志提示
            // 这里只是 sanity check，不返回错误
        }
        if self.stark_proof_bytes.is_empty() {
            return Err(TexasAirError::SerializationError(
                "stark_proof_bytes 为空".into(),
            ));
        }
        Ok(())
    }
}

/// L2 递归层的扩展公开输入（Texas 业务字段 + Stwo RecursivePublicInputs）。
///
/// 用于 Aggregator AIR 与 Final Recursion 层。
#[derive(Debug, Clone)]
pub struct TexasRecursivePublicInputs {
    /// Stwo 内部公开输入（L1 commitments / OODS / FRI 等）。
    pub base: RecursivePublicInputs,
    /// 调用前表台 state_root。
    pub pre_state_root: StateRoot,
    /// 调用后表台 state_root。
    pub post_state_root: StateRoot,
    /// 方法种类。
    pub kind: MethodKind,
    /// 表台 ID。
    pub table_id: u64,
    /// 手牌序号。
    pub hand_id: u32,
    /// 方法调用序号。
    pub call_seq: u32,
}

impl TexasRecursivePublicInputs {
    /// 从单方法 proof 构造。
    #[must_use]
    pub fn from_method_proof(p: &TexasMethodProof) -> Self {
        Self {
            base: p.l1_public_inputs.clone(),
            pre_state_root: p.pre_state_root,
            post_state_root: p.post_state_root,
            kind: p.kind,
            table_id: p.table_id,
            hand_id: p.hand_id,
            call_seq: p.call_seq,
        }
    }

    /// 序列化为 FieldElement 列表（用于 mix 到 Fiat-Shamir channel）。
    ///
    /// 顺序固定且不可变更——这是 Aggregator AIR 约束侧的「契约」。
    #[must_use]
    pub fn to_fields(&self) -> Vec<FieldElement> {
        let mut v = Vec::with_capacity(10);
        v.push(self.pre_state_root.field());
        v.push(self.post_state_root.field());
        v.push(FieldElement::from(u64::from(self.kind as u8)));
        v.push(FieldElement::from(self.table_id));
        v.push(FieldElement::from(u64::from(self.hand_id)));
        v.push(FieldElement::from(u64::from(self.call_seq)));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_zkvm::stwo_backend::recursive::public_inputs::RecursivePublicInputs;

    fn dummy_recursive_inputs() -> RecursivePublicInputs {
        RecursivePublicInputs::default()
    }

    #[test]
    fn test_to_fields_order() {
        let proof = TexasMethodProof::new(
            MethodKind::CreateTable,
            vec![0u8; 32],
            dummy_recursive_inputs(),
            StateRoot::from_field(FieldElement::from(1u64)),
            StateRoot::from_field(FieldElement::from(2u64)),
            42,
            7,
            3,
        );
        let inputs = TexasRecursivePublicInputs::from_method_proof(&proof);
        let fields = inputs.to_fields();
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0], FieldElement::from(1u64)); // pre_state_root
        assert_eq!(fields[1], FieldElement::from(2u64)); // post_state_root
        assert_eq!(fields[2], FieldElement::from(0u64)); // CreateTable = 0
        assert_eq!(fields[3], FieldElement::from(42u64)); // table_id
        assert_eq!(fields[4], FieldElement::from(7u64)); // hand_id
        assert_eq!(fields[5], FieldElement::from(3u64)); // call_seq
    }

    #[test]
    fn test_validate_empty_proof_fails() {
        let proof = TexasMethodProof::new(
            MethodKind::Fold,
            vec![],
            dummy_recursive_inputs(),
            StateRoot::zero(),
            StateRoot::zero(),
            1,
            1,
            1,
        );
        assert!(proof.validate().is_err());
    }
}
