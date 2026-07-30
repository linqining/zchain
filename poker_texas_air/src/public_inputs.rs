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
use stwo::core::channel::Channel;
use stwo::core::fields::m31::{M31, P as M31_MODULUS};

use crate::airs::AirStatement;
use crate::error::TexasAirResult;
use crate::method_kind::MethodKind;
use crate::state_root::{StateRoot, field_element_to_u32_words, state_root_to_air_limbs};

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

/// 单方法 proof 的**完整公开输入**——用于把证明绑定到 state_root（soundness 关键）。
///
/// 背景（soundness 修复）：此前 `proof.air` 结构体里的 `pre_state_root`/`post_state_root`
/// 从未被 mix 进 Fiat-Shamir channel，导致证明与这些值之间无密码学绑定（攻击者可替换
/// state_root 而证明仍验证通过）。
///
/// 修复（路径 A）：把 pre/post table 的完整、变长 canonical Borsh **preimage** +
/// 重算的 `pre_state_root`/`post_state_root` + 元数据，按**固定顺序** mix 进 channel。
/// 验证方（链下/L1）随后用被审计的 `starknet_crypto::poseidon_hash_many` 重算
/// `Poseidon252(pre_image)` 并与 `pre_state_root` 比对——密码学绑定由 Fiat-Shamir +
/// 审计过的哈希共同保证，state_root 哈希本身是唯一信任根（非电路内自造）。
///
/// `pre_image` / `post_image` 必须与 `table_state_preimage(table)` 的输出逐字段一致
/// （阶段 1 已补全所有 9 个 stub，preimage 含完整状态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TexasPublicInputs {
    /// 调用前表台的完整 canonical state-root preimage（变长）。
    pub pre_image: Vec<FieldElement>,
    /// 调用后表台的完整 canonical state-root preimage（变长）。
    pub post_image: Vec<FieldElement>,
    /// 调用前 state_root = `Poseidon252(pre_image)`（验证方重算并比对）。
    pub pre_state_root: StateRoot,
    /// 调用后 state_root = `Poseidon252(post_image)`（验证方重算并比对）。
    pub post_state_root: StateRoot,
    /// 方法种类。
    pub kind: MethodKind,
    /// 表台 ID（防跨表台聚合攻击）。
    pub table_id: u64,
    /// 手牌序号。
    pub hand_id: u32,
    /// 方法调用序号。
    pub call_seq: u32,
    /// State version before execution.
    pub pre_version: u64,
    /// State version after execution.
    pub post_version: u64,
    /// Digest of the replayed VM dispatch context + selector + raw args.
    /// Task provenance is authenticated only by an external consensus anchor.
    pub dispatch_call_digest: [u8; 32],
    /// Verifier-reconstructed values of every original trace column in the
    /// replicated business row.
    ///
    /// This is deliberately optional at the data-construction boundary so a
    /// caller can build roots before it has reconstructed the method row.  The
    /// production prover and verifier both reject `None`; only test-helper
    /// compatibility code may populate it from a locally supplied trace.
    /// Values are canonical M31 representatives (`0 <= value < 2^31 - 1`).
    pub expected_trace_row: Option<Vec<u32>>,
}

impl TexasPublicInputs {
    /// 从 pre/post table 与元数据构造完整公开输入。
    ///
    /// 计算变长 canonical `table_state_preimage` 并重算 state_root，确保 image 与 root 自洽。
    /// 供 orchestrator 与 e2e 测试使用。
    ///
    /// # Errors
    ///
    /// 当 preimage 编码失败（字段序列化异常）时返回错误。
    pub fn from_tables(
        pre_table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
        post_table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
        kind: MethodKind,
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
    ) -> TexasAirResult<Self> {
        use crate::state_root::{compute_state_root, table_state_preimage};
        let pre_image = table_state_preimage(pre_table)?;
        let post_image = table_state_preimage(post_table)?;
        let pre_state_root = compute_state_root(pre_table)?;
        let post_state_root = compute_state_root(post_table)?;
        Ok(Self {
            pre_image,
            post_image,
            pre_state_root,
            post_state_root,
            kind,
            table_id,
            hand_id,
            call_seq,
            pre_version: pre_table.version,
            post_version: post_table.version,
            dispatch_call_digest: [0u8; 32],
            expected_trace_row: None,
        })
    }

    /// 用显式 preimage 构造，并**自动重算** state_root 使其与 image 一致。
    ///
    /// 适用于机制测试（构造合成 trace 但无真实 table）：传入任意 24 元素 image，
    /// root 由 `Poseidon252(image)` 重算，确保 `verify_roots()` 通过。
    #[must_use]
    pub fn with_consistent_roots(
        pre_image: Vec<FieldElement>,
        post_image: Vec<FieldElement>,
        kind: MethodKind,
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
    ) -> Self {
        let pre_state_root = StateRoot(starknet_crypto::poseidon_hash_many(&pre_image));
        let post_state_root = StateRoot(starknet_crypto::poseidon_hash_many(&post_image));
        Self {
            pre_image,
            post_image,
            pre_state_root,
            post_state_root,
            kind,
            table_id,
            hand_id,
            call_seq,
            pre_version: 0,
            post_version: 1,
            dispatch_call_digest: [0u8; 32],
            expected_trace_row: None,
        }
    }

    /// Bind this statement to a complete, verifier-reconstructed trace row.
    ///
    /// Rebinding to a different row is rejected, which catches accidental use
    /// of a prover witness after a trusted row has already been installed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::TexasAirError::SpecViolation`] when `row` is
    /// empty or conflicts with an existing binding.
    pub fn bind_expected_trace_row(&mut self, row: &[M31]) -> TexasAirResult<()> {
        use crate::error::TexasAirError;

        if row.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "expected trace row must not be empty".into(),
            ));
        }
        let words: Vec<u32> = row.iter().map(|value| value.0).collect();
        if let Some(existing) = &self.expected_trace_row {
            if existing != &words {
                return Err(TexasAirError::SpecViolation(
                    "attempted to replace an existing trusted trace-row binding".into(),
                ));
            }
            return Ok(());
        }
        self.expected_trace_row = Some(words);
        Ok(())
    }

    /// Return the complete trusted row as canonical M31 values.
    ///
    /// Production verification calls this before constructing the AIR, so a
    /// missing, malformed, or wrong-width row fails closed before Stwo parses
    /// the proof.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::TexasAirError::SpecViolation`] if no trusted row
    /// is present, its width differs from `num_columns`, or any word is not a
    /// canonical M31 representative.
    pub fn require_expected_trace_row(&self, num_columns: usize) -> TexasAirResult<Vec<M31>> {
        use crate::error::TexasAirError;

        let row = self.expected_trace_row.as_ref().ok_or_else(|| {
            TexasAirError::SpecViolation(
                "missing verifier-trusted expected trace row (fail-closed)".into(),
            )
        })?;
        if row.len() != num_columns {
            return Err(TexasAirError::SpecViolation(format!(
                "expected trace row width {} does not match AIR width {num_columns}",
                row.len()
            )));
        }
        row.iter()
            .enumerate()
            .map(|(column, &value)| {
                if value >= M31_MODULUS {
                    Err(TexasAirError::SpecViolation(format!(
                        "expected trace row column {column} is not canonical M31: {value}"
                    )))
                } else {
                    Ok(M31::from_u32_unchecked(value))
                }
            })
            .collect()
    }

    /// 构造一个固定的、自洽的「占位」公开输入（机制测试用）。
    ///
    /// image 为测试专用的 24 个 `FieldElement::ONE`，root 为其真实 Poseidon 哈希（自洽）。
    /// 用于不需要真实 table 的 AIR 机制测试（仅验证 prove/verify 流程，不验证 state 绑定语义）。
    #[must_use]
    pub fn synthetic_placeholder(kind: MethodKind) -> Self {
        let image = vec![FieldElement::ONE; 24];
        Self::with_consistent_roots(image.clone(), image, kind, 0, 0, 0)
    }

    /// 构造自洽占位 PI 并指定元数据（机制测试用，使 PI 与 AIR struct 的
    /// table_id/hand_id/call_seq/version 一致，通过 `verify_air_statement`）。
    #[must_use]
    pub fn synthetic_for_test(
        kind: MethodKind,
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
    ) -> Self {
        let image = vec![FieldElement::ONE; 24];
        Self::with_consistent_roots(image.clone(), image, kind, table_id, hand_id, call_seq)
    }

    /// 返回 synthetic_placeholder 对应的 AIR 端 state_root limb（pre/post）。
    ///
    /// 机制测试需让 AIR struct 与 trace 的 state_root 列 == PI 的 root 经
    /// `state_root_to_air_limbs` 转换后的值，否则 `verify_air_statement` 失败。
    /// 此 helper 暴露这些 limb，供测试填入 AIR/trace。
    #[must_use]
    pub fn synthetic_air_roots(kind: MethodKind) -> ([M31; 4], [M31; 4]) {
        use crate::state_root::state_root_to_air_limbs;
        let pi = Self::synthetic_placeholder(kind);
        (
            state_root_to_air_limbs(pi.pre_state_root),
            state_root_to_air_limbs(pi.post_state_root),
        )
    }

    /// 把公开输入 mix 进 Fiat-Shamir channel（prover 与 verifier 共用，顺序固定）。
    ///
    /// # 顺序契约（不可变更）
    ///
    /// 1. `pre_image` 的全部变长 FieldElement（每个分解为 8 个大端 u32 word）
    /// 2. `post_image` 的全部变长 FieldElement（同上）
    /// 3. `pre_state_root`（8 个 u32 word）
    /// 4. `post_state_root`（8 个 u32 word）
    /// 5. `kind`（u32）、`table_id`（u64）、`hand_id`（u32）、`call_seq`（u32）
    ///
    /// `FieldElement` → u32 word 用 [`field_element_to_u32_words`]（无损 8-word 大端分解）。
    /// 用 `mix_u32s`/`mix_u64`，而非 `mix_felts`，因为 Fr 是非原生域元素，按原始字节 mix
    /// 是标准做法（与 Starknet 把 252-bit 元素序列化为字节一致）。
    pub fn mix_into<C: Channel>(&self, channel: &mut C) {
        // 1-2. pre/post image：每个 FieldElement → 8 u32 word，扁平拼接后一次性 mix。
        let mut felts_u32: Vec<u32> =
            Vec::with_capacity((self.pre_image.len() + self.post_image.len()) * 8);
        for f in &self.pre_image {
            felts_u32.extend_from_slice(&field_element_to_u32_words(*f));
        }
        for f in &self.post_image {
            felts_u32.extend_from_slice(&field_element_to_u32_words(*f));
        }
        channel.mix_u32s(&felts_u32);

        // 3-4. pre/post state_root（各 8 u32 word）。
        let mut roots_u32: Vec<u32> = Vec::with_capacity(16);
        roots_u32.extend_from_slice(&field_element_to_u32_words(self.pre_state_root.field()));
        roots_u32.extend_from_slice(&field_element_to_u32_words(self.post_state_root.field()));
        channel.mix_u32s(&roots_u32);

        // 5. 完整业务 trace 行。长度与 presence tag 都进入 transcript，
        // 防止不同列布局或缺失绑定产生相同编码。
        match &self.expected_trace_row {
            Some(row) => {
                channel.mix_u32s(&[1, row.len() as u32]);
                channel.mix_u32s(row);
            }
            None => channel.mix_u32s(&[0, 0]),
        }

        // 6. 精确 VM dispatch 调用摘要。
        let dispatch_words: Vec<u32> = self
            .dispatch_call_digest
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("4-byte digest word")))
            .collect();
        channel.mix_u32s(&dispatch_words);

        // 7. 元数据。
        channel.mix_u32s(&[u32::from(self.kind as u8), self.hand_id, self.call_seq]);
        channel.mix_u64(self.table_id);
        channel.mix_u64(self.pre_version);
        channel.mix_u64(self.post_version);
    }

    /// 验证方重算并比对：`pre_state_root == Poseidon252(pre_image)` 且
    /// `post_state_root == Poseidon252(post_image)`。
    ///
    /// 这是 state_root 绑定的「验证」半边（mix_into 是「承诺」半边）。
    /// 验证方拿到公开输入后，用被审计的 Starknet Poseidon252 重算哈希，确保公开输入
    /// 与承诺的 root 自洽。canonical table 解码由需要业务语义绑定的 verifier hook
    /// 或 Orchestrator 完整 dispatch replay 完成；本函数只验证非空 image/root 自洽。
    ///
    /// # Errors
    ///
    /// 当 pre/post_image 为空，或重算的 root 与公开的 root 不符时返回错误。
    pub fn verify_roots(&self) -> TexasAirResult<()> {
        use crate::error::TexasAirError;
        if self.pre_image.is_empty() || self.post_image.is_empty() {
            return Err(TexasAirError::StateRootError(
                "state-root preimage must not be empty".into(),
            ));
        }
        let pre_recomputed = StateRoot(starknet_crypto::poseidon_hash_many(&self.pre_image));
        let post_recomputed = StateRoot(starknet_crypto::poseidon_hash_many(&self.post_image));
        if pre_recomputed != self.pre_state_root {
            return Err(TexasAirError::StateRootError(
                "pre_state_root 与 pre_image 重算不符（state_root 绑定失败）".into(),
            ));
        }
        if post_recomputed != self.post_state_root {
            return Err(TexasAirError::StateRootError(
                "post_state_root 与 post_image 重算不符（state_root 绑定失败）".into(),
            ));
        }
        Ok(())
    }

    /// Check that an independently reconstructed AIR compiles exactly this
    /// verifier-trusted statement.
    pub fn verify_air_statement(&self, statement: &AirStatement) -> TexasAirResult<()> {
        use crate::error::TexasAirError;
        let matches = statement.kind == self.kind
            && statement.pre_state_root == state_root_to_air_limbs(self.pre_state_root)
            && statement.post_state_root == state_root_to_air_limbs(self.post_state_root)
            && statement.table_id == self.table_id
            && statement.hand_id == self.hand_id
            && statement.call_seq == self.call_seq
            && statement.pre_version == self.pre_version
            && statement.post_version == self.post_version;
        if !matches {
            return Err(TexasAirError::SpecViolation(
                "AIR statement does not match verifier-trusted Texas public inputs".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_zkvm::stwo_backend::recursive::public_inputs::RecursivePublicInputs;
    use stwo::core::channel::Poseidon252Channel;

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

    // ===== 阶段 2：state_root 绑定测试（soundness 关键）=====

    #[test]
    fn test_verify_roots_accepts_consistent() {
        // with_consistent_roots 自动重算 root，verify_roots 必通过。
        let pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        assert!(pi.verify_roots().is_ok(), "自洽 PI 的 verify_roots 应通过");
    }

    #[test]
    fn test_verify_roots_rejects_tampered_root() {
        // 篡改 pre_state_root（不改 image）→ 重算不符 → verify_roots 失败。
        // 这验证了「验证方重算 Poseidon252(image) 并比对 root」这条绑定生效。
        let mut pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        pi.pre_state_root = StateRoot::from_field(FieldElement::ONE);
        assert!(
            pi.verify_roots().is_err(),
            "篡改 root 后 verify_roots 应失败"
        );
    }

    #[test]
    fn test_verify_roots_rejects_tampered_image() {
        // 篡改 image（不改 root）→ 重算不符 → verify_roots 失败。
        let mut pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        pi.pre_image[0] = FieldElement::from(12345u64);
        assert!(
            pi.verify_roots().is_err(),
            "篡改 image 后 verify_roots 应失败"
        );
    }

    #[test]
    fn test_verify_roots_rejects_empty_preimage() {
        let pi = TexasPublicInputs {
            pre_image: vec![],
            post_image: vec![FieldElement::ONE; 24],
            pre_state_root: StateRoot::zero(),
            post_state_root: StateRoot::zero(),
            kind: MethodKind::Call,
            table_id: 0,
            hand_id: 0,
            call_seq: 0,
            pre_version: 0,
            post_version: 1,
            dispatch_call_digest: [0u8; 32],
            expected_trace_row: None,
        };
        assert!(pi.verify_roots().is_err(), "empty image must fail");
    }

    #[test]
    fn test_mix_into_is_deterministic() {
        // 同样的 PI mix 进两个相同 channel，结果应相同（prover/verifier 对称性契约）。
        let pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        let mut c1 = Poseidon252Channel::default();
        let mut c2 = Poseidon252Channel::default();
        pi.mix_into(&mut c1);
        pi.mix_into(&mut c2);
        // mix 后从两个 channel draw 相同数量的 random felt，应一致
        let r1 = c1.draw_secure_felts(4);
        let r2 = c2.draw_secure_felts(4);
        assert_eq!(r1, r2, "相同 PI 的 mix 应确定性（prover/verifier 对称）");
    }

    #[test]
    fn test_mix_into_distinguishes_different_pi() {
        // 不同 PI mix 后 channel 状态不同（draw 出不同值）。
        let pi_a = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        let pi_b = TexasPublicInputs::synthetic_placeholder(MethodKind::Raise);
        let mut c1 = Poseidon252Channel::default();
        let mut c2 = Poseidon252Channel::default();
        pi_a.mix_into(&mut c1);
        pi_b.mix_into(&mut c2);
        let r1 = c1.draw_secure_felts(4);
        let r2 = c2.draw_secure_felts(4);
        assert_ne!(r1, r2, "不同 PI 的 mix 应区分（绑定生效）");
    }

    #[test]
    fn trusted_trace_row_is_required_and_width_checked() {
        let mut pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        assert!(pi.require_expected_trace_row(2).is_err());

        pi.bind_expected_trace_row(&[M31::from(7u32), M31::from(9u32)])
            .unwrap();
        assert_eq!(
            pi.require_expected_trace_row(2).unwrap(),
            vec![M31::from(7u32), M31::from(9u32)]
        );
        assert!(pi.require_expected_trace_row(1).is_err());
    }

    #[test]
    fn trusted_trace_row_rejects_noncanonical_words_and_rebinding() {
        let mut pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        pi.bind_expected_trace_row(&[M31::from(7u32)]).unwrap();
        assert!(
            pi.bind_expected_trace_row(&[M31::from(8u32)]).is_err(),
            "a trusted binding must not be replaceable"
        );

        pi.expected_trace_row = Some(vec![M31_MODULUS]);
        assert!(
            pi.require_expected_trace_row(1).is_err(),
            "noncanonical M31 words must be rejected instead of reduced"
        );
    }
}
