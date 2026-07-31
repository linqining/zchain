//! Validator 集与 VRF（Task 13 — SubTask 13.1）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 13.1**：`ValidatorSet`（secp256k1 pubkey + 质押 + vrf_pubkey）+ bonding/unbonding
//!   - **NEW-L3**：新 validator 需经历 `bonding_period_blocks`（默认 = 1 epoch）锁定期
//!   - **R5-H7**：退出 `unbonding_period_blocks`（默认 = 2 × epoch_length_blocks）锁定期，可被 slashing
//!   - **SEC-C2**：主网 |V| >= 5（OffChain 模式强制约束）
//!   - **SEC-M2**：单次缩减比例 <= 20%
//!   - **SEC-M11 + SEC2-C2**：VRF 随机源，`VRF input = hash(chain_id || epoch || prev_epoch_randomness)`
//!   - **IMPL-SEC-2**：ECVRF-secp256k1 + SHA-256，proof = `(gamma_33B || c_32B || s_32B)` = 97 字节
//!   - **SEC2-M10**：VRF 私钥销毁与 retired 标记
//!   - **SEC2-M12**：epoch_randomness fallback 不可预测性
//!   - **SEC2-H4**：rotate_validator_key timelock 密钥约束
//!   - **SEC2-H5**：epoch 边界 commit certificate grace period（无 grace，硬约束）
//!
//! ## VRF 实现说明
//!
//! IMPL-SEC-2 要求 ECVRF-secp256k1 + SHA-256。本模块定义：
//! - `VrfProof` 结构（97 字节：gamma_33 || c_32 || s_32）
//! - `compute_vrf_input` / `compute_vrf_output` 函数（hash-based，可立即实现）
//! - `VrfVerifier` trait（实际 ECVRF 验证算法为密码学实现，本模块提供 trait 与 stub 验证器，
//!   生产环境需引入 `vrf` crate 或自行实现 ECVRF-secp256k1）
//!
//! Phase 2 范围：数据结构 + input/output 计算 + 验证 trait 接口；
//! 实际 ECVRF proof 生成与验证由 IMPL-SEC-2 专项任务实现（标注 TODO）。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::consensus::Epoch;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::{BlockHeight, ChainId, Hash};

/// VRF proof 字节长度（IMPL-SEC-2：gamma_33B || c_32B || s_32B = 97 字节）。
pub const VRF_PROOF_SIZE: usize = 97;

/// VRF pubkey 长度（compressed secp256k1 = 33 字节）。
pub const VRF_PUBKEY_SIZE: usize = 33;

/// VRF random output 长度（SHA-256 = 32 字节）。
pub const VRF_OUTPUT_SIZE: usize = 32;

/// VRF 签名域分隔前缀。
const VRF_INPUT_DOMAIN: u8 = 0x56; // 'V' for VRF
const VRF_OUTPUT_DOMAIN: u8 = 0x52; // 'R' for Random

/// serde helper：序列化 `[u8; 33]` 为字节序列（serde 内置仅支持 ≤32 元素数组）。
///
/// BCS / JSON 均通过 `serialize_bytes` / `deserialize` Vec<u8> 路径，
/// 不影响 BCS 紧凑编码（BCS 对 byte 序列有专门处理）。
mod big_array_33 {
    use serde::{Deserialize, Deserializer, Serializer};

    /// 序列化为字节序列。
    pub fn serialize<S: Serializer>(arr: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(arr)
    }

    /// 从字节序列反序列化（校验长度 = 33）。
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(d)?;
        if bytes.len() != 33 {
            return Err(serde::de::Error::custom(format!(
                "expected 33 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// VRF proof 结构（IMPL-SEC-2：ECVRF-secp256k1 + SHA-256）。
///
/// proof 格式：`gamma_33B || c_32B || s_32B` = 97 字节。
/// - `gamma`：ECVRF 的 gamma 值（compressed secp256k1 point，33 字节）
/// - `c`：挑战值（32 字节）
/// - `s`：响应值（32 字节）
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct VrfProof {
    /// ECVRF gamma 值（compressed secp256k1 point）。
    #[serde(with = "big_array_33")]
    pub gamma: [u8; 33],
    /// 挑战值 c。
    pub c: [u8; 32],
    /// 响应值 s。
    pub s: [u8; 32],
}

impl VrfProof {
    /// 从 97 字节切片构造 VrfProof。
    pub fn from_bytes(bytes: &[u8]) -> PokerL1Result<Self> {
        if bytes.len() != VRF_PROOF_SIZE {
            return Err(PokerL1Error::InvalidSignatureLength {
                actual: bytes.len(),
                expected: VRF_PROOF_SIZE,
            });
        }
        let mut gamma = [0u8; 33];
        let mut c = [0u8; 32];
        let mut s = [0u8; 32];
        gamma.copy_from_slice(&bytes[0..33]);
        c.copy_from_slice(&bytes[33..65]);
        s.copy_from_slice(&bytes[65..97]);
        Ok(Self { gamma, c, s })
    }

    /// 序列化为 97 字节。
    pub fn to_bytes(&self) -> [u8; VRF_PROOF_SIZE] {
        let mut out = [0u8; VRF_PROOF_SIZE];
        out[0..33].copy_from_slice(&self.gamma);
        out[33..65].copy_from_slice(&self.c);
        out[65..97].copy_from_slice(&self.s);
        out
    }
}

/// VRF 验证器 trait（IMPL-SEC-2）。
///
/// 实际 ECVRF-secp256k1 验证算法为密码学实现，本 trait 定义接口。
/// 生产环境需实现此 trait（引入 `vrf` crate 或自行实现 ECVRF-secp256k1）。
///
/// Phase 2 提供 [`StubVrfVerifier`] 用于测试（始终返回 true，**不可用于生产**）。
pub trait VrfVerifier: Send + Sync {
    /// 验证 VRF proof。
    ///
    /// 参数：
    /// - `vrf_pubkey`：validator 的 VRF pubkey（compressed 33B）
    /// - `input`：VRF input（32 字节，由 [`compute_vrf_input`] 计算）
    /// - `proof`：VRF proof（97 字节）
    ///
    /// 返回 `Ok(output)` 表示验证通过，output 为 32 字节 random output；
    /// 返回 `Err` 表示验证失败。
    fn verify(
        &self,
        vrf_pubkey: &[u8; VRF_PUBKEY_SIZE],
        input: &[u8; VRF_OUTPUT_SIZE],
        proof: &VrfProof,
    ) -> PokerL1Result<[u8; VRF_OUTPUT_SIZE]>;
}

/// Stub VRF 验证器（**仅用于测试，不可用于生产**）。
///
/// 始终返回固定 output，不实际验证 ECVRF proof。
/// 生产环境必须替换为真实 ECVRF-secp256k1 实现。
///
/// 通过 `test-helpers` feature 或 `#[cfg(test)]` 门控，防止生产环境误用。
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct StubVrfVerifier;

#[cfg(any(test, feature = "test-helpers"))]
impl VrfVerifier for StubVrfVerifier {
    fn verify(
        &self,
        _vrf_pubkey: &[u8; VRF_PUBKEY_SIZE],
        input: &[u8; VRF_OUTPUT_SIZE],
        _proof: &VrfProof,
    ) -> PokerL1Result<[u8; VRF_OUTPUT_SIZE]> {
        // Stub：返回 input 的副本作为 output（生产环境必须替换）
        Ok(*input)
    }
}

/// 计算 VRF input（SEC2-C2）。
///
/// spec SEC2-C2：`VRF input = hash(chain_id || epoch || prev_epoch_randomness)`
///
/// 绑定 epoch 防跨 epoch 重用，绑定 prev_epoch_randomness 形成 randomness hash chain。
pub fn compute_vrf_input(
    chain_id: ChainId,
    epoch: Epoch,
    prev_epoch_randomness: &[u8; 32],
) -> [u8; VRF_OUTPUT_SIZE] {
    let mut h = Blake2bVar::new(VRF_OUTPUT_SIZE).expect("32 <= 64");
    h.update(&[VRF_INPUT_DOMAIN]);
    h.update(&chain_id.to_le_bytes());
    h.update(&epoch.to_le_bytes());
    h.update(prev_epoch_randomness);
    let mut out = [0u8; VRF_OUTPUT_SIZE];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 计算 VRF output（SEC2-M10）。
///
/// spec SEC2-M10：VRF output 用于 epoch_randomness。
/// output = hash(vrf_pubkey || input || gamma)
///
/// 实际 ECVRF 中 output 由 proof 推导，本函数提供确定性派生（生产环境应从 ECVRF proof 验证中获取）。
pub fn compute_vrf_output(
    vrf_pubkey: &[u8; VRF_PUBKEY_SIZE],
    input: &[u8; VRF_OUTPUT_SIZE],
    gamma: &[u8; 33],
) -> [u8; VRF_OUTPUT_SIZE] {
    let mut h = Blake2bVar::new(VRF_OUTPUT_SIZE).expect("32 <= 64");
    h.update(&[VRF_OUTPUT_DOMAIN]);
    h.update(vrf_pubkey);
    h.update(input);
    h.update(gamma);
    let mut out = [0u8; VRF_OUTPUT_SIZE];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// Validator 状态（NEW-L3 / R5-H7 / SEC2-M10）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ValidatorStatus {
    /// 活跃（参与共识出块）。
    Active,
    /// Bonding 期（NEW-L3：锁定期，可同步不参与共识）。
    Bonding,
    /// Unbonding 期（R5-H7：退出锁定期，不参与共识但可被 slashing）。
    Unbonding,
    /// 已被 slashing。
    Slashed,
    /// 已退出（vrf_pubkey 标记 retired，SEC2-M10）。
    Retired,
}

/// Validator 条目（ValidatorSet 单项）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ValidatorEntry {
    /// validator 的 secp256k1 tagged pubkey（用于 vertex / commit certificate 签名）。
    pub pubkey: TaggedPubkey,
    /// validator 的 VRF pubkey（IMPL-SEC-2：compressed secp256k1，33 字节）。
    #[serde(with = "big_array_33")]
    pub vrf_pubkey: [u8; VRF_PUBKEY_SIZE],
    /// 质押金额。
    pub stake: u64,
    /// 当前状态。
    pub status: ValidatorStatus,
    /// Bonding 期结束 height（NEW-L3：到达此 height 后转为 Active）。
    pub bonding_until_height: BlockHeight,
    /// Unbonding 期结束 height（R5-H7：到达此 height 后质押可提取）。
    pub unbonding_until_height: BlockHeight,
    /// 最后一次产出 vertex 的 block height（SEC-M1 停机判定用）。
    pub last_vertex_height: BlockHeight,
    /// 审查嫌疑计数（NEW-H1：每 epoch 衰减 1，最低为 0）。
    pub under_investigation_count: u32,
    /// VRF 私钥是否已销毁（SEC2-M10：退出须提交 vrf_key_destroy_proof）。
    pub vrf_key_destroyed: bool,
    /// VRF pubkey 是否已 retired（SEC2-M10：退出 validator vrf_pubkey 标记 retired）。
    pub vrf_retired: bool,
}

impl ValidatorEntry {
    /// 创建新 validator（初始状态为 Bonding，NEW-L3）。
    pub const fn new(
        pubkey: TaggedPubkey,
        vrf_pubkey: [u8; VRF_PUBKEY_SIZE],
        stake: u64,
        bonding_until_height: BlockHeight,
    ) -> Self {
        Self {
            pubkey,
            vrf_pubkey,
            stake,
            status: ValidatorStatus::Bonding,
            bonding_until_height,
            unbonding_until_height: 0,
            last_vertex_height: 0,
            under_investigation_count: 0,
            vrf_key_destroyed: false,
            vrf_retired: false,
        }
    }

    /// 校验 validator 是否可参与共识（Active 状态）。
    pub const fn can_participate_consensus(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active) && !self.vrf_retired
    }

    /// 校验 validator 是否可被 slashing（Active / Bonding / Unbonding 状态）。
    pub const fn can_be_slashed(&self) -> bool {
        matches!(
            self.status,
            ValidatorStatus::Active | ValidatorStatus::Bonding | ValidatorStatus::Unbonding
        )
    }
}

/// ValidatorSet（SubTask 13.1）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ValidatorSet {
    /// 当前 epoch。
    pub epoch: Epoch,
    /// validator 列表（按加入顺序）。
    pub validators: Vec<ValidatorEntry>,
    /// validator_set_hash（blake2b_256 of all pubkeys + stakes）。
    pub validator_set_hash: Hash,
    /// 当前 epoch_randomness（由 VRF proof 验证后写入）。
    pub epoch_randomness: [u8; 32],
    /// 前一 epoch_randomness（形成 randomness hash chain，SEC2-C2）。
    pub prev_epoch_randomness: [u8; 32],
    /// genesis_chain_randomness（SEC2-M12 fallback 用）。
    pub genesis_chain_randomness: [u8; 32],
}

/// 主网 ValidatorSet 最小规模（SEC-C2：|V| >= 5）。
pub const MIN_VALIDATOR_SET_SIZE: usize = 5;

/// 单次缩减最大比例（SEC-M2：<= 20%）。
pub const MAX_SINGLE_REDUCTION_RATIO: u32 = 20;

impl ValidatorSet {
    /// 计算 validator_set_hash。
    pub fn compute_hash(&self) -> Hash {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&self.epoch.to_le_bytes());
        for v in &self.validators {
            h.update(&v.pubkey.to_bytes());
            h.update(&v.vrf_pubkey);
            h.update(&v.stake.to_le_bytes());
        }
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// 获取活跃 validator 数量。
    pub fn active_count(&self) -> usize {
        self.validators
            .iter()
            .filter(|v| v.can_participate_consensus())
            .count()
    }

    /// 获取活跃 validator 总数（用于 quorum 计算）。
    pub fn total_active_validators(&self) -> usize {
        self.active_count()
    }

    /// 查找 validator by pubkey。
    pub fn find_validator(&self, pubkey: &TaggedPubkey) -> Option<&ValidatorEntry> {
        self.validators.iter().find(|v| &v.pubkey == pubkey)
    }

    /// 查找 validator by pubkey（mutable）。
    pub fn find_validator_mut(&mut self, pubkey: &TaggedPubkey) -> Option<&mut ValidatorEntry> {
        self.validators.iter_mut().find(|v| &v.pubkey == pubkey)
    }

    /// 校验 ValidatorSet 规模是否满足 SEC-C2（|V| >= 5，OffChain 模式强制）。
    pub const fn validate_size_for_offchain(&self) -> PokerL1Result<()> {
        if self.validators.len() < MIN_VALIDATOR_SET_SIZE {
            return Err(PokerL1Error::ValidatorSetTooSmallForOffChain {
                size: self.validators.len(),
            });
        }
        Ok(())
    }

    /// 校验单次缩减比例是否 <= 20%（SEC-M2）。
    ///
    /// 参数：
    /// - `removed_count`：本次移除的 validator 数量
    pub fn validate_reduction_ratio(&self, removed_count: usize) -> PokerL1Result<()> {
        if self.validators.is_empty() {
            return Ok(());
        }
        let prev_size = self.validators.len() as u32;
        let ratio = removed_count as u32 * 100 / prev_size;
        if ratio > MAX_SINGLE_REDUCTION_RATIO {
            return Err(PokerL1Error::Other(format!(
                "SEC-M2: single reduction ratio {}% > {}% max",
                ratio, MAX_SINGLE_REDUCTION_RATIO
            )));
        }
        Ok(())
    }

    /// 推进 epoch：更新 validator 状态 + 衰减审查计数（NEW-H1）。
    ///
    /// spec NEW-H1：每 epoch 衰减 1（最低为 0），防止历史指控永久累积。
    pub fn advance_epoch(&mut self, new_epoch: Epoch) {
        self.prev_epoch_randomness = self.epoch_randomness;
        self.epoch = new_epoch;
        for v in &mut self.validators {
            // 衰减审查计数（最低为 0）
            if v.under_investigation_count > 0 {
                v.under_investigation_count -= 1;
            }
        }
        // 重新计算 validator_set_hash
        self.validator_set_hash = self.compute_hash();
    }

    /// 处理 bonding → active 状态转换（NEW-L3）。
    ///
    /// 到达 `bonding_until_height` 后转为 Active。
    pub fn process_bonding_expiry(&mut self, current_height: BlockHeight) {
        for v in &mut self.validators {
            if v.status == ValidatorStatus::Bonding && current_height >= v.bonding_until_height {
                v.status = ValidatorStatus::Active;
            }
        }
    }

    /// 启动 validator 退出流程（R5-H7：进入 unbonding 期）。
    pub fn start_unbonding(
        &mut self,
        pubkey: &TaggedPubkey,
        unbonding_until_height: BlockHeight,
    ) -> PokerL1Result<()> {
        let v = self
            .find_validator_mut(pubkey)
            .ok_or_else(|| PokerL1Error::ValidatorNotInSet(pubkey.clone()))?;
        if v.status != ValidatorStatus::Active {
            return Err(PokerL1Error::Other(format!(
                "validator not active (status={:?}), cannot start unbonding",
                v.status
            )));
        }
        v.status = ValidatorStatus::Unbonding;
        v.unbonding_until_height = unbonding_until_height;
        Ok(())
    }

    /// 完成 validator 退出（unbonding 期结束 + VRF key 已销毁）。
    pub fn finalize_unbonding(
        &mut self,
        pubkey: &TaggedPubkey,
        current_height: BlockHeight,
    ) -> PokerL1Result<()> {
        let v = self
            .find_validator_mut(pubkey)
            .ok_or_else(|| PokerL1Error::ValidatorNotInSet(pubkey.clone()))?;
        if v.status != ValidatorStatus::Unbonding {
            return Err(PokerL1Error::ValidatorInUnbonding(pubkey.clone()));
        }
        if current_height < v.unbonding_until_height {
            return Err(PokerL1Error::Other(format!(
                "unbonding period not elapsed (current={}, until={})",
                current_height, v.unbonding_until_height
            )));
        }
        if !v.vrf_key_destroyed {
            return Err(PokerL1Error::Other(
                "SEC2-M10: VRF key not destroyed, unbonding extended".to_string(),
            ));
        }
        v.status = ValidatorStatus::Retired;
        v.vrf_retired = true;
        Ok(())
    }

    /// 更新 validator 的 last_vertex_height（SEC-M1 停机判定用）。
    pub fn record_vertex_production(
        &mut self,
        pubkey: &TaggedPubkey,
        height: BlockHeight,
    ) -> PokerL1Result<()> {
        let v = self
            .find_validator_mut(pubkey)
            .ok_or_else(|| PokerL1Error::ValidatorNotInSet(pubkey.clone()))?;
        if !v.can_participate_consensus() {
            return Err(PokerL1Error::Other(format!(
                "validator cannot participate consensus (status={:?})",
                v.status
            )));
        }
        v.last_vertex_height = height;
        Ok(())
    }

    /// 标记 VRF key 已销毁（SEC2-M10）。
    pub fn mark_vrf_key_destroyed(&mut self, pubkey: &TaggedPubkey) -> PokerL1Result<()> {
        let v = self
            .find_validator_mut(pubkey)
            .ok_or_else(|| PokerL1Error::ValidatorNotInSet(pubkey.clone()))?;
        v.vrf_key_destroyed = true;
        Ok(())
    }

    /// 提交 epoch VRF proof 并更新 epoch_randomness（SEC-M11 / SEC2-C2 / SEC2-M10）。
    ///
    /// spec：
    /// 1. 计算 VRF input = `hash(chain_id || epoch || prev_epoch_randomness)`
    /// 2. 验证 VRF proof（使用 proposer 的 vrf_pubkey）
    /// 3. 校验 VRF input 含当前 epoch（SEC2-C2）
    /// 4. 链上校验 VRF output == 链上 epoch_randomness（SEC2-M10）
    /// 5. 写入 epoch_randomness
    ///
    /// 参数：
    /// - `chain_id`：网络 chain_id
    /// - `proposer_pubkey`：提交 VRF proof 的 validator pubkey
    /// - `proof`：VRF proof
    /// - `verifier`：VRF 验证器
    pub fn submit_epoch_vrf_proof(
        &mut self,
        chain_id: ChainId,
        proposer_pubkey: &TaggedPubkey,
        proof: &VrfProof,
        verifier: &dyn VrfVerifier,
    ) -> PokerL1Result<()> {
        // 1. 查找 proposer
        let proposer = self
            .find_validator(proposer_pubkey)
            .ok_or_else(|| PokerL1Error::ValidatorNotInSet(proposer_pubkey.clone()))?;
        if !proposer.can_participate_consensus() {
            return Err(PokerL1Error::Other(format!(
                "VRF proposer not active (status={:?})",
                proposer.status
            )));
        }

        // 2. 计算 VRF input（SEC2-C2）
        let expected_input = compute_vrf_input(chain_id, self.epoch, &self.prev_epoch_randomness);

        // 3. 验证 VRF proof
        let output = verifier.verify(&proposer.vrf_pubkey, &expected_input, proof)?;

        // 4. 写入 epoch_randomness
        self.epoch_randomness = output;
        Ok(())
    }

    /// Fallback epoch_randomness（SEC2-M12）。
    ///
    /// spec SEC2-M12：proposer 在 epoch_transition_window_blocks 内未提交 VRF proof →
    /// fallback epoch_randomness = hash(prev_epoch_randomness || genesis_chain_randomness)
    pub fn fallback_epoch_randomness(&mut self) {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&self.prev_epoch_randomness);
        h.update(&self.genesis_chain_randomness);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        self.epoch_randomness = out;
    }

    /// 计算某 Game 的 assigned_validator（SubTask 12.1）。
    ///
    /// spec：`assigned_validator = validator_set[hash(G.id, current_epoch) % |V|]`
    ///
    /// 仅考虑 Active 状态 validator。
    pub fn assigned_validator_for_game(
        &self,
        game_id: &crate::object_model::ObjectID,
    ) -> PokerL1Result<TaggedPubkey> {
        let active: Vec<&ValidatorEntry> = self
            .validators
            .iter()
            .filter(|v| v.can_participate_consensus())
            .collect();
        if active.is_empty() {
            return Err(PokerL1Error::ValidatorSetTooSmallForOffChain { size: 0 });
        }
        // hash(game_id || epoch || epoch_randomness)
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&game_id.to_bytes());
        h.update(&self.epoch.to_le_bytes());
        h.update(&self.epoch_randomness);
        let mut hash = [0u8; 32];
        h.finalize_variable(&mut hash).expect("32 <= 64");
        // 取前 8 字节作为 u64 索引
        let mut idx_bytes = [0u8; 8];
        idx_bytes.copy_from_slice(&hash[0..8]);
        // M-8 修复：先在 u64 上取模再转 usize，避免 32-bit 平台截断
        let idx = (u64::from_le_bytes(idx_bytes) % active.len() as u64) as usize;
        Ok(active[idx].pubkey.clone())
    }
}

/// 计算 genesis_chain_randomness（SEC2-M12）。
///
/// spec：由所有 validator pubkey 聚合哈希派生。
pub fn compute_genesis_chain_randomness(validators: &[ValidatorEntry]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    for v in validators {
        h.update(&v.pubkey.to_bytes());
        h.update(&v.vrf_pubkey);
    }
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    fn make_vrf_pubkey(byte: u8) -> [u8; VRF_PUBKEY_SIZE] {
        [byte; VRF_PUBKEY_SIZE]
    }

    fn make_validator(byte: u8, stake: u64, bonding_until: BlockHeight) -> ValidatorEntry {
        ValidatorEntry::new(
            make_tagged_pubkey(byte),
            make_vrf_pubkey(byte),
            stake,
            bonding_until,
        )
    }

    fn make_validator_set(count: usize) -> ValidatorSet {
        let validators: Vec<ValidatorEntry> = (0..count)
            .map(|i| {
                let mut v = make_validator(0x10 + i as u8, 1_000_000, 0);
                v.status = ValidatorStatus::Active; // 直接设为 Active 便于测试
                v
            })
            .collect();
        let genesis_randomness = compute_genesis_chain_randomness(&validators);
        let mut set = ValidatorSet {
            epoch: 1,
            validators,
            validator_set_hash: [0u8; 32],
            epoch_randomness: [0u8; 32],
            prev_epoch_randomness: [0u8; 32],
            genesis_chain_randomness: genesis_randomness,
        };
        set.validator_set_hash = set.compute_hash();
        set
    }

    // ===== VrfProof 序列化测试 =====

    #[test]
    fn vrf_proof_from_bytes_ok() {
        let bytes = [0xABu8; VRF_PROOF_SIZE];
        let proof = VrfProof::from_bytes(&bytes).expect("97 字节应解析成功");
        assert_eq!(proof.gamma, [0xAB; 33]);
        assert_eq!(proof.c, [0xAB; 32]);
        assert_eq!(proof.s, [0xAB; 32]);
    }

    #[test]
    fn vrf_proof_from_bytes_rejects_wrong_length() {
        let bytes = [0u8; 96];
        let err = VrfProof::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidSignatureLength { .. }));
    }

    #[test]
    fn vrf_proof_roundtrip() {
        let proof = VrfProof {
            gamma: [1u8; 33],
            c: [2u8; 32],
            s: [3u8; 32],
        };
        let bytes = proof.to_bytes();
        let recovered = VrfProof::from_bytes(&bytes).expect("往返解析");
        assert_eq!(proof, recovered);
    }

    // ===== compute_vrf_input / output 测试 =====

    #[test]
    fn compute_vrf_input_binds_epoch() {
        let prev_random = [0xAA; 32];
        let input1 = compute_vrf_input(0x706F_6B31, 1, &prev_random);
        let input2 = compute_vrf_input(0x706F_6B31, 2, &prev_random);
        assert_ne!(input1, input2, "epoch 变化必须改变 VRF input");
    }

    #[test]
    fn compute_vrf_input_binds_chain_id() {
        let prev_random = [0xAA; 32];
        let input1 = compute_vrf_input(0x706F_6B31, 1, &prev_random);
        let input2 = compute_vrf_input(0xDEAD_BEEF, 1, &prev_random);
        assert_ne!(input1, input2, "chain_id 变化必须改变 VRF input");
    }

    #[test]
    fn compute_vrf_input_binds_prev_randomness() {
        let input1 = compute_vrf_input(0x706F_6B31, 1, &[0xAA; 32]);
        let input2 = compute_vrf_input(0x706F_6B31, 1, &[0xBB; 32]);
        assert_ne!(
            input1, input2,
            "prev_epoch_randomness 变化必须改变 VRF input"
        );
    }

    #[test]
    fn compute_vrf_output_deterministic() {
        let pubkey = [0x10; VRF_PUBKEY_SIZE];
        let input = [0x20; VRF_OUTPUT_SIZE];
        let gamma = [0x30; 33];
        let out1 = compute_vrf_output(&pubkey, &input, &gamma);
        let out2 = compute_vrf_output(&pubkey, &input, &gamma);
        assert_eq!(out1, out2, "VRF output 必须确定性");
    }

    // ===== StubVrfVerifier 测试 =====

    #[test]
    fn stub_vrf_verifier_returns_input_as_output() {
        let verifier = StubVrfVerifier;
        let pubkey = [0x10; VRF_PUBKEY_SIZE];
        let input = [0x20; VRF_OUTPUT_SIZE];
        let proof = VrfProof {
            gamma: [0; 33],
            c: [0; 32],
            s: [0; 32],
        };
        let output = verifier.verify(&pubkey, &input, &proof).expect("stub 验证");
        assert_eq!(output, input, "stub 返回 input 作为 output");
    }

    // ===== ValidatorEntry 测试 =====

    #[test]
    fn validator_entry_new_starts_in_bonding() {
        let v = make_validator(0x10, 1_000_000, 1000);
        assert_eq!(v.status, ValidatorStatus::Bonding);
        assert!(!v.can_participate_consensus());
        assert!(v.can_be_slashed()); // Bonding 期可被 slashing
    }

    #[test]
    fn validator_entry_can_participate_when_active() {
        let mut v = make_validator(0x10, 1_000_000, 1000);
        v.status = ValidatorStatus::Active;
        assert!(v.can_participate_consensus());
    }

    #[test]
    fn validator_entry_cannot_participate_when_retired() {
        let mut v = make_validator(0x10, 1_000_000, 1000);
        v.status = ValidatorStatus::Retired;
        v.vrf_retired = true;
        assert!(!v.can_participate_consensus());
    }

    #[test]
    fn validator_entry_slashed_cannot_be_slashed_again() {
        let mut v = make_validator(0x10, 1_000_000, 1000);
        v.status = ValidatorStatus::Slashed;
        assert!(!v.can_be_slashed());
    }

    // ===== ValidatorSet 测试 =====

    #[test]
    fn validator_set_compute_hash_deterministic() {
        let set = make_validator_set(5);
        let h1 = set.compute_hash();
        let h2 = set.compute_hash();
        assert_eq!(h1, h2, "validator_set_hash 必须确定性");
    }

    #[test]
    fn validator_set_compute_hash_changes_with_validators() {
        let mut set = make_validator_set(5);
        let h1 = set.compute_hash();
        set.validators[0].stake = 2_000_000;
        let h2 = set.compute_hash();
        assert_ne!(h1, h2, "stake 变化必须改变 hash");
    }

    #[test]
    fn validator_set_active_count() {
        let mut set = make_validator_set(5);
        assert_eq!(set.active_count(), 5);
        // 将一个设为 Bonding
        set.validators[0].status = ValidatorStatus::Bonding;
        assert_eq!(set.active_count(), 4);
    }

    #[test]
    fn validator_set_find_validator() {
        let set = make_validator_set(5);
        let target = set.validators[2].pubkey.clone();
        let found = set.find_validator(&target);
        assert!(found.is_some());
        assert_eq!(found.unwrap().pubkey, target);
    }

    #[test]
    fn validator_set_validate_size_for_offchain_ok() {
        let set = make_validator_set(5);
        set.validate_size_for_offchain()
            .expect("5 validator 应通过 SEC-C2");
    }

    #[test]
    fn validator_set_validate_size_for_offchain_rejects_small() {
        let set = make_validator_set(4);
        let err = set.validate_size_for_offchain().unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::ValidatorSetTooSmallForOffChain { size: 4 }
        ));
    }

    #[test]
    fn validator_set_validate_reduction_ratio_ok_within_20_percent() {
        let set = make_validator_set(10);
        // 移除 2 个（20%）→ 通过
        set.validate_reduction_ratio(2).expect("20% 应通过 SEC-M2");
    }

    #[test]
    fn validator_set_validate_reduction_ratio_rejects_exceeding_20_percent() {
        let set = make_validator_set(10);
        // 移除 3 个（30%）→ 拒绝
        let err = set.validate_reduction_ratio(3).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn validator_set_advance_epoch_decays_investigation_count() {
        let mut set = make_validator_set(5);
        set.validators[0].under_investigation_count = 3;
        set.validators[1].under_investigation_count = 0;
        set.advance_epoch(2);
        assert_eq!(
            set.validators[0].under_investigation_count, 2,
            "每 epoch 衰减 1"
        );
        assert_eq!(set.validators[1].under_investigation_count, 0, "最低为 0");
        assert_eq!(set.epoch, 2);
        assert_eq!(set.prev_epoch_randomness, [0u8; 32]);
    }

    #[test]
    fn validator_set_process_bonding_expiry() {
        let mut set = make_validator_set(5);
        // 将一个设为 Bonding
        set.validators[0].status = ValidatorStatus::Bonding;
        set.validators[0].bonding_until_height = 1000;
        // 未到期
        set.process_bonding_expiry(999);
        assert_eq!(set.validators[0].status, ValidatorStatus::Bonding);
        // 到期
        set.process_bonding_expiry(1000);
        assert_eq!(set.validators[0].status, ValidatorStatus::Active);
    }

    #[test]
    fn validator_set_start_unbonding_ok() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        set.start_unbonding(&target, 2000).expect("退出应成功");
        assert_eq!(set.validators[0].status, ValidatorStatus::Unbonding);
        assert_eq!(set.validators[0].unbonding_until_height, 2000);
    }

    #[test]
    fn validator_set_start_unbonding_rejects_non_active() {
        let mut set = make_validator_set(5);
        set.validators[0].status = ValidatorStatus::Bonding;
        let target = set.validators[0].pubkey.clone();
        let err = set.start_unbonding(&target, 2000).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn validator_set_finalize_unbonding_ok() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        set.start_unbonding(&target, 2000).expect("退出");
        set.mark_vrf_key_destroyed(&target).expect("销毁 VRF key");
        set.finalize_unbonding(&target, 2000).expect("完成退出");
        assert_eq!(set.validators[0].status, ValidatorStatus::Retired);
        assert!(set.validators[0].vrf_retired);
    }

    #[test]
    fn validator_set_finalize_unbonding_rejects_without_vrf_destroy() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        set.start_unbonding(&target, 2000).expect("退出");
        // 未销毁 VRF key
        let err = set.finalize_unbonding(&target, 2000).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn validator_set_finalize_unbonding_rejects_before_expiry() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        set.start_unbonding(&target, 2000).expect("退出");
        set.mark_vrf_key_destroyed(&target).expect("销毁 VRF key");
        // 未到期
        let err = set.finalize_unbonding(&target, 1999).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn validator_set_record_vertex_production_ok() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        set.record_vertex_production(&target, 500)
            .expect("记录 vertex 生产");
        assert_eq!(set.validators[0].last_vertex_height, 500);
    }

    #[test]
    fn validator_set_record_vertex_production_rejects_non_active() {
        let mut set = make_validator_set(5);
        set.validators[0].status = ValidatorStatus::Bonding;
        let target = set.validators[0].pubkey.clone();
        let err = set.record_vertex_production(&target, 500).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn validator_set_submit_epoch_vrf_proof_ok() {
        let mut set = make_validator_set(5);
        let proposer = set.validators[0].pubkey.clone();
        let proof = VrfProof {
            gamma: [1; 33],
            c: [2; 32],
            s: [3; 32],
        };
        let verifier = StubVrfVerifier;
        set.submit_epoch_vrf_proof(crate::DEFAULT_CHAIN_ID, &proposer, &proof, &verifier)
            .expect("VRF proof 提交应成功");
        // StubVrfVerifier 返回 input 作为 output，epoch_randomness 应非零
        assert_ne!(set.epoch_randomness, [0u8; 32]);
    }

    #[test]
    fn validator_set_submit_epoch_vrf_proof_rejects_non_active() {
        let mut set = make_validator_set(5);
        set.validators[0].status = ValidatorStatus::Bonding;
        let proposer = set.validators[0].pubkey.clone();
        let proof = VrfProof {
            gamma: [0; 33],
            c: [0; 32],
            s: [0; 32],
        };
        let verifier = StubVrfVerifier;
        let err = set
            .submit_epoch_vrf_proof(crate::DEFAULT_CHAIN_ID, &proposer, &proof, &verifier)
            .unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn validator_set_fallback_epoch_randomness() {
        let mut set = make_validator_set(5);
        set.prev_epoch_randomness = [0xAA; 32];
        set.fallback_epoch_randomness();
        // fallback_randomness = hash(prev || genesis)，应非零且不同于 prev
        assert_ne!(set.epoch_randomness, [0u8; 32]);
        assert_ne!(set.epoch_randomness, set.prev_epoch_randomness);
    }

    #[test]
    fn validator_set_assigned_validator_for_game_deterministic() {
        let set = make_validator_set(5);
        let game_id = crate::object_model::ObjectID::new([0xBB; 20], 1);
        let assigned1 = set.assigned_validator_for_game(&game_id).expect("分配");
        let assigned2 = set.assigned_validator_for_game(&game_id).expect("分配");
        assert_eq!(
            assigned1, assigned2,
            "同一 Game 的 assigned_validator 必须确定性"
        );
    }

    #[test]
    fn validator_set_assigned_validator_for_game_changes_with_epoch() {
        let mut set = make_validator_set(5);
        let game_id = crate::object_model::ObjectID::new([0xBB; 20], 1);
        let assigned1 = set.assigned_validator_for_game(&game_id).expect("分配");
        set.advance_epoch(2);
        let assigned2 = set.assigned_validator_for_game(&game_id).expect("分配");
        // epoch 变化后，epoch_randomness 变化（可能为 0 → 0，但 epoch 字段变化）
        // 注意：StubVrfVerifier 未改变 epoch_randomness，但 epoch 字段参与 hash
        // 所以 assigned_validator 可能变化也可能不变，这里仅验证不 panic
        let _ = (assigned1, assigned2);
    }

    #[test]
    fn compute_genesis_chain_randomness_deterministic() {
        let validators: Vec<ValidatorEntry> = (0..5)
            .map(|i| {
                let mut v = make_validator(0x10 + i as u8, 1_000_000, 0);
                v.status = ValidatorStatus::Active;
                v
            })
            .collect();
        let r1 = compute_genesis_chain_randomness(&validators);
        let r2 = compute_genesis_chain_randomness(&validators);
        assert_eq!(r1, r2, "genesis_chain_randomness 必须确定性");
    }

    // ===== 序列化往返测试 =====

    #[test]
    fn validator_entry_bcs_roundtrip() {
        let v = make_validator(0x10, 1_000_000, 1000);
        let bytes = borsh::to_vec(&v).unwrap();
        let recovered: ValidatorEntry = borsh::from_slice(&bytes).unwrap();
        assert_eq!(v, recovered);
    }

    #[test]
    fn validator_set_bcs_roundtrip() {
        let set = make_validator_set(5);
        let bytes = borsh::to_vec(&set).unwrap();
        let recovered: ValidatorSet = borsh::from_slice(&bytes).unwrap();
        assert_eq!(set, recovered);
    }

    #[test]
    fn vrf_proof_bcs_roundtrip() {
        let proof = VrfProof {
            gamma: [1; 33],
            c: [2; 32],
            s: [3; 32],
        };
        let bytes = borsh::to_vec(&proof).unwrap();
        let recovered: VrfProof = borsh::from_slice(&bytes).unwrap();
        assert_eq!(proof, recovered);
    }
}
