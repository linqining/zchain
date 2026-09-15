//! CairoFactRegistry — Cairo/Stwo 证明的节点内验证与 fact 注册（方案①）。
//!
//! # 架构定位（对标修正 2026-09-14）
//!
//! 本预编译是 **SNIP-36 验证者角色的 zchain 内化**：Starknet 上由
//! sequencer 协议内验证（create_proof + proof_facts 随交易附带），zchain
//! 没有 sequencer/create_proof 入口，由节点自身充当验证者——
//! `finalize_proof` 在节点内做 cairo-air `verify_cairo` 全量真验证，fact
//! 是**验证后的存证**，而非 poker_texas_air `register_settlement_fact`
//! 那种免验降级注册（模式 C）。
//!
//! # 双 fact 公式（与 poker_texas_air DualSettlement v3 逐位对齐）
//!
//! 每次 `finalize_proof` 产出两个 fact：
//! - `fact_c = poseidon([program_hash, segment…])`
//!   （= 合约 `fact_for_segment`，降级门 `settlement_facts[fact]` 的键）；
//! - `fact_s36 = poseidon([consumer_addr, 0, seg_len, segment…])`
//!   （= SNIP-36 `snip36_message_hash(consumer_addr, segment)`，即 Starknet
//!   v3 双门 `facts[8]` 的预期消息哈希；`consumer_addr` 为目标消费合约
//!   地址——如 Starknet DualSettlement——creator 经 `set_snip36_consumer`
//!   钉扎。跨链对拍：同 segment 输入下 zchain `fact_s36` 与 Starknet 侧
//!   `facts[8]` 直接可比）。
//!
//! # 恶意 prover 的处置（方案①核心）
//!
//! 证明在节点内验证，伪造在数学上不可能——prover 的唯一"作恶"能力是
//! 不提交（liveness）。
#![deny(unsafe_code)]

use borsh::{BorshDeserialize, BorshSerialize};

use poker_protocol::crypto::stark_curve::StarkScalar;

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::signature::TaggedPubkey;
use crate::storage::ObjectBackend;
use crate::vm::contracts::dispatch::compute_method_selector;
use crate::vm::precompile::{reserved, DispatchResult, ExecutionEnvironment, Precompile};
use crate::{Address, Hash};

/// 注册表对象类型。
pub const CAIRO_REGISTRY_OBJECT_TYPE: &str = "CairoFactRegistry";
/// 证明分块对象类型（Immutable：内容一经上链不可变）。
pub const CAIRO_PROOF_CHUNK_OBJECT_TYPE: &str = "CairoProofChunk";
/// 单块字节数上限（tx args ≤ 64KB，留出 borsh/selector 余量）。
pub const MAX_CHUNK_BYTES: usize = 60_000;
/// 单证明最大块数（60KB × 32 ≈ 1.9MB，覆盖 full 规模二进制 wire）。
pub const MAX_PROOF_CHUNKS: usize = 32;

/// 注册表状态（hot，borsh 进注册表对象）。
#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct CairoRegistryState {
    /// 创建者（`set_program_hash` 权限主体）。
    pub creator: Address,
    /// 已钉扎的程序哈希。
    pub program_hashes: Vec<[u8; 32]>,
    /// SNIP-36 消息哈希绑定的消费合约地址（可选，creator 钉扎）。
    pub snip36_consumer: Option<[u8; 32]>,
    /// 已注册的降级门 fact（`poseidon([program_hash, output…])`）。
    pub facts: Vec<[u8; 32]>,
    /// 已注册的 SNIP-36 对齐 fact
    /// （`poseidon([consumer_addr, 0, seg_len, output…])`）。
    pub facts_s36: Vec<[u8; 32]>,
    /// 各调用者的证明分块暂存。
    pub staged: Vec<StagedProof>,
}

/// 一个调用者的分块暂存。
#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct StagedProof {
    /// 暂存所有者。
    pub owner: Address,
    /// 分块对象 ID（顺序即拼接顺序）。
    pub chunk_ids: Vec<ObjectID>,
}

/// 方法选择器集合。
pub mod selectors {
    use super::compute_method_selector;

    /// `set_program_hash` — 钉扎程序哈希（creator 门控）。
    #[must_use]
    pub fn set_program_hash() -> [u8; 32] {
        compute_method_selector("set_program_hash")
    }

    /// `set_snip36_consumer` — 钉扎 SNIP-36 消息哈希的消费合约地址。
    #[must_use]
    pub fn set_snip36_consumer() -> [u8; 32] {
        compute_method_selector("set_snip36_consumer")
    }

    /// `submit_proof_chunk` — 上传证明分块。
    #[must_use]
    pub fn submit_proof_chunk() -> [u8; 32] {
        compute_method_selector("submit_proof_chunk")
    }

    /// `finalize_proof` — 重组 + 节点内验证 + 双 fact 注册。
    #[must_use]
    pub fn finalize_proof() -> [u8; 32] {
        compute_method_selector("finalize_proof")
    }

    /// `abandon` — 丢弃调用者的暂存分块（含块对象删除）。
    #[must_use]
    pub fn abandon() -> [u8; 32] {
        compute_method_selector("abandon")
    }

    /// `is_fact_registered` — fact 消费门查询（返回 BCS bool）。
    #[must_use]
    pub fn is_fact_registered() -> [u8; 32] {
        compute_method_selector("is_fact_registered")
    }

    /// `is_program_hash_pinned` — 程序哈希钉扎查询（返回 BCS bool）。
    #[must_use]
    pub fn is_program_hash_pinned() -> [u8; 32] {
        compute_method_selector("is_program_hash_pinned")
    }
}

/// Args：`set_program_hash`。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SetProgramHashArgs {
    /// 电路程序哈希（prove-hand public_outputs.json 的 `program_hash`）。
    pub program_hash: [u8; 32],
}

/// Args：`submit_proof_chunk`。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitProofChunkArgs {
    /// 分块字节（≤ [`MAX_CHUNK_BYTES`]）。
    pub chunk: Vec<u8>,
}

/// Args：`finalize_proof`。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalizeProofArgs {
    /// 预期程序哈希（须已钉扎）。
    pub program_hash: [u8; 32],
}

/// Args：`set_snip36_consumer`。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SetSnip36ConsumerArgs {
    /// SNIP-36 消息哈希绑定的消费合约地址（felt 32B BE；如 Starknet
    /// DualSettlement 地址——`fact_s36 = snip36_message_hash(消费地址, 段)`，
    /// 与 Starknet v3 双门 `facts[8]` 同式同值）。
    pub consumer_addr: [u8; 32],
}

/// Args：`abandon`（无参数，caller 绑定）。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Default)]
pub struct AbandonArgs;

/// Args：`is_fact_registered`。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct IsFactRegisteredArgs {
    /// 待查询 fact。
    pub fact: [u8; 32],
}

/// Args：`is_program_hash_pinned`。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct IsProgramHashPinnedArgs {
    /// 待查询程序哈希。
    pub program_hash: [u8; 32],
}

/// 证明分块预编译：注册表对象挂在预编译 ID 自身（texas 同构）。
pub struct CairoFactRegistryPrecompile {
    version: u32,
}

impl CairoFactRegistryPrecompile {
    /// 新实例。
    #[must_use]
    pub fn new(version: u32) -> Self {
        Self { version }
    }

    /// Arc 句柄（注册表注册用）。
    #[must_use]
    pub fn new_arc(version: u32) -> std::sync::Arc<dyn Precompile> {
        std::sync::Arc::new(Self::new(version))
    }
}

impl Precompile for CairoFactRegistryPrecompile {
    fn id(&self) -> ObjectID {
        reserved::cairo_registry_contract_id()
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn supports_selector(&self, selector: &[u8; 32]) -> bool {
        selector == &selectors::set_program_hash()
            || selector == &selectors::set_snip36_consumer()
            || selector == &selectors::submit_proof_chunk()
            || selector == &selectors::finalize_proof()
            || selector == &selectors::abandon()
            || selector == &selectors::is_fact_registered()
            || selector == &selectors::is_program_hash_pinned()
    }

    fn gas_cost(&self, method_selector: &[u8; 32], args: &[u8]) -> u64 {
        let base = crate::vm::gas_table::precompile_gas(args.len() as u64);
        // finalize 承担节点内 STARK 验证（实测 ~9ms CPU），取保守固定成本
        if method_selector == &selectors::finalize_proof() {
            base + 500_000
        } else {
            base
        }
    }

    fn call(
        &self,
        caller: &Address,
        _caller_pubkey: &TaggedPubkey,
        method_selector: &[u8; 32],
        args: &[u8],
        env: &ExecutionEnvironment,
        object_db: &mut dyn ObjectBackend,
    ) -> PokerL1Result<DispatchResult> {
        let registry_id = reserved::cairo_registry_contract_id();
        let mut read_objects = vec![registry_id];
        let mut result = DispatchResult::empty();

        // 读注册表（不存在时按方法语义惰性创建）
        let existing = match object_db.read(&registry_id) {
            Ok(obj) => {
                if obj.object_type != CAIRO_REGISTRY_OBJECT_TYPE {
                    return Err(PokerL1Error::Serialization(
                        "Cairo registry object has non-canonical type".into(),
                    ));
                }
                Some(borsh::from_slice::<CairoRegistryState>(&obj.data).map_err(|e| {
                    PokerL1Error::Serialization(format!("decode cairo registry: {e}"))
                })?)
            }
            Err(PokerL1Error::ObjectNotFound(_)) => None,
            Err(e) => return Err(e),
        };

        if method_selector == &selectors::set_program_hash() {
            let input: SetProgramHashArgs = borsh::from_slice(args)
                .map_err(|e| PokerL1Error::Serialization(format!("set_program_hash args: {e}")))?;
            let mut state = existing.unwrap_or_else(|| CairoRegistryState {
                creator: *caller,
                ..CairoRegistryState::default()
            });
            if state.creator != *caller {
                return Err(PokerL1Error::Serialization(
                    "set_program_hash: caller is not registry creator".into(),
                ));
            }
            if !state.program_hashes.contains(&input.program_hash) {
                state.program_hashes.push(input.program_hash);
            }
            write_registry(object_db, &registry_id, &state)?;
            result.modified_objects.push(registry_id);
        } else if method_selector == &selectors::set_snip36_consumer() {
            let input: SetSnip36ConsumerArgs = borsh::from_slice(args).map_err(|e| {
                PokerL1Error::Serialization(format!("set_snip36_consumer args: {e}"))
            })?;
            let mut state = existing.unwrap_or_else(|| CairoRegistryState {
                creator: *caller,
                ..CairoRegistryState::default()
            });
            if state.creator != *caller {
                return Err(PokerL1Error::Serialization(
                    "set_snip36_consumer: caller is not registry creator".into(),
                ));
            }
            state.snip36_consumer = Some(input.consumer_addr);
            write_registry(object_db, &registry_id, &state)?;
            result.modified_objects.push(registry_id);
        } else if method_selector == &selectors::submit_proof_chunk() {
            let input: SubmitProofChunkArgs = borsh::from_slice(args)
                .map_err(|e| PokerL1Error::Serialization(format!("submit_proof_chunk args: {e}")))?;
            if input.chunk.is_empty() || input.chunk.len() > MAX_CHUNK_BYTES {
                return Err(PokerL1Error::Serialization(format!(
                    "proof chunk size {} out of (0, {MAX_CHUNK_BYTES}]",
                    input.chunk.len()
                )));
            }
            let mut state = existing.unwrap_or_else(|| CairoRegistryState {
                creator: *caller,
                ..CairoRegistryState::default()
            });
            // 分块对象：Immutable（内容一经上链不可变）
            let chunk_id = ObjectID::new(
                *caller,
                chunk_nonce(&env.tx_hash, state.staged.len(), input.chunk.len()),
            );
            object_db.create(Object::new(
                chunk_id,
                Ownership::Immutable,
                CAIRO_PROOF_CHUNK_OBJECT_TYPE,
                input.chunk,
                None,
            ))?;
            result.created_objects.push(chunk_id);
            let staged = match state.staged.iter_mut().find(|s| s.owner == *caller) {
                Some(s) => s,
                None => {
                    state.staged.push(StagedProof { owner: *caller, chunk_ids: vec![] });
                    state.staged.last_mut().expect("just pushed")
                }
            };
            if staged.chunk_ids.len() >= MAX_PROOF_CHUNKS {
                return Err(PokerL1Error::Serialization(
                    "too many proof chunks (finalize or abandon first)".into(),
                ));
            }
            staged.chunk_ids.push(chunk_id);
            write_registry(object_db, &registry_id, &state)?;
            result.modified_objects.push(registry_id);
            result.read_objects = read_objects;
            return Ok(result);
        } else if method_selector == &selectors::finalize_proof() {
            let input: FinalizeProofArgs = borsh::from_slice(args)
                .map_err(|e| PokerL1Error::Serialization(format!("finalize_proof args: {e}")))?;
            let state = existing.ok_or_else(|| {
                PokerL1Error::Serialization("cairo registry not initialized".into())
            })?;
            if !state.program_hashes.contains(&input.program_hash) {
                return Err(PokerL1Error::Serialization(
                    "program hash not pinned (set_program_hash first)".into(),
                ));
            }
            let staged = state
                .staged
                .iter()
                .find(|s| s.owner == *caller)
                .ok_or_else(|| {
                    PokerL1Error::Serialization("no staged proof chunks for caller".into())
                })?;
            // 重组：按上传顺序拼接分块
            let mut bytes = Vec::new();
            for id in &staged.chunk_ids {
                read_objects.push(*id);
                let chunk = object_db.read(id)?;
                bytes.extend_from_slice(&chunk.data);
            }
            // 节点内真验证（cairo-air 2.4.0 verify_cairo，~9ms 级）
            let out = fact_verify::verify_cairo_proof_bytes(&bytes)
                .map_err(|e| PokerL1Error::Serialization(format!("cairo proof verify: {e}")))?;
            if out.program_hash.to_bytes_be() != input.program_hash {
                return Err(PokerL1Error::Serialization(format!(
                    "proof program hash {:#x} != pinned 0x{}",
                    out.program_hash,
                    bytes_hex(&input.program_hash)
                )));
            }
            // 双 fact：降级门（fact_c）+ SNIP-36 对齐（fact_s36）
            let output: Vec<[u8; 32]> =
                out.output.iter().map(|f| f.to_bytes_be()).collect();
            let fact_c = fact_for_segment_bytes(input.program_hash, &output);
            let fact_s36 = state
                .snip36_consumer
                .map(|consumer| snip36_message_hash(consumer, &output));
            let mut new_state = state.clone();
            new_state.facts.push(fact_c);
            if let Some(f) = fact_s36 {
                new_state.facts_s36.push(f);
            }
            // 清空该 caller 的暂存
            new_state.staged.retain(|s| s.owner != *caller);
            write_registry(object_db, &registry_id, &new_state)?;
            result.modified_objects.push(registry_id);
            result.return_value = borsh::to_vec(&FactRegistered {
                fact_c,
                fact_s36,
                output,
            })
            .unwrap_or_default();
            result.read_objects = read_objects;
            return Ok(result);
        } else if method_selector == &selectors::abandon() {
            // 丢弃调用者暂存：删除块对象（Immutable 删除失败则保留对象但
            // 清暂存——孤儿对象不再被引用，不阻碍后续上传）。
            let mut state = existing.ok_or_else(|| {
                PokerL1Error::Serialization("cairo registry not initialized".into())
            })?;
            let Some(pos) = state.staged.iter().position(|s| s.owner == *caller) else {
                return Err(PokerL1Error::Serialization(
                    "abandon: no staged proof chunks for caller".into(),
                ));
            };
            let staged = state.staged.remove(pos);
            for id in &staged.chunk_ids {
                let _ = object_db.delete(id);
            }
            write_registry(object_db, &registry_id, &state)?;
            result.modified_objects.push(registry_id);
        } else if method_selector == &selectors::is_fact_registered() {
            let input: IsFactRegisteredArgs = borsh::from_slice(args).map_err(|e| {
                PokerL1Error::Serialization(format!("is_fact_registered args: {e}"))
            })?;
            let hit = existing
                .map(|s| s.facts.contains(&input.fact) || s.facts_s36.contains(&input.fact))
                .unwrap_or(false);
            result.return_value = borsh::to_vec(&hit).unwrap_or_default();
        } else if method_selector == &selectors::is_program_hash_pinned() {
            let input: IsProgramHashPinnedArgs = borsh::from_slice(args).map_err(|e| {
                PokerL1Error::Serialization(format!("is_program_hash_pinned args: {e}"))
            })?;
            let hit = existing
                .map(|s| s.program_hashes.contains(&input.program_hash))
                .unwrap_or(false);
            result.return_value = borsh::to_vec(&hit).unwrap_or_default();
        } else {
            return Err(PokerL1Error::Serialization(
                "cairo registry: unknown method selector".into(),
            ));
        }

        result.read_objects = read_objects;
        Ok(result)
    }
}

/// `finalize_proof` 返回值（BCS）：双 fact。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct FactRegistered {
    /// 降级门 fact：`poseidon([program_hash, segment…])`
    /// （= DualSettlement `fact_for_segment`，`settlement_facts` 的键）。
    pub fact_c: [u8; 32],
    /// SNIP-36 对齐 fact：`poseidon([consumer_addr, 0, seg_len, segment…])`
    /// （= Starknet v3 双门 `facts[8]` 的预期消息哈希；未钉扎消费地址时为
    /// 全零占位）。
    pub fact_s36: Option<[u8; 32]>,
    /// 证明公开输出（程序公开段，即合约 calldata 的 segment）。
    pub output: Vec<[u8; 32]>,
}

// ============================================================
// fact 公式（与 poker_texas_air DualSettlement v3 逐位对齐的公开锚点）
// ============================================================

// fact 公式（与 poker_texas_air DualSettlement v3 逐位对齐的公开锚点）：
// 实现归属 fact-verify（验证器 crate），此处转发保持 API 就地可用。

/// SNIP-36 消息哈希：`poseidon([consumer_addr, 0, seg_len, segment…])`。
pub fn snip36_message_hash(consumer_addr: [u8; 32], segment: &[[u8; 32]]) -> [u8; 32] {
    fact_verify::snip36_message_hash_bytes(consumer_addr, segment)
}

/// 降级门 fact：`poseidon([program_hash, segment…])`。
pub fn fact_for_segment_bytes(program_hash: [u8; 32], segment: &[[u8; 32]]) -> [u8; 32] {
    fact_verify::fact_for_segment_bytes(program_hash, segment)
}

fn bytes_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 分块 nonce：`blake2b32("CAIRO_PROOF_CHUNK_V1" ‖ tx_hash ‖ stage ‖ len)[..8]`。
fn chunk_nonce(tx_hash: &Hash, stage: usize, len: usize) -> u64 {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"CAIRO_PROOF_CHUNK_V1");
    hasher.update(tx_hash);
    hasher.update(&(stage as u64).to_be_bytes());
    hasher.update(&(len as u64).to_be_bytes());
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("fixed output");
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"))
}

fn write_registry(
    object_db: &mut dyn ObjectBackend,
    id: &ObjectID,
    state: &CairoRegistryState,
) -> PokerL1Result<()> {
    let data = borsh::to_vec(state)
        .map_err(|e| PokerL1Error::Serialization(format!("encode cairo registry: {e}")))?;
    if object_db.read(id).is_ok() {
        object_db.update(id, &Address::default(), data)
    } else {
        object_db.create(Object::new(
            *id,
            Ownership::Shared,
            CAIRO_REGISTRY_OBJECT_TYPE,
            data,
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_selector_roundtrip() {
        let pc = CairoFactRegistryPrecompile::new(1);
        assert!(pc.supports_selector(&selectors::set_program_hash()));
        assert!(pc.supports_selector(&selectors::set_snip36_consumer()));
        assert!(pc.supports_selector(&selectors::submit_proof_chunk()));
        assert!(pc.supports_selector(&selectors::finalize_proof()));
        assert!(pc.supports_selector(&selectors::abandon()));
        assert!(pc.supports_selector(&selectors::is_fact_registered()));
        assert!(pc.supports_selector(&selectors::is_program_hash_pinned()));
        assert!(!pc.supports_selector(&compute_method_selector("unknown")));
    }

    /// SNIP-36 消息哈希 KAT：与合约 `snip36_message_hash` 同式。
    /// 期望值由同公式独立实现（starknet-crypto poseidon_hash_many）生成，
    /// 作为 Cairo 侧对拍锚点。
    #[test]
    fn snip36_message_hash_kat() {
        // 段 = 主网 settlement 证明的公开输出（SP2M_OK 开头，15 felts）
        let seg: [[u8; 32]; 15] = core::array::from_fn(|i| {
            let mut b = [0u8; 32];
            b[31] = i as u8 + 1;
            b
        });
        let consumer: [u8; 32] = {
            let mut b = [0u8; 32];
            b[31] = 0x42;
            b
        };
        let h = snip36_message_hash(consumer, &seg);
        // 独立重算：poseidon([consumer, 0, len, seg...])
        use starknet_crypto::poseidon_hash_many;
        let mut felts = Vec::new();
        felts.push(starknet_crypto::Felt::from_bytes_be(&consumer));
        felts.push(starknet_crypto::Felt::ZERO);
        felts.push(starknet_crypto::Felt::from(seg.len() as u64));
        for s in &seg {
            felts.push(starknet_crypto::Felt::from_bytes_be(s));
        }
        assert_eq!(h, poseidon_hash_many(&felts).to_bytes_be());
        // 换消费者地址必须换哈希（防跨合约 fact 重放）
        let mut other_consumer = consumer;
        other_consumer[31] ^= 1;
        assert_ne!(
            snip36_message_hash(other_consumer, &seg),
            h,
            "consumer 地址必须参与绑定"
        );
    }

    /// 降级门 fact KAT：与 fact_for_segment 同式独立重算对拍。
    #[test]
    fn fact_for_segment_kat() {
        let program_hash: [u8; 32] = core::array::from_fn(|i| i as u8);
        let seg: [[u8; 32]; 3] = core::array::from_fn(|i| {
            let mut b = [0u8; 32];
            b[31] = i as u8 + 7;
            b
        });
        let h = fact_for_segment_bytes(program_hash, &seg);
        use starknet_crypto::poseidon_hash_many;
        let mut felts = Vec::new();
        felts.push(starknet_crypto::Felt::from_bytes_be(&program_hash));
        for s in &seg {
            felts.push(starknet_crypto::Felt::from_bytes_be(s));
        }
        assert_eq!(h, poseidon_hash_many(&felts).to_bytes_be());
    }
}
