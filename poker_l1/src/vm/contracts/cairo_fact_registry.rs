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
use crate::vm::gas_table::MAX_OBJECT_SIZE;
use crate::vm::precompile::{reserved, DispatchResult, ExecutionEnvironment, Precompile};
use crate::{Address, ChainId, Hash};

/// 注册表对象类型。
pub const CAIRO_REGISTRY_OBJECT_TYPE: &str = "CairoFactRegistry";
/// 证明分块对象类型（Immutable：内容一经上链不可变）。
pub const CAIRO_PROOF_CHUNK_OBJECT_TYPE: &str = "CairoProofChunk";
/// 单块字节数上限（tx args ≤ 64KB，留出 borsh/selector 余量）。
pub const MAX_CHUNK_BYTES: usize = 60_000;
/// 单证明最大块数（60KB × 32 ≈ 1.9MB，覆盖 full 规模二进制 wire）。
pub const MAX_PROOF_CHUNKS: usize = 32;
/// 单个 fact 列表（`facts` / `facts_s36`）的环形容量（P1 审计修复 2026-09）。
///
/// 注册表状态序列化进**单个**保留共享对象，对象层硬上限
/// `MAX_OBJECT_SIZE` = 64KB——无界增长会永久砖化 fact 桥（连
/// abandon/finalize 都要写同一对象）。超限按 FIFO 淘汰最旧 fact：
/// **消费方（Starknet 双门 / 降级门）必须及时消费**，fact 是验证存证
/// 而非永久归档（devnet 语义；归档应订阅链事件离线保存）。
pub const MAX_REGISTRY_FACTS: usize = 256;
/// 钉扎的程序哈希上限（环形淘汰最旧；旧 circuit 退场即让位）。
pub const MAX_PROGRAM_HASHES: usize = 16;
/// 分块暂存调用者上限（P1 审计修复 2026-09）。
///
/// 超限淘汰**最旧调用者**的整个暂存（其块对象一并删除——孤儿化）。
/// devnet 可接受：被打断的 prover abandon 后重传即可。
pub const MAX_STAGED_CALLERS: usize = 40;

/// 状态最坏序列化尺寸（borsh，定长布局）：
/// creator(20) + program_hashes(4+16×32) + snip36(Option 1+32)
/// + facts(4+256×32) + facts_s36(4+256×32)
/// + staged(4 + 40×(owner 20 + chunk_ids 4+32×28))。
const fn worst_case_state_len() -> usize {
    20 // creator: Address = [u8; 20]
        + (4 + MAX_PROGRAM_HASHES * 32)
        + (1 + 32)
        + (4 + MAX_REGISTRY_FACTS * 32)
        + (4 + MAX_REGISTRY_FACTS * 32)
        + (4 + MAX_STAGED_CALLERS * (20 + 4 + 28 * MAX_PROOF_CHUNKS)) // ObjectID borsh = 20 + 8
}
/// 状态尺寸硬上限（= 最坏尺寸；编译期保证 < 64KB 且留 ≥ 4KB 余量）。
const MAX_REGISTRY_STATE_BYTES: usize = worst_case_state_len();
const _: () = assert!(MAX_REGISTRY_STATE_BYTES + 4 * 1024 <= MAX_OBJECT_SIZE);

/// 注册表状态（hot，borsh 进注册表对象）。
///
/// 尺寸有界（P1 审计修复 2026-09）：各列表按 [`MAX_REGISTRY_FACTS`] /
/// [`MAX_PROGRAM_HASHES`] / [`MAX_STAGED_CALLERS`] 环形淘汰，最坏序列化
/// 尺寸由 [`MAX_REGISTRY_STATE_BYTES`] 编译期钳制在 64KB 对象硬上限之内。
#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct CairoRegistryState {
    /// 创建者（`set_program_hash` 权限主体；genesis 预建时钉扎为首个
    /// validator 的地址，见 `genesis_registry_object`）。
    pub creator: Address,
    /// 已钉扎的程序哈希（≤ [`MAX_PROGRAM_HASHES`]，环形淘汰 + 去重）。
    pub program_hashes: Vec<[u8; 32]>,
    /// SNIP-36 消息哈希绑定的消费合约地址（可选，creator 钉扎）。
    pub snip36_consumer: Option<[u8; 32]>,
    /// 已注册的降级门 fact（`poseidon([program_hash, output…])`；
    /// ≤ [`MAX_REGISTRY_FACTS`]，环形淘汰 + 去重，消费方须及时消费）。
    pub facts: Vec<[u8; 32]>,
    /// 已注册的 SNIP-36 对齐 fact
    /// （`poseidon([consumer_addr, 0, seg_len, output…])`；
    /// ≤ [`MAX_REGISTRY_FACTS`]，环形淘汰 + 去重）。
    pub facts_s36: Vec<[u8; 32]>,
    /// 各调用者的证明分块暂存（≤ [`MAX_STAGED_CALLERS`]，满员淘汰最旧）。
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
            // TODO(audit P2 2026-09)：保留 ID 公开下的 creator 抢跑竞态。
            // 主修复：genesis 预建钩子——`economics::genesis_mint_with_system_objects`
            // 在链初始化（及每次重启幂等重放）时种入 creator=首个 validator 的
            // 注册表对象。以下惰性初始化仅覆盖未走 genesis 的非标准部署/单测，
            // 此时首个调用者仍会成为 creator（见 creator_front_run_race_documented）。
            if existing.is_none() {
                tracing::warn!(
                    caller = ?caller,
                    "CairoFactRegistry 惰性初始化：首个调用者将成为永久 creator（creator 抢跑竞态残留路径，审计 P2；生产链应经 genesis 预建）"
                );
            }
            let mut state = existing.unwrap_or_else(|| CairoRegistryState {
                creator: *caller,
                ..CairoRegistryState::default()
            });
            if state.creator != *caller {
                return Err(PokerL1Error::Serialization(
                    "set_program_hash: caller is not registry creator".into(),
                ));
            }
            ring_push_dedup(&mut state.program_hashes, MAX_PROGRAM_HASHES, input.program_hash);
            write_registry(object_db, &registry_id, &state)?;
            result.modified_objects.push(registry_id);
        } else if method_selector == &selectors::set_snip36_consumer() {
            let input: SetSnip36ConsumerArgs = borsh::from_slice(args).map_err(|e| {
                PokerL1Error::Serialization(format!("set_snip36_consumer args: {e}"))
            })?;
            // 同 set_program_hash：惰性初始化是 creator 抢跑残留路径（见上方 TODO）。
            if existing.is_none() {
                tracing::warn!(
                    caller = ?caller,
                    "CairoFactRegistry 惰性初始化：首个调用者将成为永久 creator（creator 抢跑竞态残留路径，审计 P2；生产链应经 genesis 预建）"
                );
            }
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
            // P2 审计修复 2026-09：先全量校验，后落对象——被拒路径不得产生
            // 孤儿块对象；且不得借 submit 惰性绑 creator（旧实现首个 chunk
            // 提交者即成 creator，是比 set_program_hash 更廉价的抢跑入口）。
            if input.chunk.is_empty() || input.chunk.len() > MAX_CHUNK_BYTES {
                return Err(PokerL1Error::Serialization(format!(
                    "proof chunk size {} out of (0, {MAX_CHUNK_BYTES}]",
                    input.chunk.len()
                )));
            }
            let mut state = existing.ok_or_else(|| {
                PokerL1Error::Serialization(
                    "cairo registry not initialized (set_program_hash first)".into(),
                )
            })?;
            // 定位/腾出该 caller 的暂存槽：新 caller 满员时淘汰最旧 caller 的
            // 整个暂存（其块对象一并删除，避免孤儿堆积；devnet 语义——被打断
            // 的 prover abandon 后重传即可）。
            let owner_pos = match state.staged.iter().position(|s| s.owner == *caller) {
                Some(pos) => pos,
                None => {
                    evict_oldest_staged_if_full(object_db, &mut state);
                    state.staged.push(StagedProof { owner: *caller, chunk_ids: vec![] });
                    state.staged.len() - 1
                }
            };
            if state.staged[owner_pos].chunk_ids.len() >= MAX_PROOF_CHUNKS {
                return Err(PokerL1Error::Serialization(
                    "too many proof chunks (finalize or abandon first)".into(),
                ));
            }
            // 校验全部通过后才创建 Immutable 分块对象
            let chunk_id = ObjectID::new(
                *caller,
                chunk_nonce(&env.tx_hash, owner_pos, input.chunk.len()),
            );
            object_db.create(Object::new(
                chunk_id,
                Ownership::Immutable,
                CAIRO_PROOF_CHUNK_OBJECT_TYPE,
                input.chunk,
                None,
            ))?;
            result.created_objects.push(chunk_id);
            state.staged[owner_pos].chunk_ids.push(chunk_id);
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
            // P1 审计修复 2026-09：环形容量 + 去重——重复验证同一证明不膨胀
            // 状态；满容量淘汰最旧 fact（消费方须及时消费，见 MAX_REGISTRY_FACTS）。
            ring_push_dedup(&mut new_state.facts, MAX_REGISTRY_FACTS, fact_c);
            if let Some(f) = fact_s36 {
                ring_push_dedup(&mut new_state.facts_s36, MAX_REGISTRY_FACTS, f);
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

/// 环形插入（P1 审计修复 2026-09）：已存在则跳过（去重延缓增长），满容量
/// 则淘汰最旧后追加。
fn ring_push_dedup(list: &mut Vec<[u8; 32]>, cap: usize, value: [u8; 32]) {
    if list.contains(&value) {
        return;
    }
    if list.len() >= cap {
        list.remove(0);
    }
    list.push(value);
}

/// staged 满员时淘汰最旧调用者的整个暂存（块对象一并删除；删除失败容忍
/// ——孤儿对象不再被引用，不阻碍后续上传，与 abandon 同语义）。
fn evict_oldest_staged_if_full(
    object_db: &mut dyn ObjectBackend,
    state: &mut CairoRegistryState,
) {
    if state.staged.len() >= MAX_STAGED_CALLERS {
        if let Some(evicted) = state.staged.first().cloned() {
            for id in &evicted.chunk_ids {
                let _ = object_db.delete(id);
            }
        }
        state.staged.remove(0);
    }
}

/// 将（升级残留的）超限状态收敛到结构性上限：从最旧端截断各列表，并删除
/// 被淘汰 staged 调用者的块对象。
///
/// P1 审计修复 2026-09：旧版本无上限，升级前已越界的状态若不收敛，注册表
/// 会在 64KB 对象硬上限处永久砖化（连 abandon/finalize 都要写同一对象）。
fn clamp_state_to_caps(
    object_db: &mut dyn ObjectBackend,
    state: &mut CairoRegistryState,
) -> PokerL1Result<()> {
    if state.program_hashes.len() > MAX_PROGRAM_HASHES {
        let drop = state.program_hashes.len() - MAX_PROGRAM_HASHES;
        state.program_hashes.drain(..drop);
    }
    if state.facts.len() > MAX_REGISTRY_FACTS {
        let drop = state.facts.len() - MAX_REGISTRY_FACTS;
        state.facts.drain(..drop);
    }
    if state.facts_s36.len() > MAX_REGISTRY_FACTS {
        let drop = state.facts_s36.len() - MAX_REGISTRY_FACTS;
        state.facts_s36.drain(..drop);
    }
    while state.staged.len() > MAX_STAGED_CALLERS {
        evict_oldest_staged_if_full(object_db, state);
    }
    Ok(())
}

fn write_registry(
    object_db: &mut dyn ObjectBackend,
    id: &ObjectID,
    state: &CairoRegistryState,
) -> PokerL1Result<()> {
    // 收敛升级残留的超限状态（仅写路径触发；读方法无副作用）
    let mut state = state.clone();
    clamp_state_to_caps(object_db, &mut state)?;
    let data = borsh::to_vec(&state)
        .map_err(|e| PokerL1Error::Serialization(format!("encode cairo registry: {e}")))?;
    // fail-closed 兜底：结构性上限 + 编译期断言保证正常路径到不了这里；
    // 越界即拒绝写（对象层同样会在 64KB 拒绝，此处给出更早、更明确的错误）。
    if data.len() > MAX_OBJECT_SIZE {
        return Err(PokerL1Error::ObjectTooLarge {
            actual: data.len(),
            limit: MAX_OBJECT_SIZE,
        });
    }
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

// ============================================================
// genesis 预建钩子（P2 审计修复 2026-09：creator 抢跑）
// ============================================================

/// 从 genesis 系统对象（validator set）推导 operator 地址 = **首个
/// validator**（按加入顺序）的账户地址。
///
/// 由 `economics::genesis_mint_with_system_objects` 调用：链初始化时预建
/// 注册表对象并把 creator 钉扎到该地址，使保留 ID 上的"首调用者即 creator"
/// 抢跑不可行（攻击者无法把自己塞进 validator 列表的首位）。
pub(crate) fn genesis_creator_from_system_objects(
    chain_id: ChainId,
    system_objects: &[Object],
) -> Option<Address> {
    let object = system_objects
        .iter()
        .find(|o| crate::consensus::validator_set::is_validator_set_object(o))?;
    let set = crate::consensus::validator_set::decode_validator_set_object(object, chain_id).ok()?;
    let first = set.validators.first()?;
    Some(crate::account::derive_address(&first.pubkey))
}

/// genesis 预建的注册表对象：空状态 + creator 钉扎（Shared 保留对象）。
pub(crate) fn genesis_registry_object(creator: Address) -> PokerL1Result<Object> {
    let state = CairoRegistryState {
        creator,
        ..CairoRegistryState::default()
    };
    let data = borsh::to_vec(&state)
        .map_err(|e| PokerL1Error::Serialization(format!("encode cairo registry: {e}")))?;
    Ok(Object::new(
        reserved::cairo_registry_contract_id(),
        Ownership::Shared,
        CAIRO_REGISTRY_OBJECT_TYPE,
        data,
        None,
    ))
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

    // ============================================================
    // P1/P2 审计修复 2026-09：容量上限 / 先校验后写 / creator 抢跑
    // ============================================================

    use crate::object_model::{Object, Ownership};
    use crate::storage::ObjectDb;

    fn make_env(tx_hash: [u8; 32]) -> ExecutionEnvironment {
        ExecutionEnvironment {
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
            tx_inputs: vec![],
            tx_hash,
        }
    }

    fn make_actor(n: u8) -> (Address, TaggedPubkey) {
        (
            [n; 20],
            TaggedPubkey {
                tag: 0,
                raw: vec![n; 32],
            },
        )
    }

    fn pin_hash(
        pc: &CairoFactRegistryPrecompile,
        caller: &Address,
        pk: &TaggedPubkey,
        object_db: &mut ObjectDb,
        program_hash: [u8; 32],
    ) -> PokerL1Result<DispatchResult> {
        let args = borsh::to_vec(&SetProgramHashArgs { program_hash }).unwrap();
        pc.call(caller, pk, &selectors::set_program_hash(), &args, &make_env([0; 32]), object_db)
    }

    fn submit_chunk(
        pc: &CairoFactRegistryPrecompile,
        caller: &Address,
        pk: &TaggedPubkey,
        object_db: &mut ObjectDb,
        tx_hash: [u8; 32],
        chunk: &[u8],
    ) -> PokerL1Result<DispatchResult> {
        let args = borsh::to_vec(&SubmitProofChunkArgs { chunk: chunk.to_vec() }).unwrap();
        pc.call(caller, pk, &selectors::submit_proof_chunk(), &args, &make_env(tx_hash), object_db)
    }

    fn read_state(object_db: &ObjectDb) -> CairoRegistryState {
        let obj = object_db
            .read(&reserved::cairo_registry_contract_id())
            .expect("registry object");
        borsh::from_slice(&obj.data).expect("decode registry state")
    }

    /// (i) fact 超过环形容量：淘汰最旧、不报错；重复 fact 去重。
    #[test]
    fn facts_beyond_cap_evict_oldest_no_error() {
        // 值须跨 u8 回绕保持互异（i > 255 时 [i as u8; 32] 会碰撞导致去重
        // 短路，淘汰永远不触发）。
        let val = |i: usize| {
            let mut v = [0u8; 32];
            v[0] = i as u8;
            v[1] = (i >> 8) as u8;
            v
        };
        let mut list: Vec<[u8; 32]> = Vec::new();
        for i in 0..(MAX_REGISTRY_FACTS + 10) {
            ring_push_dedup(&mut list, MAX_REGISTRY_FACTS, val(i));
        }
        assert_eq!(list.len(), MAX_REGISTRY_FACTS, "环形容量必须钳制长度");
        assert_eq!(list[0], val(10), "最旧的 10 条被淘汰");
        assert_eq!(*list.last().unwrap(), val(MAX_REGISTRY_FACTS + 9));
        // 去重：重复 push 不增长
        let before = list.len();
        ring_push_dedup(&mut list, MAX_REGISTRY_FACTS, val(10));
        assert_eq!(list.len(), before, "已存在的 fact 不得重复追加");
    }

    /// (iii) 状态最坏序列化尺寸 < 64KB 对象硬上限（与编译期断言对拍）。
    #[test]
    fn worst_case_state_size_below_object_cap() {
        let mut state = CairoRegistryState {
            creator: [0xAB; 20],
            snip36_consumer: Some([0xCD; 32]),
            ..CairoRegistryState::default()
        };
        state.program_hashes = (0..MAX_PROGRAM_HASHES).map(|i| [i as u8; 32]).collect();
        state.facts = (0..MAX_REGISTRY_FACTS).map(|i| [i as u8; 32]).collect();
        state.facts_s36 = (0..MAX_REGISTRY_FACTS).map(|i| [i as u8; 32]).collect();
        let chunk_ids: Vec<ObjectID> =
            (0..MAX_PROOF_CHUNKS).map(|i| ObjectID::new([0x99; 20], i as u64)).collect();
        state.staged = (0..MAX_STAGED_CALLERS)
            .map(|i| StagedProof { owner: [i as u8; 20], chunk_ids: chunk_ids.clone() })
            .collect();
        let bytes = borsh::to_vec(&state).unwrap();
        assert_eq!(bytes.len(), MAX_REGISTRY_STATE_BYTES, "最坏尺寸须与常量推导一致");
        assert!(
            bytes.len() + 4 * 1024 <= MAX_OBJECT_SIZE,
            "最坏尺寸须 < 64KB 且留 ≥ 4KB 余量：{}",
            bytes.len()
        );
    }

    /// (ii) submit_proof_chunk 先校验后写：caller 已达块数上限时，拒绝路径
    /// **不得**产生任何新对象（无孤儿块）。
    #[test]
    fn submit_proof_chunk_at_cap_creates_no_object() {
        let pc = CairoFactRegistryPrecompile::new(1);
        let (caller, pk) = make_actor(0x01);
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        pin_hash(&pc, &caller, &pk, &mut object_db, [0x11; 32]).unwrap();
        let base_objects = object_db.iter().count();
        // 填满 MAX_PROOF_CHUNKS
        for i in 0..MAX_PROOF_CHUNKS as u64 {
            let tx_hash = [i as u8 + 1; 32]; // 每块独立 tx_hash → 独立 nonce
            let result =
                submit_chunk(&pc, &caller, &pk, &mut object_db, tx_hash, &[0x42, 0x43]).unwrap();
            assert_eq!(result.created_objects.len(), 1);
        }
        assert_eq!(object_db.iter().count(), base_objects + MAX_PROOF_CHUNKS);
        // 第 33 块被拒：无新对象、无注册表写入
        let before = object_db.iter().count();
        let err = submit_chunk(&pc, &caller, &pk, &mut object_db, [0xEE; 32], &[0x42])
            .expect_err("超过单证明块数上限必须被拒");
        assert!(err.to_string().contains("too many proof chunks"));
        assert_eq!(
            object_db.iter().count(),
            before,
            "拒绝路径不得创建任何对象（created_objects 为空且对象库不变）"
        );
        // 块尺寸越界同样先拒后写
        let oversized = vec![0x00; MAX_CHUNK_BYTES + 1];
        assert!(submit_chunk(&pc, &caller, &pk, &mut object_db, [0xEF; 32], &oversized).is_err());
        assert_eq!(object_db.iter().count(), before);
    }

    /// submit_proof_chunk 不得惰性绑 creator：注册表未初始化时直接拒绝。
    #[test]
    fn submit_proof_chunk_requires_initialized_registry() {
        let pc = CairoFactRegistryPrecompile::new(1);
        let (attacker, pk) = make_actor(0x02);
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        let err = submit_chunk(&pc, &attacker, &pk, &mut object_db, [0x01; 32], &[0x01])
            .expect_err("未初始化注册表必须拒绝 chunk 上传");
        assert!(err.to_string().contains("not initialized"));
        assert!(
            object_db.read(&reserved::cairo_registry_contract_id()).is_err(),
            "chunk 提交不得创建注册表对象（更不得绑 creator）"
        );
    }

    /// staged 调用者环形淘汰：第 MAX_STAGED_CALLERS+1 个 caller 落位时，
    /// 最旧 caller 的暂存与其块对象一并被清。
    #[test]
    fn staged_caller_ring_eviction_beyond_cap() {
        let pc = CairoFactRegistryPrecompile::new(1);
        let (creator, creator_pk) = make_actor(0x09);
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        pin_hash(&pc, &creator, &creator_pk, &mut object_db, [0x11; 32]).unwrap();
        let (first, first_pk) = make_actor(0x10);
        let first_result =
            submit_chunk(&pc, &first, &first_pk, &mut object_db, [0x10; 32], &[0x55]).unwrap();
        let first_chunk_id = first_result.created_objects[0];
        assert!(object_db.read(&first_chunk_id).is_ok());
        // 再灌 MAX_STAGED_CALLERS - 1 个 caller（连同 first 共满员）
        for n in 0x11u8..(0x10 + MAX_STAGED_CALLERS as u8) {
            let (caller, pk) = make_actor(n);
            submit_chunk(&pc, &caller, &pk, &mut object_db, [n; 32], &[0x56]).unwrap();
        }
        assert_eq!(read_state(&object_db).staged.len(), MAX_STAGED_CALLERS);
        // 新 caller 触发淘汰：first 的暂存与块对象被清
        let (newcomer, newcomer_pk) = make_actor(0x7A);
        submit_chunk(&pc, &newcomer, &newcomer_pk, &mut object_db, [0x7A; 32], &[0x57]).unwrap();
        let state = read_state(&object_db);
        assert_eq!(state.staged.len(), MAX_STAGED_CALLERS, "容量恒定");
        assert!(
            state.staged.iter().all(|s| s.owner != first),
            "最旧 caller 的暂存被淘汰"
        );
        assert!(
            state.staged.iter().any(|s| s.owner == newcomer),
            "新 caller 已落位"
        );
        assert!(
            object_db.read(&first_chunk_id).is_err(),
            "被淘汰 caller 的块对象必须删除（避免孤儿堆积）"
        );
    }

    /// 升级残留的超限状态在写路径被收敛到结构性上限（自愈，防 64KB 砖化）。
    #[test]
    fn oversized_legacy_state_clamped_on_write() {
        let pc = CairoFactRegistryPrecompile::new(1);
        let (creator, creator_pk) = make_actor(0x03);
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        // 直接注入旧版本可产生的越界状态
        let mut legacy = CairoRegistryState {
            creator,
            snip36_consumer: Some([0x0E; 32]),
            ..CairoRegistryState::default()
        };
        legacy.program_hashes = (0..MAX_PROGRAM_HASHES + 4).map(|i| [i as u8; 32]).collect();
        legacy.facts = (0..MAX_REGISTRY_FACTS + 44).map(|i| [i as u8; 32]).collect();
        legacy.facts_s36 = (0..MAX_REGISTRY_FACTS + 44).map(|i| [i as u8; 32]).collect();
        legacy.staged = (0..MAX_STAGED_CALLERS + 5)
            .map(|i| StagedProof { owner: [i as u8; 20], chunk_ids: vec![] })
            .collect();
        object_db
            .create(Object::new(
                reserved::cairo_registry_contract_id(),
                Ownership::Shared,
                CAIRO_REGISTRY_OBJECT_TYPE,
                borsh::to_vec(&legacy).unwrap(),
                None,
            ))
            .unwrap();
        // creator 写入触发收敛，不报错
        pin_hash(&pc, &creator, &creator_pk, &mut object_db, [0x33; 32]).unwrap();
        let state = read_state(&object_db);
        assert_eq!(state.program_hashes.len(), MAX_PROGRAM_HASHES);
        assert_eq!(state.facts.len(), MAX_REGISTRY_FACTS);
        assert_eq!(state.facts_s36.len(), MAX_REGISTRY_FACTS);
        assert_eq!(state.staged.len(), MAX_STAGED_CALLERS);
        // 淘汰发生在最旧端
        assert_eq!(state.facts[0], [44u8; 32], "最旧 44 条 fact 被淘汰");
        assert!(state.facts.contains(&[(MAX_REGISTRY_FACTS + 43) as u8; 32]));
    }

    /// (1d) creator 抢跑竞态（残留路径的文档化测试）：未走 genesis 预建的
    /// 非标准部署里，首个 `set_program_hash` 调用者成为永久 creator——
    /// 攻击者抢在 operator 之前即可劫持。生产链由 genesis 钩子预建
    /// creator=首个 validator（见 genesis_creator_from_first_validator），
    /// 使本测试描述的竞态不可达。
    #[test]
    fn creator_front_run_race_documented() {
        let pc = CairoFactRegistryPrecompile::new(1);
        let (attacker, attacker_pk) = make_actor(0xE0);
        let (operator, operator_pk) = make_actor(0x0F);
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        // 抢跑：攻击者先调用惰性初始化路径
        pin_hash(&pc, &attacker, &attacker_pk, &mut object_db, [0x11; 32]).unwrap();
        assert_eq!(read_state(&object_db).creator, attacker, "残留路径：首调用者即 creator");
        // operator 随后被永久拒绝
        let err = pin_hash(&pc, &operator, &operator_pk, &mut object_db, [0x12; 32])
            .expect_err("非 creator 必须被拒");
        assert!(err.to_string().contains("not registry creator"));
    }

    /// (1d 主修复) genesis 预建：creator = 首个 validator 的地址；
    /// 预建后 operator（=首 validator）可钉扎，其他人被拒。
    #[test]
    fn genesis_creator_from_first_validator() {
        use crate::consensus::validator_set::{
            ValidatorSet, VALIDATOR_SET_OBJECT_ID, VALIDATOR_SET_OBJECT_TYPE,
        };
        use crate::consensus::{ValidatorEntry, ValidatorStatus};

        let (operator, operator_pk) = make_actor(0x21);
        // make_actor 的地址是占位 [n;20]，与 derive_address(&pk) 不同；
        // genesis creator 取派生地址，故 caller 必须用同一派生值。
        let operator: Address = crate::account::derive_address(&operator_pk);
        let entry = ValidatorEntry {
            pubkey: operator_pk.clone(),
            vrf_pubkey: [0x02; 33],
            stake: 0,
            status: ValidatorStatus::Active,
            bonding_until_height: 0,
            unbonding_until_height: 0,
            last_vertex_height: 0,
            under_investigation_count: 0,
            vrf_key_destroyed: false,
            vrf_retired: false,
        };
        let mut set = ValidatorSet {
            epoch: 0,
            validators: vec![entry],
            validator_set_hash: [0u8; 32],
            epoch_randomness: [7u8; 32],
            prev_epoch_randomness: [0u8; 32],
            genesis_chain_randomness: [7u8; 32],
        };
        set.validator_set_hash = set.compute_hash();
        let vs_object = crate::consensus::validator_set::validator_set_object(1, &set, 0).unwrap();
        assert_eq!(vs_object.id, VALIDATOR_SET_OBJECT_ID);
        assert_eq!(vs_object.object_type, VALIDATOR_SET_OBJECT_TYPE);

        // 无系统对象 → 不预建（回退惰性路径）
        assert_eq!(genesis_creator_from_system_objects(1, &[]), None);
        // 有 validator set → creator = 首 validator 地址
        assert_eq!(
            genesis_creator_from_system_objects(1, &[vs_object.clone()]),
            Some(crate::account::derive_address(&operator_pk))
        );

        // 预建对象种入后：operator（首 validator）可写，攻击者被拒
        let registry = genesis_registry_object(crate::account::derive_address(&operator_pk))
            .unwrap();
        assert_eq!(registry.id, reserved::cairo_registry_contract_id());
        assert_eq!(registry.object_type, CAIRO_REGISTRY_OBJECT_TYPE);
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        object_db.create(registry).unwrap();
        let pc = CairoFactRegistryPrecompile::new(1);
        let (attacker, attacker_pk) = make_actor(0xE1);
        let err = pin_hash(&pc, &attacker, &attacker_pk, &mut object_db, [0x11; 32])
            .expect_err("genesis 预建后抢跑者必须被拒");
        assert!(err.to_string().contains("not registry creator"));
        pin_hash(&pc, &operator, &operator_pk, &mut object_db, [0x22; 32]).unwrap();
        assert!(read_state(&object_db).program_hashes.contains(&[0x22; 32]));
    }
}
