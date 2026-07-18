//! 交易执行引擎（P0 修复 — C-3：state_root 接入交易执行）。
//!
//! 参考 `solana_rbpf` 执行模型（加载 → 验证 → metering 执行 → 状态提交），
//! 将 block 内 tx 按通道路由执行并提交状态变更：
//!
//! - **Public / ForceSync 通道**：account nonce 校验 + gas 计费（`apply_public_tx`）。
//!   `contract_call` 走 rBPF [`execute_contract`]；`outputs` 直接创建对象。
//! - **GameTurn / CheckpointAnchor 通道**：免 gas。原生游戏合约 dispatch
//!   属 P0 第二批（P0-5），骨架期无 `contract_call` 的此类 tx 返回
//!   `success=false`（fail-closed，不产生任何状态变更）。
//!
//! # 安全设计
//!
//! - 执行前重跑完整校验链（limits / chain_id / 签名 / nonce），纵深防御：
//!   即使 RPC / P2P 入口校验被绕过，执行层仍拒绝非法 tx。
//! - rBPF 合约状态提交**全有或全无**：先在内存中校验所有待写对象
//!   （存在性 + 所有权 + 大小），全部通过后才落 `ObjectDb`；任一失败则
//!   整个 tx 状态不变。
//! - 执行失败的 tx **不扣 gas、不推进 nonce**（MVP 语义，与既有
//!   `apply_public_tx` 仅在成功后调用一致）。已知局限：失败 tx 免费，
//!   后续硬化版本将引入 failed-tx 扣费。
//! - 创建对象校验 `ObjectID.creator_address == caller`，防止冒名创建。
//! - block 级 gas 累计超过 `block_gas_limit` 的 tx 跳过执行（状态不变）。
//!
//! # 确定性
//!
//! 同一组有序 tx + 同一初始状态 → 同一 `state_root`。出块方与验证方
//! 均通过 [`execute_block`] 得出 `state_root` 并比对（P0-2 接入）。

use crate::account::{AccountStore, apply_public_tx, derive_address, validate_public_tx};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::offline::zk_verifier::ZkVerifierRegistry;
use crate::storage::ObjectDb;
use crate::transaction::{Transaction, TxLane, validate_tx_limits};
use crate::vm::context::{PokerL1Context, TxContext};
use crate::vm::gas_table::{BLOCK_GAS_LIMIT, MAX_OBJECT_SIZE, TX_GAS_LIMIT};
use crate::vm::contracts::{dispatch, DispatchContext, DispatchResult, GameContract};
use crate::vm::{ContractObject, execute_contract, load_contract_bytecode, PrecompileRegistry};
use crate::block::validator::{validate_tx_chain_id, validate_tx_signature};
use crate::{BlockHeight, ChainId, Hash, TimestampMs};
use std::sync::Arc;

/// 执行环境（block 级上下文）。
#[derive(Debug, Clone)]
pub struct ExecutionEnvironment {
    /// 网络 chain_id（SEC-L4）。
    pub chain_id: ChainId,
    /// 当前 block height。
    pub block_height: BlockHeight,
    /// 当前 block timestamp（毫秒）。
    pub block_timestamp: TimestampMs,
    /// block gas 上限（默认 [`BLOCK_GAS_LIMIT`] = 50M）。
    pub block_gas_limit: u64,
    /// ZK verifier 注册表（合约内 `zk_verify` syscall 使用；`None` 时该 syscall 报错）。
    pub zk_verifier: Option<ZkVerifierRegistry>,
    /// 预编译合约注册表（用于路由预编译合约调用）。
    pub precompile_registry: Option<Arc<PrecompileRegistry>>,
}

impl ExecutionEnvironment {
    /// 创建执行环境（使用默认 block gas limit）。
    #[must_use]
    pub fn new(chain_id: ChainId, block_height: BlockHeight, block_timestamp: TimestampMs) -> Self {
        Self {
            chain_id,
            block_height,
            block_timestamp,
            block_gas_limit: BLOCK_GAS_LIMIT,
            zk_verifier: None,
            precompile_registry: None,
        }
    }

    /// 注入 ZK verifier 注册表（builder 模式）。
    #[must_use]
    pub fn with_zk_verifier(mut self, registry: ZkVerifierRegistry) -> Self {
        self.zk_verifier = Some(registry);
        self
    }

    /// 注入预编译合约注册表（builder 模式）。
    #[must_use]
    pub fn with_precompile_registry(mut self, registry: PrecompileRegistry) -> Self {
        self.precompile_registry = Some(Arc::new(registry));
        self
    }

    /// 覆盖 block gas limit（测试用）。
    #[must_use]
    pub const fn with_block_gas_limit(mut self, limit: u64) -> Self {
        self.block_gas_limit = limit;
        self
    }
}

/// 单笔 tx 执行回执。
#[derive(Debug, Clone)]
pub struct TxReceipt {
    /// tx 哈希（`signing_hash`，含 chain_id 域）。
    pub tx_hash: Hash,
    /// tx 通道。
    pub lane: TxLane,
    /// 是否执行成功（状态变更仅在 success=true 时提交）。
    pub success: bool,
    /// 失败原因（success=false 时为 `Some`）。
    pub error: Option<String>,
    /// 实际消耗 gas（GameTurn 通道恒为 0；失败 tx 为 0）。
    pub gas_used: u64,
    /// 实际收取费用（= gas_used，与既有 `apply_public_tx` 语义一致）。
    pub fee_charged: u64,
    /// 本 tx 创建的对象 ID。
    pub created_objects: Vec<ObjectID>,
    /// 本 tx 修改的对象 ID。
    pub modified_objects: Vec<ObjectID>,
}

impl TxReceipt {
    /// 构造失败回执（无 gas、无状态变更）。
    fn failure(tx: &Transaction, err: &PokerL1Error) -> Self {
        Self {
            tx_hash: tx.signing_hash(),
            lane: tx.lane_hint,
            success: false,
            error: Some(err.to_string()),
            gas_used: 0,
            fee_charged: 0,
            created_objects: Vec::new(),
            modified_objects: Vec::new(),
        }
    }
}

/// Block 执行结果。
#[derive(Debug, Clone)]
pub struct BlockExecutionOutcome {
    /// 每笔 tx 的回执（与输入顺序一致）。
    pub receipts: Vec<TxReceipt>,
    /// 执行全部 tx 后的全局状态根（ObjectDb SMT root）。
    pub state_root: Hash,
    /// block 累计消耗 gas（仅 Public / ForceSync 成功 tx）。
    pub total_gas_used: u64,
}

/// 执行单笔 tx（骨架版，P0-1）。
///
/// 失败语义：返回 `success=false` 的回执，**不产生任何状态变更**（不写对象、
/// 不推进 nonce、不扣 gas）。本函数本身不返回 `Err` —— 所有执行级错误都
/// 转化为回执，保证 block 内后续 tx 继续执行。
///
/// # 参数
///
/// - `env`：执行环境（chain_id / height / timestamp / gas limit / ZK registry）
/// - `tx`：待执行交易
/// - `object_db`：对象数据库（直接可变引用，由调用方持有锁）
/// - `account_store`：账户存储
pub fn execute_tx(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    object_db: &mut ObjectDb,
    account_store: &mut AccountStore,
) -> TxReceipt {
    match execute_tx_inner(env, tx, object_db, account_store) {
        Ok(receipt) => receipt,
        Err(err) => TxReceipt::failure(tx, &err),
    }
}

/// `execute_tx` 内部实现（错误向上传播，由外层转为失败回执）。
fn execute_tx_inner(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    object_db: &mut ObjectDb,
    account_store: &mut AccountStore,
) -> PokerL1Result<TxReceipt> {
    // ===== 1. 防御性重校验（limits / chain_id / 签名）=====
    validate_tx_limits(tx)?;
    validate_tx_chain_id(tx, env.chain_id)?;
    validate_tx_signature(tx)?;

    let caller = derive_address(&tx.tagged_pubkey);
    let is_gameturn = matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor);

    // ===== 2. 账户与 nonce / 余额预检（Public / ForceSync）=====
    if !is_gameturn {
        let account = account_store
            .get(&caller)
            .ok_or_else(|| {
                PokerL1Error::Other(format!("account not found for caller {caller:?}"))
            })?;
        validate_public_tx(account, tx, env.chain_id)?;
        // 费用预检：fee = gas_used ≤ budget，余额必须覆盖 budget
        if account.balance < tx.gas.budget {
            return Err(PokerL1Error::InsufficientBalance {
                needed: tx.gas.budget,
                has: account.balance,
            });
        }
    }

    // ===== 3. 分通道执行 =====
    let mut all_created: Vec<ObjectID> = Vec::new();
    let mut all_modified: Vec<ObjectID> = Vec::new();
    let mut gas_used: u64 = 0;

    if let Some(call) = &tx.contract_call {
        // 优先检查预编译合约注册表（参考以太坊预编译合约设计）
        if let Some(registry) = &env.precompile_registry {
            if registry.is_precompile(call.contract_id) {
                let precompile_env = crate::vm::precompile::ExecutionEnvironment {
                    chain_id: env.chain_id,
                    block_height: env.block_height,
                    block_timestamp: env.block_timestamp,
                };
                let selector: [u8; 32] = call.method_selector
                    .try_into()
                    .map_err(|e| PokerL1Error::Serialization(format!("method_selector: {e}")))?;
                let dispatch_result = registry.execute(
                    call.contract_id,
                    &caller,
                    &tx.tagged_pubkey,
                    &selector,
                    &call.args,
                    &precompile_env,
                    object_db,
                )?;
                all_created.extend(dispatch_result.created_objects);
                all_modified.extend(dispatch_result.modified_objects);
            } else {
                // 非预编译合约，走 rBPF 执行
                let (created, modified, used) = execute_contract_call(env, tx, &caller, call, object_db)?;
                all_created.extend(created);
                all_modified.extend(modified);
                gas_used = used;
            }
        } else {
            // 无预编译注册表，所有合约调用走 rBPF
            let (created, modified, used) = execute_contract_call(env, tx, &caller, call, object_db)?;
            all_created.extend(created);
            all_modified.extend(modified);
            gas_used = used;
        }
    } else if is_gameturn {
        return Err(PokerL1Error::Other("GameTurn native dispatch not yet implemented".to_string()));
    }

    // tx.outputs 直接创建（与 contract_call 创建的对象并列）。
    let outputs_created = apply_tx_outputs(tx, &caller, object_db)?;
    all_created.extend(outputs_created);

    // ===== 4. 账户结算（仅 Public / ForceSync 成功后）=====
    let mut fee_charged = 0u64;
    if !is_gameturn {
        let account = account_store
            .get_mut(&caller)
            .ok_or_else(|| PokerL1Error::Other("account disappeared mid-execution".into()))?;
        apply_public_tx(account, tx, gas_used)?;
        fee_charged = gas_used;
    }

    Ok(TxReceipt {
        tx_hash: tx.signing_hash(),
        lane: tx.lane_hint,
        success: true,
        error: None,
        gas_used,
        fee_charged,
        created_objects: all_created,
        modified_objects: all_modified,
    })
}

/// 执行 rBPF 合约调用并提交状态（全有或全无）。
///
/// 返回 `(created_objects, modified_objects, gas_used)`。
fn execute_contract_call(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    caller: &crate::Address,
    call: &crate::transaction::ContractCall,
    object_db: &mut ObjectDb,
) -> PokerL1Result<(Vec<ObjectID>, Vec<ObjectID>, u64)> {
    // 1. 读取合约对象并反序列化 ContractObject
    let contract_obj = object_db.read(&call.contract_id).map_err(|e| match e {
        PokerL1Error::ObjectNotFound(_) => PokerL1Error::ContractNotFound(call.contract_id),
        other => other,
    })?;
    let contract: ContractObject = bcs::from_bytes(&contract_obj.data)
        .map_err(|e| PokerL1Error::Serialization(format!("ContractObject BCS: {e}")))?;
    if !contract.is_active {
        return Err(PokerL1Error::OldVersionNotCallable {
            contract_id: call.contract_id,
            version: contract.version,
        });
    }

    // 2. 加载 + RequisiteVerifier 验证字节码（IMPL-SEC-4：(1)）
    let loaded = load_contract_bytecode(&contract.bytecode, call.contract_id, contract.version)?;

    // 3. 构造执行上下文（gas：GameTurn 免费 / Public 按 budget，上限 TX_GAS_LIMIT）
    let is_gameturn = matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor);
    let gas_limit = if is_gameturn {
        u64::MAX
    } else {
        tx.gas.budget.min(TX_GAS_LIMIT)
    };
    let tx_ctx = TxContext {
        caller: *caller,
        caller_pubkey: tx.tagged_pubkey.clone(),
        chain_id: env.chain_id,
        nonce: tx.nonce,
        block_height: env.block_height,
        block_timestamp: env.block_timestamp,
        is_gameturn,
    };
    let mut ctx = PokerL1Context::new(tx_ctx, gas_limit);
    if let Some(registry) = &env.zk_verifier {
        ctx = ctx.with_zk_verifier(registry.clone());
    }

    // 4. 预加载输入对象到 object_cache（contract_id 不预载，防止合约改写自身字节码对象）
    for id in &tx.inputs {
        let obj = object_db.read(id)?; // ObjectNotFound 直接失败
        ctx.object_cache.insert(*id, obj.data);
    }

    // 5. 执行（input = method_selector || args，合约自行解析）
    let mut input = Vec::with_capacity(call.method_selector.len() + call.args.len());
    input.extend_from_slice(&call.method_selector);
    input.extend_from_slice(&call.args);
    let result = execute_contract(&loaded, &mut ctx, &input)?;

    // 6. 全有或全无提交：先校验全部待写对象，再落库
    commit_object_cache(object_db, caller, &ctx)?;

    Ok((result.created_objects, result.modified_objects, result.gas_used))
}

/// 将合约执行后的 `object_cache` 提交到 `ObjectDb`（全有或全无）。
///
/// 阶段 1（只读校验）：所有待更新对象必须存在、caller 可写、数据 ≤ 64KB；
/// 所有待创建对象必须不存在（防碰撞）。
/// 阶段 2（写入）：校验全部通过后才落库。
fn commit_object_cache(
    object_db: &mut ObjectDb,
    caller: &crate::Address,
    ctx: &PokerL1Context,
) -> PokerL1Result<()> {
    // ----- 阶段 1：只读校验 -----
    for (id, data) in &ctx.object_cache {
        if data.len() > MAX_OBJECT_SIZE {
            return Err(PokerL1Error::ObjectTooLarge {
                actual: data.len(),
                limit: MAX_OBJECT_SIZE,
            });
        }
        if ctx.created_objects.contains(id) {
            if object_db.read(id).is_ok() {
                return Err(PokerL1Error::ObjectIDCollision(*id));
            }
        } else {
            let existing = object_db.read(id)?;
            if !existing.can_write(caller) {
                return Err(PokerL1Error::NotOwner(*id));
            }
        }
    }

    // ----- 阶段 2：写入 -----
    for (id, data) in &ctx.object_cache {
        if ctx.created_objects.contains(id) {
            let object = Object::new(
                *id,
                Ownership::AddressOwned { owner: *caller },
                "Generic",
                data.clone(),
                None,
            );
            object_db.create(object)?;
        } else {
            object_db.update(id, caller, data.clone())?;
        }
    }
    Ok(())
}

/// 创建 `tx.outputs` 中的对象。
///
/// 校验：creator 必须等于 caller（防冒名创建）、data ≤ 64KB、无 ID 碰撞。
/// 返回创建的对象 ID 列表。
fn apply_tx_outputs(
    tx: &Transaction,
    caller: &crate::Address,
    object_db: &mut ObjectDb,
) -> PokerL1Result<Vec<ObjectID>> {
    // 只读预检（全有或全无）
    for obj in &tx.outputs {
        if obj.id.creator_address != *caller {
            return Err(PokerL1Error::Other(format!(
                "output object creator {:?} != caller {:?}",
                obj.id.creator_address, caller
            )));
        }
        if obj.data.len() > MAX_OBJECT_SIZE {
            return Err(PokerL1Error::ObjectTooLarge {
                actual: obj.data.len(),
                limit: MAX_OBJECT_SIZE,
            });
        }
        if object_db.read(&obj.id).is_ok() {
            return Err(PokerL1Error::ObjectIDCollision(obj.id));
        }
    }

    let mut created = Vec::with_capacity(tx.outputs.len());
    for obj in &tx.outputs {
        object_db.create(obj.clone())?;
        created.push(obj.id);
    }
    Ok(created)
}

/// 执行一个 block 的有序 tx 序列，返回回执与执行后状态根。
///
/// - 逐笔执行，失败 tx 仅记录回执，不中断后续 tx。
/// - block gas 累计（`receipt.gas_used`）超过 `env.block_gas_limit` 后，
///   后续需 gas 的 tx 跳过执行（回执标记 `OutOfGas`），免 gas tx 不受影响。
/// - 返回的 `state_root` 为全部 tx 执行后的 `ObjectDb` SMT root。
pub fn execute_block(
    env: &ExecutionEnvironment,
    txs: &[Transaction],
    object_db: &mut ObjectDb,
    account_store: &mut AccountStore,
) -> BlockExecutionOutcome {
    let mut receipts = Vec::with_capacity(txs.len());
    let mut total_gas: u64 = 0;

    for tx in txs {
        let needs_gas = !matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor);
        if needs_gas && total_gas.saturating_add(tx.gas.budget.min(TX_GAS_LIMIT)) > env.block_gas_limit
        {
            receipts.push(TxReceipt::failure(
                tx,
                &PokerL1Error::OutOfGas {
                    used: total_gas,
                    limit: env.block_gas_limit,
                },
            ));
            continue;
        }
        let receipt = execute_tx(env, tx, object_db, account_store);
        // 仅 gas 计费通道的成功 tx 累计 block gas（GameTurn 免 gas，不计入）
        if receipt.success && needs_gas {
            total_gas = total_gas.saturating_add(receipt.gas_used);
        }
        receipts.push(receipt);
    }

    BlockExecutionOutcome {
        receipts,
        state_root: object_db.state_root(),
        total_gas_used: total_gas,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CHAIN_ID;
    use crate::account::Account;
    use crate::object_model::{Object, Ownership};
    use crate::signature::TaggedPubkey;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{ContractCall, Gas, RouteHint, TxRequest};
    use rand::rngs::OsRng;
    use secp256k1::{Message, Secp256k1};

    // ===== 测试辅助：最小 ELF 构造 =====

    /// BPF `mov64 r0, 0` 指令（8 字节）。
    const BPF_MOV0: [u8; 8] = [0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    /// BPF `exit` 指令（8 字节）。
    const BPF_EXIT: [u8; 8] = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    /// 构造 `n` 条 `mov64 r0, 0` + `exit` 的 BPF 程序。
    fn make_program(n_movs: usize) -> Vec<u8> {
        let mut text = Vec::with_capacity((n_movs + 1) * 8);
        for _ in 0..n_movs {
            text.extend_from_slice(&BPF_MOV0);
        }
        text.extend_from_slice(&BPF_EXIT);
        text
    }

    /// 手工构造最小合法 ELF64（EM_BPF / ET_DYN / SBPF V1），
    /// 含 `.text`（BPF 指令）与 `.shstrtab` 两个 section。
    ///
    /// 布局：`[ELF header 64B][.text][.shstrtab][3 × section header 64B]`。
    /// SBPF V1 要求 `.text` 的 `sh_addr == sh_offset`（`reject_broken_elfs`），
    /// 且 `e_entry` 落在 `.text` 的 vm_range 内（取 offset 0）。
    fn build_test_elf(text: &[u8]) -> Vec<u8> {
        const EHDR_SIZE: usize = 64;
        const SHDR_SIZE: usize = 64;
        const EM_BPF: u16 = 247;
        const ET_DYN: u16 = 3;
        const SHT_PROGBITS: u32 = 1;
        const SHT_STRTAB: u32 = 3;
        const SHF_ALLOC_EXEC: u64 = 0x2 | 0x4;

        let shstrtab: &[u8] = b"\0.text\0.shstrtab\0";
        let text_off = EHDR_SIZE as u64;
        let strtab_off = text_off + text.len() as u64;
        // section header 表起始必须按 align_of::<Elf64Shdr>()=8 对齐（解析器硬校验）
        let shoff = (strtab_off + shstrtab.len() as u64).next_multiple_of(8);

        let mut elf = Vec::with_capacity(shoff as usize + 3 * SHDR_SIZE);

        // ---- ELF header ----
        elf.extend_from_slice(&[0x7F, b'E', b'L', b'F']); // magic
        elf.push(2); // EI_CLASS = ELFCLASS64
        elf.push(1); // EI_DATA = ELFDATA2LSB
        elf.push(1); // EI_VERSION
        elf.push(0); // EI_OSABI = ELFOSABI_NONE
        elf.extend_from_slice(&[0u8; 8]); // EI_ABIVERSION + EI_PAD
        elf.extend_from_slice(&ET_DYN.to_le_bytes()); // e_type
        elf.extend_from_slice(&EM_BPF.to_le_bytes()); // e_machine
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&text_off.to_le_bytes()); // e_entry = .text 起始
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff（无 program header）
        elf.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags = 0（SBPF V1）
        elf.extend_from_slice(&(EHDR_SIZE as u16).to_le_bytes()); // e_ehsize
        // e_phentsize：解析器要求恒等于 sizeof(Elf64Phdr)=56（即使 e_phnum=0）
        elf.extend_from_slice(&56u16.to_le_bytes());
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&(SHDR_SIZE as u16).to_le_bytes()); // e_shentsize
        elf.extend_from_slice(&3u16.to_le_bytes()); // e_shnum
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_shstrndx

        // ---- .text ----
        elf.extend_from_slice(text);
        // ---- .shstrtab ----
        elf.extend_from_slice(shstrtab);
        // ---- 填充至 8 字节对齐 ----
        elf.resize(shoff as usize, 0);

        // ---- section header [0]：NULL ----
        elf.extend_from_slice(&[0u8; SHDR_SIZE]);
        // ---- section header [1]：.text ----
        elf.extend_from_slice(&1u32.to_le_bytes()); // sh_name = ".text"
        elf.extend_from_slice(&SHT_PROGBITS.to_le_bytes());
        elf.extend_from_slice(&SHF_ALLOC_EXEC.to_le_bytes());
        elf.extend_from_slice(&text_off.to_le_bytes()); // sh_addr == sh_offset（V1 硬约束）
        elf.extend_from_slice(&text_off.to_le_bytes()); // sh_offset
        elf.extend_from_slice(&(text.len() as u64).to_le_bytes()); // sh_size
        elf.extend_from_slice(&0u32.to_le_bytes()); // sh_link
        elf.extend_from_slice(&0u32.to_le_bytes()); // sh_info
        elf.extend_from_slice(&8u64.to_le_bytes()); // sh_addralign
        elf.extend_from_slice(&0u64.to_le_bytes()); // sh_entsize
        // ---- section header [2]：.shstrtab ----
        elf.extend_from_slice(&7u32.to_le_bytes()); // sh_name = ".shstrtab"
        elf.extend_from_slice(&SHT_STRTAB.to_le_bytes());
        elf.extend_from_slice(&0u64.to_le_bytes()); // sh_flags
        elf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
        elf.extend_from_slice(&strtab_off.to_le_bytes()); // sh_offset
        elf.extend_from_slice(&(shstrtab.len() as u64).to_le_bytes()); // sh_size
        elf.extend_from_slice(&0u32.to_le_bytes());
        elf.extend_from_slice(&0u32.to_le_bytes());
        elf.extend_from_slice(&1u64.to_le_bytes()); // sh_addralign
        elf.extend_from_slice(&0u64.to_le_bytes());

        elf
    }

    // ===== 测试辅助：签名者与交易构造 =====

    /// secp256k1 测试签名者。
    struct TestSigner {
        sk: secp256k1::SecretKey,
        pk: secp256k1::PublicKey,
    }

    impl TestSigner {
        fn new() -> Self {
            let secp = Secp256k1::new();
            let (sk, pk) = secp.generate_keypair(&mut OsRng);
            Self { sk, pk }
        }

        fn tagged_pubkey(&self) -> TaggedPubkey {
            TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: self.pk.serialize().to_vec(),
            }
        }

        fn address(&self) -> crate::Address {
            derive_address(&self.tagged_pubkey())
        }

        fn sign(&self, req: TxRequest) -> Transaction {
            let hash = req.signing_hash();
            let secp = Secp256k1::new();
            let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(hash), &self.sk);
            let (rid, compact) = sig.serialize_compact();
            let mut full_sig = compact.to_vec();
            full_sig.push(rid.to_i32() as u8);
            req.into_transaction(self.tagged_pubkey(), full_sig)
        }
    }

    /// 构造默认 Public 通道 TxRequest（budget=1_000_000, price=1）。
    fn public_request(nonce: u64) -> TxRequest {
        TxRequest {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            gas: Gas::new(1_000_000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    /// 构造 GameTurn 通道 TxRequest（免 gas）。
    fn gameturn_request() -> TxRequest {
        TxRequest {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            gas: Gas::zero(),
            lane_hint: TxLane::GameTurn,
            route_hint: RouteHint::AssignedValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: Some(0),
            is_fallback: false,
        }
    }

    /// 构造归属 `owner` 的输出对象。
    fn make_output(owner: crate::Address, creation_nonce: u64, data: &[u8]) -> Object {
        Object::new(
            ObjectID::new(owner, creation_nonce),
            Ownership::AddressOwned { owner },
            "TestOutput",
            data.to_vec(),
            None,
        )
    }

    /// 部署测试合约（以对象形式写入 ObjectDb），返回 contract_id。
    fn deploy_contract(
        object_db: &mut ObjectDb,
        caller: crate::Address,
        bytecode: Vec<u8>,
        creation_nonce: u64,
        is_active: bool,
    ) -> ObjectID {
        let contract_id = ObjectID::new(caller, creation_nonce);
        let mut contract = ContractObject::new(contract_id, 1, bytecode, caller, 0);
        contract.is_active = is_active;
        let data = bcs::to_bytes(&contract).expect("序列化 ContractObject");
        let obj = Object::new(
            contract_id,
            Ownership::AddressOwned { owner: caller },
            "Contract",
            data,
            None,
        );
        object_db.create(obj).expect("写入合约对象");
        contract_id
    }

    fn make_env() -> ExecutionEnvironment {
        ExecutionEnvironment::new(DEFAULT_CHAIN_ID, 100, 1_000_000)
    }

    /// 基础 fixture：空 ObjectDb + 含 signer 账户（balance=1_000_000）的 AccountStore。
    struct Fixture {
        object_db: ObjectDb,
        account_store: AccountStore,
        signer: TestSigner,
        initial_root: crate::Hash,
    }

    impl Fixture {
        fn new() -> Self {
            let object_db = ObjectDb::open_inmemory().expect("打开内存 ObjectDb");
            let mut account_store = AccountStore::new();
            let signer = TestSigner::new();
            let account = Account::new(signer.tagged_pubkey(), 1_000_000);
            account_store.create(account).expect("创建账户");
            let initial_root = object_db.state_root();
            Self {
                object_db,
                account_store,
                signer,
                initial_root,
            }
        }

        fn caller(&self) -> crate::Address {
            self.signer.address()
        }

        fn account(&self) -> &Account {
            self.account_store
                .get(&self.caller())
                .expect("账户必须存在")
        }
    }

    /// 断言状态未变（state_root 与账户 nonce/balance 均不变）。
    fn assert_state_unchanged(fx: &Fixture, nonce_before: u64, balance_before: u64) {
        assert_eq!(
            fx.object_db.state_root(),
            fx.initial_root,
            "失败 tx 不得改变 state_root"
        );
        let account = fx.account_store.get(&fx.caller());
        if let Some(acc) = account {
            assert_eq!(acc.nonce, nonce_before, "失败 tx 不得推进 nonce");
            assert_eq!(acc.balance, balance_before, "失败 tx 不得扣费");
        }
    }

    // ===== execute_tx 正向路径 =====

    #[test]
    fn test_execute_tx_outputs_success() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();

        let mut req = public_request(0);
        req.outputs = vec![
            make_output(caller, 0, b"obj0"),
            make_output(caller, 1, b"obj1"),
        ];
        let tx = fx.signer.sign(req);
        let expected_hash = tx.signing_hash();

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(receipt.success, "应执行成功: {:?}", receipt.error);
        assert_eq!(receipt.tx_hash, expected_hash);
        assert_eq!(receipt.lane, TxLane::Public);
        assert_eq!(receipt.gas_used, 0, "无合约调用时 gas_used 为 0");
        assert_eq!(receipt.fee_charged, 0);
        assert_eq!(receipt.created_objects.len(), 2);
        assert!(receipt.error.is_none());

        // 对象已创建且 state_root 改变
        assert_ne!(fx.object_db.state_root(), fx.initial_root);
        for id in &receipt.created_objects {
            fx.object_db.read(id).expect("对象应已创建");
        }
        // nonce 推进
        assert_eq!(fx.account().nonce, 1);
        assert_eq!(fx.account().balance, 1_000_000);
    }

    #[test]
    fn test_execute_tx_contract_call_success() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1)); // mov r0,0; exit
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);
        let root_after_deploy = fx.object_db.state_root();

        let mut req = public_request(0);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(receipt.success, "应执行成功: {:?}", receipt.error);
        assert!(
            receipt.gas_used >= 2,
            "至少消耗 mov+exit 两条指令 gas: {}",
            receipt.gas_used
        );
        assert_eq!(receipt.fee_charged, receipt.gas_used);
        // 余额扣费 + nonce 推进
        assert_eq!(fx.account().balance, 1_000_000 - receipt.gas_used);
        assert_eq!(fx.account().nonce, 1);
        // 空 object_cache → 无状态变更
        assert_eq!(fx.object_db.state_root(), root_after_deploy);
    }

    #[test]
    fn test_execute_tx_gameturn_contract_call_gas_free() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);

        let mut req = gameturn_request();
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(receipt.success, "GameTurn 合约调用应成功: {:?}", receipt.error);
        assert_eq!(receipt.gas_used, 0, "GameTurn 免 gas");
        assert_eq!(receipt.fee_charged, 0);
        // 账户不被触碰（GameTurn 不走 account nonce）
        assert_eq!(fx.account().nonce, 0);
        assert_eq!(fx.account().balance, 1_000_000);
    }

    #[test]
    fn test_execute_tx_gameturn_without_contract_fail_closed() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let tx = fx.signer.sign(gameturn_request());
        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(!receipt.success, "骨架期游戏原生 tx 应 fail-closed");
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("not yet implemented")),
            "错误应说明 dispatch 未实现: {:?}",
            receipt.error
        );
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    // ===== execute_tx 反向路径：防御性重校验 =====

    #[test]
    fn test_execute_tx_wrong_chain_id() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let mut req = public_request(0);
        req.chain_id = DEFAULT_CHAIN_ID + 1;
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("chain_id") || e.contains("chain id")),
            "错误应为 WrongChainId: {:?}",
            receipt.error
        );
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_invalid_signature() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let mut tx = fx.signer.sign(public_request(0));
        tx.signature[0] ^= 0x01; // 篡改签名

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_nonce_too_high() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let tx = fx.signer.sign(public_request(5)); // account.nonce = 0
        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("nonce")),
            "错误应为 nonce 不匹配: {:?}",
            receipt.error
        );
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_nonce_replay_rejected() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();

        let mut req = public_request(0);
        req.outputs = vec![make_output(caller, 0, b"obj0")];
        let tx = fx.signer.sign(req);

        // 第一次执行成功
        let r1 = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(r1.success);
        let root_after_first = fx.object_db.state_root();

        // 重放同一 tx → NonceTooLow
        let r2 = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!r2.success, "重放 tx 必须被拒绝");
        assert_eq!(
            fx.object_db.state_root(),
            root_after_first,
            "重放失败后状态不变"
        );
        assert_eq!(fx.account().nonce, 1);
    }

    #[test]
    fn test_execute_tx_insufficient_balance() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let mut req = public_request(0);
        req.gas = Gas::new(2_000_000, 1); // budget > balance(1_000_000)
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("balance") || e.contains("insufficient")),
            "错误应为余额不足: {:?}",
            receipt.error
        );
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_account_not_found() {
        let object_db = ObjectDb::open_inmemory().expect("打开内存 ObjectDb");
        let mut object_db = object_db;
        let mut account_store = AccountStore::new(); // 空账户库
        let env = make_env();
        let signer = TestSigner::new();
        let initial_root = object_db.state_root();

        let tx = signer.sign(public_request(0));
        let receipt = execute_tx(&env, &tx, &mut object_db, &mut account_store);

        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("account not found")),
            "错误应为账户不存在: {:?}",
            receipt.error
        );
        assert_eq!(object_db.state_root(), initial_root);
    }

    // ===== execute_tx 反向路径：合约调用 =====

    #[test]
    fn test_execute_tx_contract_not_found() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let mut req = public_request(0);
        req.contract_call = Some(ContractCall {
            contract_id: ObjectID::new(fx.caller(), 999), // 不存在
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("contract not found")),
            "错误应为 ContractNotFound: {:?}",
            receipt.error
        );
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_invalid_contract_bytecode() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        // 部署垃圾字节码合约
        let contract_id = deploy_contract(
            &mut fx.object_db,
            caller,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            100,
            true,
        );
        let root_after_deploy = fx.object_db.state_root();

        let mut req = public_request(0);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("bytecode") || e.contains("ELF")),
            "错误应为 InvalidBytecode: {:?}",
            receipt.error
        );
        // 部署后的 root 不变（执行无效果）
        assert_eq!(fx.object_db.state_root(), root_after_deploy);
        assert_eq!(fx.account().nonce, 0, "失败 tx 不推进 nonce");
    }

    #[test]
    fn test_execute_tx_inactive_contract_rejected() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, false); // is_active=false

        let mut req = public_request(0);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("no longer callable")),
            "错误应为 OldVersionNotCallable: {:?}",
            receipt.error
        );
        assert_eq!(fx.account().nonce, 0);
    }

    #[test]
    fn test_execute_tx_input_object_not_found() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);
        let root_after_deploy = fx.object_db.state_root();

        let mut req = public_request(0);
        req.inputs = vec![ObjectID::new(caller, 999)]; // 输入对象不存在
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("object not found")),
            "错误应为 ObjectNotFound: {:?}",
            receipt.error
        );
        assert_eq!(fx.object_db.state_root(), root_after_deploy);
        assert_eq!(fx.account().nonce, 0);
    }

    #[test]
    fn test_execute_tx_out_of_gas() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        // 101 条指令的程序，budget=10 → 第 11 条指令处 gas 耗尽
        let elf = build_test_elf(&make_program(100));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);
        let root_after_deploy = fx.object_db.state_root();

        let mut req = public_request(0);
        req.gas = Gas::new(10, 1);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("out of gas")),
            "错误应为 OutOfGas: {:?}",
            receipt.error
        );
        assert_eq!(receipt.gas_used, 0, "失败 tx 不计费（MVP 语义）");
        // 状态不变：nonce 不推进、不扣费、state_root 不变
        assert_eq!(fx.object_db.state_root(), root_after_deploy);
        assert_eq!(fx.account().nonce, 0);
        assert_eq!(fx.account().balance, 1_000_000);
    }

    // ===== execute_tx 反向路径：outputs 创建 =====

    #[test]
    fn test_execute_tx_output_creator_mismatch() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let mut req = public_request(0);
        // 输出对象 creator 是别人 → 冒名创建
        req.outputs = vec![make_output([0xAA; 20], 0, b"forged")];
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("creator")),
            "错误应为 creator 不匹配: {:?}",
            receipt.error
        );
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_output_id_collision_atomic() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();

        // 预创建对象（将与第二个输出碰撞）
        let collision_id = ObjectID::new(caller, 42);
        fx.object_db
            .create(make_output(caller, 42, b"existing"))
            .expect("预创建对象");
        let root_after_pre = fx.object_db.state_root();

        let mut req = public_request(0);
        req.outputs = vec![
            make_output(caller, 0, b"new_obj"),   // 本可成功
            make_output(caller, 42, b"collides"), // 碰撞
        ];
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        // 全有或全无：第一个对象也不得创建
        assert!(
            fx.object_db.read(&ObjectID::new(caller, 0)).is_err(),
            "碰撞时整个 tx 不得产生任何对象"
        );
        // 已有对象数据未被覆盖
        let existing = fx.object_db.read(&collision_id).expect("已有对象仍在");
        assert_eq!(existing.data, b"existing");
        assert_eq!(fx.object_db.state_root(), root_after_pre);
        assert_eq!(fx.account().nonce, 0);
    }

    #[test]
    fn test_execute_tx_output_too_large() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);
        let caller = fx.caller();

        let mut req = public_request(0);
        req.outputs = vec![make_output(caller, 0, &vec![0u8; MAX_OBJECT_SIZE + 1])];
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("too large")),
            "错误应为 ObjectTooLarge: {:?}",
            receipt.error
        );
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    // ===== execute_block =====

    #[test]
    fn test_execute_block_mixed_txs() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);

        // tx1：outputs 创建（成功）
        let mut req1 = public_request(0);
        req1.outputs = vec![make_output(caller, 0, b"obj0")];
        let tx1 = fx.signer.sign(req1);

        // tx2：合约调用（成功，消耗 gas）
        let mut req2 = public_request(1);
        req2.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx2 = fx.signer.sign(req2);

        // tx3：签名被篡改（失败）
        let mut tx3 = fx.signer.sign(public_request(2));
        tx3.signature[0] ^= 0x01;

        let outcome = execute_block(&env, &[tx1, tx2, tx3], &mut fx.object_db, &mut fx.account_store);

        assert_eq!(outcome.receipts.len(), 3);
        assert!(outcome.receipts[0].success);
        assert!(outcome.receipts[1].success);
        assert!(!outcome.receipts[2].success, "篡改签名的 tx 应失败");

        // block gas 仅累计成功且需 gas 的 tx
        assert_eq!(outcome.total_gas_used, outcome.receipts[1].gas_used);
        assert!(outcome.total_gas_used > 0);

        // state_root 与 ObjectDb 一致；仅成功 tx 的变更可见
        assert_eq!(outcome.state_root, fx.object_db.state_root());
        fx.object_db
            .read(&ObjectID::new(caller, 0))
            .expect("tx1 的对象应存在");
        // nonce 仅被成功 tx 推进两次
        assert_eq!(fx.account().nonce, 2);
    }

    #[test]
    fn test_execute_block_gas_limit_skips_public_not_gameturn() {
        let mut fx = Fixture::new();
        // block_gas_limit=100：tx1(budget=60) 执行，tx2(budget=99) 超出跳过
        let env = make_env().with_block_gas_limit(100);
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);

        let mut req1 = public_request(0);
        req1.gas = Gas::new(60, 1);
        req1.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx1 = fx.signer.sign(req1);

        let mut req2 = public_request(1);
        req2.gas = Gas::new(99, 1);
        req2.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [1u8; 32],
            args: vec![],
        });
        let tx2 = fx.signer.sign(req2);

        // GameTurn tx（免 gas）：即使 block gas 受限仍执行
        let mut req3 = gameturn_request();
        req3.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [2u8; 32],
            args: vec![],
        });
        let tx3 = fx.signer.sign(req3);

        let outcome = execute_block(&env, &[tx1, tx2, tx3], &mut fx.object_db, &mut fx.account_store);

        assert_eq!(outcome.receipts.len(), 3);
        assert!(outcome.receipts[0].success, "tx1 应执行成功");
        assert!(!outcome.receipts[1].success, "tx2 应被 block gas limit 跳过");
        assert!(
            outcome.receipts[1]
                .error
                .as_deref()
                .is_some_and(|e| e.contains("out of gas")),
            "tx2 错误应为 OutOfGas: {:?}",
            outcome.receipts[1].error
        );
        assert!(
            outcome.receipts[2].success,
            "GameTurn 免 gas tx 不受 block gas limit 影响: {:?}",
            outcome.receipts[2].error
        );
        assert_eq!(outcome.receipts[2].gas_used, 0);
        // block gas 仅含 tx1 的消耗
        assert_eq!(outcome.total_gas_used, outcome.receipts[0].gas_used);
        // tx2 未推进 nonce：tx1 一次 + tx3 不走 account nonce
        assert_eq!(fx.account().nonce, 1);
    }

    #[test]
    fn test_execute_block_deterministic_state_root() {
        // 同一 signer + 同一 tx 序列 + 两个全新状态 → 相同 state_root
        let signer = TestSigner::new();
        let caller = signer.address();
        let elf = build_test_elf(&make_program(2));

        let run = || {
            let mut object_db = ObjectDb::open_inmemory().expect("打开内存 ObjectDb");
            let mut account_store = AccountStore::new();
            account_store
                .create(Account::new(signer.tagged_pubkey(), 1_000_000))
                .expect("创建账户");
            let contract_id = deploy_contract(&mut object_db, caller, elf.clone(), 100, true);

            let mut req1 = public_request(0);
            req1.outputs = vec![make_output(caller, 0, b"obj0")];
            let tx1 = signer.sign(req1);

            let mut req2 = public_request(1);
            req2.contract_call = Some(ContractCall {
                contract_id,
                method_selector: [0u8; 32],
                args: vec![1, 2, 3],
            });
            let tx2 = signer.sign(req2);

            let env = make_env();
            execute_block(&env, &[tx1, tx2], &mut object_db, &mut account_store)
        };

        let outcome1 = run();
        let outcome2 = run();

        assert_eq!(
            outcome1.state_root, outcome2.state_root,
            "相同输入必须产生相同 state_root（出块/验证确定性）"
        );
        assert_eq!(outcome1.total_gas_used, outcome2.total_gas_used);
        assert!(outcome1.receipts.iter().all(|r| r.success));
    }

    #[test]
    fn test_execute_block_empty() {
        let mut fx = Fixture::new();
        let env = make_env();
        let outcome = execute_block(&env, &[], &mut fx.object_db, &mut fx.account_store);

        assert!(outcome.receipts.is_empty());
        assert_eq!(outcome.total_gas_used, 0);
        assert_eq!(outcome.state_root, fx.initial_root, "空 block 状态根不变");
    }
}
