//! settlement-adapter — 链无关结算适配器 trait（多结算层架构的形式化接口）。
//!
//! 设计目标（docs/plan-multi-settlement-architecture.md）：**新增一条结算链 =
//! 实现一个 [`SettlementAdapter`]**，引擎（poker-appchain / daemon / 钱包买入
//! 链路）零改动。四个职责面与 poker-appchain 的承诺产出一一对应：
//!
//! | trait 方法 | 承诺产物（L2 侧） | 宿主侧落点 |
//! | --- | --- | --- |
//! | [`SettlementAdapter::submit_anchor`] | batch_root / aggregate_root / checkpoint | 各链 Inbox（EVM: L1Inbox；Solana: Anchor program） |
//! | [`SettlementAdapter::poll`] | — | 回执 + 最终性推进（EVM: finalized 标签；Solana: finalized commitment） |
//! | [`SettlementAdapter::poll_deposits`] | DepositV2 op（deposit_id 幂等） | 各链 Bridge（EVM: L1Bridge 事件；Solana: 程序事件） |
//! | [`SettlementAdapter::claim_calldata`] | withdrawal_root + Merkle proof | 各链 Outbox（EVM: L1Outbox.claim；Solana: claim 指令） |
//!
//! 字节纪律：**payload 是不透明字节**——适配器不解释内容，承诺语义由
//! poker-appchain / poker_texas_air 冻结（borsh 紧凑编码、域分隔哈希）。
//! 这使同一份承诺产物可以无缝换宿主链。

use serde::{Deserialize, Serialize};

/// 结算锚定数据类型（与 L2 侧承诺产物一一对应）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    /// 批次根（ProofPipeline per-batch）。
    Batch,
    /// 聚合根（批次根二级折叠）。
    Aggregate,
    /// checkpoint（state root + 可选提现根，BFT finalized 产物）。
    Checkpoint,
}

impl AnchorKind {
    /// 去重 key 前缀（跨链通用；最终 key = prefix + 根 hex 由调用方拼装）。
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Batch => "batch",
            Self::Aggregate => "aggregate",
            Self::Checkpoint => "checkpoint",
        }
    }
}

/// 上锚任务（链无关；`payload` = 该链适配器自己的调用编码产物）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorTask {
    /// 幂等 key（建议 = kind.prefix() + ":" + root hex；跨重启/跨链去重）。
    pub key: String,
    /// 锚定类型。
    pub kind: AnchorKind,
    /// 宿主调用载荷（EVM = calldata；Solana = instruction data）。适配器不解释。
    pub payload: Vec<u8>,
    /// gas/计算预算上界（EVM gas；Solana CU。0 = 适配器默认值）。
    pub budget: u64,
}

impl AnchorTask {
    /// 快捷构造（budget=0 → 适配器默认）。
    #[must_use]
    pub fn new(key: String, kind: AnchorKind, payload: Vec<u8>) -> Self {
        Self { key, kind, payload, budget: 0 }
    }
}

/// 交易标识（32B；EVM tx hash / Solana signature 同形）。
pub type TxId = [u8; 32];

/// 上锚状态机：Submitted →（回执）→ Included →（最终性）→ Finalized。
///
/// 语义与各宿主链对齐：
/// - Submitted：已广播、未确认；
/// - Included：已打包（EVM receipt / Solana confirmed）；
/// - Finalized：不可逆（EVM `finalized` 标签 / Solana finalized commitment）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorState {
    /// 已广播，未确认。
    Submitted {
        /// 交易标识。
        tx: TxId,
    },
    /// 已打包，等最终性。
    Included {
        /// 交易标识。
        tx: TxId,
        /// 打包高度。
        block: u64,
    },
    /// 已终结（不可逆）。
    Finalized {
        /// 交易标识。
        tx: TxId,
        /// 打包高度。
        block: u64,
    },
}

impl AnchorState {
    /// 交易标识。
    #[must_use]
    pub fn tx(&self) -> TxId {
        match self {
            Self::Submitted { tx } | Self::Included { tx, .. } | Self::Finalized { tx, .. } => *tx,
        }
    }

    /// 打包高度（Submitted → None）。
    #[must_use]
    pub fn block(&self) -> Option<u64> {
        match self {
            Self::Submitted { .. } => None,
            Self::Included { block, .. } | Self::Finalized { block, .. } => Some(*block),
        }
    }

    /// 是否已终结。
    #[must_use]
    pub fn is_finalized(&self) -> bool {
        matches!(self, Self::Finalized { .. })
    }
}

/// 入金记录（宿主链 → L2 铸 note 的触发源）。
///
/// `token` 32B 兼容两种地址形态：EVM 低 20B（零填充）与 Solana 32B pubkey；
/// `[u8;20] = token`（原生币语义）由各链适配器定义（EVM: address(0)）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositRecord {
    /// 宿主侧幂等序号（单调递增；L2 侧 deposit_id 原料）。
    pub nonce: u64,
    /// 资产标识（32B：EVM 地址零填充 / Solana mint pubkey；EVM 原生 = 全零）。
    pub token: [u8; 32],
    /// L2 收款人（32B 投影；EVM 低 20B）。
    pub recipient: [u8; 32],
    /// 锁仓金额（最小单位）。
    pub amount: u128,
    /// 入金所在宿主高度（审计/重放定位）。
    pub host_block: u64,
}

/// 强制包含记录（宿主链 escape channel；L2 引擎必须按 seq 升序消费）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedOpRecord {
    /// 宿主侧单调序号（审查审计的排序基准）。
    pub seq: u64,
    /// 提交者（32B 投影；可为代办方，操作语义里的账户以 payload 为准）。
    pub submitter: [u8; 32],
    /// L2 操作字节（poker-appchain borsh Operation；适配器不解释）。
    pub payload: Vec<u8>,
    /// 宿主高度。
    pub host_block: u64,
}

/// 适配器错误（链无关；各实现把链上错误映射到通用类别）。
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// 宿主 RPC/传输失败（可重试）。
    #[error("host transport ({method}): {message}")]
    Transport {
        /// 出错的方法面（诊断）。
        method: String,
        /// 描述。
        message: String,
    },
    /// 链身份不符（防错链，fail-closed）。
    #[error("chain id mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch {
        /// 期望。
        expected: u64,
        /// 实际。
        actual: u64,
    },
    /// 该链未配置所需设施（如 bridge 地址缺失 → 买入不可用）。
    #[error("not configured on this host: {0}")]
    NotConfigured(String),
    /// 其他实现内部错误。
    #[error("adapter error: {0}")]
    Other(String),
}

/// 链无关结算适配器（**新增一条结算链 = 实现本 trait**）。
///
/// 实现约束：
/// 1. `connect` 必须做链身份校验（`chain_id` 不符 → [`AdapterError::ChainIdMismatch`]，
///    fail-closed，防错链全流程—— Monad 侧已有先例实现）；
/// 2. `submit_anchor` 按 `task.key` 幂等：已存在 → 返回 `Ok(None)`，不重复广播；
/// 3. `poll` 单轮推进所有未终结项（回执 + 最终性），失败不中断其余项；
/// 4. `poll_deposits` 只产出**已终结**的入金（宿主 reorg 窗口由实现负责消化）；
/// 5. 快照/恢复：`snapshot()` 序列化友好，`restore()` 幂等合并（重启不重放）。
pub trait SettlementAdapter: Send {
    /// 宿主链身份（chainId / genesis hash 等；connect 时已校验）。
    fn chain_id(&self) -> u64;

    /// 链族标签（诊断/UI：如 "monad" / "solana"；engine 不据此分支业务）。
    fn host(&self) -> &'static str;

    /// 连接并校验链身份。
    ///
    /// # Errors
    /// chainId 不符 / 传输失败。
    fn connect(&mut self) -> Result<(), AdapterError>;

    /// 提交上锚任务（key 已存在 → 幂等跳过返回 `None`）。
    ///
    /// # Errors
    /// 传输失败 / 签名失败。
    fn submit_anchor(&mut self, task: &AnchorTask) -> Result<Option<TxId>, AdapterError>;

    /// 一轮推进：回执确认 + 最终性推进。
    ///
    /// # Errors
    /// 传输失败（实现应保证单条失败不影响其余项）。
    fn poll(&mut self) -> Result<(), AdapterError>;

    /// 未终结项数量（daemon 退出条件 / 告警面）。
    fn pending_finality(&self) -> usize;

    /// 状态快照（daemon 持久化；JSON 友好）。
    fn snapshot(&self) -> serde_json::Value;

    /// 恢复快照（幂等合并；重启续跑）。
    fn restore(&mut self, snapshot: &serde_json::Value);

    /// 拉取已终结的入金（一轮；内部水位推进 + nonce 去重）。
    ///
    /// # Errors
    /// 传输失败 / 事件解析失败（fail-closed）。
    fn poll_deposits(&mut self) -> Result<Vec<DepositRecord>, AdapterError>;

    /// 构建提现领取的宿主调用载荷（引擎不解释字节；由适配器按链编码）。
    ///
    /// # Errors
    /// 该链未配置 claim 面（如 PLAY 类资产不可跨链兑付）。
    fn claim_payload(&self, request: &ClaimRequest) -> Result<Vec<u8>, AdapterError>;

    /// 拉取已终结的强制包含操作（escape channel；一轮，seq 升序）。
    ///
    /// 默认实现 = 空流（该链未实现 escape 面时安全缺省；引擎侧审计按
    /// `host()` 报告"该链无强制包含面"而非静默丢失）。
    ///
    /// # Errors
    /// 传输失败 / 事件解析失败（fail-closed）。
    fn poll_forced_ops(&mut self) -> Result<Vec<ForcedOpRecord>, AdapterError> {
        Ok(Vec::new())
    }
}

/// 提现领取请求（链无关字段；与 poker-appchain `WithdrawalLeaf` 一一对应）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// 提现请求幂等键。
    pub request_id: [u8; 32],
    /// 外部收款地址（32B 投影）。
    pub recipient: [u8; 32],
    /// 资产标签（1=原生 / 3=USDT / 4=USDC；2=PLAY 不可跨链）。
    pub asset_tag: u8,
    /// 打款净额。
    pub amount: u64,
    /// 被销毁 note 承诺。
    pub burned_note_commitment: [u8; 32],
    /// 承载 checkpoint 高度。
    pub checkpoint_height: u64,
    /// 提现根（Merkle 根；窗口 root）。
    pub withdrawal_root: [u8; 32],
    /// 窗口真实叶子数。
    pub leaf_count: u64,
    /// 叶子在规范化树中的位置。
    pub leaf_index: u64,
    /// Merkle 兄弟路径（自叶向根）。
    pub proof: Vec<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 假适配器：验证 trait 契约（幂等/状态机/快照往返）——任何实现必须满足。
    struct FakeAdapter {
        connected: bool,
        states: std::collections::BTreeMap<String, AnchorState>,
        deposits: Vec<DepositRecord>,
        deposits_drained: bool,
    }

    impl FakeAdapter {
        fn new() -> Self {
            Self {
                connected: false,
                states: std::collections::BTreeMap::new(),
                deposits: vec![DepositRecord {
                    nonce: 1,
                    token: [0u8; 32],
                    recipient: [9u8; 32],
                    amount: 100,
                    host_block: 42,
                }],
                deposits_drained: false,
            }
        }
    }

    impl SettlementAdapter for FakeAdapter {
        fn chain_id(&self) -> u64 {
            10143
        }

        fn host(&self) -> &'static str {
            "fake"
        }

        fn connect(&mut self) -> Result<(), AdapterError> {
            self.connected = true;
            Ok(())
        }

        fn submit_anchor(&mut self, task: &AnchorTask) -> Result<Option<TxId>, AdapterError> {
            if !self.connected {
                return Err(AdapterError::Other("not connected".into()));
            }
            if self.states.contains_key(&task.key) {
                return Ok(None);
            }
            let tx = [task.key.len() as u8; 32];
            self.states.insert(task.key.clone(), AnchorState::Submitted { tx });
            Ok(Some(tx))
        }

        fn poll(&mut self) -> Result<(), AdapterError> {
            let keys: Vec<String> = self.states.keys().cloned().collect();
            for key in keys {
                let state = self.states.get(&key).cloned();
                match state {
                    Some(AnchorState::Submitted { tx }) => {
                        self.states.insert(key, AnchorState::Included { tx, block: 7 });
                    }
                    Some(AnchorState::Included { tx, block }) => {
                        self.states.insert(key, AnchorState::Finalized { tx, block });
                    }
                    _ => {}
                }
            }
            Ok(())
        }

        fn pending_finality(&self) -> usize {
            self.states.values().filter(|s| !s.is_finalized()).count()
        }

        fn snapshot(&self) -> serde_json::Value {
            serde_json::json!({ "states": self.states.len(), "drained": self.deposits_drained })
        }

        fn restore(&mut self, snapshot: &serde_json::Value) {
            if let Some(n) = snapshot.get("states").and_then(serde_json::Value::as_u64) {
                self.states.clear();
                for i in 0..n {
                    self.states.insert(
                        format!("restored-{i}"),
                        AnchorState::Finalized { tx: [0; 32], block: i },
                    );
                }
            }
        }

        fn poll_deposits(&mut self) -> Result<Vec<DepositRecord>, AdapterError> {
            if self.deposits_drained {
                return Ok(Vec::new());
            }
            self.deposits_drained = true;
            Ok(std::mem::take(&mut self.deposits))
        }

        fn claim_payload(&self, request: &ClaimRequest) -> Result<Vec<u8>, AdapterError> {
            if request.asset_tag == 2 {
                return Err(AdapterError::NotConfigured("PLAY not claimable".into()));
            }
            Ok(request.request_id.to_vec())
        }

        fn poll_forced_ops(&mut self) -> Result<Vec<ForcedOpRecord>, AdapterError> {
            if self.deposits_drained {
                return Ok(Vec::new());
            }
            self.deposits_drained = true;
            Ok(vec![ForcedOpRecord {
                seq: 0,
                submitter: [7u8; 32],
                payload: vec![0x01, 0x02],
                host_block: 43,
            }])
        }
    }

    #[test]
    fn trait_contract_submit_idempotent_and_state_machine() {
        let mut a = FakeAdapter::new();
        assert!(matches!(a.submit_anchor(&AnchorTask::new("k".into(), AnchorKind::Batch, vec![])), Err(AdapterError::Other(_))));
        a.connect().expect("connects");

        let task = AnchorTask::new("batch:0:aa".into(), AnchorKind::Batch, vec![1, 2, 3]);
        let tx = a.submit_anchor(&task).expect("submits").expect("fresh");
        assert_eq!(tx, [10; 32]); // key "batch:0:aa".len() = 10
        // 幂等。
        assert!(a.submit_anchor(&task).expect("dedupe").is_none());
        assert_eq!(a.pending_finality(), 1);

        a.poll().expect("poll1");
        match &a.states["batch:0:aa"] {
            AnchorState::Included { block: 7, .. } => {}
            other => panic!("expected Included, got {other:?}"),
        }
        a.poll().expect("poll2");
        assert!(a.states["batch:0:aa"].is_finalized());
        assert_eq!(a.pending_finality(), 0);
    }

    #[test]
    fn trait_contract_deposits_drain_once_and_claim_gates() {
        let mut a = FakeAdapter::new();
        a.connect().expect("connects");
        let d = a.poll_deposits().expect("first drain");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].nonce, 1);
        assert!(a.poll_deposits().expect("second drain").is_empty());

        let req = ClaimRequest {
            request_id: [1; 32],
            recipient: [2; 32],
            asset_tag: 1,
            amount: 3,
            burned_note_commitment: [4; 32],
            checkpoint_height: 5,
            withdrawal_root: [6; 32],
            leaf_count: 1,
            leaf_index: 0,
            proof: vec![],
        };
        assert_eq!(a.claim_payload(&req).expect("native ok"), vec![1; 32]);
        let play = ClaimRequest { asset_tag: 2, ..req };
        assert!(matches!(a.claim_payload(&play), Err(AdapterError::NotConfigured(_))));
    }

    #[test]
    fn snapshot_restore_roundtrip() {
        let mut a = FakeAdapter::new();
        a.connect().expect("connects");
        let snap = a.snapshot();
        a.restore(&snap);
        assert!(a.snapshot()["drained"].as_bool() == Some(false));
        a.restore(&serde_json::json!({"states": 3}));
        assert_eq!(a.pending_finality(), 0); // 全 Finalized
        assert_eq!(a.states.len(), 3);
    }

    /// 不实现 escape 面的适配器：default poll_forced_ops 返回空流。
    struct NoEscapeAdapter(FakeAdapter);

    impl SettlementAdapter for NoEscapeAdapter {
        fn chain_id(&self) -> u64 {
            self.0.chain_id()
        }
        fn host(&self) -> &'static str {
            "fake-no-escape"
        }
        fn connect(&mut self) -> Result<(), AdapterError> {
            self.0.connect()
        }
        fn submit_anchor(&mut self, t: &AnchorTask) -> Result<Option<TxId>, AdapterError> {
            self.0.submit_anchor(t)
        }
        fn poll(&mut self) -> Result<(), AdapterError> {
            self.0.poll()
        }
        fn pending_finality(&self) -> usize {
            self.0.pending_finality()
        }
        fn snapshot(&self) -> serde_json::Value {
            self.0.snapshot()
        }
        fn restore(&mut self, s: &serde_json::Value) {
            self.0.restore(s)
        }
        fn poll_deposits(&mut self) -> Result<Vec<DepositRecord>, AdapterError> {
            self.0.poll_deposits()
        }
        fn claim_payload(&self, r: &ClaimRequest) -> Result<Vec<u8>, AdapterError> {
            self.0.claim_payload(r)
        }
        // poll_forced_ops：不 override → default 空流。
    }

    #[test]
    fn forced_ops_default_noop_and_override_paths() {
        // default：无 escape 面 → 空流（引擎按 host() 报告缺省，不静默丢失语义由引擎管）。
        let mut plain = NoEscapeAdapter(FakeAdapter::new());
        assert!(plain.poll_forced_ops().expect("default").is_empty());

        // override：按序产出并幂等。
        let mut a = FakeAdapter::new();
        a.connect().expect("connects");
        let ops = a.poll_forced_ops().expect("first");
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].seq, 0);
        assert_eq!(ops[0].payload, vec![1, 2]);
        assert!(a.poll_forced_ops().expect("second").is_empty());
    }

    #[test]
    fn anchor_kind_prefixes_stable() {
        assert_eq!(AnchorKind::Batch.prefix(), "batch");
        assert_eq!(AnchorKind::Aggregate.prefix(), "aggregate");
        assert_eq!(AnchorKind::Checkpoint.prefix(), "checkpoint");
    }
}
