//! M3：Sequencer——软确认应用引擎。
//!
//! 构造性无冲突（桌与桌 note 集合不相交）：**不需要 Block-STM**，只需要
//! nullifier 查重 + 桌级互斥（BTreeMap 天然互斥）。单 sequencer 串行应用，
//! 软确认 = 签名帧落 WAL + 内存状态更新，毫秒级。
//!
//! ## 应用管线（每笔操作，P0-4 原子提交）
//!
//! ```text
//! 限流 → 语义校验 + 试算（克隆态上 apply，真实状态零接触）
//!      → 帧签名 → WAL append + fsync（承诺点）→ 内存态原子换入
//! ```
//!
//! write-ahead 顺序：**先 WAL 后内存应用**。任何一步失败 = 整笔拒绝
//! （fail-closed）：试算失败则真实状态从未被接触；WAL 写/fsync 失败则
//! 试算态被丢弃，内存态/链/时间戳全部未动（内存与 WAL 不可能分叉）。
//! 重启后从 WAL 全量重放恢复。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write as _};
use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use starknet_crypto::poseidon_hash_many;

use crate::aggregate::AggregateRecord;
// TE-M1：v2 账本资产身份模型（迁移比对与余额分域聚合使用；v1 路径零变更）
use crate::asset_id::AssetId;
use crate::error::{AppchainError, AppchainResult};
use crate::fee::{FeePolicy, FeeRegistry};
use crate::felt::{bytes32_to_felts, felt_from_u64, felt_to_bytes32};
// TE-M3：GTS 游戏币标准（注册表 / 价带 / 发行模式 / 供给对账）
// TE-M6：桌级 GasPolicy + gas credit 计量账（Free 模式 gas 服务费）
use crate::game_token::{
    validate_rate, GameReconciliation, GasCreditLedger, GasPolicy, GameTokenRegistry,
    GameTokenSpec, GameSupplyReport, IssuanceMode, RateBand, RECONCILIATION_FORMAT,
};
use crate::keys::{blake2s32, spend_digest, SequencerKey};
use crate::merkle::PoseidonMerkleTree;
use crate::metrics::MetricsRegistry;
use crate::note::Note;
use crate::note_v2::{
    migration_nullifier, validate_settlement_v2, NoteV2, SettlementRecordV2, SettleInputV2,
};
use crate::nullifier_set::NullifierSet;
// TE-M2：追加变体载荷与 v2 提现 scope 标签（ DepositV2 / WithdrawRequestV2 ）
// TE-M3：GTS 三变体载荷（ RegisterGameToken / IssueGameToken / BurnGameToken ）
// TE-M6：Free 模式三变体载荷（ FaucetMint / BuyGasCredits / BindGasPolicy ）
use crate::ops::{
    scope, BindGasPolicyOp, BurnGameTokenOp, BuyGasCreditsOp, DepositV2Op, FaucetMintOp,
    IssueGameTokenOp, MigrateNoteOp, Operation, RegisterGameTokenOp, WithdrawRequestV2Op,
};
use crate::owner_v2::{
    check_envelope_freshness, owner_commitment, validate_envelope, validate_migrate_note,
    validate_migrate_note_structure, v2_spend_digest, verify_owner_signature, OwnerRef,
    VerifierMaterial, OWNER_V2_ABI_VERSION,
};
use crate::real_policy::{FinalityEvidence, WithdrawalProvenance};
// TE-M2：v2 提现 provenance（AssetId 粒度；定义在 vault，sequencer 只导出）
use crate::vault::WithdrawalProvenanceV2;
use crate::settlement::validate_settlement;
use crate::soft_confirm::{chain_head, SignedFrame, SoftConfirmFrame};
use crate::wal::WalWriter;

/// sequencer 配置。
#[derive(Debug, Clone)]
pub struct SequencerConfig {
    /// 桌准入只收 proven note（M8 污染防御；plan §M3）。
    pub admission_proven_only: bool,
    /// 每 principal 每分钟操作数（burst 同值）。
    pub ops_per_min: u32,
    /// 每 principal 每分钟开桌数（burst 同值）。
    pub open_table_per_min: u32,
    /// 单桌最大 seat note 数（容量限制）。
    pub max_seats: usize,
    /// 本链 network id（ABI v2：参与迁移记录与 v2 花费 scope 绑定，
    /// 防跨网重放；默认 devnet 值，生产网络必须显式覆盖）。
    pub network_id: [u8; 32],
    /// TE-M3：发行价带下界 R_min（治理参数，版本化；默认 =
    /// [`crate::game_token::RATE_MIN_DEFAULT`]）。**全网一致参数**：变更
    /// 必须同步所有重放方，否则边界注册的 WAL 重放分叉（fail-closed 暴露，
    /// 与 network_id 同纪律）。
    pub game_rate_min: u64,
    /// TE-M3：发行价带上界 R_max（成本覆盖推导 `1/(k·c), k≥5` 的治理
    /// 定版；默认 = [`crate::game_token::RATE_MAX_DEFAULT`]，B-TE-2）。
    pub game_rate_max: u64,
    /// TE-M6：每手摊薄运营成本估算 c_hand（以 GasPolicy 计价资产计；
    /// 成本覆盖校验 `fee_per_hand ≥ k·c_hand` 的配置输入）。**运营参数**
    /// ——真实计量（结算 gas + 证明成本 + 基础设施）/ 预期手数属部署面
    /// （B-TE-2 同源），非协议常量，如实标注。默认 0 = 覆盖强制未激活
    /// （诚实缺省；生产必须注入真实值）。**全网一致参数**：变更必须同步
    /// 所有重放方，否则边界绑定的 WAL 重放分叉（与 `game_rate_min/max`
    /// 同纪律）。
    pub gas_c_hand_estimate: u64,
    /// 洗牌/发牌证明链（ABI v1.3，SHUFFLE_CONSUME.md §3-1 排队项收口）：
    /// hand_binding **迁移窗**运营开关。false（默认）= 迁移窗开放（现状：
    /// Legacy/Unbound 绑定接受并计数）；true = 窗关闭（Legacy/Unbound 一律
    /// 拒绝，单轨 v2 deck 链绑定）。**additive 字段，默认 false = 现状**。
    /// 生效路径：进程启动时刻调用 [`Self::apply_settlement_gates`] 把本值
    /// 刻入 `settlement::set_full_chain_enforcement` 的进程级原子量——
    /// **replay / build_index / watcher 等重放面禁止调用**（见该方法文档：
    /// 重放确定性）。生产翻转点 = 生产者接线完成 + 全量结清 v1 存量。
    pub full_chain_enforcement: bool,
    /// 洗牌/发牌证明链（ABI v1.3）：路线 B **crypto receipt 门**。false
    /// （默认）= 关（现状：v2 记录不要求引擎回执）；true = 运营方承诺引擎
    /// 侧路线 A 原生验证（BG/DLEq 逐行 + 承诺链重导）与 receipt 归责
    /// （attestation v2.2）已接线——接线前开启 = v2 全链结算 fail-closed
    /// **停摆**（宁可停不可假）。**additive 字段，默认 false = 现状**。
    /// 生效路径同 [`Self::apply_settlement_gates`]（重放面禁止调用）。
    pub crypto_receipt_enforcement: bool,
    /// 合规运营化框架（排期表 §4b + TEC-v1；[`crate::compliance`]）：
    /// 版本化 geo_policy + 本部署市场代码。`None`（默认）= 合规门未启用
    /// （测试/预览部署口径；**持牌市场生产部署必须配置**，C-M1 出口）。
    /// **全网一致参数**：门在 apply 路径执行（WAL 重放同路径复核），变更
    /// 必须同步所有重放方，否则边界 op 重放分叉（与 `game_rate_min/max`
    /// 同纪律）。
    pub compliance: Option<crate::compliance::ComplianceParams>,
}

impl Default for SequencerConfig {
    fn default() -> Self {
        Self {
            admission_proven_only: true,
            ops_per_min: 600,
            open_table_per_min: 30,
            max_seats: 10,
            network_id: crate::note_v2::default_network_id(),
            // TE-M3：默认价带 = 设计 §3.2 参考值（围绕典型发行 1U = 100 万
            // 币上下各一个数量级）
            game_rate_min: crate::game_token::RATE_MIN_DEFAULT,
            game_rate_max: crate::game_token::RATE_MAX_DEFAULT,
            // TE-M6：默认 c_hand = 0（覆盖强制未激活的诚实缺省——部署面
            // 未配置成本数据时不做成本覆盖拒绝；生产必须显式注入）
            gas_c_hand_estimate: 0,
            // 洗牌/发牌证明链（ABI v1.3）：两门默认关 = 迁移窗开放 + 不要求
            // 引擎回执（既有 v1/v2 流量零回退的双轨迁移期语义）
            full_chain_enforcement: false,
            crypto_receipt_enforcement: false,
            // 合规门默认未启用（fail-closed 缺省在策略侧：配置了 policy 的
            // 市场，未显式放行的资产类全关）
            compliance: None,
        }
    }
}

impl SequencerConfig {
    /// 运营面接线（ABI v1.3，SHUFFLE_CONSUME.md §3-1 排队项收口）：把本
    /// 配置的 [`Self::full_chain_enforcement`] /
    /// [`Self::crypto_receipt_enforcement`] 刻入 settlement 模块的进程级
    /// fail-closed 原子量（`set_full_chain_enforcement` /
    /// `set_crypto_receipt_enforcement`）。
    ///
    /// **调用点纪律**：只准在进程**启动装配路径**调用一次（sequencer /
    /// 验证引擎 main）；[`Sequencer::replay`](crate::sequencer::Sequencer::replay)、
    /// `archive_index::build_index`、watcher 等重放面**禁止调用**——
    /// `validate_settlement` 在重放 apply 路径上执行，其判定必须与帧提交
    /// 时刻一致（WAL 重放确定性）：门随重放配置漂移会让含旧格式绑定的
    /// 历史 WAL 无法恢复（破坏 P0-4 重承诺）。
    pub fn apply_settlement_gates(&self) {
        // 逐行注明（TE 纪律）：两行均为"启动面 → 进程级原子量"的一次性
        // 刻入，不做读改写、无条件分支——配置即真相（source of truth）。
        crate::settlement::set_full_chain_enforcement(self.full_chain_enforcement);
        crate::settlement::set_crypto_receipt_enforcement(self.crypto_receipt_enforcement);
    }
}

/// note 状态：pending（软确认未证明）→ proven（批次已落证明）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteStatus {
    /// 已软确认，等待证明覆盖。
    Pending,
    /// 已被证明批次覆盖。
    Proven,
}

/// 账本中的 note 条目。
#[derive(Debug, Clone)]
pub struct NoteEntry {
    /// note 全量内容。
    pub note: Note,
    /// 承诺树叶索引。
    pub leaf_index: u64,
    /// 创建时的操作序号（= 帧链 index）。
    pub created_at_op: u64,
    /// 证明状态。
    pub status: NoteStatus,
}

/// 账本中的 v2 note 条目（ABI v2；v2 note 不进 v1 承诺树——独立账本，
/// 状态承诺经 [`LedgerState::root`] 的 v2 折叠段进入状态根）。
#[derive(Debug, Clone)]
pub struct NoteV2Entry {
    /// note 全量内容。
    pub note: NoteV2,
    /// 创建时的操作序号（= 帧链 index）。
    pub created_at_op: u64,
    /// 证明状态。
    pub status: NoteStatus,
}

/// 桌状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableState {
    /// 开放中。
    pub open: bool,
    /// 当前 seat note 数。
    pub seats: usize,
}

/// 令牌桶（每 principal）。
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_ms: u64,
}

/// 限流器。
#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: HashMap<[u8; 32], TokenBucket>,
}

impl RateLimiter {
    /// 判定并扣减一个令牌（不足则拒绝且不扣）。
    pub fn allow(&mut self, principal: &[u8; 32], now_ms: u64, rate_per_min: u32) -> bool {
        let rate = f64::from(rate_per_min);
        let b = self.buckets.entry(*principal).or_insert_with(|| TokenBucket {
            tokens: rate,
            last_ms: now_ms,
        });
        let elapsed_ms = now_ms.saturating_sub(b.last_ms);
        b.tokens = (b.tokens + elapsed_ms as f64 / 60_000.0 * rate).min(rate);
        b.last_ms = now_ms;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

    /// 账本状态（可重放重建；Clone 供提交路径克隆态试算，P0-4）。
    #[derive(Debug, Clone, Default)]
    pub struct LedgerState {
        /// notes：承诺字节 → 条目。
        pub notes: HashMap<[u8; 32], NoteEntry>,
        /// owner 二级索引（B5）：owner 压缩公钥 → 该 owner 名下 **live**
        /// note 承诺集合。纯性能结构（**不入状态根**，行为等价由
        /// `tests/proptests.rs::owner_index_matches_full_scan` 属性测试
        /// 钉住）：mint/consume 全路径（deposit/buy-in/settle payout+
        /// rake/transfer 输出/withdraw 销毁）经 [`Sequencer::mint_note`]/
        /// [`Sequencer::consume_note`] 同步维护，消费即移除（集合空则连
        /// owner 键一并删除，索引语义 == 对 `notes` 的全量扫描）。WAL 重放
        /// 复用同一 `apply_op` → mint/consume 路径，重启自然重建。
        pub owner_index: HashMap<[u8; 33], HashSet<[u8; 32]>>,
        /// note 承诺 → 铸出来源 op（§5.4 provenance 映射）。与
        /// [`NoteEntry::created_at_op`] 同源（`mint_note` 写入），但**消费后
        /// 不删除**——提现销毁后托管打款侧仍需查来源 op 过 finality 门；
        /// WAL 重放重建。
        pub note_origins: HashMap<[u8; 32], u64>,
        /// 承诺树。
        pub tree: PoseidonMerkleTree,
        /// nullifier 集。
        pub nullifiers: NullifierSet,
        /// 桌状态。
        pub tables: BTreeMap<u64, TableState>,
        /// 费率注册表（开桌冻结）。
        pub registry: FeeRegistry,
        /// 已结算 hand_binding。
        pub settled_bindings: HashSet<[u8; 32]>,
        /// 已处理充值幂等键。
        pub deposit_ids: HashSet<[u8; 32]>,
        /// 已接受提现幂等键。
        pub withdrawal_ids: HashSet<[u8; 32]>,
        /// 被销毁（提现）note 记录：(request_id, 面额)。
        pub burned: Vec<([u8; 32], u64)>,
        /// 已应用操作数（= 帧链 index 的下一个）。
        pub seq: u64,
        /// 证明水位：op index ≤ watermark 的产出 note 已被证明覆盖。只按**最大
        /// 连续前缀**推进（见 [`Sequencer::mark_proven`]）；不在 WAL 重放路径上
        /// ——崩溃重启后保守归零（note 回 Pending，桌准入重新拦截），由证明
        /// 管道对已验证批次重新回调恢复。
        pub proven_watermark: u64,
        /// v2 note 账本（ABI v2）：承诺字节 → 条目。BTreeMap 保证状态根
        /// 折叠的确定性（与 v1 HashMap+外部树不同，v2 无独立树，折叠序
        /// 即迭代序）。
        pub notes_v2: BTreeMap<[u8; 32], NoteV2Entry>,
        /// v2 owner 二级索引：owner_commitment（含 scheme/key_version）→
        /// 该 owner 名下 **live** v2 note 承诺集合。纯性能结构（不入状态
        /// 根），mint/consume_v2 全路径同步维护，消费即移除（语义 ==
        /// 对 `notes_v2` 的全量扫描）；WAL 重放经同一 apply 路径重建。
        pub owner_index_v2: HashMap<[u8; 32], HashSet<[u8; 32]>>,
        /// 已消费 migration_nonce 全局集（ABI v2 准入门）：禁止重复迁移
        /// 同一 nonce（跨 note/跨 owner 一并阻断）。入状态根（排序折叠）。
        pub migration_nonces: HashSet<[u8; 32]>,
        /// v2 信封 per-signer nonce 水位：owner_commitment → 已见最大
        /// envelope nonce（严格单调；MigrateNote 与 SettleV2 共用）。
        /// 入状态根（BTreeMap 序折叠）。
        pub owner_nonces_v2: BTreeMap<[u8; 32], u64>,
        /// TE-M2：v2 note 承诺 → 铸出来源 op（§5.4 provenance；与 v1
        /// `note_origins` 同纪律——**消费后保留**，提现销毁后托管打款侧
        /// 仍查来源 op 过 finality 门；不入状态根，WAL 重放经
        /// `mint_note_v2` 重建）。
        pub note_origins_v2: HashMap<[u8; 32], u64>,
        /// TE-M2：v2 销毁（提现）记录：(request_id, asset_id, 毛额)。
        /// 与 v1 `burned` 同纪律（只增列表；不入状态根；WAL 重放重建）
        /// ——托管侧 issued/by-token 对账与打款通道分离的输入。
        pub burned_v2: Vec<([u8; 32], AssetId, u64)>,
        /// TE-M2：v2 入金记录：deposit_id → (asset_id, 面额, note 承诺)。
        /// 幂等集与载荷一体（重复 deposit_id 一律拒、冲突载荷可判别；
        /// 托管侧 confirm 重放与队列重建的输入）。**跨版本幂等**：本表
        /// 与 v1 `deposit_ids` 双向查重（v2 存款同时插两侧；v1 路径冻结
        /// 不动——跨版本重复确认由 v2 侧拦截）。不入状态根；WAL 重放重建。
        pub deposit_records_v2: BTreeMap<[u8; 32], (AssetId, u64, [u8; 32])>,
        /// TE-M3：GTS token 注册表（token_id → genesis 规格；注册即冻结，
        /// 重注册拒——重定价 = 发新 token）。由 `RegisterGameToken` op
        /// 驱动；不入状态根（与 `deposit_records_v2` 同纪律），WAL 重放经
        /// apply 路径重建。GAME 域注册判定经
        /// [`crate::asset_id::AssetDomain::is_registered_token_in`]（唯一
        /// 扩展点，不得绕过）。
        pub game_registry: GameTokenRegistry,
        /// TE-M3：GAME 发行幂等集（`IssueGameToken.issue_id`；**跨路径**
        /// 查重见 apply_issue_game_token——与 v1/v2 deposit_id 双向互斥，
        /// 同一外部支付不得既走 REAL Deposit 又走 GAME 发行）。本集只含
        /// GAME 侧已用键；不入状态根，WAL 重放重建。
        pub game_issue_ids: HashSet<[u8; 32]>,
        /// TE-M3：GAME 销毁幂等集（`BurnGameToken.burn_id`；op 族内查重）。
        /// 不入状态根，WAL 重放重建。
        pub game_burn_ids: HashSet<[u8; 32]>,
        /// TE-M3：Σminted per token（供给恒等式 `outstanding = Σminted −
        /// Σburned` 的账本聚合侧；不入状态根，WAL 重放重建）。
        pub game_minted: BTreeMap<u32, u128>,
        /// TE-M3：Σburned per token（同上）。
        pub game_burned: BTreeMap<u32, u128>,
        /// TE-M3：Free 模式 faucet 终身记账：(token_id, owner_commitment)
        /// → 已铸总量（`player_lifetime_max` 强制输入；时间窗限流属
        /// TE-M6）。不入状态根，WAL 重放重建。
        pub game_faucet_issued: HashMap<(u32, [u8; 32]), u64>,
        /// TE-M6：FaucetMint 领取幂等集（`FaucetMint.claim_id`；op 族内
        /// 查重——faucet 无外部支付身份，不与 deposit/issue 幂等集交叉）。
        /// 不入状态根，WAL 重放重建。
        pub game_faucet_ids: HashSet<[u8; 32]>,
        /// TE-M6：Free 桌 GasPolicy 绑定（table_id → (token_id, policy)；
        /// 绑定即冻结，重绑拒）。INV-TE-9 的判定账：Free 模式 token 的
        /// 结算出现在未绑定（或绑定 token 不匹配）桌即拒。不入状态根
        /// （与 `game_registry` 同纪律），WAL 重放经 apply 路径重建。
        pub gas_policies: BTreeMap<u64, (u32, GasPolicy)>,
        /// TE-M6：gas credit 计量账（`BuyGasCredits` 入账、Free 桌结算
        /// 受理消耗）。**收入非储备**：不铸 note、不进 CustodyLedger 对账
        /// 恒等式（`delta[code] = reserved − issued == 0` 与本账物理隔离
        /// ——保护"服务费"定性，见 [`GasCreditLedger`] 模块文档）。不入
        /// 状态根，WAL 重放经 apply 路径重建。
        pub gas_credits: GasCreditLedger,
        /// 合规审计账（排期表 §4b"审计留痕"出口；[`crate::compliance::
        /// ComplianceAuditLog`]）。**运营观测面，不入状态根、不属共识态**
        /// ——失败路径允许留痕（C1 纪律的 metrics 同款豁免）；WAL 重放
        /// 按同序重建 accepted 侧，rejected 侧只在提交时刻产生（拒绝不进
        /// WAL），导出侧如实标注。
        pub compliance_events: crate::compliance::ComplianceAuditLog,
    }

impl LedgerState {
    /// 账本状态根：`poseidon` 折叠（树根、nullifier 根、注册表根、桌折叠、
    /// 序号、**v2 账本段**）。
    ///
    /// **不含** `proven_watermark`：水位是证明管道的恢复态元数据（不入 WAL，
    /// 崩溃后由批次回调重放恢复），不是帧链承诺的账本状态——否则两次帧间
    /// 的水位推进会嵌入后续帧的 `state_root`，使 WAL 重放（重放从零水位
    /// 开始）必然分叉，破坏 P0-4"重启后从 WAL 全量重放恢复"。
    ///
    /// **v2 账本段**（ABI v2 正式版）：`notes_v2`（BTreeMap 承诺序）、
    /// `migration_nonces`（排序折叠，消除 HashSet 迭代序不确定性）、
    /// `owner_nonces_v2`（BTreeMap 序）依次折叠进状态根——v2 账本与 nonce
    /// 集是承诺状态，WAL 重放必须逐位重现（`tests/note_v2.rs` 钉住）。
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut acc = self.tree.root();
        acc = poseidon_hash_many(&[acc, self.nullifiers.root()]);
        acc = poseidon_hash_many(&[acc, self.registry.root()]);
        for (table_id, ts) in &self.tables {
            acc = poseidon_hash_many(&[
                acc,
                felt_from_u64(*table_id),
                felt_from_u64(u64::from(ts.open)),
                felt_from_u64(ts.seats as u64),
            ]);
        }
        acc = poseidon_hash_many(&[
            acc,
            felt_from_u64(self.seq),
            felt_from_u64(self.nullifiers.spent_count),
        ]);
        // v2 账本段（顺序冻结：notes_v2 → migration_nonces → owner_nonces_v2）
        acc = poseidon_hash_many(&[acc, felt_from_u64(u64::try_from(self.notes_v2.len()).unwrap_or(u64::MAX))]);
        for (c, e) in &self.notes_v2 {
            let (hi, lo) = bytes32_to_felts(c);
            acc = poseidon_hash_many(&[acc, hi, lo, felt_from_u64(e.created_at_op)]);
        }
        acc = poseidon_hash_many(&[
            acc,
            felt_from_u64(u64::try_from(self.migration_nonces.len()).unwrap_or(u64::MAX)),
        ]);
        let mut nonces: Vec<[u8; 32]> = self.migration_nonces.iter().copied().collect();
        nonces.sort_unstable();
        for n in &nonces {
            let (hi, lo) = bytes32_to_felts(n);
            acc = poseidon_hash_many(&[acc, hi, lo]);
        }
        for (k, v) in &self.owner_nonces_v2 {
            let (hi, lo) = bytes32_to_felts(k);
            acc = poseidon_hash_many(&[acc, hi, lo, felt_from_u64(*v)]);
        }
        felt_to_bytes32(&acc)
    }

    /// 某 owner 名下的全部 live note 承诺（B5：O(1) 索引命中；承诺集引用，
    /// 零拷贝）。
    #[must_use]
    pub fn commitments_of(&self, owner: &[u8; 33]) -> Option<&HashSet<[u8; 32]>> {
        self.owner_index.get(owner)
    }

    /// 某 owner 名下的全部 live note（B5：走 owner_index，O(1) 定位 +
    /// k 次查表，不再全账本线性扫描）。
    #[must_use]
    pub fn notes_of(&self, owner: &[u8; 33]) -> Vec<Note> {
        self.note_entries_of(owner).into_iter().map(|e| e.note.clone()).collect()
    }

    /// 某 owner 名下的全部 live 条目（含 leaf_index/status 等账本元数据；
    /// B5 索引路径）。顺序不保证（HashSet 迭代序）。
    #[must_use]
    pub fn note_entries_of(&self, owner: &[u8; 33]) -> Vec<&NoteEntry> {
        match self.owner_index.get(owner) {
            Some(set) => set
                .iter()
                .filter_map(|c| self.notes.get(c))
                .collect(),
            None => Vec::new(),
        }
    }

    /// 某 owner 的余额聚合（(REAL, PLAY)）。B5：走 owner_index，与全量
    /// 扫描等价（`owner_index_matches_full_scan` 属性测试钉住）。
    #[must_use]
    pub fn balances_of(&self, owner: &[u8; 33]) -> (u128, u128) {
        let mut real = 0u128;
        let mut play = 0u128;
        if let Some(set) = self.owner_index.get(owner) {
            for c in set {
                if let Some(e) = self.notes.get(c) {
                    match e.note.asset_class {
                        crate::note::AssetClass::Real => real += u128::from(e.note.amount),
                        crate::note::AssetClass::Play => play += u128::from(e.note.amount),
                    }
                }
            }
        }
        (real, play)
    }

    /// 某 v2 owner（账户 = [`OwnerRef`]）名下的全部 live v2 note 条目
    /// （走 owner_index_v2；顺序不保证）。
    #[must_use]
    pub fn note_entries_v2_of(&self, owner: &OwnerRef) -> Vec<&NoteV2Entry> {
        match self.owner_index_v2.get(&owner_commitment(owner)) {
            Some(set) => set.iter().filter_map(|c| self.notes_v2.get(c)).collect(),
            None => Vec::new(),
        }
    }

    /// 某 v2 owner 的余额聚合（(REAL 域合计, GAME 域合计)）——ABI v2
    /// 账户视图，与 v1 [`LedgerState::balances_of`] 同纪律（索引语义 ==
    /// 全量扫描）。
    ///
    /// TE-M1：列语义从 AssetClass（Real/Play）升级为 AssetDomain
    /// （按 [`crate::asset_id::AssetId`] 的 domain 分列，token 无关）：
    /// REAL 域任何 token（含 TE-M2 的 USDT/USDC）计入 real 列，GAME 域
    /// 任何 token（含遗留 PLAY）计入 play 列。逐 token 细分视图见
    /// [`crate::client_view::v2_balances_by_asset`]。
    #[must_use]
    pub fn balances_v2_of(&self, owner: &OwnerRef) -> (u128, u128) {
        let mut real = 0u128;
        let mut play = 0u128;
        if let Some(set) = self.owner_index_v2.get(&owner_commitment(owner)) {
            for c in set {
                if let Some(e) = self.notes_v2.get(c) {
                    // TE-M1：按 AssetId 域分列（finality 语义同款判据——
                    // 豁免按 domain 而非 token）
                    if e.note.asset_id.is_real_domain() {
                        real += u128::from(e.note.amount);
                    } else {
                        play += u128::from(e.note.amount);
                    }
                }
            }
        }
        (real, play)
    }

    /// TE-M2：REAL 域各 token 已发行总额（live note 面额 + 已销毁毛额，
    /// 按 [`AssetId`] 分组；托管对账 `issued_token` 的唯一合法来源——
    /// plan §2.2 `issued_real_total[code]`）。GAME 域 v2 note（遗留 PLAY
    /// 迁移产物）**不入** REAL 托管口径（隔离边界）；BTreeMap 序确定。
    #[must_use]
    pub fn issued_v2_real_by_token(&self) -> BTreeMap<AssetId, u128> {
        let mut out: BTreeMap<AssetId, u128> = BTreeMap::new();
        // live：存续 v2 note（REAL 域）
        for e in self.notes_v2.values() {
            if e.note.asset_id.is_real_domain() {
                *out.entry(e.note.asset_id).or_insert(0u128) += u128::from(e.note.amount);
            }
        }
        // burned：已销毁毛额（提现中/已提现；费从余额内扣、销毁面额不变
        // ——与 v1 issued 语义逐点一致；burned_v2 准入门保证全为 REAL 域）
        for (_, asset, gross) in &self.burned_v2 {
            *out.entry(*asset).or_insert(0u128) += u128::from(*gross);
        }
        out
    }

    /// TE-M2：v2 入金记录只读视图（deposit_id → (asset_id, 面额, note
    /// 承诺)；托管侧 confirm 重放 / WAL 重放后队列重建的输入）。
    #[must_use]
    pub fn deposit_records_v2(
        &self,
    ) -> &BTreeMap<[u8; 32], (AssetId, u64, [u8; 32])> {
        &self.deposit_records_v2
    }

    /// TE-M2：v2 提现 provenance 导出（§5.4 配套；live 条目优先
    /// `created_at_op`，销毁后回落 `note_origins_v2`——两者同源同值，
    /// 消费后保留；None = 账本从未见过该承诺）。资产身份按 v2 note 的
    /// [`AssetId`] 表达，finality 门按其 domain 判。
    #[must_use]
    pub fn withdrawal_provenance_v2(&self, note: &NoteV2) -> Option<WithdrawalProvenanceV2> {
        let c = note.commitment_bytes();
        let op = self
            .notes_v2
            .get(&c)
            .map(|e| e.created_at_op)
            .or_else(|| self.note_origins_v2.get(&c).copied())?;
        Some(WithdrawalProvenanceV2 {
            asset_id: note.asset_id,
            source_op_index: op,
        })
    }

    /// TE-M3：GAME token 供给查询（INV-TE-7 聚合侧）：
    /// `outstanding = Σminted − Σburned`（saturating；账本不变量保证
    /// burned ≤ minted，本函数是对账导出入口不是强制点）。
    #[must_use]
    pub fn game_outstanding(&self, token_id: u32) -> u128 {
        let minted = self.game_minted.get(&token_id).copied().unwrap_or(0);
        let burned = self.game_burned.get(&token_id).copied().unwrap_or(0);
        minted.saturating_sub(burned)
    }

    /// TE-M3：GAME 域日终对账（INV-TE-7 + 设计 §4.3）：逐 token 导出
    /// `outstanding == Σminted − Σburned == Σ 存续 GAME note 面额` 的三边
    /// 核对。`live_note_sum` 对 `notes_v2` 全量扫描（GAME 域 any token），
    /// `consistent == (outstanding == live_note_sum)`——任何 false 即账本
    /// bug 信号（日终告警面）。token 集合 = 注册表 ∪ 聚合账 ∪ 存续
    /// note 出现过的 token（升序确定）。
    #[must_use]
    pub fn game_reconciliation(&self) -> GameReconciliation {
        // 存续 GAME note 面额按 token 聚合（全量扫描，对账口径不走路索引）
        let mut live: BTreeMap<u32, u128> = BTreeMap::new();
        for e in self.notes_v2.values() {
            if e.note.asset_id.is_game_domain() {
                *live.entry(e.note.asset_id.token_id).or_insert(0u128) +=
                    u128::from(e.note.amount);
            }
        }
        let mut token_ids: std::collections::BTreeSet<u32> = self.game_registry.token_ids().collect();
        token_ids.extend(self.game_minted.keys().copied());
        token_ids.extend(self.game_burned.keys().copied());
        token_ids.extend(live.keys().copied());
        let tokens: Vec<GameSupplyReport> = token_ids
            .into_iter()
            .map(|t| {
                let minted_total = self.game_minted.get(&t).copied().unwrap_or(0);
                let burned_total = self.game_burned.get(&t).copied().unwrap_or(0);
                let outstanding = minted_total.saturating_sub(burned_total);
                let live_note_sum = live.get(&t).copied().unwrap_or(0);
                GameSupplyReport {
                    token_id: t,
                    minted_total,
                    burned_total,
                    outstanding,
                    live_note_sum,
                    consistent: outstanding == live_note_sum,
                }
            })
            .collect();
        let all_consistent = tokens.iter().all(|t| t.consistent);
        GameReconciliation { tokens, all_consistent }
    }

    /// TE-M3：GAME 域日终对账 JSON 导出（格式标签
    /// [`crate::game_token::RECONCILIATION_FORMAT`]；u128 十进制字符串）。
    #[must_use]
    pub fn game_reconciliation_json(&self) -> serde_json::Value {
        let rec = self.game_reconciliation();
        let mut v = rec.to_json();
        if let Some(obj) = v.as_object_mut() {
            obj.insert("format".into(), serde_json::json!(RECONCILIATION_FORMAT));
        }
        v
    }

    /// TE-M6：gas credit 计量账只读视图（审计/日终导出入口；**非储备**
    /// ——本账与 CustodyLedger 对账恒等式物理隔离，见
    /// [`GasCreditLedger`] 模块文档）。
    #[must_use]
    pub fn gas_credit_ledger(&self) -> &GasCreditLedger {
        &self.gas_credits
    }

    /// TE-M6：Free 桌 GasPolicy 绑定查询（table_id；None = 未绑定）。
    #[must_use]
    pub fn gas_policy_of(&self, table_id: u64) -> Option<(u32, GasPolicy)> {
        self.gas_policies.get(&table_id).copied()
    }
}

/// Sequencer。
pub struct Sequencer {
    config: SequencerConfig,
    key: SequencerKey,
    state: LedgerState,
    rate: RateLimiter,
    wal: Option<WalWriter>,
    metrics: Arc<MetricsRegistry>,
    last_ts_ms: u64,
    chain: Vec<SignedFrame>,
    /// 水位之上的单点证明完成集合（P0-5 连续前缀语义的"缺口"记录）；
    /// 不入状态根——崩溃重启后由证明管道重新回调恢复。
    proven_marks: HashSet<u64>,
    /// 已记录批次根：through_op → batch_root（§5.4 finality 证据）。
    /// 内存态，与证明水位同生命周期——重启后由证明管道对已验证批次
    /// 重新回调恢复（[`Sequencer::record_batch_root`]）；挂载 sidecar 后
    /// 同时由 proven-log 持久化（M8）。
    batch_roots: BTreeMap<u64, [u8; 32]>,
    /// M8 proven-log sidecar 写端（None = 未挂载，纯内存语义不变）。
    proven_log: Option<ProvenLogWriter>,
    /// M4 outer aggregate：已记录聚合记录（按聚合序；`aggregate.log`
    /// sidecar 持久化，重启恢复——与 proven log 同容错语义）。
    aggregates: Vec<AggregateRecord>,
    /// aggregate-log sidecar 写端（None = 未挂载）。
    aggregate_log: Option<AggregateLogWriter>,
}

/// proven-log sidecar 行格式（**冻结契约**，读取方
/// `src/bin/explorer_gateway/proven_log.rs` 与 watcher 依赖，不得改字段名
/// /顺序语义）：每行一个紧凑 JSON 对象 + 换行
///
/// ```text
/// {"op_index":<u64>,"batch_root":"<64hex>","ts_ms":<u64>}
/// ```
///
/// 写入纪律（与 WAL 同源）：每行完整追加（含换行）；默认只 flush 不
/// fsync（撕裂尾行由读取方按"忽略 + 告警"处理——诚实取舍：sidecar 是
/// 恢复优化而非承诺点，真正的承诺点仍是 WAL fsync）。
struct ProvenLogWriter {
    file: BufWriter<File>,
    /// true 时追加后 `sync_all`（数据 + 元数据真落盘）。
    fsync: bool,
    /// 一次写失败后置位（fail-closed：此后水位推进被挂起，内存与
    /// sidecar 永不分叉；恢复需重建实例）。
    failed: bool,
}

impl ProvenLogWriter {
    fn open(path: &Path) -> AppchainResult<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| AppchainError::WalCorrupted("proven log open failed"))?;
        Ok(Self {
            file: BufWriter::new(file),
            fsync: false,
            failed: false,
        })
    }

    /// 追加一行冻结契约记录（完整行 + 换行；flush；可选 fsync）。
    fn append(&mut self, op_index: u64, batch_root: &[u8; 32], ts_ms: u64) -> AppchainResult<()> {
        // 字段顺序冻结：op_index → batch_root → ts_ms（紧凑、无空格）。
        let line = format!(
            "{{\"op_index\":{},\"batch_root\":\"{}\",\"ts_ms\":{}}}\n",
            op_index,
            hex::encode(batch_root),
            ts_ms
        );
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.flush())
            .map_err(|_| AppchainError::WalCorrupted("proven log write failed"))?;
        if self.fsync {
            self.file
                .get_ref()
                .sync_all()
                .map_err(|_| AppchainError::WalCorrupted("proven log fsync failed"))?;
        }
        Ok(())
    }
}

/// 解析一行 proven log（冻结契约）：`(op_index, batch_root, ts_ms)`。
///
/// 任何字段缺失/类型错/root 非 64hex → None（调用方决定容错策略）。
#[must_use]
fn parse_proven_line(line: &str) -> Option<(u64, [u8; 32], u64)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let obj = v.as_object()?;
    let op_index = obj.get("op_index")?.as_u64()?;
    let root_hex = obj.get("batch_root")?.as_str()?;
    let ts_ms = obj.get("ts_ms")?.as_u64()?;
    let root_bytes = hex::decode(root_hex).ok()?;
    let batch_root: [u8; 32] = root_bytes.try_into().ok()?;
    Some((op_index, batch_root, ts_ms))
}

/// 当前墙钟毫秒（sidecar `ts_ms` 用）。
fn wallclock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// aggregate-log sidecar 行格式（**冻结契约**，读取方
/// `src/bin/explorer_gateway/aggregate_log.rs` 与 watcher 依赖，不得改
/// 字段名/顺序语义）：每行一个紧凑 JSON 对象 + 换行
///
/// ```text
/// {"index":<u64>,"through_op":<u64>,"root":"<64hex>","ts_ms":<u64>,"batch_count":<u64>}
/// ```
///
/// 写入纪律与 [`ProvenLogWriter`] 完全同源：逐行完整追加；默认只 flush
/// 不 fsync（撕裂尾行由读取方"忽略 + 告警"）；一次写失败后置位挂起。
struct AggregateLogWriter {
    file: BufWriter<File>,
    /// true 时追加后 `sync_all`。
    fsync: bool,
    /// 一次写失败后置位（fail-closed：此后本实例不再追加聚合记录——
    /// 内存与 sidecar 永不分叉；恢复需重建实例）。
    failed: bool,
}

impl AggregateLogWriter {
    fn open(path: &Path) -> AppchainResult<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| AppchainError::WalCorrupted("aggregate log open failed"))?;
        Ok(Self {
            file: BufWriter::new(file),
            fsync: false,
            failed: false,
        })
    }

    /// 追加一行冻结契约记录（完整行 + 换行；flush；可选 fsync）。
    fn append(&mut self, rec: &AggregateRecord) -> AppchainResult<()> {
        // 字段顺序冻结：index → through_op → root → ts_ms → batch_count。
        let line = format!(
            "{{\"index\":{},\"through_op\":{},\"root\":\"{}\",\"ts_ms\":{},\"batch_count\":{}}}\n",
            rec.index,
            rec.through_op,
            hex::encode(rec.root),
            rec.ts_ms,
            rec.batch_count
        );
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.flush())
            .map_err(|_| AppchainError::WalCorrupted("aggregate log write failed"))?;
        if self.fsync {
            self.file
                .get_ref()
                .sync_all()
                .map_err(|_| AppchainError::WalCorrupted("aggregate log fsync failed"))?;
        }
        Ok(())
    }
}

/// 解析一行 aggregate log（冻结契约）：`(index, through_op, root, ts_ms, batch_count)`。
///
/// 任何字段缺失/类型错/root 非 64hex → None（调用方决定容错策略）。
#[must_use]
fn parse_aggregate_line(line: &str) -> Option<(u64, u64, [u8; 32], u64, u64)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let obj = v.as_object()?;
    let index = obj.get("index")?.as_u64()?;
    let through_op = obj.get("through_op")?.as_u64()?;
    let root_hex = obj.get("root")?.as_str()?;
    let ts_ms = obj.get("ts_ms")?.as_u64()?;
    let batch_count = obj.get("batch_count")?.as_u64()?;
    let root: [u8; 32] = hex::decode(root_hex).ok()?.try_into().ok()?;
    Some((index, through_op, root, ts_ms, batch_count))
}

/// 读取并解析 aggregate log（严格纪律，与 [`read_proven_log_strict`] 同款）：
/// 返回按序 [`AggregateRecord`]。
///
/// 恢复纪律：空文件合法；撕裂尾行忽略 + 告警；中间行损坏 / `index`
/// 非连续（首行必须为 0，此后 +1 递进）/ `through_op` 非严格递增 → 拒绝
/// （fail-closed）。
fn read_aggregate_log_strict(path: &Path) -> AppchainResult<Vec<AggregateRecord>> {
    let bytes = std::fs::read(path)
        .map_err(|_| AppchainError::WalCorrupted("aggregate log open failed"))?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| AppchainError::WalCorrupted("aggregate log not utf-8"))?;
    let ends_with_newline = text.ends_with('\n');
    let mut lines: Vec<&str> = text.split('\n').collect();
    if ends_with_newline {
        lines.pop();
    } else {
        match lines.pop() {
            Some(tail) if !tail.trim().is_empty() => {
                eprintln!(
                    "[poker-appchain::sequencer] warning: aggregate log torn final line \
                     ignored ({} bytes, no newline)",
                    tail.len()
                );
            }
            _ => {}
        }
    }
    let mut out: Vec<AggregateRecord> = Vec::with_capacity(lines.len());
    for raw in &lines {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let (index, through_op, root, ts_ms, batch_count) = parse_aggregate_line(line)
            .ok_or(AppchainError::WalCorrupted(
                "aggregate log line corrupt (frozen contract)",
            ))?;
        // index 从 0 起连续递增（行序即期望值）；through_op 严格递增。
        if index != u64::try_from(out.len()).unwrap_or(u64::MAX) {
            return Err(AppchainError::WalCorrupted(
                "aggregate log index not consecutive",
            ));
        }
        if let Some(prev) = out.last() {
            if through_op <= prev.through_op {
                return Err(AppchainError::WalCorrupted(
                    "aggregate log through_op does not advance",
                ));
            }
        }
        out.push(AggregateRecord {
            index,
            through_op,
            root,
            ts_ms,
            batch_count,
        });
    }
    Ok(out)
}

/// 读取并解析 proven log（[`Sequencer::replay_restoring_proven`] 的严格
/// 纪律，见其文档）：返回按序 `(op_index, batch_root)` 对。
///
/// `chain_len`：恢复边界（`op_index` 必须覆盖链内的操作，0..=chain_len
/// 皆合法——与 `mark_proven_through` 的 0..=n 语义一致）。
fn read_proven_log_strict(path: &Path, chain_len: u64) -> AppchainResult<Vec<(u64, [u8; 32])>> {
    let bytes = std::fs::read(path)
        .map_err(|_| AppchainError::WalCorrupted("proven log open failed"))?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| AppchainError::WalCorrupted("proven log not utf-8"))?;
    let ends_with_newline = text.ends_with('\n');
    let mut lines: Vec<&str> = text.split('\n').collect();
    if ends_with_newline {
        lines.pop(); // split 对换行结尾产生的空尾串
    } else {
        // 撕裂尾行：无换行结尾的最后一行一律忽略并告警（即使可解析——
        // 契约要求写入方逐行完整追加，未终结的行不可信）。
        match lines.pop() {
            Some(tail) if !tail.trim().is_empty() => {
                eprintln!(
                    "[poker-appchain::sequencer] warning: proven log torn final line \
                     ignored ({} bytes, no newline)",
                    tail.len()
                );
            }
            _ => {}
        }
    }
    let mut out: Vec<(u64, [u8; 32])> = Vec::with_capacity(lines.len());
    for raw in &lines {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let (op_index, root, _) = parse_proven_line(line).ok_or(
            AppchainError::WalCorrupted("proven log line corrupt (frozen contract)"),
        )?;
        // 写入方只在水位真实推进时追加 → op_index 必须严格递增。
        if let Some(&(prev, _)) = out.last()
            && op_index <= prev
        {
            return Err(AppchainError::WalCorrupted(
                "proven log op_index does not advance",
            ));
        }
        if op_index > chain_len {
            return Err(AppchainError::WalCorrupted(
                "proven log op_index beyond chain length",
            ));
        }
        out.push((op_index, root));
    }
    Ok(out)
}

impl Sequencer {
    /// 新建（内存模式，无 WAL）。
    ///
    /// **密钥来源纪律（外部评审建议 4）**：`key` 参数是注入点——生产装配
    /// 必须经 [`crate::key_provider::KeyProvider`] 取钥（env / file /
    /// remote-KMS 三实现，fail-closed，无默认种子回退），例如
    /// `SequencerKey::from_provider(key_provider::from_config("ZCHAIN")?)`
    /// （见 [`crate::key_provider`] 模块文档的完整装配示例）。`from_seed`
    /// 仅供测试工具与单测使用（loadtest / selftest / fixture / tests）；
    /// 生产代码中出现常量种子一律视为评审阻断项。
    #[must_use]
    pub fn new(
        key: SequencerKey,
        config: SequencerConfig,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        Self {
            config,
            key,
            state: LedgerState::default(),
            rate: RateLimiter::default(),
            wal: None,
            metrics,
            last_ts_ms: 0,
            chain: Vec::new(),
            proven_marks: HashSet::new(),
            batch_roots: BTreeMap::new(),
            proven_log: None,
            aggregates: Vec::new(),
            aggregate_log: None,
        }
    }

    /// 挂载 WAL（追加模式；调用方负责先 [`Sequencer::replay`] 恢复）。
    ///
    /// fsync 默认开启（每次提交 [`WalWriter::sync`] 真落盘）；测试提速可用
    /// [`WalWriter::with_fsync(false)`] 构造后经 `attach_wal_writer` 注入。
    ///
    /// # Errors
    /// 打开失败 → [`AppchainError::WalCorrupted`]。
    pub fn attach_wal(&mut self, path: &Path) -> AppchainResult<()> {
        self.wal = Some(WalWriter::open_append(path)?);
        Ok(())
    }

    /// 注入已构造的 WAL writer（测试故障注入用；生产路径走 [`Sequencer::attach_wal`]）。
    #[cfg(test)]
    pub(crate) fn attach_wal_writer(&mut self, w: WalWriter) {
        self.wal = Some(w);
    }

    /// 挂载 proven-log sidecar（M8）：此后每次**携带批次根的水位推进**
    /// （[`Sequencer::mark_proven_through_with_root`]，即生产装配点的批次
    /// 回调路径）追加一行冻结契约 JSONL：
    ///
    /// ```text
    /// {"op_index":<u64>,"batch_root":"<64hex>","ts_ms":<u64>}
    /// ```
    ///
    /// 取舍（文档化）：默认只 flush 不 fsync——sidecar 是重启恢复优化而非
    /// 承诺点（承诺点仍是 WAL fsync）；撕裂尾行由读取方按"忽略 + 告警"
    /// 处理。需要更强持久性可用 [`Sequencer::with_proven_fsync`]。
    ///
    /// fail-closed：sidecar 写失败后本实例**停止推进证明水位**（内存与
    /// 日志永不分叉），计 `proven_log_write_failed_total`；只记批次根之外
    /// 的水位推进（[`Sequencer::mark_proven_through`] 直推）不落 sidecar
    /// ——它们由证明管道重回调恢复，与既有语义一致。
    ///
    /// # Errors
    /// 打开失败 → [`AppchainError::WalCorrupted`]。
    pub fn attach_proven_log(&mut self, path: &Path) -> AppchainResult<()> {
        self.proven_log = Some(ProvenLogWriter::open(path)?);
        Ok(())
    }

    /// proven-log fsync 开关（builder 风格）：`true` = 每行追加后
    /// `sync_all` 真落盘；`false`（默认）= 只做用户态 flush。未挂载
    /// sidecar 时为无操作。
    pub fn with_proven_fsync(&mut self, enabled: bool) -> &mut Self {
        if let Some(w) = self.proven_log.as_mut() {
            w.fsync = enabled;
        }
        self
    }

    /// 挂载 aggregate-log sidecar（M4 outer aggregate）：此后每次
    /// [`Sequencer::record_aggregate`] 追加一行冻结契约 JSONL：
    ///
    /// ```text
    /// {"index":<u64>,"through_op":<u64>,"root":"<64hex>","ts_ms":<u64>,"batch_count":<u64>}
    /// ```
    ///
    /// 写入纪律与 proven log 同口径：默认只 flush 不 fsync（撕裂尾行由
    /// 读取方"忽略 + 告警"处理）；fail-closed——sidecar 写失败后本实例
    /// **停止记录聚合**（内存与 sidecar 永不分叉），计
    /// `aggregate_log_write_failed_total`。
    ///
    /// # Errors
    /// 打开失败 → [`AppchainError::WalCorrupted`]。
    pub fn attach_aggregate_log(&mut self, path: &Path) -> AppchainResult<()> {
        self.aggregate_log = Some(AggregateLogWriter::open(path)?);
        Ok(())
    }

    /// aggregate-log fsync 开关（builder 风格）。未挂载 sidecar 时无操作。
    pub fn with_aggregate_fsync(&mut self, enabled: bool) -> &mut Self {
        if let Some(w) = self.aggregate_log.as_mut() {
            w.fsync = enabled;
        }
        self
    }

    /// 记录一条聚合记录（生产装配点：`ProofPipeline::aggregate_due` 返回
    /// `Some(rec)` 后调用）。
    ///
    /// 挂载 sidecar 时先落盘后进内存（fail-closed：写失败 → 本实例挂起
    /// 聚合记录——内存与 sidecar 永不分叉，语义与 proven-log 写失败一致；
    /// 聚合记录是可由批次根重算的派生证据，挂起不阻塞主链）。未挂载时纯
    /// 内存记录。
    pub fn record_aggregate(&mut self, rec: AggregateRecord) {
        if let Some(w) = self.aggregate_log.as_mut() {
            if w.failed {
                self.metrics.inc("aggregate_log_write_failed_total");
                return;
            }
            if w.append(&rec).is_err() {
                w.failed = true;
                self.metrics.inc("aggregate_log_write_failed_total");
                eprintln!(
                    "[poker-appchain::sequencer] warning: aggregate log write failed \
                     (aggregate recording suspended for this instance)"
                );
                return;
            }
        }
        self.aggregates.push(rec);
    }

    /// 已记录聚合记录（按聚合序，只读）。
    #[must_use]
    pub fn aggregates(&self) -> &[AggregateRecord] {
        &self.aggregates
    }

    /// 最新一条聚合记录（None = 尚无聚合）。
    #[must_use]
    pub fn latest_aggregate(&self) -> Option<&AggregateRecord> {
        self.aggregates.last()
    }

    /// 从 WAL 全量重放并（可选）从 proven-log sidecar 恢复证明水位与
    /// 批次根（M8）。`proven_log = None` 时与 [`Sequencer::replay`] 完全
    /// 等价（`replay` 签名与语义不变）。
    ///
    /// sidecar 恢复纪律（与冻结契约读取方一致）：
    /// - 空文件 → 无恢复（合法）；
    /// - 撕裂尾行（最后一行无换行结尾）→ 忽略 + 告警（即使恰好可解析）；
    /// - 中间行损坏 → **拒绝**（fail-closed：连续前缀承诺已破）；
    /// - `op_index` 不严格递增 → 拒绝；
    /// - `op_index` 越界（> 链长）→ 拒绝。
    ///
    /// # Errors
    /// WAL 重放失败，或 sidecar 中间行损坏 / op_index 非递增 / 越界 →
    /// 对应 [`AppchainError`]。
    pub fn replay_restoring_proven(
        wal: &Path,
        proven_log: Option<&Path>,
        key_public: [u8; 32],
        config: SequencerConfig,
        metrics: Arc<MetricsRegistry>,
    ) -> AppchainResult<Self> {
        Self::replay_restoring_proven_and_aggregates(
            wal,
            proven_log,
            None,
            key_public,
            config,
            metrics,
        )
    }

    /// [`Sequencer::replay_restoring_proven`] 的超集（v1.2.3 additive）：
    /// 额外支持从 aggregate-log sidecar 恢复 M4 outer aggregate 聚合记录
    /// （[`Sequencer::aggregates`] / [`Sequencer::latest_aggregate`]）。
    /// `aggregate_log = None` 时与 `replay_restoring_proven` **完全等价**
    /// （既有签名语义不变，本 fn 为新增）。
    ///
    /// aggregate-log 恢复纪律（与 proven log 同款）：空文件合法；撕裂尾行
    /// 忽略 + 告警；中间行损坏 / `index` 非连续 / `through_op` 非严格递增
    /// → 拒绝。恢复实例不挂 sidecar（不二次落盘）。
    ///
    /// # Errors
    /// WAL 重放失败，或任一 sidecar 违反恢复纪律 → 对应 [`AppchainError`]。
    pub fn replay_restoring_proven_and_aggregates(
        wal: &Path,
        proven_log: Option<&Path>,
        aggregate_log: Option<&Path>,
        key_public: [u8; 32],
        config: SequencerConfig,
        metrics: Arc<MetricsRegistry>,
    ) -> AppchainResult<Self> {
        let mut seq = Self::replay(wal, key_public, config, metrics)?;
        if let Some(p) = proven_log {
            let chain_len = u64::try_from(seq.chain.len()).unwrap_or(u64::MAX);
            for (op_index, root) in read_proven_log_strict(p, chain_len)? {
                // 与生产装配点同路径恢复（水位 + §5.4 批次根证据 + note 翻
                // Proven）；重放实例未挂 sidecar，不会二次落盘。
                seq.mark_proven_through_with_root(op_index, root);
            }
        }
        if let Some(a) = aggregate_log {
            // 直接进内存（重放实例未挂 sidecar；record_aggregate 会在无
            // sidecar 时同样入内存，这里语义一致且不走失败计数）。
            seq.aggregates = read_aggregate_log_strict(a)?;
        }
        Ok(seq)
    }

    /// 从 WAL 全量重放（fail-closed：链签名、每帧状态根都重验）。
    ///
    /// # Errors
    /// 链断裂/签名坏/状态根分叉 → 对应错误。
    /// 崩溃安全重放（2026-09-17 长跑复现）：追加写 WAL 的尾帧可能因进程
    /// 被强杀而撕裂/半写——严格 [`Self::replay`] 会整链拒绝（网关数据面
    /// 保持该纪律），生产方（嵌入式 runtime）则用本函数：对有效前缀重建
    /// 状态并把 WAL 文件**物理截回前缀末尾**（fsync），后续追加基于干净
    /// 尾部。截断只发生在首坏帧处；首帧即坏 → 无可恢复，返回错误。
    ///
    /// # Errors
    /// 文件不可读或首帧解析/验签失败 → 对应 [`AppchainError`]。
    pub fn replay_recover_torn_tail(
        path: &Path,
        key_public: [u8; 32],
        config: SequencerConfig,
        metrics: Arc<MetricsRegistry>,
    ) -> AppchainResult<Self> {
        let (frames, valid_bytes, tail_reason) =
            crate::wal::read_all_strict_prefix(path, &key_public)?;
        if let Some(reason) = tail_reason {
            let drop = std::fs::metadata(path)
                .map(|m| m.len().saturating_sub(valid_bytes))
                .unwrap_or(0);
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|e| AppchainError::WalCorrupted("truncate open failed"))?;
            f.set_len(valid_bytes)
                .map_err(|e| AppchainError::WalCorrupted("truncate set_len failed"))?;
            f.sync_all()
                .map_err(|e| AppchainError::WalCorrupted("truncate sync failed"))?;
            eprintln!(
                "[sequencer] WAL torn-tail recovery: dropped {drop} trailing byte(s) ({reason});                  {} valid frame(s) kept",
                frames.len()
            );
        }
        Self::rebuild_from_frames(path, frames, key_public, config, metrics)
    }

    /// 重放占位 signing key（**非生产回退路径**，生产区唯一 `from_seed`
    /// 字面量，tests/key_provider.rs 的 grep 级断言钉住恰此一处）：
    /// 重放只验签不签名（`verify_chain` 已用调用方传入的 `key_public`
    /// 验全链），此密钥在重放实例上永不使用；不走 KeyProvider——replay
    /// 是纯公钥 API（语义冻结，见外部评审建议 4 接线文档）。
    fn replay_placeholder_key() -> SequencerKey {
        SequencerKey::from_seed(&[0u8; 32])
    }

    fn rebuild_from_frames(
        path: &Path,
        frames: Vec<SignedFrame>,
        key_public: [u8; 32],
        config: SequencerConfig,
        metrics: Arc<MetricsRegistry>,
    ) -> AppchainResult<Self> {
        crate::soft_confirm::verify_chain(&frames, &key_public)?;
        // 证明水位不入 WAL（崩溃重启后保守归零）。历史帧在提交时已通过
        // 全部在线准入（含"桌准入只收 proven note"），重放是**重建已承诺
        // 状态**而非新准入——若按原配置重放，任何含成功 BuyIn 的 WAL 都会
        // 因水位丢失而无法恢复（破坏 P0-4"重启后从 WAL 全量重放恢复"的
        // 承诺点语义）。恢复期覆盖该单项，重放完成后恢复原始配置——
        // 重启后的**新**提交仍受完整在线准入约束（M8 污染防御不变）。
        let recovery_config = SequencerConfig {
            admission_proven_only: false,
            ..config.clone()
        };
        let mut seq = Self::new(
            // 重放占位 signing key，语义见 replay_placeholder_key。
            Self::replay_placeholder_key(),
            recovery_config,
            metrics,
        );
        seq.chain = Vec::with_capacity(frames.len());
        for f in &frames {
            let expect_root = f.frame.state_root;
            let ts = f.frame.ts_ms;
            Self::apply_op(&seq.config, &seq.metrics, &mut seq.state, &f.frame.op, ts, None)?;
            let got = seq.state.root();
            if got != expect_root {
                return Err(AppchainError::WalCorrupted("state root divergence on replay"));
            }
            seq.last_ts_ms = ts;
            seq.chain.push(f.clone());
        }
        seq.config = config;
        let _ = path;
        Ok(seq)
    }

    /// 从 WAL 全量重放（fail-closed：链签名、每帧状态根都重验）。
    ///
    /// # Errors
    /// 链断裂/签名坏/状态根分叉 → 对应错误。
    pub fn replay(
        path: &Path,
        key_public: [u8; 32],
        config: SequencerConfig,
        metrics: Arc<MetricsRegistry>,
    ) -> AppchainResult<Self> {
        let frames = crate::wal::read_all(path)?;
        crate::soft_confirm::verify_chain(&frames, &key_public)?;
        // 证明水位不入 WAL（崩溃重启后保守归零）。历史帧在提交时已通过
        // 全部在线准入（含"桌准入只收 proven note"），重放是**重建已承诺
        // 状态**而非新准入——若按原配置重放，任何含成功 BuyIn 的 WAL 都会
        // 因水位丢失而无法恢复（破坏 P0-4"重启后从 WAL 全量重放恢复"的
        // 承诺点语义）。恢复期覆盖该单项，重放完成后恢复原始配置——
        // 重启后的**新**提交仍受完整在线准入约束（M8 污染防御不变）。
        let recovery_config = SequencerConfig {
            admission_proven_only: false,
            ..config.clone()
        };
        let mut seq = Self::new(
            // 重放占位 signing key，语义见 replay_placeholder_key。
            Self::replay_placeholder_key(),
            recovery_config,
            metrics,
        );
        seq.chain = Vec::with_capacity(frames.len());
        for f in &frames {
            let expect_root = f.frame.state_root;
            let ts = f.frame.ts_ms;
            // 关联字段分离借用（config/metrics 共享、state 可变），不走 &self。
            // v2 边界：MigrateNote 帧重放走材料无关校验（material = None，
            // 见 apply_migrate / docs/ABI_V2.md）；SettleV2 材料随 op 携带，
            // 重放全量复核。
            Self::apply_op(&seq.config, &seq.metrics, &mut seq.state, &f.frame.op, ts, None)?;
            let got = seq.state.root();
            if got != expect_root {
                return Err(AppchainError::WalCorrupted("state root divergence on replay"));
            }
            seq.last_ts_ms = ts;
            seq.chain.push(f.clone());
        }
        seq.config = config;
        Ok(seq)
    }

    /// 账本状态引用。
    #[must_use]
    pub fn state(&self) -> &LedgerState {
        &self.state
    }

    /// 软确认链引用。
    #[must_use]
    pub fn chain(&self) -> &[SignedFrame] {
        &self.chain
    }

    /// 链头哈希。
    ///
    /// # Errors
    /// 序列化失败 → Codec。
    pub fn head_hash(&self) -> AppchainResult<[u8; 32]> {
        chain_head(&self.chain)
    }

    /// 配置引用。
    #[must_use]
    pub fn config(&self) -> &SequencerConfig {
        &self.config
    }

    /// 证明水位只读访问器（管道/观测用）。
    #[must_use]
    pub fn proven_watermark(&self) -> u64 {
        self.state.proven_watermark
    }

    /// 标记单个 op_index 证明完成（P0-5 连续前缀语义）：内部只把
    /// `proven_watermark` 推进到**最大连续前缀**——存在失败/未完成的缺口
    /// 时水位停住，绝不越过未证明操作。
    ///
    /// 持久化语义（P0-4 复核）：水位是唯一不走 WAL 的状态变更——内存态可
    /// 由证明管道从批次重放恢复（崩溃后保守归零），无需独立持久化。
    /// 替换签名密钥（生产方重启恢复专用）：`replay` 构建的实例携带占位
    /// 密钥（重放只验签），若生产方（嵌入式 appchain runtime）复用该实例
    /// 继续追加出帧，必须先重设真实密钥——否则所有新帧签名无效，下游
    /// 验签方（网关/桥）整链拒绝。
    pub fn set_signing_key(&mut self, key: SequencerKey) {
        self.key = key;
    }

    /// 证明水位推进（单 op 标记 + 连续前缀折算）：标记 `op_index` 已证明，
    /// 并把可连续的前缀一并推进（`proven_marks` 折算）。
    pub fn mark_proven(&mut self, op_index: u64) {
        if op_index <= self.state.proven_watermark || !self.proven_marks.insert(op_index) {
            return; // 已被水位覆盖或重复标记
        }
        let mut w = self.state.proven_watermark;
        while self.proven_marks.remove(&(w + 1)) {
            w += 1;
        }
        if w > self.state.proven_watermark {
            self.state.proven_watermark = w;
            for e in self.state.notes.values_mut() {
                if e.created_at_op <= w {
                    e.status = NoteStatus::Proven;
                }
            }
            for e in self.state.notes_v2.values_mut() {
                if e.created_at_op <= w {
                    e.status = NoteStatus::Proven;
                }
            }
            self.metrics.set_gauge("proven_watermark", w);
        }
    }

    /// 证明水位推进（pipeline 批次回调）：标记 `0..=n` 全部已证明（批次
    /// 覆盖到 through_op，其间所有操作一并视为已证明），内部同一连续前缀
    /// 语义（这里前缀天然连续，直接推进）。
    pub fn mark_proven_through(&mut self, op_index: u64) {
        if op_index <= self.state.proven_watermark {
            return;
        }
        self.proven_marks.retain(|&g| g > op_index);
        self.state.proven_watermark = op_index;
        for e in self.state.notes.values_mut() {
            if e.created_at_op <= op_index {
                e.status = NoteStatus::Proven;
            }
        }
        for e in self.state.notes_v2.values_mut() {
            if e.created_at_op <= op_index {
                e.status = NoteStatus::Proven;
            }
        }
        self.metrics.set_gauge("proven_watermark", op_index);
    }

    /// 批次根记录（§5.4 finality 证据）：批次回调带 root 时快照
    /// `through_op → root`。内存态——重启后由证明管道对已验证批次重新
    /// 回调恢复（与证明水位同生命周期）。
    pub fn record_batch_root(&mut self, through_op: u64, root: [u8; 32]) {
        self.batch_roots.insert(through_op, root);
    }

    /// 水位推进 + 批次根记录（生产装配点：pipeline 批次回调一次调用完成
    /// 证明水位与 §5.4 finality 证据的同步推进）。
    ///
    /// 语义冻结：`record_batch_root` 无条件执行（水位未推进的重复回调也
    /// 要补齐批次根证据——`tests/finality_flow.rs` 钉住该行为）；水位推进
    /// 保持 `mark_proven_through` 的只进不退语义。
    ///
    /// M8：挂载 proven-log sidecar 后，**水位真实推进**的调用会先向 sidecar
    /// 追加一行冻结契约 JSONL（`op_index`/`batch_root`/`ts_ms`），成功后才
    /// 推进内存水位（fail-closed：写失败 → 水位挂起 + 告警计数，内存与
    /// 日志永不分叉；批次根证据仍无条件记录）。重复/回退调用（`op_index`
    /// ≤ 当前水位）不落 sidecar（保证恢复侧"严格递增"纪律）。
    pub fn mark_proven_through_with_root(&mut self, op_index: u64, root: [u8; 32]) {
        let advancing = op_index > self.state.proven_watermark;
        if advancing {
            if let Some(w) = self.proven_log.as_mut() {
                if w.failed {
                    // 此前已失败：挂起水位推进（fail-closed），只暴露告警计数。
                    self.metrics.inc("proven_log_write_failed_total");
                } else {
                    match w.append(op_index, &root, wallclock_ms()) {
                        Ok(()) => {}
                        Err(_) => {
                            w.failed = true;
                            self.metrics.inc("proven_log_write_failed_total");
                        }
                    }
                }
            }
            if self.proven_log.as_ref().is_some_and(|w| w.failed) {
                self.record_batch_root(op_index, root);
                return;
            }
        }
        self.record_batch_root(op_index, root);
        self.mark_proven_through(op_index);
    }

    /// 已记录批次根覆盖到的最大 op（None = 尚无批次根记录）。
    #[must_use]
    pub fn batch_covered_through(&self) -> Option<u64> {
        self.batch_roots.keys().next_back().copied()
    }

    /// 已记录批次根查询（观测/审计用）。
    #[must_use]
    pub fn batch_root_at(&self, through_op: u64) -> Option<[u8; 32]> {
        self.batch_roots.get(&through_op).copied()
    }

    /// 全部已记录批次根（through_op 升序，BTreeMap 序确定；M8 checkpoint
    /// 导出与 watcher 审计用）。
    #[must_use]
    pub fn batch_roots(&self) -> Vec<(u64, [u8; 32])> {
        self.batch_roots.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// 提现 provenance 导出（§5.4 配套）：note 铸出来源 op
    /// （`LedgerState.note_origins`，消费后保留——提现销毁后托管侧仍可查；
    /// WAL 重放重建）。
    #[must_use]
    pub fn withdrawal_provenance(&self, note: &Note) -> Option<WithdrawalProvenance> {
        let c = felt_to_bytes32(&note.commitment());
        // 优先查 live 条目（created_at_op），销毁后回落到 origins 映射——
        // 两者同源同值
        let op = self
            .state
            .notes
            .get(&c)
            .map(|e| e.created_at_op)
            .or_else(|| self.state.note_origins.get(&c).copied())?;
        let asset_class = self
            .state
            .notes
            .get(&c)
            .map(|e| e.note.asset_class)
            .unwrap_or(note.asset_class);
        Some(WithdrawalProvenance {
            asset_class,
            source_op_index: op,
        })
    }

    /// finality 证据快照（托管账提现申请的判定输入）。
    #[must_use]
    pub fn finality_evidence(&self) -> FinalityEvidence {
        FinalityEvidence {
            proven_watermark: self.state.proven_watermark,
            batch_covered_through: self.batch_covered_through(),
        }
    }

    /// 提交一笔操作：软确认全管线，成功返回已签名帧。
    ///
    /// # Errors
    /// 见 [`AppchainError`] 全部变体——每个拒绝路径唯一。
    pub fn submit(
        &mut self,
        op: Operation,
        now_ms: u64,
    ) -> AppchainResult<SignedFrame> {
        // MigrateNote 需要呈递验签材料（fail-closed：submit 通道不带材料
        // 一律拒绝；走 submit_migrate）
        if matches!(op, Operation::MigrateNote(_)) {
            self.metrics.inc("ops_rejected_total");
            return Err(AppchainError::AdmissionRejected(
                "migrate requires submit_migrate with verifier material",
            ));
        }
        self.submit_inner(op, None, now_ms)
    }

    /// 提交一笔 MigrateNote 迁移（ABI v2 准入通道）：`op` 必须是
    /// [`Operation::MigrateNote`]，`material` 是 `record.old_owner_sig`
    /// 的验签材料（按 scheme 呈递，见 [`VerifierMaterial`]）。
    ///
    /// 与 [`Sequencer::submit`] 同一软确认管线（限流 → 准入 → 帧 → WAL
    /// → 换入）；差异仅在迁移验签需要帧外材料（op borsh 载荷形状冻结，
    /// 不含材料，见 docs/ABI_V2.md §边界）。重放侧经
    /// [`validate_migrate_note_structure`] 复核材料无关关系。
    ///
    /// # Errors
    /// op 不是 MigrateNote → [`AppchainError::AdmissionRejected`]；其余
    /// 见 [`Sequencer::submit`]。
    pub fn submit_migrate(
        &mut self,
        op: Operation,
        material: &VerifierMaterial,
        now_ms: u64,
    ) -> AppchainResult<SignedFrame> {
        if !matches!(op, Operation::MigrateNote(_)) {
            self.metrics.inc("ops_rejected_total");
            return Err(AppchainError::AdmissionRejected(
                "submit_migrate requires an Operation::MigrateNote op",
            ));
        }
        self.submit_inner(op, Some(material), now_ms)
    }

    fn submit_inner(
        &mut self,
        op: Operation,
        material: Option<&VerifierMaterial>,
        now_ms: u64,
    ) -> AppchainResult<SignedFrame> {
        let t0 = Instant::now();
        let principal = self.principal_of(&op);
        // 限流（开桌单独配额）
        let is_table_op = matches!(op, Operation::OpenTable { .. });
        let rate = if is_table_op {
            self.config.open_table_per_min
        } else {
            self.config.ops_per_min
        };
        if !self.rate.allow(&principal, now_ms, rate) {
            self.metrics.inc("ops_rejected_total");
            return Err(AppchainError::RateLimited(principal));
        }

        let op_index = self.state.seq; // 本操作位置（apply 成功后 = seq-1 不变式）
        let ts = now_ms.max(self.last_ts_ms);
        let prev = self.head_hash()?;

        // P0-4 原子提交，两段式（试算 → 持久化承诺 → 生效）：
        // - 持久模式（挂 WAL）：在**克隆态**上试算（语义失败在此返回，真实
        //   状态零接触），帧携带试算后的状态根；WAL append + sync（fsync 承诺
        //   点）成功后才把试算态原子换入——WAL 写/fsync 失败时内存态、链、
        //   时间戳全部未动（内存与 WAL 不可能分叉）。试算阶段的 metrics 观测
        //   可能包含最终被 WAL 拒绝的操作（仅影响观测，不影响共识态）。
        // - 内存模式（无 WAL，测试/压测）：直接原地应用，免克隆开销。
        // 失败路径共同点：限流令牌已扣（DoS 防御从宽，可接受）。
        let signed = if self.wal.is_some() {
            let mut staged = self.state.clone();
            Self::apply_op(&self.config, &self.metrics, &mut staged, &op, ts, material)?;
            let frame = SoftConfirmFrame {
                index: op_index,
                prev_hash: prev,
                op,
                state_root: staged.root(),
                ts_ms: ts,
            };
            let signed = SignedFrame::sign(frame, &self.key)?;
            // write-ahead：先持久化后生效
            let w = self.wal.as_mut().expect("wal presence checked");
            w.append(&signed)?;
            w.sync()?;
            self.state = staged;
            signed
        } else {
            Self::apply_op(&self.config, &self.metrics, &mut self.state, &op, ts, material)?;
            let frame = SoftConfirmFrame {
                index: op_index,
                prev_hash: prev,
                op,
                state_root: self.state.root(),
                ts_ms: ts,
            };
            SignedFrame::sign(frame, &self.key)?
        };
        self.last_ts_ms = ts;
        self.chain.push(signed.clone());
        self.metrics.inc("ops_total");
        self.metrics.observe(
            "soft_confirm_us",
            u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        Ok(signed)
    }

    fn principal_of(&self, op: &Operation) -> [u8; 32] {
        let owner32 = |pk: &[u8; 33]| -> [u8; 32] {
            let mut h = [0u8; 32];
            h.copy_from_slice(&pk[1..33]);
            h
        };
        match op {
            Operation::OpenTable { .. } | Operation::CloseTable { .. }
            | Operation::Deposit { .. } => [0u8; 32], // operator
            Operation::WithdrawRequest { note, .. } => owner32(&note.owner),
            Operation::BuyIn { notes, .. } | Operation::Transfer { notes, .. } => {
                notes.first().map(|n| owner32(&n.owner)).unwrap_or([0u8; 32])
            }
            Operation::Settle(r) => r
                .inputs
                .first()
                .map(|i| owner32(&i.note.owner))
                .unwrap_or([0u8; 32]),
            // v2 变体：MigrateNote 的 principal = 旧 signer account_id；
            // SettleV2 取首个输入的身份字节。
            // TE-M2：DepositV2 是 operator 托管路径（同 v1 Deposit）；
            // WithdrawRequestV2 的 principal = 被销毁 note owner 的
            // account_id（信封 signer 经准入强制 == note owner）。
            Operation::MigrateNote(m) => m.record.old_owner_sig.signer_ref.account_id,
            Operation::SettleV2(r) => match r.inputs.first() {
                Some(SettleInputV2::V1 { note, .. }) => owner32(&note.owner),
                Some(SettleInputV2::V2 { note, .. }) => note.owner.account_id,
                None => [0u8; 32],
            },
            Operation::DepositV2(_) => [0u8; 32],
            Operation::WithdrawRequestV2(w) => w.note.owner.account_id,
            // TE-M3：RegisterGameToken / IssueGameToken 是 operator 托管
            // 帧（同 Deposit 系——注册与发行由 watcher 确认驱动，限流归
            // operator principal）；BurnGameToken 的 principal = 被销毁
            // note owner 的 account_id（信封 signer 经准入强制 == owner）。
            Operation::RegisterGameToken(_) => [0u8; 32],
            Operation::IssueGameToken(_) => [0u8; 32],
            Operation::BurnGameToken(b) => b.note.owner.account_id,
            // TE-M6：三变体均为 operator 帧（FaucetMint 无外部支付、
            // BuyGasCredits watcher 确认外驱动、BindGasPolicy 桌配置帧同
            // OpenTable 纪律）——限流归 operator principal。
            Operation::FaucetMint(_) => [0u8; 32],
            Operation::BuyGasCredits(_) => [0u8; 32],
            Operation::BindGasPolicy(_) => [0u8; 32],
        }
    }

    // ===== 语义应用（全部检查先行，应用段零失败）=====
    //
    // P0-4：应用逻辑与 Sequencer 实例解耦（state 显式传参），使提交路径能
    // 在克隆态上试算、WAL 承诺后才换入真实状态。注意：试算阶段 metrics 观测
    // 可能包含最终被 WAL 拒绝的操作（仅影响观测，不影响共识态）。

    fn apply_op(
        config: &SequencerConfig,
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        op: &Operation,
        ts_ms: u64,
        material: Option<&VerifierMaterial>,
    ) -> AppchainResult<()> {
        // 合规门（排期表 §4b + TEC-v1；geography/KYC/限额/自排除准入）。
        // 检查先行：拒绝在此返回（零账本变更），审计留痕见
        // [`crate::compliance::ComplianceAuditLog`] 的观测面豁免注释。
        let compliance_accepted = Self::compliance_gate(config, metrics, state, op, ts_ms)?;
        // 效果摘要（审计 S1）：绑定操作全部语义载荷，纳入花费签名验证
        let effect = op.effect_digest();
        let res = match op {
            Operation::OpenTable { table_id, policy } => {
                Self::apply_open_table(state, *table_id, policy)
            }
            Operation::CloseTable { table_id } => Self::apply_close_table(state, *table_id),
            Operation::Deposit { deposit_id, owner, asset_class, amount } => {
                Self::apply_deposit(state, deposit_id, owner, *asset_class, *amount)
            }
            // 审计 P1：payout_recipient 经 effect 摘要进签名验证（apply
            // 内不再单独使用，`..` 略过——摘要已在 apply_op 顶部计算）。
            Operation::WithdrawRequest { spend, note, request_id, .. } => {
                Self::apply_withdraw(state, spend, note, request_id, &effect)
            }
            Operation::Transfer { spends, notes, outputs } => {
                Self::apply_transfer(state, spends, notes, outputs, &effect)
            }
            Operation::BuyIn { table_id, spends, notes, seat_owner } => {
                Self::apply_buy_in(config, state, *table_id, spends, notes, seat_owner, &effect)
            }
            Operation::Settle(record) => Self::apply_settle(metrics, state, record),
            // ABI v2 变体：迁移 / 混合结算（ts_ms 参与新鲜度判定——帧时间
            // 戳即权威时钟，提交与 WAL 重放同值，重放确定性成立）
            Operation::MigrateNote(m) => {
                let r = Self::apply_migrate(config, state, m, ts_ms, material);
                if r.is_ok() {
                    metrics.inc("ops_migrate_total");
                }
                r
            }
            Operation::SettleV2(record) => {
                let r = Self::apply_settle_v2(config, metrics, state, record, ts_ms);
                if r.is_ok() {
                    metrics.inc("ops_settle_v2_total");
                }
                r
            }
            // TE-M2 变体：多币种存款 / 提现申请（准入见各自 apply；效果
            // 摘要随 op 预先计算，提现验签在 apply 内全量执行——材料随
            // 载荷携带，WAL 重放同路径全量复核）
            Operation::DepositV2(payload) => {
                let r = Self::apply_deposit_v2(state, payload);
                if r.is_ok() {
                    metrics.inc("ops_deposit_v2_total");
                } else if payload.asset_id.is_game_domain() {
                    // TE-M3：GAME 域拒入对称纪律的观测面（DepositV2 × GAME
                    // ——TE-M2 语义零变更，只补计数）
                    metrics.inc("game_token_rejected_total");
                }
                r
            }
            Operation::WithdrawRequestV2(payload) => {
                let r = Self::apply_withdraw_request_v2(config, state, payload, &effect, ts_ms);
                if r.is_ok() {
                    metrics.inc("ops_withdraw_v2_total");
                } else if payload.asset_id.is_game_domain() {
                    // TE-M3：GAME 域提现拒绝计数（设计 §3.3/§6——出现非零
                    // 即有人尝试 GAME 赎回，审计信号）
                    metrics.inc("game_token_rejected_total");
                    metrics.inc("game_withdraw_rejected_total");
                }
                r
            }
            // TE-M3 变体：GTS 游戏币注册 / 发行 / 销毁（准入见各自 apply；
            // Register/Issue 是 operator 帧，Burn 验签在 apply 内全量执行
            // ——材料随载荷携带，WAL 重放同路径全量复核）
            Operation::RegisterGameToken(payload) => {
                let r = Self::apply_register_game_token(config, metrics, state, payload);
                if r.is_ok() {
                    metrics.inc("ops_game_register_total");
                }
                r
            }
            Operation::IssueGameToken(payload) => {
                let r = Self::apply_issue_game_token(metrics, state, payload);
                if r.is_ok() {
                    metrics.inc("ops_game_issue_total");
                }
                r
            }
            Operation::BurnGameToken(payload) => {
                let r = Self::apply_burn_game_token(config, metrics, state, payload, &effect, ts_ms);
                if r.is_ok() {
                    metrics.inc("ops_game_burn_total");
                }
                r
            }
            // TE-M6 变体：Free 模式 faucet 领取 / gas credit 购买 / Free 桌
            // gas 策略绑定（准入见各自 apply；三者为 operator 帧，无验签
            // 材料，幂等与语义核对在 apply 内执行）
            Operation::FaucetMint(payload) => {
                let r = Self::apply_faucet_mint(metrics, state, payload);
                if r.is_ok() {
                    metrics.inc("ops_faucet_mint_total");
                }
                r
            }
            Operation::BuyGasCredits(payload) => {
                let r = Self::apply_buy_gas_credits(metrics, state, payload);
                if r.is_ok() {
                    metrics.inc("ops_buy_gas_credits_total");
                }
                r
            }
            Operation::BindGasPolicy(payload) => {
                let r = Self::apply_bind_gas_policy(config, metrics, state, payload);
                if r.is_ok() {
                    metrics.inc("ops_bind_gas_policy_total");
                }
                r
            }
        };
        if res.is_ok() {
            // 成功才推进序号（失败路径零状态变更）
            state.seq += 1;
            if let Some((op_tag, subject, amount)) = compliance_accepted {
                Self::compliance_record_accept(config, state, op_tag, subject, amount, ts_ms);
            }
        }
        res
    }

    /// 合规操作分类（gated op → (op_tag, 类别)）；非 gated op 返回 `None`。
    ///
    /// gated 面（TEC-v1 §5/§10）：REAL `Deposit`/`DepositV2`、GAME
    /// `IssueGameToken`/`FaucetMint`、`BuyGasCredits`（与 IssueGameToken
    /// 同口径）。**PLAY 免费层不设门**（永久免费层是合规防御，TEC-v1 §2）；
    /// GAME 域 `DepositV2` 不设门（TE-M2 准入本就拒绝，不重复计合规指标）。
    fn compliance_class(
        op: &Operation,
    ) -> Option<(&'static str, crate::compliance::ComplianceOpClass)> {
        use crate::asset_id::TOKEN_NATIVE;
        use crate::compliance::{owner_key_v1, owner_key_v2, ComplianceOpClass};
        use crate::note::AssetClass;
        match op {
            Operation::Deposit { owner, asset_class, .. } => match asset_class {
                AssetClass::Real => Some(("deposit", ComplianceOpClass::RealDeposit {
                    owner32: owner_key_v1(owner),
                    token: TOKEN_NATIVE,
                })),
                AssetClass::Play => None,
            },
            Operation::DepositV2(p) => {
                let token = crate::compliance::real_token_of(&p.asset_id)?;
                Some((
                    "deposit_v2",
                    ComplianceOpClass::RealDeposit {
                        owner32: owner_key_v2(&p.owner),
                        token,
                    },
                ))
            }
            Operation::IssueGameToken(p) => Some((
                "issue_game_token",
                ComplianceOpClass::GameIssue {
                    owner32: owner_key_v2(&p.buyer),
                },
            )),
            Operation::FaucetMint(p) => Some((
                "faucet_mint",
                ComplianceOpClass::GameIssue {
                    owner32: owner_key_v2(&p.owner),
                },
            )),
            Operation::BuyGasCredits(p) => Some((
                "buy_gas_credits",
                ComplianceOpClass::GasPurchase {
                    owner32: owner_key_v2(&p.payer),
                },
            )),
            _ => None,
        }
    }

    /// 金额提取（合规限额口径：申请/支付额；文档见 [`crate::compliance`]）。
    fn compliance_amount(op: &Operation) -> Option<u64> {
        match op {
            Operation::Deposit { amount, .. } => Some(*amount),
            Operation::DepositV2(p) => Some(p.amount),
            Operation::IssueGameToken(p) => Some(p.pay_amount),
            Operation::FaucetMint(p) => Some(p.amount),
            Operation::BuyGasCredits(p) => Some(p.pay_amount),
            _ => None,
        }
    }

    /// 合规门（apply 路径强制点）：未配置合规参数 → 直通；gated op 逐类
    /// 判定，拒绝即计指标 + 审计留痕 + Err。返回 `Ok(Some((op_tag,
    /// subject, amount)))` 表示已放行（body 成功后须补记 accepted 事件）。
    fn compliance_gate(
        config: &SequencerConfig,
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        op: &Operation,
        ts_ms: u64,
    ) -> AppchainResult<Option<(&'static str, [u8; 32], Option<u64>)>> {
        use crate::compliance::{gate_gas_purchase, gate_game_issue, gate_real_deposit, ComplianceOpClass, Rejection};
        let Some(params) = &config.compliance else {
            return Ok(None);
        };
        let Some((op_tag, class)) = Self::compliance_class(op) else {
            return Ok(None);
        };
        let amount = Self::compliance_amount(op);
        let (owner32, decision) = match &class {
            ComplianceOpClass::RealDeposit { owner32, token } => {
                (*owner32, gate_real_deposit(&params.policy, &params.market, owner32, *token, amount.unwrap_or(0)))
            }
            ComplianceOpClass::GameIssue { owner32 } => {
                (*owner32, gate_game_issue(&params.policy, &params.market, owner32, amount.unwrap_or(0)))
            }
            ComplianceOpClass::GasPurchase { owner32 } => {
                (*owner32, gate_gas_purchase(&params.policy, &params.market, owner32, amount.unwrap_or(0)))
            }
        };
        if let Err(rejection) = decision {
            metrics.inc(&format!(
                "geo_policy_rejected_total{{market=\"{}\"}}",
                params.market
            ));
            if matches!(
                rejection,
                Rejection::KycGateReal | Rejection::KycGateGame
            ) {
                metrics.inc("kyc_gate_rejected_total");
            }
            state.compliance_events.record(crate::compliance::ComplianceEvent {
                ts_ms,
                policy_version: params.policy.version,
                policy_digest: params.policy.digest(),
                market: params.market.clone(),
                op_tag,
                decision: Err(rejection),
                subject: owner32,
                amount,
            });
            return Err(AppchainError::AdmissionRejected("compliance gate rejected"));
        }
        Ok(Some((op_tag, owner32, amount)))
    }

    /// accepted 事件补记（body 成功后调用；C1 纪律：审计accepted 只在
    /// op 真正生效时落账）。
    fn compliance_record_accept(
        config: &SequencerConfig,
        state: &mut LedgerState,
        op_tag: &'static str,
        subject: [u8; 32],
        amount: Option<u64>,
        ts_ms: u64,
    ) {
        let Some(params) = &config.compliance else {
            return;
        };
        state.compliance_events.record(crate::compliance::ComplianceEvent {
            ts_ms,
            policy_version: params.policy.version,
            policy_digest: params.policy.digest(),
            market: params.market.clone(),
            op_tag,
            decision: Ok(()),
            subject,
            amount,
        });
    }

    fn apply_open_table(
        state: &mut LedgerState,
        table_id: u64,
        policy: &FeePolicy,
    ) -> AppchainResult<()> {
        if state.tables.contains_key(&table_id) {
            return Err(AppchainError::TableNotOpen(table_id));
        }
        state.registry.bind(table_id, *policy)?;
        state.tables.insert(
            table_id,
            TableState {
                open: true,
                seats: 0,
            },
        );
        Ok(())
    }

    fn apply_close_table(state: &mut LedgerState, table_id: u64) -> AppchainResult<()> {
        match state.tables.get_mut(&table_id) {
            Some(ts) if ts.open => {
                ts.open = false;
                Ok(())
            }
            _ => Err(AppchainError::TableNotOpen(table_id)),
        }
    }

    fn apply_deposit(
        state: &mut LedgerState,
        deposit_id: &[u8; 32],
        owner: &[u8; 33],
        asset_class: crate::note::AssetClass,
        amount: u64,
    ) -> AppchainResult<()> {
        // C1：先完成全部可失败检查，幂等键最后插入（失败零状态变更）
        let nonce = Self::mint_nonce(state.seq, b"deposit", deposit_id);
        let note = Note::new(asset_class, amount, *owner, nonce, None)?;
        let c = felt_to_bytes32(&note.commitment());
        if state.notes.contains_key(&c) {
            return Err(AppchainError::AdmissionRejected("duplicate note commitment"));
        }
        if !state.deposit_ids.insert(*deposit_id) {
            return Err(AppchainError::WithdrawalConflict("duplicate deposit id".into()));
        }
        Self::mint_note(state, note)
    }

    /// v1 消费路径读侧预检（审计 P2 修复：变更前全量校验，C1 加严）。
    ///
    /// 复用 v2 读侧预检的精确检查集（apply_withdraw_request_v2 第 5/6 条）：
    /// 零 nullifier 拒、felt 规范性（felt_from_bytes32_exact）、nullifier
    /// 未消费（共享 nullifier 集 + **op 内重复**一并拒——同 op 两笔 spend
    /// 声明同一 nullifier 的投毒双花在变更前即拒）、note 仍在账本 +
    /// op 内承诺不重复。通过后 consume_note 对同一输入不再失败——旧路径
    /// 在 no-WAL 模式（apply 直接落 self.state，无克隆态回滚）下"先删 note
    /// 再发现 nullifier 已花"会留下半变更状态（note 已删、幂等键已烧、
    /// burn 未记账），此预检关闭该窗口。
    fn precheck_consume_v1<'a, I>(state: &LedgerState, pairs: I) -> AppchainResult<()>
    where
        I: IntoIterator<Item = (&'a crate::settlement::SpendAuth, &'a Note)>,
    {
        let mut seen_nf = std::collections::HashSet::new();
        let mut seen_c = std::collections::HashSet::new();
        for (s, n) in pairs {
            if s.nullifier == [0u8; 32] {
                return Err(AppchainError::AdmissionRejected("zero nullifier"));
            }
            let nf = crate::felt::felt_from_bytes32_exact(&s.nullifier)?;
            if state.nullifiers.contains(&nf) || !seen_nf.insert(nf) {
                return Err(AppchainError::DoubleSpend);
            }
            let c = felt_to_bytes32(&n.commitment());
            if !state.notes.contains_key(&c) || !seen_c.insert(c) {
                return Err(AppchainError::NoteNotFound);
            }
        }
        Ok(())
    }

    /// v2 消费路径读侧预检（v1 侧 [`Self::precheck_consume_v1`] 的 nullifier
    /// 段；note 账本核对由各 apply 的账本检查段承担）。
    fn precheck_nullifiers_v2<'a, I>(state: &LedgerState, nullifiers: I) -> AppchainResult<()>
    where
        I: IntoIterator<Item = &'a [u8; 32]>,
    {
        let mut seen_nf = std::collections::HashSet::new();
        for nf_bytes in nullifiers {
            if *nf_bytes == [0u8; 32] {
                return Err(AppchainError::AdmissionRejected("zero nullifier"));
            }
            let nf = crate::felt::felt_from_bytes32_exact(nf_bytes)?;
            if state.nullifiers.contains(&nf) || !seen_nf.insert(nf) {
                return Err(AppchainError::DoubleSpend);
            }
        }
        Ok(())
    }

    fn apply_withdraw(
        state: &mut LedgerState,
        spend: &crate::settlement::SpendAuth,
        note: &Note,
        request_id: &[u8; 32],
        effect: &[u8; 32],
    ) -> AppchainResult<()> {
        // C1：签名/note/账本校验全部先行，幂等键销毁在变更段。
        // 审计 P2：request_id 查重与 nullifier 预检一并先行（只读）——
        // 旧序先 withdrawal_ids.insert 再 consume_note，no-WAL 模式下
        // consume 失败（双花/非规范 felt）会留下半变更状态。
        let c = felt_to_bytes32(&note.commitment());
        if c != spend.commitment || !state.notes.contains_key(&c) {
            return Err(AppchainError::NoteNotFound);
        }
        let d = spend_digest(&spend.commitment, &spend.nullifier, scope::WITHDRAW, effect);
        crate::keys::verify_ecsdsa(&note.owner, &d, &spend.sig)?;
        if state.withdrawal_ids.contains(request_id) {
            return Err(AppchainError::WithdrawalConflict("duplicate request id".into()));
        }
        Self::precheck_consume_v1(state, [(spend, note)])?;

        // ===== 变更段（以上全部通过，以下不再失败）=====
        state.withdrawal_ids.insert(*request_id);
        Self::consume_note(state, note, &spend.nullifier)?;
        state.burned.push((*request_id, note.amount));
        Ok(())
    }

    fn apply_transfer(
        state: &mut LedgerState,
        spends: &[crate::settlement::SpendAuth],
        notes: &[Note],
        outputs: &[crate::note::NoteSpec],
        effect: &[u8; 32],
    ) -> AppchainResult<()> {
        if spends.len() != notes.len() || notes.is_empty() || outputs.is_empty() {
            return Err(AppchainError::AdmissionRejected("transfer arity"));
        }
        let class = notes[0].asset_class;
        let mut input_sum = 0u128;
        for (s, n) in spends.iter().zip(notes.iter()) {
            let d = spend_digest(&s.commitment, &s.nullifier, scope::TRANSFER, effect);
            crate::keys::verify_ecsdsa(&n.owner, &d, &s.sig)?;
            if n.asset_class != class {
                return Err(AppchainError::AssetClassMismatch(
                    class.name(),
                    n.asset_class.name(),
                ));
            }
            input_sum += u128::from(n.amount);
        }
        crate::settlement::assert_single_class(class, outputs)?;
        let mut output_sum = 0u128;
        for o in outputs {
            output_sum += u128::from(o.amount);
        }
        if input_sum != output_sum {
            return Err(AppchainError::ConservationViolated {
                inputs: input_sum,
                outputs: output_sum,
                rake: 0,
            });
        }
        // 审计 P2：消费段读侧预检先行——旧路径第 1 张 note 先被删除后才
        // 发现第 2 张的 nullifier 已花（投毒双花），no-WAL 模式下无回滚，
        // 留下半转账状态。预检过后下方 consume 循环不再失败。
        Self::precheck_consume_v1(state, spends.iter().zip(notes.iter()))?;
        for (s, n) in spends.iter().zip(notes.iter()) {
            Self::consume_note(state, n, &s.nullifier)?;
        }
        for (i, o) in outputs.iter().enumerate() {
            let payload = blake2s32(&[
                b"transfer-out",
                &felt_to_bytes32(&felt_from_u64(u64::try_from(i).unwrap_or(u64::MAX))),
            ]);
            let nonce = Self::mint_nonce(state.seq, b"transfer", &payload);
            Self::mint_note(state, o.clone().mint(nonce)?)?;
        }
        Ok(())
    }

    fn apply_buy_in(
        config: &SequencerConfig,
        state: &mut LedgerState,
        table_id: u64,
        spends: &[crate::settlement::SpendAuth],
        notes: &[Note],
        seat_owner: &[u8; 33],
        effect: &[u8; 32],
    ) -> AppchainResult<()> {
        let ts = state
            .tables
            .get(&table_id)
            .copied()
            .ok_or(AppchainError::TableNotOpen(table_id))?;
        if !ts.open {
            return Err(AppchainError::TableNotOpen(table_id));
        }
        if ts.seats + notes.len() > config.max_seats {
            return Err(AppchainError::AdmissionRejected("table full"));
        }
        if notes.is_empty() {
            return Err(AppchainError::AdmissionRejected("empty buy-in"));
        }
        let class = notes[0].asset_class;
        let mut total = 0u128;
        for (s, n) in spends.iter().zip(notes.iter()) {
            let d = spend_digest(&s.commitment, &s.nullifier, scope::BUYIN, effect);
            crate::keys::verify_ecsdsa(&n.owner, &d, &s.sig)?;
            if n.asset_class != class {
                return Err(AppchainError::AssetClassMismatch(
                    class.name(),
                    n.asset_class.name(),
                ));
            }
            // 桌准入：只收 proven note（M8 污染防御）
            if config.admission_proven_only {
                let key = felt_to_bytes32(&n.commitment());
                let e = state
                    .notes
                    .get(&key)
                    .ok_or(AppchainError::NoteNotFound)?;
                if e.status != NoteStatus::Proven {
                    return Err(AppchainError::AdmissionRejected("note not proven"));
                }
            }
            total += u128::from(n.amount);
        }
        let amount = u64::try_from(total).map_err(|_| AppchainError::InvalidAmount(u64::MAX))?;
        // 审计 P2：消费段读侧预检先行（同 apply_transfer——变更前全量校验）
        Self::precheck_consume_v1(state, spends.iter().zip(notes.iter()))?;
        for (s, n) in spends.iter().zip(notes.iter()) {
            Self::consume_note(state, n, &s.nullifier)?;
        }
        let payload = blake2s32(&[b"buyin", &felt_to_bytes32(&felt_from_u64(table_id))]);
        let nonce = Self::mint_nonce(state.seq, b"buyin", &payload);
        let seat = Note::new(
            class,
            amount,
            *seat_owner,
            nonce,
            Some(table_id),
        )?;
        Self::mint_note(state, seat)?;
        if let Some(t) = state.tables.get_mut(&table_id) {
            t.seats += 1;
        }
        Ok(())
    }

    fn apply_settle(
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        record: &crate::settlement::SettlementRecord,
    ) -> AppchainResult<()> {
        let ts = state
            .tables
            .get(&record.table_id)
            .copied()
            .ok_or(AppchainError::TableNotOpen(record.table_id))?;
        if !ts.open {
            return Err(AppchainError::TableNotOpen(record.table_id));
        }
        // C1：replay 检查只读；hand_binding 的销毁移到全部校验通过之后——
        // 校验失败的结算不得烧掉绑定（否则合法修正版会被误判重放）
        if state.settled_bindings.contains(&record.hand_binding) {
            return Err(AppchainError::SettlementReplay);
        }
        let policy = *state.registry.require(record.table_id)?;
        validate_settlement(record, &policy)?;
        // 账本核对：输入 note 存在且内容一致
        for input in &record.inputs {
            let key = felt_to_bytes32(&input.note.commitment());
            let e = state
                .notes
                .get(&key)
                .ok_or(AppchainError::NoteNotFound)?;
            if e.note != input.note {
                return Err(AppchainError::AdmissionRejected("input note mismatch"));
            }
        }
        // 审计 P2：消费段读侧预检先行——settled_bindings.insert 后 consume
        // 失败（nullifier 已花）会烧掉绑定且留下部分消费，合法修正版会被
        // 误判重放（C1 注释描述的窗口）。预检过后下方消费循环不再失败。
        Self::precheck_consume_v1(state, record.inputs.iter().map(|i| (&i.spend, &i.note)))?;
        // ===== 变更段（以上全部通过，以下不再失败）=====
        if !state.settled_bindings.insert(record.hand_binding) {
            return Err(AppchainError::SettlementReplay);
        }
        // 消费 + 铸造（已通过纯函数校验，守恒有保证）
        for input in &record.inputs {
            Self::consume_note(state, &input.note, &input.spend.nullifier)?;
        }
        for (i, o) in record.payouts.iter().enumerate() {
            let payload = blake2s32(&[
                b"settle-out",
                record.hand_binding.as_slice(),
                &felt_to_bytes32(&felt_from_u64(u64::try_from(i).unwrap_or(u64::MAX))),
            ]);
            let nonce = Self::mint_nonce(state.seq, b"settle", &payload);
            Self::mint_note(state, o.clone().mint(nonce)?)?;
        }
        if record.rake.total > 0 {
            let (t_spec, o_spec) = crate::settlement::rake_outputs(record, &policy);
            if let Some(spec) = t_spec {
                let nonce = Self::mint_nonce(state.seq, b"rake-t", &record.hand_binding);
                Self::mint_note(state, spec.mint(nonce)?)?;
            }
            if let Some(spec) = o_spec {
                let nonce = Self::mint_nonce(state.seq, b"rake-o", &record.hand_binding);
                Self::mint_note(state, spec.mint(nonce)?)?;
            }
        }
        // 结算释放全部被消费的 seat
        if let Some(t) = state.tables.get_mut(&record.table_id) {
            t.seats = t.seats.saturating_sub(record.inputs.len());
        }
        metrics.add("rake_total", u64::from(record.rake.total));
        Ok(())
    }

    // ===== ABI v2 准入与应用（迁移 / 混合结算）=====

    /// MigrateNote 准入与应用（C1 纪律：全部可失败检查先行，变更段零失败）。
    ///
    /// 准入清单（顺序即实现）：
    /// 1. `network_id` 与本链配置一致（防跨网重放）；
    /// 2. `abi_version == OWNER_V2_ABI_VERSION`（防跨版重放）；
    /// 3. `minted` 与 `record` 一致（amount/asset_id/new_owner_ref；
    ///    TE-M1：`record.asset_class` 是 v1 层身份（MigrateNoteRecord
    ///    冻结字段、migrate_digest 覆盖不变），经冻结映射
    ///    [`AssetId::of_v1`] 升维后与 v2 note 的 `asset_id` 全等比对
    ///    ——Real→REAL/0、Play→GAME/0，无第二种换算）；
    /// 4. `minted` 必须是自由余额形态（table None、pot/runout 0——桌绑定
    ///    不在 `migrate_digest` 签名覆盖内，fail-closed 拒绝未签名语义）；
    /// 5. 旧 v1 note 存在（键 = `old_commitment`）；
    /// 6. `migration_nonce` 全局查重（跨 note/跨 owner 阻断）；
    /// 7. 新承诺查重（`notes_v2`）；
    /// 8. owner_v2 校验：材料在场 → 全 8 步
    ///    [`validate_migrate_note`]；无材料（WAL 重放侧）→ 材料无关
    ///    [`validate_migrate_note_structure`]（边界见 docs/ABI_V2.md）。
    ///    新鲜度的 `now` 取帧时间戳秒（提交与重放同值）。
    ///
    /// 应用：消费旧 v1 note（nullifier = [`migration_nullifier`]，链侧
    /// 确定性派生，不要求旧 owner 交出 spend secret）→ 登记
    /// migration_nonce → 推进旧 signer 的 v2 nonce 水位 → 铸 NoteV2 入
    /// v2 账本。
    fn apply_migrate(
        config: &SequencerConfig,
        state: &mut LedgerState,
        payload: &MigrateNoteOp,
        ts_ms: u64,
        material: Option<&VerifierMaterial>,
    ) -> AppchainResult<()> {
        let record = &payload.record;
        let minted = &payload.minted;
        let now = ts_ms / 1000;

        // —— 全部可失败检查 ——
        if record.network_id != config.network_id {
            return Err(AppchainError::AdmissionRejected("migrate network id mismatch"));
        }
        if record.abi_version != OWNER_V2_ABI_VERSION {
            return Err(AppchainError::AdmissionRejected("migrate abi version mismatch"));
        }
        if minted.amount != record.amount
            // TE-M1：资产一致性按 AssetId 全等判（v1 资产类经冻结映射
            // 升维；伪造"跨域/跨 token"的 minted 在此 fail-closed 拒）
            || minted.asset_id != AssetId::of_v1(record.asset_class)
            || minted.owner != record.new_owner_ref
        {
            return Err(AppchainError::AdmissionRejected("migrate minted/record mismatch"));
        }
        if minted.table_id.is_some() || minted.pot_index != 0 || minted.runout_index != 0 {
            return Err(AppchainError::AdmissionRejected(
                "migrate mints free balance notes only",
            ));
        }
        let old_note = state
            .notes
            .get(&record.old_commitment)
            .map(|e| e.note.clone())
            .ok_or(AppchainError::NoteNotFound)?;
        if state.migration_nonces.contains(&record.migration_nonce) {
            return Err(AppchainError::SettlementReplay);
        }
        let mint_key = minted.commitment_bytes();
        if state.notes_v2.contains_key(&mint_key) {
            return Err(AppchainError::AdmissionRejected("duplicate note commitment"));
        }
        let signer_key = owner_commitment(&record.old_owner_sig.signer_ref);
        let last_nonce = state.owner_nonces_v2.get(&signer_key).copied();
        match material {
            Some(m) => validate_migrate_note(record, now, last_nonce, m)?,
            None => validate_migrate_note_structure(record, now, last_nonce)?,
        }

        // ===== 变更段（以上全部通过）=====
        let nf = migration_nullifier(record);
        Self::consume_note(state, &old_note, &nf)?;
        state.migration_nonces.insert(record.migration_nonce);
        state.owner_nonces_v2.insert(signer_key, record.old_owner_sig.nonce);
        Self::mint_note_v2(state, minted.clone())?;
        Ok(())
    }

    /// SettleV2 准入与应用（混合输入；双 verifier 在
    /// [`validate_settlement_v2`] 内逐输入分派）。
    ///
    /// 相对 v1 [`Self::apply_settle`] 的差异：无 plan（v2 单层 contested
    /// 口径，见模块文档）、输入按版本分账本核对（v1 → `notes`，v2 →
    /// `notes_v2`）、v2 信封消费 per-signer nonce 水位、赔付铸入 v2 账本
    /// （rake 输出仍铸 v1 账本——treasury/operator 是 legacy 身份）。
    /// `hand_binding` 与 v1 共享 `settled_bindings` 集（跨版本重放一并
    /// 阻断）。
    ///
    /// **TE-M4：FixedRakeBurn 桌（GAME 桌销毁计费）**：
    /// - 准入追加 GAME 域门——计价资产必须是 GAME 域**已注册 GTS token**
    ///   （REAL 域误用 burn 策略拒；遗留 PLAY(0) 无 GTS 规格、outstanding
    ///   恒等式不经 Issue 维护，同样拒）；
    /// - rake 处置 = burn：rake 输出本就为 `None`（`validate_settlement_v2`
    ///   第 8 条强制），应用段 `game_burned[token] += rake.total`——
    ///   `game_outstanding` 随之收缩，GAME 域供给对账闭合。
    fn apply_settle_v2(
        config: &SequencerConfig,
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        record: &SettlementRecordV2,
        ts_ms: u64,
    ) -> AppchainResult<()> {
        let now = ts_ms / 1000;
        let ts = state
            .tables
            .get(&record.table_id)
            .copied()
            .ok_or(AppchainError::TableNotOpen(record.table_id))?;
        if !ts.open {
            return Err(AppchainError::TableNotOpen(record.table_id));
        }
        // C1：replay 检查只读；binding 销毁移到全部校验通过之后
        if state.settled_bindings.contains(&record.hand_binding) {
            return Err(AppchainError::SettlementReplay);
        }
        let policy = *state.registry.require(record.table_id)?;
        // TE-M4：FixedRakeBurn 桌准入门（v2 结算先行；v1 路径已在
        // `validate_settlement` 对 burn 桌整体拒）。计价资产必须 GAME 域
        // 且已注册 GTS token——REAL 域误用 burn 策略 / 遗留 PLAY(0) /
        // 未注册 token 一律 fail-closed（inputs 为空同样落本门的拒绝臂，
        // 不放行任何状态；空输入的规范诊断由下方 validate 兜底）。
        let burn_token_id = if matches!(policy, FeePolicy::FixedRakeBurn { .. }) {
            match record.inputs.first().map(crate::note_v2::SettleInputV2::asset_id) {
                Some(asset) if asset.is_game_domain()
                    && asset.token_id != crate::asset_id::GAME_TOKEN_PLAY
                    && state.game_registry.contains(asset.token_id) =>
                {
                    metrics.inc("game_settle_burn_admitted_total");
                    Some(asset.token_id)
                }
                _ => {
                    metrics.inc("game_token_rejected_total");
                    return Err(AppchainError::AdmissionRejected(
                        "fixed rake burn settlement requires a registered GAME domain token",
                    ));
                }
            }
        } else {
            None
        };
        // TE-M6：Free 桌 gas 服务费门（每手结算受理前；INV-TE-9 / INV-TE-8）。
        //
        // 判据：首输入资产为 GAME 域**已注册且 Free 模式**的 GTS token
        // （GTS token 只在 v2 账本存在，发起方必为 v2 输入）。分支语义：
        // - Free token + 桌已绑定同 token GasPolicy → INV-TE-8 前置校验
        //   发起方（首输入 owner）credit ≥ fee_per_hand，不足拒
        //   （计 `gas_credit_insufficient_total`）；
        // - Free token + 桌未绑定（或绑定 token 不匹配）→ INV-TE-9 拒
        //   （计 `gas_policy_missing_rejected_total`）；
        // - Paid token → 不触发（TE-D7：Paid 桌叠加 gas 收费 v1 禁止，
        //   且 Paid token 桌的绑定在 BindGasPolicy 准入已拒）；
        // - 遗留 PLAY(0) / REAL 域 → 不触发（PLAY 永久免费层）。
        let gas_charge: Option<([u8; 32], GasPolicy)> =
            match record.inputs.first().map(crate::note_v2::SettleInputV2::asset_id) {
                Some(asset)
                    if asset.is_game_domain()
                        && asset.token_id != crate::asset_id::GAME_TOKEN_PLAY =>
                {
                    match state.game_registry.get(asset.token_id) {
                        Some(spec) if matches!(spec.mode, IssuanceMode::Free { .. }) => {
                            match state.gas_policies.get(&record.table_id) {
                                Some((bound_token, policy)) if *bound_token == asset.token_id => {
                                    let initiator = match record.inputs.first() {
                                        Some(crate::note_v2::SettleInputV2::V2 { note, .. }) => {
                                            note.owner.clone()
                                        }
                                        // 结构不可达（GTS token 不在 v1 账本
                                        // 存在）；fail-closed 兜底臂
                                        _ => {
                                            metrics.inc("gas_policy_missing_rejected_total");
                                            return Err(AppchainError::AdmissionRejected(
                                                "free-table gas fee requires a v2 initiator input",
                                            ));
                                        }
                                    };
                                    let owner_key = owner_commitment(&initiator);
                                    // INV-TE-8 前置校验（检查段；变更段前
                                    // 零状态变更，扣减在下方受理段执行）
                                    if let Err(e) = state.gas_credits.ensure_spendable(
                                        &owner_key,
                                        policy.pricing_asset_id,
                                        policy.fee_per_hand,
                                    ) {
                                        metrics.inc("gas_credit_insufficient_total");
                                        return Err(e);
                                    }
                                    Some((owner_key, *policy))
                                }
                                _ => {
                                    // INV-TE-9：Free 桌未绑 GasPolicy（或绑定
                                    // token 不匹配）→ 本手受理拒绝
                                    metrics.inc("gas_policy_missing_rejected_total");
                                    return Err(AppchainError::AdmissionRejected(
                                        "free-token settlement requires a bound gas policy for this table (INV-TE-9)",
                                    ));
                                }
                            }
                        }
                        _ => None,
                    }
                }
                _ => None,
            };
        // 账本核对：输入按版本在对应账本存在且内容一致
        for input in &record.inputs {
            match input {
                SettleInputV2::V1 { note, .. } => {
                    let key = felt_to_bytes32(&note.commitment());
                    let e = state
                        .notes
                        .get(&key)
                        .ok_or(AppchainError::NoteNotFound)?;
                    if e.note != *note {
                        return Err(AppchainError::AdmissionRejected("input note mismatch"));
                    }
                }
                SettleInputV2::V2 { note, .. } => {
                    let key = note.commitment_bytes();
                    let e = state
                        .notes_v2
                        .get(&key)
                        .ok_or(AppchainError::NoteNotFound)?;
                    if e.note != *note {
                        return Err(AppchainError::AdmissionRejected("input note mismatch"));
                    }
                }
            }
        }
        // 纯函数校验（含双 verifier 签名分派；nonce 查询借 state 只读）
        let nonce_of = |o: &crate::owner_v2::OwnerRef| {
            state.owner_nonces_v2.get(&owner_commitment(o)).copied()
        };
        validate_settlement_v2(
            record,
            &policy,
            &config.network_id,
            OWNER_V2_ABI_VERSION,
            now,
            &nonce_of,
        )?;
        // 审计 P2：消费段读侧预检先行（v1/v2 双臂 nullifier + v1 臂账本
        // 存在性/重复）——settled_bindings.insert 后 consume 失败同样会烧
        // 绑定且留部分消费。预检过后下方消费循环不再失败。
        Self::precheck_consume_v1(
            state,
            record.inputs.iter().filter_map(|i| match i {
                SettleInputV2::V1 { note, spend } => Some((spend, note)),
                SettleInputV2::V2 { .. } => None,
            }),
        )?;
        Self::precheck_nullifiers_v2(
            state,
            record
                .inputs
                .iter()
                .filter_map(|i| match i {
                    SettleInputV2::V2 { nullifier, .. } => Some(nullifier),
                    SettleInputV2::V1 { .. } => None,
                }),
        )?;

        // ===== 变更段（以上全部通过，以下不再失败）=====
        if !state.settled_bindings.insert(record.hand_binding) {
            return Err(AppchainError::SettlementReplay);
        }
        // 消费（v1/nullifier 声明一致性与签名已验）+ v2 nonce 水位推进
        for input in &record.inputs {
            match input {
                SettleInputV2::V1 { note, spend } => {
                    Self::consume_note(state, note, &spend.nullifier)?;
                }
                SettleInputV2::V2 { note, nullifier, envelope, .. } => {
                    Self::consume_note_v2(state, note, nullifier)?;
                    let signer = owner_commitment(&envelope.signer_ref);
                    state
                        .owner_nonces_v2
                        .entry(signer)
                        .and_modify(|last| {
                            if envelope.nonce > *last {
                                *last = envelope.nonce;
                            }
                        })
                        .or_insert(envelope.nonce);
                }
            }
        }
        // 铸赔付（v2 账本）
        for (i, o) in record.payouts.iter().enumerate() {
            let payload = blake2s32(&[
                b"settle-v2-out",
                record.hand_binding.as_slice(),
                &felt_to_bytes32(&felt_from_u64(u64::try_from(i).unwrap_or(u64::MAX))),
            ]);
            let nonce = Self::mint_nonce_v2(state.seq, b"settle-v2", &payload);
            Self::mint_note_v2(state, o.clone().mint(nonce)?)?;
        }
        // 铸 rake 输出（v1 账本；legacy 收款人）。
        // TE-M4：FixedRakeBurn 桌的 rake 输出恒为 None（validate 第 8 条
        // 强制），本循环对 burn 桌自然跳过——不铸任何 treasury/operator
        // note；销毁记账在下一步。
        if record.rake.total > 0 {
            if let Some(spec) = &record.rake.treasury_out {
                let nonce = Self::mint_nonce(state.seq, b"rake-v2-t", &record.hand_binding);
                Self::mint_note(state, spec.clone().mint(nonce)?)?;
            }
            if let Some(spec) = &record.rake.operator_out {
                let nonce = Self::mint_nonce(state.seq, b"rake-v2-o", &record.hand_binding);
                Self::mint_note(state, spec.clone().mint(nonce)?)?;
            }
        }
        // TE-M4：burn 处置记账（变更段，零失败）——rake 份额计入
        // `Σburned`，`game_outstanding = Σminted − Σburned` 随之收缩，
        // GAME 域供给对账（INV-TE-7）闭合。重复计入被
        // `settled_bindings`（重放拒）+ 无 rake 输出（双计拒）双重阻断。
        if let Some(token_id) = burn_token_id {
            if record.rake.total > 0 {
                *state
                    .game_burned
                    .entry(token_id)
                    .or_insert(0u128) += u128::from(record.rake.total);
                metrics.inc("game_token_burned_total");
                metrics.add("game_settle_burn_amount_total", record.rake.total);
                let outstanding = state.game_outstanding(token_id);
                metrics.set_gauge(
                    &format!("game_token_outstanding{{token=\"{token_id}\"}}"),
                    u64::try_from(outstanding).unwrap_or(u64::MAX),
                );
            }
        }
        // TE-M6：gas 服务费计提（受理即消耗，设计 §3.8.3；与结算守恒/AIR
        // 零交集——不进结算记录、不进 pot 数学）。INV-TE-8 由检查段
        // `ensure_spendable` + 检查到变更之间零状态变更保证（spend 在此
        // 不可失败；Result 保持强制点单一）。计量账与 CustodyLedger 物理隔离。
        if let Some((owner_key, policy)) = &gas_charge {
            state
                .gas_credits
                .spend(owner_key, policy.pricing_asset_id, policy.fee_per_hand)?;
            metrics.add("gas_credits_consumed_total", policy.fee_per_hand);
            metrics.add(
                &format!(
                    "gas_credits_consumed_total{{currency=\"{}\"}}",
                    policy.pricing_asset_id
                ),
                policy.fee_per_hand,
            );
            let balance_total = state.gas_credits.total_balance_of(policy.pricing_asset_id);
            metrics.set_gauge(
                &format!(
                    "gas_credit_balance{{currency=\"{}\"}}",
                    policy.pricing_asset_id
                ),
                u64::try_from(balance_total).unwrap_or(u64::MAX),
            );
        }
        metrics.add("rake_total", u64::from(record.rake.total));
        Ok(())
    }

    // ===== TE-M2 准入与应用（多币种存款 / 提现申请）=====

    /// REAL 域封闭枚举门（TE-M2 存/提两 op 共用；fail-closed）：
    /// GAME 域任何 token 拒入本两 op（GAME 发行是 TE-M3 的 IssueGameToken
    /// 另行追加变体；GAME 赎回同属 TE-M3+ 独立通道）；REAL 域未注册
    /// token（borsh 伪造载荷绕过 `AssetId::real` 构造器的情形）同拒
    /// ——"不认识 ≠ 接受"。
    fn ensure_real_registered_asset(asset: &AssetId) -> AppchainResult<()> {
        if !asset.is_real_domain() || !asset.domain.is_registered_token(asset.token_id) {
            return Err(AppchainError::AdmissionRejected(
                "op accepts REAL domain registered tokens only",
            ));
        }
        Ok(())
    }

    /// DepositV2 准入与应用（TE-M2 判别值 9；C1 纪律：全部可失败检查
    /// 先行，变更段零失败）。
    ///
    /// 准入清单：
    /// 1. REAL 域封闭枚举门（GAME 域拒入本 op）；
    /// 2. 收款人结构合法 + 面额 > 0（[`NoteV2::new`]）；
    /// 3. 承诺查重（`notes_v2`）；
    /// 4. deposit_id 幂等（**跨版本双向**：v1 `deposit_ids` 与 v2
    ///    `deposit_records_v2` 任一命中即拒——同一外部支付不得经两条
    ///    路径重复铸造；v1 路径冻结不动，跨版本防线由 v2 侧承担）。
    ///
    /// 应用：铸 v2 REAL note（nonce = `mint_nonce_v2(b"deposit-v2",
    /// deposit_id)`——同 deposit_id 同载荷必得同承诺，幂等拒绝；自由
    /// 余额形态）+ 登记 v2 入金记录（托管侧 confirm 重放/队列重建输入）
    /// + 双侧幂等集插入。
    fn apply_deposit_v2(
        state: &mut LedgerState,
        payload: &DepositV2Op,
    ) -> AppchainResult<()> {
        // —— 全部可失败检查 ——
        Self::ensure_real_registered_asset(&payload.asset_id)?;
        let note = NoteV2::new(
            payload.asset_id,
            payload.amount,
            payload.owner.clone(),
            Self::mint_nonce_v2(state.seq, b"deposit-v2", &payload.deposit_id),
            None,
            0,
            0,
        )?;
        let c = note.commitment_bytes();
        if state.notes_v2.contains_key(&c) {
            return Err(AppchainError::AdmissionRejected("duplicate note commitment"));
        }
        // TE-M3：跨路径幂等——GAME 发行已用同一外部支付 id → DepositV2 拒
        //（同一外部支付不得既走 GAME 发行又走 REAL 存款；反向防线在
        // apply_issue_game_token 内双侧查重）
        if state.deposit_ids.contains(&payload.deposit_id)
            || state.deposit_records_v2.contains_key(&payload.deposit_id)
            || state.game_issue_ids.contains(&payload.deposit_id)
        {
            return Err(AppchainError::WithdrawalConflict("duplicate deposit id".into()));
        }

        // ===== 变更段（以上全部通过，以下不再失败）=====
        state.deposit_ids.insert(payload.deposit_id);
        state
            .deposit_records_v2
            .insert(payload.deposit_id, (payload.asset_id, payload.amount, c));
        Self::mint_note_v2(state, note)?;
        Ok(())
    }

    /// WithdrawRequestV2 准入与应用（TE-M2 判别值 10；C1 纪律）。
    ///
    /// 准入清单（顺序即实现，全 fail-closed）：
    /// 1. REAL 域封闭枚举门（GAME 域拒入本 op）；
    /// 2. 载荷一致性：销毁面额 == `gross_amount`、note 资产 == `asset_id`
    ///    （[`AssetId::ensure_same`]——跨域/跨 token 一律
    ///    [`AppchainError::AssetMismatch`]）；
    /// 3. 信封结构一致（[`validate_envelope`]：scheme 匹配 + signer 合法）；
    /// 4. 信封签名者 == note owner（防"他人代签"）；
    /// 5. nullifier 非零且可规范化（canonical felt）；
    /// 6. nullifier 未消费（读侧查重先行——变更段零失败的 C1 加严，
    ///    v1 apply_withdraw 的已知边界在此不复现）；
    /// 7. 摘要一致：`owner_sig.typed_data_digest == v2_spend_digest(
    ///    owner, note 承诺, nullifier, scope, effect)`，其中 scope =
    ///    `spend_scope(network_id, abi_version, scope::WITHDRAW_V2)`
    ///    （network/abi 绑定防跨网/跨版重放；effect 绑定全部语义载荷）；
    /// 8. 新鲜度：`now < expiry` 且 per-signer nonce 严格单调（帧时间戳
    ///    即权威时钟，提交与 WAL 重放同值）；
    /// 9. request_id 幂等（跨版本共享 `withdrawal_ids`，只读检查）；
    /// 10. note 存在且内容一致（`notes_v2` 账本核对）；
    /// 11. 按 scheme 分派验签（材料随载荷呈递，变体不匹配即拒）。
    ///
    /// 应用：登记 request_id → 推进 signer 的 v2 nonce 水位 → 销毁 note
    /// （共享 nullifier 集）→ 记录 `burned_v2`（托管对账/通道分离输入）。
    /// 托管侧队列/储备/finality 门在 [`crate::vault::CustodyLedgerV2`]
    /// （外挂托管账，与 v1 同架构；见模块边界文档）。
    fn apply_withdraw_request_v2(
        config: &SequencerConfig,
        state: &mut LedgerState,
        payload: &WithdrawRequestV2Op,
        effect: &[u8; 32],
        ts_ms: u64,
    ) -> AppchainResult<()> {
        // —— 全部可失败检查 ——
        Self::ensure_real_registered_asset(&payload.asset_id)?;
        if payload.note.amount != payload.gross_amount {
            return Err(AppchainError::AdmissionRejected(
                "withdraw v2 gross amount does not match note face",
            ));
        }
        payload.asset_id.ensure_same(payload.note.asset_id)?;
        validate_envelope(&payload.owner_sig)?;
        if payload.owner_sig.signer_ref != payload.note.owner {
            return Err(AppchainError::AdmissionRejected(
                "withdraw v2 envelope signer is not the note owner",
            ));
        }
        if payload.nullifier == [0u8; 32] {
            return Err(AppchainError::AdmissionRejected("zero nullifier"));
        }
        let nf = crate::felt::felt_from_bytes32_exact(&payload.nullifier)?;
        if state.nullifiers.contains(&nf) {
            return Err(AppchainError::DoubleSpend);
        }
        let scope = crate::note_v2::spend_scope(
            &config.network_id,
            OWNER_V2_ABI_VERSION,
            scope::WITHDRAW_V2,
        );
        let digest = v2_spend_digest(
            &payload.note.owner,
            &payload.note.commitment_bytes(),
            &payload.nullifier,
            &scope,
            effect,
        );
        if payload.owner_sig.typed_data_digest != digest {
            return Err(crate::owner_v2::OwnerV2Error::DigestMismatch.into());
        }
        let signer_key = owner_commitment(&payload.owner_sig.signer_ref);
        let last_nonce = state.owner_nonces_v2.get(&signer_key).copied();
        check_envelope_freshness(&payload.owner_sig, ts_ms / 1000, last_nonce)?;
        if state.withdrawal_ids.contains(&payload.request_id) {
            return Err(AppchainError::WithdrawalConflict("duplicate request id".into()));
        }
        let key = payload.note.commitment_bytes();
        match state.notes_v2.get(&key) {
            Some(e) if e.note == payload.note => {}
            Some(_) => {
                return Err(AppchainError::AdmissionRejected("input note mismatch"));
            }
            None => return Err(AppchainError::NoteNotFound),
        }
        verify_owner_signature(
            &payload.owner_sig.signer_ref,
            &payload.owner_sig.typed_data_digest,
            &payload.owner_sig.signature,
            &payload.material,
        )?;

        // ===== 变更段（以上全部通过，以下不再失败）=====
        state.withdrawal_ids.insert(payload.request_id);
        state
            .owner_nonces_v2
            .entry(signer_key)
            .and_modify(|last| {
                if payload.owner_sig.nonce > *last {
                    *last = payload.owner_sig.nonce;
                }
            })
            .or_insert(payload.owner_sig.nonce);
        Self::consume_note_v2(state, &payload.note, &payload.nullifier)?;
        state.burned_v2.push((
            payload.request_id,
            payload.asset_id,
            payload.gross_amount,
        ));
        Ok(())
    }

    // ===== TE-M3 准入与应用（GTS 游戏币：注册 / 发行 / 销毁）=====

    /// RegisterGameToken 准入与应用（TE-M3 判别值 11；C1 纪律：全部可
    /// 失败检查先行，变更段零失败）。
    ///
    /// 准入清单（顺序即实现，全 fail-closed）：
    /// 1. 规格结构校验（[`GameTokenSpec::new`]：token_id ≠ 0 遗留 PLAY
    ///    保留位、issuer 非零、Paid anchor 为 REAL 域已注册 token、
    ///    Paid rate > 0、Free faucet 参数合法）；
    /// 2. genesis 摘要全等核对（客户端声明摘要 == 链侧重算——全部字段
    ///    绑定，任何载荷篡改必失配）；
    /// 3. 价带校验（INV-TE-4 validation 层：Paid `rate ∉
    ///    [R_min, R_max]` → [`AppchainError::RateOutOfBand`]，计
    ///    `issuance_rate_rejected_total`；band 经 [`SequencerConfig`]
    ///    注入，全网一致参数）；Free 模式无 rate，跳过本步（其成本
    ///    覆盖是 gas 服务费定价，TE-M6）；
    /// 4. 冻结语义：同 token_id 重注册拒（重定价 = 发新 token，TE-D2）。
    ///
    /// 应用：规格入注册表（append-only）+ 计数。
    fn apply_register_game_token(
        config: &SequencerConfig,
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        payload: &RegisterGameTokenOp,
    ) -> AppchainResult<()> {
        // —— 全部可失败检查 ——
        let spec = GameTokenSpec::new(
            payload.token_id,
            &payload.issuer,
            payload.mode.clone(),
            payload.max_supply,
        )?;
        if spec.genesis_digest != payload.genesis_digest {
            metrics.inc("game_token_rejected_total");
            return Err(AppchainError::AdmissionRejected(
                "game token genesis digest mismatch",
            ));
        }
        if let IssuanceMode::Paid { rate, .. } = spec.mode {
            // INV-TE-4 第 1 层（validation）；第 2 层 = rate 已进 genesis
            // 摘要（带外发行的 witness 不可证明）
            if let Err(e) = validate_rate(
                rate,
                &RateBand {
                    min: config.game_rate_min,
                    max: config.game_rate_max,
                },
            ) {
                metrics.inc("issuance_rate_rejected_total");
                metrics.inc("game_token_rejected_total");
                return Err(e);
            }
        }
        if state.game_registry.contains(payload.token_id) {
            metrics.inc("game_token_rejected_total");
            return Err(AppchainError::GameRegistryRejected(
                "token_id already registered (genesis is frozen; repricing = new token)",
            ));
        }

        // ===== 变更段（以上全部通过，以下不再失败）=====
        state.game_registry.register(spec)?;
        metrics.inc("game_token_registered_total");
        Ok(())
    }

    /// IssueGameToken 准入与应用（TE-M3 判别值 12；C1 纪律）。GAME 域
    /// **唯一入口**——复用 Deposit 的幂等托管确认模式。
    ///
    /// 准入清单：
    /// 1. 注册表门（经 [`crate::asset_id::AssetDomain::
    ///    is_registered_token_in`] 扩展点 + 规格存在；遗留 PLAY(0) 无
    ///    GTS 规格，拒入）；
    /// 2. 铸造量计算（Paid：`floor(pay_amount * R / 1e18)`，尘埃支付
    ///    —— 不足 1 币 —— 拒绝；Free：申请量直铸，受 faucet 骨架限量：
    ///    单次上限 + 每玩家终身累计上限，超限
    ///    [`AppchainError::RateLimited`]，TE-M6 前时间窗限流不做）；
    /// 3. max_supply 上限（0 = 不限；超限
    ///    [`AppchainError::SupplyCapExceeded`]）；
    /// 4. `issue_id` 幂等（**跨路径**：v1 `deposit_ids` / v2
    ///    `deposit_records_v2` / GAME `game_issue_ids` 任一命中即拒——
    ///    同一外部支付不得经两条路径重复铸造）；
    /// 5. 承诺查重（`notes_v2`）。
    ///
    /// 应用：铸 GAME 域自由余额 v2 note（nonce = `mint_nonce_v2(b"issue-
    /// game", issue_id)`）+ 登记幂等集 + 聚合账 `game_minted` / faucet
    /// 记账 + 计数与 outstanding gauge。
    fn apply_issue_game_token(
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        payload: &IssueGameTokenOp,
    ) -> AppchainResult<()> {
        // —— 全部可失败检查 ——
        // 1. 注册表门（GAME 域唯一扩展点；未注册/遗留 PLAY 一律拒）
        if payload.token_id == crate::asset_id::GAME_TOKEN_PLAY
            || !crate::asset_id::AssetDomain::Game
                .is_registered_token_in(payload.token_id, &state.game_registry)
        {
            metrics.inc("game_token_rejected_total");
            return Err(AppchainError::GameRegistryRejected(
                "issue requires a registered GTS token",
            ));
        }
        let spec = state
            .game_registry
            .get(payload.token_id)
            .cloned()
            .expect("registry membership checked above");
        let owner_key = owner_commitment(&payload.buyer);

        // 2. 铸造量（Paid 价率换算 / Free faucet 骨架限量）
        let mint = match &spec.mode {
            IssuanceMode::Paid { .. } => {
                let m = spec.mint_for(payload.pay_amount);
                if m == 0 {
                    // 尘埃支付：不足 1 币，fail-closed 拒绝（无零面额
                    // note；未铸侧不留部分记账——watcher 侧按外部流水
                    // 对账该支付）
                    metrics.inc("game_token_rejected_total");
                    return Err(AppchainError::AdmissionRejected(
                        "issuance pays less than one game token (dust stays unminted)",
                    ));
                }
                m
            }
            IssuanceMode::Free { faucet } => {
                if payload.pay_amount == 0 {
                    return Err(AppchainError::InvalidAmount(0));
                }
                if payload.pay_amount > faucet.single_max {
                    metrics.inc("faucet_rate_limited_total");
                    metrics.inc("game_token_rejected_total");
                    return Err(AppchainError::RateLimited(payload.buyer.account_id));
                }
                let issued = state
                    .game_faucet_issued
                    .get(&(payload.token_id, owner_key))
                    .copied()
                    .unwrap_or(0);
                let new_total = issued.saturating_add(payload.pay_amount);
                if new_total > faucet.player_lifetime_max {
                    metrics.inc("faucet_rate_limited_total");
                    metrics.inc("game_token_rejected_total");
                    return Err(AppchainError::RateLimited(payload.buyer.account_id));
                }
                u128::from(payload.pay_amount)
            }
        };

        // 3. max_supply 上限
        if spec.max_supply != 0 {
            let minted = state.game_minted.get(&payload.token_id).copied().unwrap_or(0);
            if minted + mint > u128::from(spec.max_supply) {
                metrics.inc("game_token_rejected_total");
                return Err(AppchainError::SupplyCapExceeded {
                    token_id: payload.token_id,
                    minted,
                    requested: mint,
                    cap: spec.max_supply,
                });
            }
        }

        // 4. issue_id 幂等（跨路径双向）
        if state.game_issue_ids.contains(&payload.issue_id)
            || state.deposit_ids.contains(&payload.issue_id)
            || state.deposit_records_v2.contains_key(&payload.issue_id)
        {
            return Err(AppchainError::WithdrawalConflict("duplicate issue id".into()));
        }

        // 5. 铸出 note（GAME 域自由余额形态）+ 承诺查重
        let amount = u64::try_from(mint).map_err(|_| {
            metrics.inc("game_token_rejected_total");
            AppchainError::OutOfRange("game token mint amount")
        })?;
        let note = NoteV2::new(
            crate::asset_id::AssetId::game(payload.token_id),
            amount,
            payload.buyer.clone(),
            Self::mint_nonce_v2(state.seq, b"issue-game", &payload.issue_id),
            None,
            0,
            0,
        )?;
        let c = note.commitment_bytes();
        if state.notes_v2.contains_key(&c) {
            return Err(AppchainError::AdmissionRejected("duplicate note commitment"));
        }

        // ===== 变更段（以上全部通过，以下不再失败）=====
        state.game_issue_ids.insert(payload.issue_id);
        if matches!(spec.mode, IssuanceMode::Free { .. }) {
            *state
                .game_faucet_issued
                .entry((payload.token_id, owner_key))
                .or_insert(0) += amount;
        }
        *state.game_minted.entry(payload.token_id).or_insert(0u128) += u128::from(amount);
        Self::mint_note_v2(state, note)?;
        metrics.inc("game_token_minted_total");
        metrics.add("game_token_minted_amount_total", amount);
        let outstanding = state.game_outstanding(payload.token_id);
        metrics.set_gauge(
            &format!("game_token_outstanding{{token=\"{}\"}}", payload.token_id),
            u64::try_from(outstanding).unwrap_or(u64::MAX),
        );
        Ok(())
    }

    /// BurnGameToken 准入与应用（TE-M3 判别值 13；C1 纪律）。GAME 域
    /// **唯一出口**；验签管线镜像 [`Self::apply_withdraw_request_v2`]，
    /// scope 换用 [`scope::BURN_GAME`]。
    ///
    /// 准入清单（顺序即实现，全 fail-closed）：
    /// 1. **REAL 域拒入**（对称纪律：note 非 GAME 域一律拒，计数
    ///    `game_token_rejected_total`——REAL 资产出口是 Withdraw 系，两
    ///    通道互斥）；
    /// 2. 注册表门（`token_id` 已注册且 == note 资产的 token_id；遗留
    ///    PLAY(0) 无 GTS 规格，拒入本 op）；
    /// 3. 信封结构一致（[`validate_envelope`]）；
    /// 4. 信封签名者 == note owner；
    /// 5. nullifier 非零且可规范化；
    /// 6. nullifier 未消费（共享集——与提现/结算统一双花防线）；
    /// 7. 摘要一致：`typed_data_digest == v2_spend_digest(owner, note
    ///    承诺, nullifier, BURN_GAME scope, effect)`（network/abi 绑定防
    ///    跨网/跨版重放；effect 绑定 burn_id/token_id/承诺/nullifier——
    ///    与提现 scope 域分离，授权不可跨 op 族重放）；
    /// 8. 新鲜度：`now < expiry` 且 per-signer nonce 严格单调；
    /// 9. `burn_id` 幂等（op 族内查重）；
    /// 10. note 存在且内容一致（`notes_v2` 账本核对）；
    /// 11. 按 scheme 分派验签（材料随载荷呈递）。
    ///
    /// 应用：登记 burn_id → 推进 signer nonce 水位 → 销毁 note（共享
    /// nullifier 集）→ 聚合账 `game_burned` + 计数与 outstanding gauge。
    fn apply_burn_game_token(
        config: &SequencerConfig,
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        payload: &BurnGameTokenOp,
        effect: &[u8; 32],
        ts_ms: u64,
    ) -> AppchainResult<()> {
        // —— 全部可失败检查 ——
        // 1. REAL 域拒入（对称纪律，fail-closed + 计数）
        if !payload.note.asset_id.is_game_domain() {
            metrics.inc("game_token_rejected_total");
            return Err(AppchainError::AdmissionRejected(
                "burn accepts GAME domain tokens only",
            ));
        }
        // 2. 注册表门 + 载荷一致性
        if payload.token_id == crate::asset_id::GAME_TOKEN_PLAY
            || payload.note.asset_id.token_id != payload.token_id
            || !crate::asset_id::AssetDomain::Game
                .is_registered_token_in(payload.token_id, &state.game_registry)
        {
            metrics.inc("game_token_rejected_total");
            return Err(AppchainError::GameRegistryRejected(
                "burn requires the note's registered GTS token",
            ));
        }
        // 3. 信封结构
        validate_envelope(&payload.owner_sig)?;
        // 4. signer == owner
        if payload.owner_sig.signer_ref != payload.note.owner {
            return Err(AppchainError::AdmissionRejected(
                "burn envelope signer is not the note owner",
            ));
        }
        // 5. nullifier 形状
        if payload.nullifier == [0u8; 32] {
            return Err(AppchainError::AdmissionRejected("zero nullifier"));
        }
        let nf = crate::felt::felt_from_bytes32_exact(&payload.nullifier)?;
        // 6. 双花（共享 nullifier 集）
        if state.nullifiers.contains(&nf) {
            return Err(AppchainError::DoubleSpend);
        }
        // 7. 摘要一致（BURN_GAME scope + effect）
        let scope_tag = crate::note_v2::spend_scope(
            &config.network_id,
            OWNER_V2_ABI_VERSION,
            scope::BURN_GAME,
        );
        let digest = v2_spend_digest(
            &payload.note.owner,
            &payload.note.commitment_bytes(),
            &payload.nullifier,
            &scope_tag,
            effect,
        );
        if payload.owner_sig.typed_data_digest != digest {
            return Err(crate::owner_v2::OwnerV2Error::DigestMismatch.into());
        }
        // 8. 新鲜度 + nonce 单调
        let signer_key = owner_commitment(&payload.owner_sig.signer_ref);
        let last_nonce = state.owner_nonces_v2.get(&signer_key).copied();
        check_envelope_freshness(&payload.owner_sig, ts_ms / 1000, last_nonce)?;
        // 9. burn_id 幂等
        if state.game_burn_ids.contains(&payload.burn_id) {
            return Err(AppchainError::WithdrawalConflict("duplicate burn id".into()));
        }
        // 10. 账本核对
        let key = payload.note.commitment_bytes();
        match state.notes_v2.get(&key) {
            Some(e) if e.note == payload.note => {}
            Some(_) => {
                return Err(AppchainError::AdmissionRejected("input note mismatch"));
            }
            None => return Err(AppchainError::NoteNotFound),
        }
        // 11. 验签（材料随载荷）
        verify_owner_signature(
            &payload.owner_sig.signer_ref,
            &payload.owner_sig.typed_data_digest,
            &payload.owner_sig.signature,
            &payload.material,
        )?;

        // ===== 变更段（以上全部通过，以下不再失败）=====
        state.game_burn_ids.insert(payload.burn_id);
        state
            .owner_nonces_v2
            .entry(signer_key)
            .and_modify(|last| {
                if payload.owner_sig.nonce > *last {
                    *last = payload.owner_sig.nonce;
                }
            })
            .or_insert(payload.owner_sig.nonce);
        Self::consume_note_v2(state, &payload.note, &payload.nullifier)?;
        *state
            .game_burned
            .entry(payload.token_id)
            .or_insert(0u128) += u128::from(payload.note.amount);
        metrics.inc("game_token_burned_total");
        metrics.add("game_token_burned_amount_total", payload.note.amount);
        let outstanding = state.game_outstanding(payload.token_id);
        metrics.set_gauge(
            &format!("game_token_outstanding{{token=\"{}\"}}", payload.token_id),
            u64::try_from(outstanding).unwrap_or(u64::MAX),
        );
        Ok(())
    }

    // ===== TE-M6 准入与应用（Free 模式 gas 服务费：faucet / credit / 绑定）=====

    /// FaucetMint 准入与应用（TE-M6 判别值 14；C1 纪律：全部可失败检查
    /// 先行，变更段零失败）。Free token 的专属领取通道——**无外部支付**
    /// （不销售，合规定性见设计 §3.8.1：币刻意不稀缺）。
    ///
    /// 准入清单（顺序即实现，全 fail-closed）：
    /// 1. 注册表门（已注册 GTS token；遗留 PLAY(0) 拒）；
    /// 2. Free 模式门（Paid token 的铸造通道是 `IssueGameToken`——本 op
    ///    拒，两通道互斥）；
    /// 3. faucet 限量：`amount > 0`、`amount ≤ single_max`、终身累计
    ///    `≤ player_lifetime_max`（按 owner_commitment 记账，超限
    ///    [`AppchainError::RateLimited`]，计 `faucet_rate_limited_total`；
    ///    时间窗限流 v1 不做，如实声明）；
    /// 4. max_supply 上限（与 Issue 同口径）；
    /// 5. `claim_id` 幂等（op 族内查重；faucet 无外部支付身份，不与
    ///    deposit/issue 幂等集交叉）；
    /// 6. 承诺查重（`notes_v2`）。
    ///
    /// 应用：铸 GAME 域自由余额 v2 note（nonce =
    /// `mint_nonce_v2(b"faucet-mint", claim_id)`）+ 登记幂等集 + faucet
    /// 终身记账 + 聚合账 `game_minted` + 计数与 outstanding gauge。
    fn apply_faucet_mint(
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        payload: &FaucetMintOp,
    ) -> AppchainResult<()> {
        // —— 全部可失败检查 ——
        // 1. 注册表门
        if payload.token_id == crate::asset_id::GAME_TOKEN_PLAY
            || !crate::asset_id::AssetDomain::Game
                .is_registered_token_in(payload.token_id, &state.game_registry)
        {
            metrics.inc("game_token_rejected_total");
            return Err(AppchainError::GameRegistryRejected(
                "faucet mint requires a registered GTS token",
            ));
        }
        let spec = state
            .game_registry
            .get(payload.token_id)
            .cloned()
            .expect("registry membership checked above");
        // 2. Free 模式门（Paid 走 IssueGameToken，两通道互斥）
        let faucet = match spec.mode {
            IssuanceMode::Free { faucet } => faucet,
            IssuanceMode::Paid { .. } => {
                metrics.inc("game_token_rejected_total");
                return Err(AppchainError::AdmissionRejected(
                    "faucet mint accepts Free-mode tokens only (paid issuance is IssueGameToken)",
                ));
            }
        };
        // 3. faucet 限量（单次 + 终身）
        if payload.amount == 0 {
            return Err(AppchainError::InvalidAmount(0));
        }
        if payload.amount > faucet.single_max {
            metrics.inc("faucet_rate_limited_total");
            metrics.inc("game_token_rejected_total");
            return Err(AppchainError::RateLimited(payload.owner.account_id));
        }
        let owner_key = owner_commitment(&payload.owner);
        let issued = state
            .game_faucet_issued
            .get(&(payload.token_id, owner_key))
            .copied()
            .unwrap_or(0);
        if issued.saturating_add(payload.amount) > faucet.player_lifetime_max {
            metrics.inc("faucet_rate_limited_total");
            metrics.inc("game_token_rejected_total");
            return Err(AppchainError::RateLimited(payload.owner.account_id));
        }
        // 4. max_supply 上限
        if spec.max_supply != 0 {
            let minted = state.game_minted.get(&payload.token_id).copied().unwrap_or(0);
            if minted + u128::from(payload.amount) > u128::from(spec.max_supply) {
                metrics.inc("game_token_rejected_total");
                return Err(AppchainError::SupplyCapExceeded {
                    token_id: payload.token_id,
                    minted,
                    requested: u128::from(payload.amount),
                    cap: spec.max_supply,
                });
            }
        }
        // 5. claim_id 幂等（op 族内）
        if state.game_faucet_ids.contains(&payload.claim_id) {
            return Err(AppchainError::WithdrawalConflict(
                "duplicate faucet claim id".into(),
            ));
        }
        // 6. 铸出 note（GAME 域自由余额形态）+ 承诺查重
        let note = NoteV2::new(
            crate::asset_id::AssetId::game(payload.token_id),
            payload.amount,
            payload.owner.clone(),
            Self::mint_nonce_v2(state.seq, b"faucet-mint", &payload.claim_id),
            None,
            0,
            0,
        )?;
        let c = note.commitment_bytes();
        if state.notes_v2.contains_key(&c) {
            return Err(AppchainError::AdmissionRejected("duplicate note commitment"));
        }

        // ===== 变更段（以上全部通过，以下不再失败）=====
        state.game_faucet_ids.insert(payload.claim_id);
        *state
            .game_faucet_issued
            .entry((payload.token_id, owner_key))
            .or_insert(0) += payload.amount;
        *state.game_minted.entry(payload.token_id).or_insert(0u128) += u128::from(payload.amount);
        Self::mint_note_v2(state, note)?;
        metrics.inc("faucet_mint_total");
        metrics.add("game_token_minted_amount_total", payload.amount);
        let outstanding = state.game_outstanding(payload.token_id);
        metrics.set_gauge(
            &format!("game_token_outstanding{{token=\"{}\"}}", payload.token_id),
            u64::try_from(outstanding).unwrap_or(u64::MAX),
        );
        Ok(())
    }

    /// BuyGasCredits 准入与应用（TE-M6 判别值 15；C1 纪律）。REAL 域计价
    /// 外部支付 → credit 额度入账。**不铸 note、不进 CustodyLedger**——
    /// 服务费收入是已售服务额度（无赎回、无储备义务），与 REAL 托管恒等
    /// 式物理隔离（见 [`GasCreditLedger`] 模块文档）。
    ///
    /// 准入清单：
    /// 1. REAL 域封闭枚举门（GAME 域拒入本 op——服务费必须以真实价值
    ///    资产计价）；
    /// 2. 面额 > 0（1:1 转为 credit）；
    /// 3. `pay_digest` 幂等（**op 族 + 跨路径前向查重**：v1 `deposit_ids`
    ///    / v2 `deposit_records_v2` / GAME `game_issue_ids` 任一命中即拒
    ///    ——同一外部支付不得既走托管存款/发行又走服务费收入。反向防线
    ///    （deposit/issue 侧不反查 gas 摘要集）由 watcher 支付确认幂等
    ///    承担，如实声明）。
    ///
    /// 应用：计量账入账（digest 登记 + 余额 1:1）+ 计数与余额 gauge。
    fn apply_buy_gas_credits(
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        payload: &BuyGasCreditsOp,
    ) -> AppchainResult<()> {
        // —— 全部可失败检查 ——
        // 1. REAL 域封闭枚举门
        Self::ensure_real_registered_asset(&payload.pricing_asset_id)?;
        // 2. 面额 > 0
        if payload.pay_amount == 0 {
            return Err(AppchainError::InvalidAmount(0));
        }
        // 3. pay_digest 幂等（op 族 + 跨路径前向）
        if state.gas_credits.contains_pay_digest(&payload.pay_digest)
            || state.deposit_ids.contains(&payload.pay_digest)
            || state.deposit_records_v2.contains_key(&payload.pay_digest)
            || state.game_issue_ids.contains(&payload.pay_digest)
        {
            return Err(AppchainError::WithdrawalConflict(
                "duplicate gas credit pay digest".into(),
            ));
        }

        // ===== 变更段（以上全部通过，以下不再失败；credit 的重复 digest
        // 与零面额臂已被检查段覆盖）=====
        let owner_key = owner_commitment(&payload.payer);
        state.gas_credits.credit(
            &owner_key,
            payload.pricing_asset_id,
            &payload.pay_digest,
            payload.pay_amount,
        )?;
        metrics.add("gas_credits_purchased_total", payload.pay_amount);
        metrics.add(
            &format!(
                "gas_credits_purchased_total{{currency=\"{}\"}}",
                payload.pricing_asset_id
            ),
            payload.pay_amount,
        );
        let balance_total = state.gas_credits.total_balance_of(payload.pricing_asset_id);
        metrics.set_gauge(
            &format!(
                "gas_credit_balance{{currency=\"{}\"}}",
                payload.pricing_asset_id
            ),
            u64::try_from(balance_total).unwrap_or(u64::MAX),
        );
        Ok(())
    }

    /// BindGasPolicy 准入与应用（TE-M6 判别值 16；C1 纪律）。GAME 桌绑定
    /// 桌级 [`GasPolicy`]——**绑定即冻结**（重绑拒，同 FeePolicy 开桌
    /// 冻结纪律）；设计 §3.8.2 排序：`OpenTable` 之后、首次买入/结算受理
    /// 之前执行。
    ///
    /// 准入清单（顺序即实现，全 fail-closed）：
    /// 1. 桌门（必须已开放）；
    /// 2. token 门（已注册 GTS token；**Paid 模式拒 = TE-D7**——Paid 桌
    ///    叠加 gas 收费 v1 禁止，放开 = 治理项；遗留 PLAY(0)/未注册 token
    ///    同拒——PLAY 永久免费层，永不商业化）；
    /// 3. 策略结构（[`GasPolicy::new`]：fee > 0、k ≥ 3、计价资产 REAL 域
    ///    已注册 token）；
    /// 4. 成本覆盖（INV：`fee_per_hand ≥ k·c_hand`；`c_hand` =
    ///    `SequencerConfig::gas_c_hand_estimate` 运营参数注入，不足拒并
    ///    计 `gas_coverage_rejected_total`）；
    /// 5. 冻结语义（已绑定桌重绑拒）。
    ///
    /// 应用：绑定入账（table_id → (token_id, policy)）+ 计数。
    fn apply_bind_gas_policy(
        config: &SequencerConfig,
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        payload: &BindGasPolicyOp,
    ) -> AppchainResult<()> {
        // —— 全部可失败检查 ——
        // 1. 桌门（OpenTable 之后）
        let ts = state
            .tables
            .get(&payload.table_id)
            .copied()
            .ok_or(AppchainError::TableNotOpen(payload.table_id))?;
        if !ts.open {
            return Err(AppchainError::TableNotOpen(payload.table_id));
        }
        // 2. token 门（Free 模式专属；TE-D7：Paid 桌绑定拒）
        match state.game_registry.get(payload.token_id) {
            Some(spec) if matches!(spec.mode, IssuanceMode::Free { .. }) => {}
            Some(_) => {
                metrics.inc("game_token_rejected_total");
                metrics.inc("gas_policy_rejected_total");
                return Err(AppchainError::GasPolicyRejected(
                    "paid-mode token tables cannot bind a gas policy (TE-D7: no double charging in v1)",
                ));
            }
            None => {
                metrics.inc("game_token_rejected_total");
                return Err(AppchainError::GameRegistryRejected(
                    "bind requires a registered GTS token (legacy PLAY never binds gas)",
                ));
            }
        }
        // 3. 策略结构（fee > 0 / k ≥ 3 / REAL 域计价封闭枚举）
        let policy = GasPolicy::new(
            payload.policy.fee_per_hand,
            payload.policy.pricing_asset_id,
            payload.policy.min_coverage_k,
        )?;
        // 4. 成本覆盖（Free 模式的"价带等价物"；c_hand 是运营参数）
        if !policy.covers_cost(config.gas_c_hand_estimate) {
            metrics.inc("gas_coverage_rejected_total");
            metrics.inc("gas_policy_rejected_total");
            return Err(AppchainError::GasPolicyRejected(
                "fee_per_hand below cost coverage (fee_per_hand >= k * c_hand must hold)",
            ));
        }
        // 5. 冻结语义（重绑拒）
        if state.gas_policies.contains_key(&payload.table_id) {
            metrics.inc("gas_policy_rejected_total");
            return Err(AppchainError::GasPolicyRejected(
                "table already has a gas policy binding (frozen)",
            ));
        }

        // ===== 变更段（以上全部通过，以下不再失败）=====
        state
            .gas_policies
            .insert(payload.table_id, (payload.token_id, policy));
        metrics.inc("gas_policy_bound_total");
        Ok(())
    }



    /// 铸造 nonce：`blake2s(domain || seq_be || payload)`——seq 单调保证唯一。
    fn mint_nonce(seq: u64, domain: &[u8], payload: &[u8; 32]) -> [u8; 32] {
        blake2s32(&[domain, &seq.to_be_bytes(), payload])
    }

    /// v2 铸造 nonce：`u64::from_be_bytes(blake2s(domain || seq_be ||
    /// payload)[..8])`（v2 note nonce 是 u64；截断前 8B，唯一性另由承诺
    /// 查重兜底——同 nonce 同内容即同承诺，铸造被拒）。
    fn mint_nonce_v2(seq: u64, domain: &[u8], payload: &[u8; 32]) -> u64 {
        let h = blake2s32(&[domain, &seq.to_be_bytes(), payload]);
        u64::from_be_bytes(h[..8].try_into().expect("8B slice from 32B digest"))
    }

    fn mint_note(state: &mut LedgerState, note: Note) -> AppchainResult<()> {
        let cfelt = note.commitment();
        let c = felt_to_bytes32(&cfelt);
        if state.notes.contains_key(&c) {
            return Err(AppchainError::AdmissionRejected("duplicate note commitment"));
        }
        let leaf = state.tree.append(cfelt)?;
        let created = state.seq;
        // §5.4 provenance：铸出即记录来源 op；消费后保留（提现打款侧
        // finality 判据），WAL 重放重建
        state.note_origins.insert(c, created);
        // B5：owner 二级索引同步维护（铸入即登记；全部铸造路径——deposit/
        // buy-in seat/transfer 输出/settle payout/rake note——都经此原语）
        state.owner_index.entry(note.owner).or_default().insert(c);
        state.notes.insert(
            c,
            NoteEntry {
                note,
                leaf_index: leaf,
                created_at_op: created,
                status: NoteStatus::Pending,
            },
        );
        Ok(())
    }

    fn consume_note(
        state: &mut LedgerState,
        note: &Note,
        nullifier: &[u8; 32],
    ) -> AppchainResult<()> {
        let c = felt_to_bytes32(&note.commitment());
        if state.notes.remove(&c).is_none() {
            return Err(AppchainError::NoteNotFound);
        }
        // B5：与 notes.remove 同步（索引语义 == 全量扫描，即便后续
        // nullifier 步骤失败也不漂移）
        if let Some(set) = state.owner_index.get_mut(&note.owner) {
            set.remove(&c);
            if set.is_empty() {
                state.owner_index.remove(&note.owner);
            }
        }
        let nf = crate::felt::felt_from_bytes32_exact(nullifier)?;
        state.nullifiers.try_consume(nf)?;
        Ok(())
    }

    /// 铸造 v2 note（ABI v2 账本原语）：承诺查重 + created_at_op 登记 +
    /// owner_commitment 索引维护（v1 [`Self::mint_note`] 的 v2 对应物；
    /// v2 note 不进 v1 承诺树——状态承诺走 [`LedgerState::root`] 的 v2
    /// 折叠段）。
    fn mint_note_v2(state: &mut LedgerState, note: NoteV2) -> AppchainResult<()> {
        let c = note.commitment_bytes();
        if state.notes_v2.contains_key(&c) {
            return Err(AppchainError::AdmissionRejected("duplicate note commitment"));
        }
        let created = state.seq;
        // TE-M2：§5.4 provenance 的 v2 侧（铸出即记录来源 op；消费后保留
        // ——提现打款侧 finality 判据；不入状态根，WAL 重放重建）
        state.note_origins_v2.insert(c, created);
        let owner_key = owner_commitment(&note.owner);
        state
            .owner_index_v2
            .entry(owner_key)
            .or_default()
            .insert(c);
        state.notes_v2.insert(
            c,
            NoteV2Entry {
                note,
                created_at_op: created,
                status: NoteStatus::Pending,
            },
        );
        Ok(())
    }

    /// 消费 v2 note（ABI v2 账本原语）：账本移除 + 索引同步 + 共享
    /// nullifier 集消费（v1/v2 nullifier 派生域分离，跨版碰撞不可能；
    /// 集合共享使跨版本重放防线统一）。
    fn consume_note_v2(
        state: &mut LedgerState,
        note: &NoteV2,
        nullifier: &[u8; 32],
    ) -> AppchainResult<()> {
        let c = note.commitment_bytes();
        if state.notes_v2.remove(&c).is_none() {
            return Err(AppchainError::NoteNotFound);
        }
        let owner_key = owner_commitment(&note.owner);
        if let Some(set) = state.owner_index_v2.get_mut(&owner_key) {
            set.remove(&c);
            if set.is_empty() {
                state.owner_index_v2.remove(&owner_key);
            }
        }
        let nf = crate::felt::felt_from_bytes32_exact(nullifier)?;
        state.nullifiers.try_consume(nf)?;
        Ok(())
    }

    /// 导出全链（watcher/锚定用）。
    #[must_use]
    pub fn export_chain(&self) -> Vec<SignedFrame> {
        self.chain.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::OwnerKey;
    use crate::note::{AssetClass, NoteSpec};
    use crate::ops::scope;
    use crate::settlement::SpendAuth;

    /// 测试用户：密钥与 spend secret 成对（生产中 secret 由客户端派生）。
    struct TestUser {
        key: OwnerKey,
        secret: [u8; 32],
    }

    impl TestUser {
        fn new(seed: u8) -> Self {
            Self {
                key: OwnerKey::from_seed(&[seed; 32]).unwrap(),
                secret: [seed; 32],
            }
        }

        fn pk(&self) -> [u8; 33] {
            self.key.public_bytes()
        }

        fn note(&self, amount: u64, class: AssetClass, nonce_byte: u8) -> Note {
            let mut nonce = [0u8; 32];
            nonce[0] = nonce_byte;
            Note::new(class, amount, self.pk(), nonce, None).unwrap()
        }

        fn auth(&self, note: &Note, scope_tag: &[u8], effect: &[u8; 32]) -> SpendAuth {
            let nf = note.nullifier(&self.secret);
            let d = spend_digest(
                &note.commitment_bytes(),
                &felt_to_bytes32(&nf),
                scope_tag,
                effect,
            );
            SpendAuth {
                commitment: felt_to_bytes32(&note.commitment()),
                nullifier: felt_to_bytes32(&nf),
                sig: self.key.sign(&d),
            }
        }
    }

    fn new_sequencer() -> Sequencer {
        Sequencer::new(
            SequencerKey::from_seed(&[11u8; 32]),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
    }

    #[test]
    fn deposit_transfer_flow() {
        let mut s = new_sequencer();
        let alice = TestUser::new(1);
        let bob = TestUser::new(2);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: alice.pk(),
                asset_class: AssetClass::Play,
                amount: 1_000,
            },
            1_000,
        )
        .unwrap();
        let note = s
            .state()
            .notes
            .values()
            .find(|e| e.note.owner == alice.pk())
            .unwrap()
            .note
            .clone();
        let out = NoteSpec {
            asset_class: AssetClass::Play,
            amount: 400,
            owner: bob.pk(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        };
        let out2 = NoteSpec {
            asset_class: AssetClass::Play,
            amount: 600,
            owner: alice.pk(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        };
        let effect = Operation::Transfer {
            spends: vec![],
            notes: vec![],
            outputs: vec![out.clone(), out2.clone()],
        }
        .effect_digest();
        s.submit(
            Operation::Transfer {
                spends: vec![alice.auth(&note, scope::TRANSFER, &effect)],
                notes: vec![note],
                outputs: vec![out, out2],
            },
            2_000,
        )
        .unwrap();
        let (real, play) = s.state().balances_of(&bob.pk());
        assert_eq!((real, play), (0, 400));
    }

    #[test]
    fn double_spend_rejected() {
        let mut s = new_sequencer();
        let alice = TestUser::new(1);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: alice.pk(),
                asset_class: AssetClass::Play,
                amount: 500,
            },
            1_000,
        )
        .unwrap();
        let note = s
            .state()
            .notes
            .values()
            .find(|e| e.note.owner == alice.pk())
            .unwrap()
            .note
            .clone();
        let out = NoteSpec {
            asset_class: AssetClass::Play,
            amount: 500,
            owner: alice.pk(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        };
        let effect = Operation::Transfer {
            spends: vec![],
            notes: vec![],
            outputs: vec![out.clone()],
        }
        .effect_digest();
        let op = Operation::Transfer {
            spends: vec![alice.auth(&note, scope::TRANSFER, &effect)],
            notes: vec![note],
            outputs: vec![out],
        };
        s.submit(op.clone(), 2_000).unwrap();
        let err = s.submit(op, 3_000).unwrap_err();
        assert!(matches!(err, AppchainError::DoubleSpend | AppchainError::NoteNotFound));
    }

    #[test]
    fn replay_roundtrip_with_wal() {
        let dir = std::env::temp_dir().join("poker-appchain-seq-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seq.wal");
        let _ = std::fs::remove_file(&path);
        let key = SequencerKey::from_seed(&[21u8; 32]);
        let mut s = Sequencer::new(
            key,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        );
        s.attach_wal(&path).unwrap();
        let a = TestUser::new(1);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 9;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: a.pk(),
                asset_class: AssetClass::Play,
                amount: 777,
            },
            1_000,
        )
        .unwrap();
        // P0-4：先落盘后生效——提交成功即内存态已推进，WAL 可重放出同一状态
        let root_before = s.state().root();
        drop(s);
        let s2 = Sequencer::replay(
            &path,
            SequencerKey::from_seed(&[21u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        let (real, play) = s2.state().balances_of(&a.pk());
        assert_eq!((real, play), (0, 777));
        assert_eq!(s2.state().root(), root_before, "replay must reconstruct identical state");
    }

    /// P0-4 (a)：WAL 写失败（磁盘满模拟）→ 提交被拒、内存态零变更、
    /// 重放不含该帧。
    #[test]
    fn wal_write_failure_keeps_state_untouched() {
        let dir = std::env::temp_dir().join("poker-appchain-seq-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("walfail.wal");
        let _ = std::fs::remove_file(&path);
        let key = SequencerKey::from_seed(&[22u8; 32]);
        let mut s = Sequencer::new(
            key.clone(),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        );
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        // 预算 0 字节：append 第一个字节就失败（模拟磁盘满）
        s.attach_wal_writer(WalWriter::from_sink(
            path.clone(),
            Box::new(crate::wal::BudgetSink::new(file, 0)),
            true,
        ));
        let a = TestUser::new(3);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        let err = s
            .submit(
                Operation::Deposit {
                    deposit_id,
                    owner: a.pk(),
                    asset_class: AssetClass::Play,
                    amount: 500,
                },
                1_000,
            )
            .unwrap_err();
        assert!(matches!(err, AppchainError::WalCorrupted("write failed")));
        // 内存状态未被修改：序号、账本、链、水位全部原地
        assert_eq!(s.state().seq, 0);
        assert!(s.state().notes.is_empty());
        assert_eq!(s.chain().len(), 0);
        assert_eq!(s.proven_watermark(), 0);
        drop(s);
        // 后续重放不含该帧（WAL 为空，重放出空账本）
        assert!(crate::wal::read_all(&path).unwrap().is_empty());
        let s2 = Sequencer::replay(
            &path,
            key.public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        assert_eq!(s2.state().seq, 0);
        assert_eq!(s2.state().balances_of(&a.pk()), (0, 0));
    }

    /// P0-4 (a) 补充：半帧落盘（长度头已写、帧体失败）→ 重放 fail-closed。
    #[test]
    fn wal_partial_frame_fails_replay() {
        let dir = std::env::temp_dir().join("poker-appchain-seq-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("walpartial.wal");
        let _ = std::fs::remove_file(&path);
        let key = SequencerKey::from_seed(&[23u8; 32]);
        let mut s = Sequencer::new(
            key.clone(),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        );
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        // 预算 4 字节：恰好够 u32 长度头，帧体必失败
        s.attach_wal_writer(WalWriter::from_sink(
            path.clone(),
            Box::new(crate::wal::BudgetSink::new(file, 4)),
            true,
        ));
        let a = TestUser::new(4);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 2;
        assert!(s
            .submit(
                Operation::Deposit {
                    deposit_id,
                    owner: a.pk(),
                    asset_class: AssetClass::Play,
                    amount: 100,
                },
                1_000,
            )
            .is_err());
        assert_eq!(s.state().seq, 0);
        drop(s);
        // 半帧不可解析 → 重放拒绝（fail-closed，绝不静默丢帧）
        assert!(matches!(
            crate::wal::read_all(&path),
            Err(AppchainError::WalCorrupted("truncated frame"))
        ));
        assert!(Sequencer::replay(
            &path,
            key.public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .is_err());
    }

    /// P0-5：mark_proven 只推进最大连续前缀，缺口（失败/未完成）挡住水位。
    #[test]
    fn proven_watermark_advances_only_contiguous_prefix() {
        let mut s = new_sequencer();
        let a = TestUser::new(1);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: a.pk(),
                asset_class: AssetClass::Play,
                amount: 100,
            },
            1_000,
        )
        .unwrap();
        let commitment = s
            .state()
            .notes
            .values()
            .find(|e| e.note.owner == a.pk())
            .map(|e| e.note.commitment_bytes())
            .unwrap();
        // op 0 产出 note 处于 Pending
        assert_eq!(s.state().seq, 1);
        assert_eq!(s.proven_watermark(), 0);
        // op 2、op 3 先完成：缺口 op 1 挡住水位
        s.mark_proven(2);
        assert_eq!(s.proven_watermark(), 0);
        s.mark_proven(3);
        assert_eq!(s.proven_watermark(), 0);
        let e = s.state().notes.get(&commitment).unwrap();
        assert_eq!(e.status, NoteStatus::Pending);
        // 补上 op 1 → 连续前缀一次推进到 3，note 翻 Proven
        s.mark_proven(1);
        assert_eq!(s.proven_watermark(), 3);
        let e = s.state().notes.get(&commitment).unwrap();
        assert_eq!(e.status, NoteStatus::Proven);
        // mark_proven_through：0..=n 全部标记，只进不退，幂等
        s.mark_proven_through(5);
        assert_eq!(s.proven_watermark(), 5);
        s.mark_proven_through(4);
        assert_eq!(s.proven_watermark(), 5);
    }

    #[test]
    fn rate_limit_fires() {
        let mut s = Sequencer::new(
            SequencerKey::from_seed(&[31u8; 32]),
            SequencerConfig {
                ops_per_min: 2,
                open_table_per_min: 2,
                ..SequencerConfig::default()
            },
            Arc::new(MetricsRegistry::new()),
        );
        let a = TestUser::new(1);
        for i in 0..2u8 {
            let mut deposit_id = [0u8; 32];
            deposit_id[0] = i;
            s.submit(
                Operation::Deposit {
                    deposit_id,
                    owner: a.pk(),
                    asset_class: AssetClass::Play,
                    amount: 1,
                },
                1_000,
            )
            .unwrap();
        }
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 99;
        let err = s
            .submit(
                Operation::Deposit {
                    deposit_id,
                    owner: a.pk(),
                    asset_class: AssetClass::Play,
                    amount: 1,
                },
                1_100,
            )
            .unwrap_err();
        assert!(matches!(err, AppchainError::RateLimited(_)));
    }

    #[test]
    fn proven_only_admission_blocks_pending_buyin() {
        let mut s = new_sequencer();
        let a = TestUser::new(1);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: a.pk(),
                asset_class: AssetClass::Real,
                amount: 1_000,
            },
            1_000,
        )
        .unwrap();
        let note = s
            .state()
            .notes
            .values()
            .find(|e| e.note.owner == a.pk())
            .unwrap()
            .note
            .clone();
        s.submit(
            Operation::OpenTable { table_id: 1, policy: FeePolicy::Zero },
            1_100,
        )
        .unwrap();
        let buyin_effect = |table_id: u64, seat_owner: [u8; 33]| {
            Operation::BuyIn {
                table_id,
                spends: vec![],
                notes: vec![],
                seat_owner,
            }
            .effect_digest()
        };
        let err = s
            .submit(
                Operation::BuyIn {
                    table_id: 1,
                    spends: vec![a.auth(&note, scope::BUYIN, &buyin_effect(1, a.pk()))],
                    notes: vec![note],
                    seat_owner: a.pk(),
                },
                1_200,
            )
            .unwrap_err();
        assert!(matches!(err, AppchainError::AdmissionRejected("note not proven")));
        // 推进水位后通过
        s.mark_proven_through(s.state().seq);
        s.submit(
            Operation::BuyIn {
                table_id: 1,
                spends: vec![a.auth(
                    &s.state()
                        .notes
                        .values()
                        .find(|e| e.note.owner == a.pk())
                        .unwrap()
                        .note,
                    scope::BUYIN,
                    &buyin_effect(1, a.pk()),
                )],
                notes: vec![s
                    .state()
                    .notes
                    .values()
                    .find(|e| e.note.owner == a.pk())
                    .unwrap()
                    .note
                    .clone()],
                seat_owner: a.pk(),
            },
            1_300,
        )
        .unwrap();
    }

    /// §5.4 配套：note provenance（created_at_op）与批次根证据的导出。
    /// mark_proven_through 直推只动水位；批次回调（root + through_op）
    /// 才同时补齐 finality 证据。
    #[test]
    fn finality_evidence_tracks_provenance_and_batch_roots() {
        let mut s = new_sequencer();
        let a = TestUser::new(1);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: a.pk(),
                asset_class: AssetClass::Real,
                amount: 100,
            },
            1_000,
        )
        .unwrap();
        let note = s
            .state()
            .notes
            .values()
            .find(|e| e.note.owner == a.pk())
            .unwrap()
            .note
            .clone();
        // provenance：note 承诺 → 来源 op 0（REAL 类）
        let prov = s.withdrawal_provenance(&note).expect("note in ledger");
        assert_eq!(prov.asset_class, AssetClass::Real);
        assert_eq!(prov.source_op_index, 0);
        // 初始：无水位、无批次根
        assert_eq!(
            s.finality_evidence(),
            FinalityEvidence {
                proven_watermark: 0,
                batch_covered_through: None
            }
        );
        // mark_proven_through 直推（无批次根）：水位动、批次覆盖不动
        s.mark_proven_through(2);
        assert_eq!(
            s.finality_evidence(),
            FinalityEvidence {
                proven_watermark: 2,
                batch_covered_through: None
            }
        );
        // 批次回调（root + through_op）：finality 证据齐备
        let root = [0xAB; 32];
        s.mark_proven_through_with_root(4, root);
        assert_eq!(
            s.finality_evidence(),
            FinalityEvidence {
                proven_watermark: 4,
                batch_covered_through: Some(4)
            }
        );
        assert_eq!(s.batch_root_at(4), Some(root));
        assert_eq!(s.batch_covered_through(), Some(4));
        // 未知 note → None（provenance 不可伪造）
        let alien = Note::new(AssetClass::Real, 1, a.pk(), [0xFF; 32], None).unwrap();
        assert!(s.withdrawal_provenance(&alien).is_none());
        // 销毁后 provenance 保留（托管打款侧仍可过 finality 门）
        burn_test_note(&mut s, &a, &note, [9; 32]);
        assert_eq!(
            s.withdrawal_provenance(&note).expect("origin survives burn"),
            prov
        );
    }

    /// 测试脚手架：软确认一笔提现销毁（花费授权按 effect 摘要签名；
    /// P1：effect 绑定 payout_recipient——收款人进签名摘要）。
    fn burn_test_note(s: &mut Sequencer, a: &TestUser, note: &Note, request_id: [u8; 32]) {
        let effect = Operation::WithdrawRequest {
            spend: SpendAuth {
                commitment: [0; 32],
                nullifier: [0; 32],
                sig: crate::keys::EcdsaSig { bytes: [0; 64] },
            },
            note: note.clone(),
            request_id,
            payout_recipient: [0xEE; 32],
        }
        .effect_digest();
        let nf = felt_to_bytes32(&note.nullifier(&a.secret));
        let d = spend_digest(&note.commitment_bytes(), &nf, scope::WITHDRAW, &effect);
        s.submit(
            Operation::WithdrawRequest {
                spend: SpendAuth {
                    commitment: note.commitment_bytes(),
                    nullifier: nf,
                    sig: a.key.sign(&d),
                },
                note: note.clone(),
                request_id,
                payout_recipient: [0xEE; 32],
            },
            3_000,
        )
        .unwrap();
    }

    /// proven-log 测试目录。
    fn proven_log_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("poker-appchain-provenlog-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(tag)
    }

    /// 带持久化历史的内存+sidecar 实例：2 笔 op 落 WAL，水位推到 1 并带
    /// 批次根（落 sidecar）。返回 (实例, wal 路径, sidecar 路径)。
    fn persisted_with_proven_log(tag: &str) -> (Sequencer, std::path::PathBuf, std::path::PathBuf) {
        let wal = proven_log_dir(&format!("{tag}.wal"));
        let plog = proven_log_dir(&format!("{tag}.plog"));
        let _ = std::fs::remove_file(&wal);
        let _ = std::fs::remove_file(&plog);
        let key = SequencerKey::from_seed(&[61u8; 32]);
        let mut s = Sequencer::new(
            key.clone(),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        );
        s.attach_wal(&wal).unwrap();
        s.attach_proven_log(&plog).unwrap();
        let a = TestUser::new(7);
        for i in 0..2u8 {
            let mut deposit_id = [0u8; 32];
            deposit_id[0] = i;
            s.submit(
                Operation::Deposit {
                    deposit_id,
                    owner: a.pk(),
                    asset_class: AssetClass::Play,
                    amount: 100 + u64::from(i),
                },
                1_000 + u64::from(i) * 100,
            )
            .unwrap();
        }
        s.mark_proven_through_with_root(1, [0xCD; 32]);
        assert_eq!(s.proven_watermark(), 1);
        (s, wal, plog)
    }

    /// M8 契约：sidecar 行内容逐字段与冻结格式一致（字段名/顺序/编码）。
    #[test]
    fn proven_log_line_matches_frozen_contract() {
        let (s, _wal, plog) = persisted_with_proven_log("contract");
        drop(s);
        let text = std::fs::read_to_string(&plog).unwrap();
        assert_eq!(text.lines().count(), 1, "one advance = one line");
        let line = text.trim_end();
        // 逐字段 + 顺序冻结（紧凑 JSON，无空格）：
        // {"op_index":<u64>,"batch_root":"<64hex>","ts_ms":<u64>}
        assert_eq!(
            line,
            format!("{{\"op_index\":1,\"batch_root\":\"{}\",\"ts_ms\":{}}}", hex::encode([0xCD; 32]), {
                let (_, _, ts) = parse_proven_line(line).unwrap();
                ts
            }),
            "line must be exactly op_index,batch_root,ts_ms in frozen order"
        );
        let (op_index, root, ts) = parse_proven_line(line).expect("parse per contract");
        assert_eq!(op_index, 1);
        assert_eq!(root, [0xCD; 32]);
        assert!(ts > 0, "ts_ms must be a real epoch-millisecond value");
        assert!(text.ends_with('\n'), "every complete line ends with newline");
    }

    /// M8：replay_restoring_proven 恢复等价（watermark / batch_root_at 与
    /// 原实例一致），且不改变现有 replay 语义（None → 纯 replay）。
    #[test]
    fn replay_restoring_proven_equivalent() {
        let (s, wal, plog) = persisted_with_proven_log("restore");
        let root_before = s.state().root();
        let watermark_before = s.proven_watermark();
        let batch_before = s.batch_roots();
        drop(s);

        // 带 sidecar 恢复：水位 + 批次根一致，账本状态根一致
        let r = Sequencer::replay_restoring_proven(
            &wal,
            Some(&plog),
            SequencerKey::from_seed(&[61u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        assert_eq!(r.proven_watermark(), watermark_before);
        assert_eq!(r.batch_roots(), batch_before);
        assert_eq!(r.batch_root_at(1), Some([0xCD; 32]));
        assert_eq!(r.state().root(), root_before);
        // note 状态也随水位恢复翻 Proven
        for e in r.state().notes.values() {
            assert_eq!(e.status, NoteStatus::Proven);
        }
        // sidecar 未挂载在恢复实例上 → 恢复路径不二次落盘
        let lines = std::fs::read_to_string(&plog).unwrap().lines().count();
        assert_eq!(lines, 1);

        // 不给 sidecar：与 replay 等价（水位归零的既有保守语义）
        let r2 = Sequencer::replay_restoring_proven(
            &wal,
            None,
            SequencerKey::from_seed(&[61u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        assert_eq!(r2.proven_watermark(), 0);
        assert_eq!(r2.batch_roots(), Vec::new());
        assert_eq!(r2.state().root(), root_before);
    }

    /// M8：空 sidecar → 合法、无恢复；幂等重复 with_root 不产生重复行；
    /// 直推（无根）不落 sidecar。
    #[test]
    fn proven_log_empty_file_and_idempotent() {
        let (mut s, wal, plog) = persisted_with_proven_log("idem");
        // 回退/重复调用：无操作、无新行
        s.mark_proven_through_with_root(1, [0x11; 32]);
        s.mark_proven_through_with_root(0, [0x22; 32]);
        // 直推（无批次根）：水位动、sidecar 不动（由管道重回调恢复）
        s.mark_proven_through(1);
        drop(s);
        let text = std::fs::read_to_string(&plog).unwrap();
        assert_eq!(text.lines().count(), 1, "idempotent calls must not append");
        // 空 sidecar 恢复 = 纯 replay
        let r = Sequencer::replay_restoring_proven(
            &wal,
            Some(&plog),
            SequencerKey::from_seed(&[61u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        assert_eq!(r.proven_watermark(), 1);
    }

    /// M8：撕裂尾行（无换行结尾）忽略 + 告警；中间行损坏拒绝。
    #[test]
    fn proven_log_torn_tail_ignored_midfile_corrupt_rejected() {
        let (s, wal, plog) = persisted_with_proven_log("torn");
        drop(s);
        let good = std::fs::read_to_string(&plog).unwrap();
        // 撕裂尾行：截掉换行再补半行 → 恢复仍成功（忽略残行），水位来自完整行
        std::fs::write(&plog, format!("{}{{\"op_index\":9,\"bat", good)).unwrap();
        let r = Sequencer::replay_restoring_proven(
            &wal,
            Some(&plog),
            SequencerKey::from_seed(&[61u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        assert_eq!(r.proven_watermark(), 1);

        // 中间行损坏（可解析行之后跟坏行且以换行结尾）→ 拒绝
        let ts = wallclock_ms();
        std::fs::write(
            &plog,
            format!(
                "{good}{{\"op_index\":nonsense,\"batch_root\":\"zz\",\"ts_ms\":{ts}}}\n"
            ),
        )
        .unwrap();
        assert!(Sequencer::replay_restoring_proven(
            &wal,
            Some(&plog),
            SequencerKey::from_seed(&[61u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .is_err());
        let _ = s;
    }

    /// M8：越界 op_index（> 链长）与非递增 op_index → 拒绝（fail-closed）。
    #[test]
    fn proven_log_out_of_range_and_non_monotonic_rejected() {
        let (s, wal, plog) = persisted_with_proven_log("range");
        drop(s);
        let ts = wallclock_ms();
        // 越界：链长 = 2，op_index = 3
        std::fs::write(
            &plog,
            format!(
                "{{\"op_index\":1,\"batch_root\":\"{}\",\"ts_ms\":{ts}}}\n{{\"op_index\":3,\"batch_root\":\"{}\",\"ts_ms\":{ts}}}\n",
                hex::encode([0xCD; 32]),
                hex::encode([0xEE; 32]),
            ),
        )
        .unwrap();
        let err = match Sequencer::replay_restoring_proven(
            &wal,
            Some(&plog),
            SequencerKey::from_seed(&[61u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        ) {
            Err(e) => e,
            Ok(_) => panic!("out-of-range op_index must be rejected"),
        };
        assert!(matches!(err, AppchainError::WalCorrupted("proven log op_index beyond chain length")));

        // 非递增：op_index 回退
        std::fs::write(
            &plog,
            format!(
                "{{\"op_index\":2,\"batch_root\":\"{}\",\"ts_ms\":{ts}}}\n{{\"op_index\":2,\"batch_root\":\"{}\",\"ts_ms\":{ts}}}\n",
                hex::encode([0xCD; 32]),
                hex::encode([0xEE; 32]),
            ),
        )
        .unwrap();
        let err = match Sequencer::replay_restoring_proven(
            &wal,
            Some(&plog),
            SequencerKey::from_seed(&[61u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        ) {
            Err(e) => e,
            Ok(_) => panic!("non-advancing op_index must be rejected"),
        };
        assert!(matches!(err, AppchainError::WalCorrupted("proven log op_index does not advance")));
        let _ = s;
    }

    // ===== M4 outer aggregate：聚合记录 sidecar + 恢复 =====

    /// 构造一条聚合记录（测试样本）。
    fn sample_aggregate(index: u64, through_op: u64) -> AggregateRecord {
        AggregateRecord {
            index,
            through_op,
            root: [0xA0 + u8::try_from(index).unwrap_or(0); 32],
            ts_ms: 1_700_000_000_000 + index,
            batch_count: 1,
        }
    }

    /// aggregate-log 测试目录。
    fn aggregate_log_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("poker-appchain-agglog-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(tag)
    }

    /// 带持久化历史的内存+aggregate sidecar 实例：2 笔 op 落 WAL，两条聚合
    /// 记录落 sidecar。返回 (实例, wal 路径, sidecar 路径)。
    fn persisted_with_aggregate_log(tag: &str) -> (Sequencer, std::path::PathBuf, std::path::PathBuf) {
        let wal = aggregate_log_dir(&format!("{tag}.wal"));
        let alog = aggregate_log_dir(&format!("{tag}.alog"));
        let _ = std::fs::remove_file(&wal);
        let _ = std::fs::remove_file(&alog);
        let key = SequencerKey::from_seed(&[71u8; 32]);
        let mut s = Sequencer::new(
            key.clone(),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        );
        s.attach_wal(&wal).unwrap();
        s.attach_aggregate_log(&alog).unwrap();
        let a = TestUser::new(7);
        for i in 0..2u8 {
            let mut deposit_id = [0u8; 32];
            deposit_id[0] = i;
            s.submit(
                Operation::Deposit {
                    deposit_id,
                    owner: a.pk(),
                    asset_class: AssetClass::Play,
                    amount: 100 + u64::from(i),
                },
                1_000 + u64::from(i) * 100,
            )
            .unwrap();
        }
        s.record_aggregate(sample_aggregate(0, 1));
        s.record_aggregate(sample_aggregate(1, 2));
        assert_eq!(s.aggregates().len(), 2);
        assert_eq!(s.latest_aggregate(), Some(&sample_aggregate(1, 2)));
        (s, wal, alog)
    }

    /// M4 契约：sidecar 行内容逐字段与冻结格式一致（字段名/顺序/编码）。
    #[test]
    fn aggregate_log_line_matches_frozen_contract() {
        let (s, _wal, alog) = persisted_with_aggregate_log("contract");
        drop(s);
        let text = std::fs::read_to_string(&alog).unwrap();
        assert_eq!(text.lines().count(), 2, "two aggregates = two lines");
        let first = text.lines().next().unwrap();
        let expect_root = hex::encode([0xA0; 32]);
        assert_eq!(
            first,
            format!(
                "{{\"index\":0,\"through_op\":1,\"root\":\"{expect_root}\",\"ts_ms\":{},\"batch_count\":1}}",
                1_700_000_000_000i64,
            ),
            "line must be exactly index,through_op,root,ts_ms,batch_count in frozen order"
        );
        assert!(text.ends_with('\n'), "every complete line ends with newline");
        let (idx, top, root, _ts, bc) = parse_aggregate_line(first).expect("parse per contract");
        assert_eq!((idx, top, root, bc), (0, 1, [0xA0; 32], 1));
    }

    /// M4：replay_restoring_proven_and_aggregates 恢复等价；None 与
    /// replay_restoring_proven 等价（聚合不恢复）。
    #[test]
    fn aggregate_log_restore_equivalent() {
        let (s, wal, alog) = persisted_with_aggregate_log("restore");
        let aggregates_before = s.aggregates().to_vec();
        let root_before = s.state().root();
        drop(s);
        // 带 aggregate sidecar 恢复：聚合记录逐条一致
        let r = Sequencer::replay_restoring_proven_and_aggregates(
            &wal,
            None,
            Some(&alog),
            SequencerKey::from_seed(&[71u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        assert_eq!(r.aggregates(), aggregates_before.as_slice());
        assert_eq!(r.latest_aggregate().map(|a| a.index), Some(1));
        assert_eq!(r.state().root(), root_before);
        // 恢复实例未挂 sidecar → 不二次落盘
        let lines = std::fs::read_to_string(&alog).unwrap().lines().count();
        assert_eq!(lines, 2);
        // 不给 aggregate sidecar：聚合不恢复（与 replay_restoring_proven 等价）
        let r2 = Sequencer::replay_restoring_proven(
            &wal,
            None,
            SequencerKey::from_seed(&[71u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        assert_eq!(r2.aggregates(), &[] as &[AggregateRecord]);
    }

    /// M4：空 sidecar 合法；撕裂尾行忽略 + 告警；中间行损坏 / index 非连续
    /// / through_op 回退 → 拒绝（fail-closed）。
    #[test]
    fn aggregate_log_torn_and_corrupt_cases() {
        let (s, wal, alog) = persisted_with_aggregate_log("torn");
        drop(s);
        let good = std::fs::read_to_string(&alog).unwrap();

        // 空文件 → 合法、无恢复
        let empty = aggregate_log_dir("empty.alog");
        std::fs::write(&empty, "").unwrap();
        let r = Sequencer::replay_restoring_proven_and_aggregates(
            &wal,
            None,
            Some(&empty),
            SequencerKey::from_seed(&[71u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        assert!(r.aggregates().is_empty());

        // 撕裂尾行：截掉换行补半行 → 恢复仍成功（完整两行中的前若干行）
        std::fs::write(&alog, format!("{good}{{\"index\":2,\"thro")).unwrap();
        let r = Sequencer::replay_restoring_proven_and_aggregates(
            &wal,
            None,
            Some(&alog),
            SequencerKey::from_seed(&[71u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        assert_eq!(r.aggregates().len(), 2);

        // 中间行损坏 → 拒绝
        std::fs::write(&alog, format!("{good}not-json\n")).unwrap();
        assert!(Sequencer::replay_restoring_proven_and_aggregates(
            &wal,
            None,
            Some(&alog),
            SequencerKey::from_seed(&[71u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .is_err());

        // index 跳号 → 拒绝
        let line = |idx: u64, top: u64, root: [u8; 32]| {
            format!(
                "{{\"index\":{},\"through_op\":{},\"root\":\"{}\",\"ts_ms\":1,\"batch_count\":1}}\n",
                idx,
                top,
                hex::encode(root)
            )
        };
        std::fs::write(
            &alog,
            format!("{}{}", line(0, 1, [0xA0; 32]), line(2, 2, [0xA1; 32])),
        )
        .unwrap();
        assert!(Sequencer::replay_restoring_proven_and_aggregates(
            &wal,
            None,
            Some(&alog),
            SequencerKey::from_seed(&[71u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .is_err());

        // through_op 回退 → 拒绝
        std::fs::write(
            &alog,
            format!("{}{}", line(0, 2, [0xA0; 32]), line(1, 1, [0xA1; 32])),
        )
        .unwrap();
        assert!(Sequencer::replay_restoring_proven_and_aggregates(
            &wal,
            None,
            Some(&alog),
            SequencerKey::from_seed(&[71u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .is_err());
    }
    // ===== compliance_gate 端到端负例（C-M2 出口判据：准入控制负例测试）=====
    //
    // compliance.rs 的门函数矩阵已覆盖判定逻辑；此处覆盖 apply 路径的
    // 完整闭环：拒绝 → AdmissionRejected + 审计事件（decision=Err）+
    // 账本零变更；放行 → accepted 审计事件 + deposit_id 入账（正例对照）。

    fn compliance_sequencer(
        tune: impl FnOnce(&mut crate::compliance::MarketPolicy),
    ) -> Sequencer {
        use crate::compliance::{ComplianceParams, GeoPolicy, MarketPolicy};
        let mut im = MarketPolicy {
            real_enabled: true,
            game_enabled: true,
            ..MarketPolicy::default() // fail-closed 缺省（制动位开）
        };
        im.kyc_required_real = false;
        im.kyc_required_game = false;
        tune(&mut im);
        let mut policy = GeoPolicy { version: 1, ..GeoPolicy::default() };
        policy.markets.insert("IM".into(), im);
        let mut cfg = SequencerConfig::default();
        cfg.compliance = Some(ComplianceParams { policy, market: "IM".into() });
        Sequencer::new(
            SequencerKey::from_seed(&[11u8; 32]),
            cfg,
            Arc::new(MetricsRegistry::new()),
        )
    }

    fn real_deposit_op(user: &TestUser, deposit_id: u8, amount: u64) -> Operation {
        Operation::Deposit {
            deposit_id: [deposit_id; 32],
            owner: user.pk(),
            asset_class: AssetClass::Real,
            amount,
        }
    }

    #[test]
    fn compliance_gate_rejects_blocked_market_and_leaves_ledger_clean() {
        // 市场被封（real_enabled=false）→ 拒 + 审计 + 账本零变更
        let mut s = compliance_sequencer(|mp| mp.real_enabled = false);
        let alice = TestUser::new(1);
        let err = s.submit(real_deposit_op(&alice, 1, 100), 1_000).unwrap_err();
        assert!(matches!(err, AppchainError::AdmissionRejected(_)), "{err:?}");
        let events = s.state().compliance_events.events();
        assert_eq!(events.len(), 1, "拒绝必须留审计事件");
        assert_eq!(events[0].op_tag, "deposit");
        assert_eq!(
            events[0].decision,
            Err(crate::compliance::Rejection::RealDisabled)
        );
        assert!(s.state().deposit_ids.is_empty(), "被拒入金不得入账");
        assert!(
            s.state().notes.values().all(|e| e.note.owner != alice.pk()),
            "被拒入金不得铸 note"
        );
    }

    #[test]
    fn compliance_gate_negative_matrix_end_to_end() {
        let alice = TestUser::new(1);

        // fiat_only：NATIVE（v1 REAL Deposit 的 token 口径）被拒
        let mut s = compliance_sequencer(|mp| mp.fiat_only = true);
        let err = s.submit(real_deposit_op(&alice, 2, 100), 1_000).unwrap_err();
        assert!(matches!(err, AppchainError::AdmissionRejected(_)));
        assert_eq!(
            s.state().compliance_events.events()[0].decision,
            Err(crate::compliance::Rejection::FiatOnlyNativeRejected)
        );

        // 单笔限额：>max 拒（边界值放行见正例测试）
        let mut s = compliance_sequencer(|mp| mp.max_deposit = 100);
        let err = s.submit(real_deposit_op(&alice, 3, 101), 1_000).unwrap_err();
        assert!(matches!(err, AppchainError::AdmissionRejected(_)));
        assert_eq!(
            s.state().compliance_events.events()[0].decision,
            Err(crate::compliance::Rejection::DepositLimitExceeded)
        );
        assert!(s.state().deposit_ids.is_empty());

        // KYC 制动位：通道全拒
        let mut s = compliance_sequencer(|mp| mp.kyc_required_real = true);
        let err = s.submit(real_deposit_op(&alice, 4, 100), 1_000).unwrap_err();
        assert!(matches!(err, AppchainError::AdmissionRejected(_)));
        assert_eq!(
            s.state().compliance_events.events()[0].decision,
            Err(crate::compliance::Rejection::KycGateReal)
        );

        // RG 自排除：owner 承诺命中名单
        let mut s = compliance_sequencer(|mp| {
            mp.self_excluded
                .insert(crate::compliance::owner_key_v1(&alice.pk()));
        });
        let err = s.submit(real_deposit_op(&alice, 5, 100), 1_000).unwrap_err();
        assert!(matches!(err, AppchainError::AdmissionRejected(_)));
        assert_eq!(
            s.state().compliance_events.events()[0].decision,
            Err(crate::compliance::Rejection::SelfExcluded)
        );

        // 市场未配置（部署错配）→ fail-closed
        let mut s = compliance_sequencer(|_| {});
        s.config.compliance.as_mut().unwrap().market = "XX".into();
        let err = s.submit(real_deposit_op(&alice, 6, 100), 1_000).unwrap_err();
        assert!(matches!(err, AppchainError::AdmissionRejected(_)));
        assert_eq!(
            s.state().compliance_events.events()[0].decision,
            Err(crate::compliance::Rejection::MarketNotConfigured)
        );
    }

    #[test]
    fn compliance_gate_accept_records_audit_and_deposits() {
        // 正例对照：限额边界值（== max）放行 → accepted 审计 + deposit_id 入账
        let mut s = compliance_sequencer(|mp| mp.max_deposit = 100);
        let alice = TestUser::new(1);
        s.submit(real_deposit_op(&alice, 7, 100), 1_000).unwrap();
        let events = s.state().compliance_events.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].op_tag, "deposit");
        assert_eq!(events[0].decision, Ok(()));
        assert_eq!(events[0].amount, Some(100));
        assert!(
            s.state().deposit_ids.contains(&[7u8; 32]),
            "放行入金必须入账幂等集"
        );
    }

    #[test]
    fn compliance_gate_inactive_without_config() {
        // 未配置合规参数 = 直通（现网部署前形态；负例门只在其配置后生效）
        let mut s = new_sequencer();
        let alice = TestUser::new(1);
        s.submit(real_deposit_op(&alice, 8, 100), 1_000)
            .expect("无合规配置时 REAL Deposit 直通");
        assert!(s.state().deposit_ids.contains(&[8u8; 32]));
        assert!(s.state().compliance_events.events().is_empty());
    }
}
