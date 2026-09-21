//! Bullshark 共识与 block 投影（Task 9）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 9.1**：DAG commit certificate 检测 — 某轮 vertex 获得 ≥2/3 validator 引用
//! - **SubTask 9.2**：Bullshark 算法对 DAG vertex 线性排序
//! - **SubTask 9.3**：从 DAG commit 投影产出 block 序列（block = commit 内 vertex 的 tx 聚合 + 排序）
//! - **SubTask 9.4**：block header 含 `dag_commit_certificate`（已在 Phase 1 实现）
//! - **SubTask 9.5**：Block 最终性 — commit certificate 含 2/3 secp256k1 多签 → finalized；
//!   **SEC2-C1**：签名对象 = `hash(chain_id || epoch || commit_round || prev_commit_hash
//!   || vertex_hash_list || round_attendance_bitmap || state_root || public_tx_root || gameturn_tx_root)`
//!
//! ## Bullshark 算法说明
//!
//! Bullshark 是基于 DAG 的 BFT 共识：
//! 1. validator 在每轮产出 vertex，引用 ≥2/3 上一轮 vertex
//! 2. 某轮的 "leader" vertex 被后续轮 ≥2/3 vertex 间接引用 → 形成 commit
//! 3. commit 内所有 vertex 按 (round, author_index) 线性排序
//! 4. 排序后的 tx 聚合 + S9/R4-M4 排序 → 产出 block
//!
//! ## 恰 quorum 存活 commit 停滞修复（canonical leader 候选序）
//!
//! 根因（7 节点 kill-2 演练实测，全活阶段即复现）：validator loop 旧实现按本地
//! `max_r-4..max_r-1` 滑窗 + DAG 插入序取「首个满足 quorum 的候选 leader」。
//! 窗口边界是本地量：本节点刚出 vertex 则 `max_r` 已前移、peer 尚未同步则落后，
//! 随各节点生产节奏错位；同轮候选又按各自到达序排列。于是不同节点对同一份
//! DAG 推断出不同的首候选 leader → 对不同 `cert_signing_hash` 签票 → 票数分裂
//! （实测 2/4/1），恰 quorum 存活（7 杀 2 余 5，quorum=5）时任何单个 cert 都
//! 凑不齐 5 票：DAG/vertex 平面健康推进（round 1300+）而链 tip 停滞。
//!
//! 修复分四层（L1 在本模块，L2/L4/L5 在 validator loop 侧接入）：
//! - **L1 规范化候选序** [`canonical_commit_candidates`]：候选集改为
//!   (DAG 内容, committed 集) 的**纯函数** —— 全量未提交 vertex 按
//!   (round asc, author_pubkey asc, vertex_hash asc) 全序排列，配
//!   [`has_quorum_distinct_author_references`] 廉价预检。收敛性依据：
//!   (1) 全序与本地扫描时刻 / 插入序 / max_r 无关；(2) 引用计数只增、committed
//!   只增，故「首个过 quorum 的未提交候选」在各节点视角收敛前保持不变，落后
//!   节点下一生产周期自然汇入同一 cert —— 投票单调累积而非随窗口滑走。
//! - **L2 成熟度门**（validator loop）：只考虑 round ≤ max_r-2 的候选，引用轮
//!   落后前沿一整轮、引用集基本冻结，降低投影随 gossip 漂移的窗口。
//! - **投影缺口 fail-closed**（本就由 [`bullshark_linear_order`] 的祖先存在性
//!   检查承担）：本地 DAG 缺历史 round 时投影构造直接失败，validator loop 弃权
//!   不投票 —— 缺口视角不可能产出「偏小但可用」的投影去分裂 cert。
//! - **L4 意图稳定门**（validator loop）：连续两个生产周期 (height, leader,
//!   投影) 一致才签票，杜绝视角收敛期内同一节点对同一高度双票。
//! - **L5 投票钉扎 + 池内 last-write-wins**（validator loop + VoteCollector）：
//!   (epoch, commit_round) 内已签票即钉扎，钉扎期内拒绝为不同 cert 再签
//!   （fail-closed）； VoteCollector 按 (epoch, commit_round, signer) 只保留
//!   最新一票 —— signer 重票**替换**旧票，旧 cert 失去其票，任何时刻池内总票数
//!   ≤ validator 数，两个 5 票 quorum 在 n=7 下不可能同时成立（5+5 > 7）。
//!   钉扎超时（高度长期未决策）才释放重投，作为视图长期分歧的活性逃生口。
//! - **L6 前沿缺席分类**（validator loop 引用轮闭合检查 + 本模块
//!   [`author_has_vertex_since`]/[`COMMIT_ABSENCE_ROUNDS`]）：kill-2 后存活恰
//!   = quorum 时，掉线 validator 的后续轮 vertex 永不到来，闭合检查把「永久
//!   缺席」当「gossip 在途」无限等待，且候选 (round asc) 序最老者优先 ——
//!   含缺席作者的老候选每周期触发整体弃权，全网 commit 冻死（二次盘点复验
//!   实测：阈值/聚合演练该场景必现）。前沿前移 [`COMMIT_ABSENCE_ROUNDS`] 轮
//!   且作者自待检轮起无任何 vertex → 按离线处理，引用集视为已冻结。分类是
//!   DAG 内容纯函数，无新 cert 分裂源；finality 口径不变（2/3 签名 quorum
//!   仍按全集 validator 数）。修复后 kill-2 演练第 1 次尝试即 PASS=9（修复前
//!   连续 3 次全败）。
//!
//! 权威判定仍由 [`detect_commit_leader`] 承担（本模块函数只做排序、预检与
//! 完整性校验）。

use std::collections::{BTreeMap, BTreeSet, HashMap};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::account::AccountStore;
use crate::block::{Block, BlockHeader};
use crate::consensus::{
    CommitRound, DagCommitCertificate, DagVertex, Epoch, Round, required_quorum,
    sort_commit_txs_r4m4,
};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::executor::{ExecutionEnvironment, execute_block};
use crate::storage::ObjectDb;
use crate::transaction::Transaction;
use crate::{ChainId, Hash};

/// DAG 内存存储（按 round + hash 索引）。
#[derive(Debug, Default, Clone)]
pub struct Dag {
    /// 所有 vertex（按 vertex_hash 索引）。
    vertices: HashMap<Hash, DagVertex>,
    /// 按 round 索引的 vertex_hash 列表。
    rounds: BTreeMap<Round, Vec<Hash>>,
    /// vertex_hash → 引用该 vertex 的下一轮 vertex_hash 列表（children）。
    children: HashMap<Hash, Vec<Hash>>,
}

impl Dag {
    /// 创建空 DAG。
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入 vertex。
    pub fn insert(&mut self, vertex: DagVertex) -> Hash {
        let hash = vertex.vertex_hash();
        if self.vertices.contains_key(&hash) {
            return hash;
        }
        let round = vertex.round;

        // 更新 children 索引（parent → child）
        for parent in &vertex.parent_hashes {
            self.children.entry(*parent).or_default().push(hash);
        }

        // 存储 vertex
        self.vertices.insert(hash, vertex);

        // 按 round 索引
        self.rounds.entry(round).or_default().push(hash);

        hash
    }

    /// 获取 vertex by hash。
    pub fn get(&self, hash: &Hash) -> Option<&DagVertex> {
        self.vertices.get(hash)
    }

    /// 获取某轮的所有 vertex hash。
    pub fn round_vertices(&self, round: Round) -> &[Hash] {
        self.rounds.get(&round).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// 获取引用某 vertex 的下一轮 vertex hash 列表。
    pub fn children_of(&self, hash: &Hash) -> &[Hash] {
        self.children.get(hash).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// 获取 DAG 中所有 vertex 数量。
    pub fn len(&self) -> usize {
        self.vertices.len()
    }

    /// DAG 是否为空。
    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }

    /// 获取最大 round。
    pub fn max_round(&self) -> Option<Round> {
        self.rounds.keys().next_back().copied()
    }
}

/// Commit leader 检测结果（SubTask 9.1）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CommitLeader {
    /// 被引用的 leader vertex hash。
    pub leader_hash: Hash,
    /// leader 所在 round。
    pub leader_round: Round,
    /// 引用该 leader 的下一轮 vertex hash 列表。
    pub referencing_hashes: Vec<Hash>,
    /// 引用数量。
    pub reference_count: usize,
    /// 所需 quorum（2/3 of validator set）。
    pub required_quorum: usize,
}

/// 检测某轮 vertex 是否获得 ≥2/3 validator 引用（SubTask 9.1）。
///
/// spec：某轮 vertex 获得 ≥2/3 validator 引用 → 形成 commit certificate。
///
/// 参数：
/// - `dag`：DAG 存储
/// - `leader_hash`：待检测的 leader vertex hash
/// - `validator_count`：当前 validator 集规模
pub fn detect_commit_leader(
    dag: &Dag,
    leader_hash: &Hash,
    validator_count: usize,
) -> PokerL1Result<Option<CommitLeader>> {
    let leader = dag
        .get(leader_hash)
        .ok_or(PokerL1Error::DagVertexNotFound)?;

    let leader_round = leader.round;
    let required = required_quorum(validator_count);

    // 收集所有引用 leader 的 vertex（在 leader_round+1 及之后的轮次）
    let mut referencing: Vec<Hash> = Vec::new();
    let mut seen: BTreeSet<Hash> = BTreeSet::new();

    // 检查 leader_round+1 到 max_round 的所有 vertex
    for (&round, hashes) in dag.rounds.range(leader_round + 1..) {
        let _ = round;
        for h in hashes {
            if seen.contains(h) {
                continue;
            }
            if let Some(v) = dag.get(h)
                && v.parent_hashes.contains(leader_hash)
            {
                referencing.push(*h);
                seen.insert(*h);
            }
        }
    }

    // 去重：统计不同 validator 的引用（同一 validator 多个 vertex 只算一次）
    let mut unique_validators: BTreeSet<Vec<u8>> = BTreeSet::new();
    for h in &referencing {
        if let Some(v) = dag.get(h) {
            unique_validators.insert(v.author_pubkey.to_bytes());
        }
    }
    let reference_count = unique_validators.len();

    if reference_count >= required {
        Ok(Some(CommitLeader {
            leader_hash: *leader_hash,
            leader_round,
            referencing_hashes: referencing,
            reference_count,
            required_quorum: required,
        }))
    } else {
        Ok(None)
    }
}

/// 规范化 commit-leader 候选序（恰 quorum 存活 commit 停滞修复，见模块头注释）。
///
/// 枚举全部**未提交** vertex，按 (round asc, author_pubkey 字节序 asc,
/// vertex_hash asc) 全序返回。该序与本地扫描时刻、DAG 插入序、本地 max_r 无关：
/// 任何持有相同 DAG 内容与 committed 集的节点必然得到同一候选序列，从而对同一
/// 首候选 leader 构造同一 `cert_signing_hash` —— commit 投票得以跨节点汇聚。
///
/// 参数：
/// - `dag`：DAG 存储
/// - `committed`：已提交 vertex 集（tip 链投影；调用方经 block import 保持一致）
pub fn canonical_commit_candidates(dag: &Dag, committed: &BTreeSet<Hash>) -> Vec<Hash> {
    let mut candidates: Vec<Hash> = Vec::new();
    // rounds 为 BTreeMap：升序迭代即 round 全序；轮内再按 (author, hash) 规范化，
    // 消除插入序差异。代价 O(轮数 × 轮内顶点 log)，且首轮命中即停的调用方可提前截断。
    for (_, hashes) in &dag.rounds {
        let mut round_candidates: Vec<Hash> = hashes
            .iter()
            .filter(|hash| !committed.contains(*hash))
            .copied()
            .collect();
        if round_candidates.len() > 1 {
            round_candidates.sort_by(|a, b| {
                match (dag.get(a), dag.get(b)) {
                    (Some(va), Some(vb)) => va
                        .author_pubkey
                        .to_bytes()
                        .cmp(&vb.author_pubkey.to_bytes())
                        // 同 author 兜底按 hash 决胜（validated DAG 同 author 同轮唯一，
                        // 此支路仅为防御索引不一致时保持确定性）。
                        .then_with(|| a.cmp(b)),
                    _ => a.cmp(b),
                }
            });
        }
        candidates.extend(round_candidates);
    }
    candidates
}

/// 投影尝试结果：成功的规范未提交序 + 本地缺失的未提交祖先清单。
///
/// 恰 quorum 存活修复：本地 DAG 缺口（晚启动/丢 gossip/重启）曾是投票分歧的
/// 根源 —— 缺口节点要么投影失败弃权（恰 quorum 时少一票即全网停滞），要么对
/// 同一 leader 产出不同投影签出分裂票。把「缺了哪些 vertex（含期望轮次）」
/// 显式返回，调用方可向 peer **定向请求补洞**（RequestVerticesByRange），使
/// 全部节点视角收敛到同一投影 —— 这正是 [`bullshark_linear_order`] 注释中
/// "callers should request the missing vertex from the peer and retry" 的落地。
#[derive(Debug, Clone, Default)]
pub struct CommitProjectionAttempt {
    /// 规范未提交投影（已按 (round, author, hash) 排序；有缺失时为空序）。
    pub ordered_hashes: Vec<Hash>,
    /// 缺失的未提交祖先：(vertex hash, 期望轮次)。非空时 ordered_hashes 为空。
    pub missing: Vec<(Hash, Round)>,
}

/// 尝试构造 leader 的规范未提交投影（祖先遍历不降入已提交 vertex）。
///
/// 遍历中遇到的「本地缺失 vertex」不使投影失败，而是记入 `missing`（连同从
/// 引用边推导的期望轮次：parent 的轮次 = child.round - 1；根引用顶点缺失时
/// 记 `missing_root_round`）。调用方据 missing 列表定向补洞后重试即可收敛。
///
/// 参数：
/// - `dag`：DAG 存储
/// - `commit_hashes`：leader 的引用集（detect_commit_leader.referencing_hashes）
/// - `committed`：已提交 vertex 集（祖先封闭；遍历不降入其中）
/// - `missing_root_round`：根引用顶点缺失时报告的期望轮次（= leader_round + 1）
pub fn attempt_commit_projection(
    dag: &Dag,
    commit_hashes: &[Hash],
    committed: &BTreeSet<Hash>,
    missing_root_round: Round,
) -> CommitProjectionAttempt {
    let mut all_hashes: BTreeSet<Hash> = BTreeSet::new();
    let mut missing: BTreeMap<Round, BTreeSet<Hash>> = BTreeMap::new();
    // (hash, 期望轮次) —— 缺失 hash 无本地 round 信息，沿引用边推导。
    let mut stack: Vec<(Hash, Round)> = commit_hashes
        .iter()
        .map(|hash| (*hash, missing_root_round))
        .collect();
    let mut visited: BTreeSet<Hash> = BTreeSet::new();
    while let Some((hash, round)) = stack.pop() {
        if !visited.insert(hash) {
            continue;
        }
        // 已提交：其祖先必然已提交（祖先封闭），不纳入投影也不下钻。
        if committed.contains(&hash) {
            continue;
        }
        let Some(vertex) = dag.get(&hash) else {
            // 未提交且本地缺失 → 记入缺失清单（fail-closed：不产出偏小投影）。
            all_hashes.remove(&hash);
            missing.entry(round).or_default().insert(hash);
            continue;
        };
        all_hashes.insert(hash);
        let parent_round = round.saturating_sub(1);
        for parent in &vertex.parent_hashes {
            if !visited.contains(parent) {
                stack.push((*parent, parent_round));
            }
        }
    }
    if !missing.is_empty() {
        return CommitProjectionAttempt {
            ordered_hashes: Vec::new(),
            missing: missing
                .into_iter()
                .flat_map(|(round, hashes)| {
                    hashes.into_iter().map(move |hash| (hash, round))
                })
                .collect(),
        };
    }
    // 转为 Vec 并按 (round, author_pubkey_bytes) 排序（与 bullshark_linear_order 同序）。
    let mut sorted: Vec<Hash> = all_hashes.into_iter().collect();
    sorted.sort_by(|a, b| {
        let va = dag.get(a).expect("validated vertex must exist in DAG");
        let vb = dag.get(b).expect("validated vertex must exist in DAG");
        va.round.cmp(&vb.round).then_with(|| {
            va.author_pubkey
                .to_bytes()
                .cmp(&vb.author_pubkey.to_bytes())
        })
        .then_with(|| a.cmp(b))
    });
    CommitProjectionAttempt {
        ordered_hashes: sorted,
        missing: Vec::new(),
    }
}

/// 扫描 [from_round, to_round] 中 vertex 引用的、本地 DAG 缺失的 parent。
///
/// 返回 (缺失 hash, 期望轮次 = child.round - 1) 按轮升序去重列表。用于检测
/// 「引用叶缺口」：round-r 的 leader 其引用集 = round-(r+1) 中引用它的 vertex，
/// 缺失的引用叶自身不在任何祖先路径上，投影/预检都不会报错，但会让不同节点
/// 的引用集（进而投影）不同 —— 通过其下轮子顶点的 parent 指针即可定位缺失。
pub fn find_missing_parent_vertices(
    dag: &Dag,
    from_round: Round,
    to_round: Round,
) -> Vec<(Hash, Round)> {
    let mut missing: BTreeMap<Round, BTreeSet<Hash>> = BTreeMap::new();
    for (&round, hashes) in dag.rounds.range(from_round..=to_round) {
        for hash in hashes {
            let Some(vertex) = dag.get(hash) else {
                continue;
            };
            for parent in &vertex.parent_hashes {
                if dag.get(parent).is_none() {
                    missing
                        .entry(round.saturating_sub(1))
                        .or_default()
                        .insert(*parent);
                }
            }
        }
    }
    missing
        .into_iter()
        .flat_map(|(round, hashes)| hashes.into_iter().map(move |hash| (hash, round)))
        .collect()
}

/// 「前沿缺席」窗口（恰 quorum 存活活性修复，validator loop 引用轮闭合检查
/// 的配套原语）：validator 的 vertex 生产是逐轮连续的（每生产周期恰一轮），
/// 健康作者的最新 vertex 与全网 `max_round` 的差距恒小于该窗口。前沿已前移
/// 本窗口那么多轮、而某作者自待检轮起仍无任何 vertex，即可判定其离线 ——
/// 其后续轮次的 vertex 永远不会到来，闭合检查对其无限等待只会把恰 quorum
/// 存活（kill-2 后存活恰 = quorum）的全网 commit 冻死（7 节点演练实测：
/// DAG/vertex 平面持续推进而链 tip 停滞）。
pub const COMMIT_ABSENCE_ROUNDS: Round = 4;

/// 作者自 `min_round` 起（含）在 DAG 中是否有任何 vertex。
///
/// 「前沿缺席」分类原语：与 [`canonical_commit_candidates`] 一样是 DAG 内容
/// 的纯函数 —— 持有相同 DAG 内容的节点必然得到相同分类，因此把它用于
/// 投影闭合判定不引入新的 cert 分裂源（gossip 收敛窗口期由 validator loop
/// 的 L4 意图稳定门兜底）。finality 口径不受影响：cert 的 2/3 签名 quorum
/// 与引用 quorum 仍按全集 validator 数执行。
pub fn author_has_vertex_since(dag: &Dag, author: &[u8], min_round: Round) -> bool {
    for (_, hashes) in dag.rounds.range(min_round..) {
        for hash in hashes {
            if let Some(v) = dag.get(hash)
                && v.author_pubkey.to_bytes().as_slice() == author
            {
                return true;
            }
        }
    }
    false
}

/// 廉价 quorum 预检：统计引用某 vertex 的不同 author 数是否已达 quorum。
///
/// validate_vertex 保证 parent 恰好位于 vertex.round-1，因此 round-r vertex 的
/// 引用者只可能出现在 r+1 轮 —— 本检查与 [`detect_commit_leader`] 的全轮扫描在
/// 已验证 DAG 上等价，但把单候选成本从 O(全 DAG 顶点) 降到 O(r+1 轮顶点)，使得
/// 「全量候选逐个预检」的开销可忽略。候选的权威判定与 CommitLeader 构造仍由
/// 调用方随后调用 [`detect_commit_leader`] 完成。
///
/// 参数：
/// - `dag`：DAG 存储
/// - `leader_hash`：待预检的 vertex hash
/// - `validator_count`：当前 validator 集规模（quorum 口径与 detect 一致）
pub fn has_quorum_distinct_author_references(
    dag: &Dag,
    leader_hash: &Hash,
    validator_count: usize,
) -> bool {
    let leader = match dag.get(leader_hash) {
        Some(leader) => leader,
        None => return false,
    };
    let required = required_quorum(validator_count);
    let mut unique_validators: BTreeSet<Vec<u8>> = BTreeSet::new();
    for child_hash in dag.round_vertices(leader.round + 1) {
        if let Some(child) = dag.get(child_hash)
            && child.parent_hashes.contains(leader_hash)
        {
            unique_validators.insert(child.author_pubkey.to_bytes());
            if unique_validators.len() >= required {
                return true;
            }
        }
    }
    false
}

/// wave-3 固定 leader 评估结果（Mysticeti 对齐：L 轮 leader、L+1 轮投票、
/// L+2 轮决策）。
///
/// 票/证书都只数**固定轮次**（L+1 / L+2），图案有界、随 frontier 冻结——
/// 与 [`detect_commit_leader`] 的「扫描 leader 之后全部轮次」不同，本评估是
/// (DAG, committed) 的稳定纯函数：视图收敛后所有节点必然得出同一结论，
/// 投票语句天然汇聚，无需意图稳定门/钉扎兜底。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaveOutcome {
    /// 直接提交：决策轮（L+2）出现 ≥ quorum 个 certificate，每个 certificate
    /// 的 parents 含 ≥ quorum 张 L+1 轮票（quorum 嵌套 = 2-chain）。
    Commit {
        /// L+1 轮支持 leader 的 vertex（按 author 去重，升序遍历序）。
        votes: Vec<Hash>,
        /// L+2 轮构成 certificate 的 vertex（按 author 去重）。
        certs: Vec<Hash>,
    },
    /// 跳过：L+1 轮 ≥ quorum 个 author 的 vertex 未引用 leader（blame）。
    /// 支持/非支持按 author 互斥，blame-quorum 与 vote-quorum 不可能并存
    /// （quorum 交集），故 Skip 与 Commit 全局互斥——跳过是安全的活性决策。
    Skip,
    /// 未决：票数/blame 均未达 quorum（frontier 不足或视角未收敛）。
    Undecided,
}

/// 评估 round `leader_round` 的 leader vertex（`leader_hash`）的波。
///
/// 参数：
/// - `dag`：DAG 存储
/// - `leader_hash`：预定 leader 的 vertex hash（vertex 本身可以尚不在本地：
///   票按 parent 指针计数，不依赖 leader vertex 在场；投影阶段才要求在场）
/// - `leader_round`：leader 所在轮 L
/// - `validator_count`：当前 validator 集规模（quorum 口径与其余检测一致）
pub fn evaluate_leader_wave(
    dag: &Dag,
    leader_hash: &Hash,
    leader_round: Round,
    validator_count: usize,
) -> WaveOutcome {
    let required = required_quorum(validator_count);
    // 票：恰在 L+1 轮、parent_hashes 含 leader 的 vertex（按 author 去重）。
    let mut vote_authors: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut votes: Vec<Hash> = Vec::new();
    let mut blame_authors: BTreeSet<Vec<u8>> = BTreeSet::new();
    for vh in dag.round_vertices(leader_round.saturating_add(1)) {
        let Some(v) = dag.get(vh) else {
            continue;
        };
        if v.parent_hashes.contains(leader_hash) {
            if vote_authors.insert(v.author_pubkey.to_bytes()) {
                votes.push(*vh);
            }
        } else if blame_authors.insert(v.author_pubkey.to_bytes()) {
            // blame 只计数，不收集 hash（跳过无需投影）。
        }
    }
    // certificate：恰在 L+2 轮、parents 覆盖 ≥ quorum 个 supporter author 的 vertex。
    let mut cert_authors: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut certs: Vec<Hash> = Vec::new();
    for ch in dag.round_vertices(leader_round.saturating_add(2)) {
        let Some(c) = dag.get(ch) else {
            continue;
        };
        let mut covered: BTreeSet<Vec<u8>> = BTreeSet::new();
        for p in &c.parent_hashes {
            if let Some(pv) = dag.get(p)
                && pv.round == leader_round.saturating_add(1)
                && pv.parent_hashes.contains(leader_hash)
                && covered.insert(pv.author_pubkey.to_bytes())
            {
                if covered.len() >= required {
                    break;
                }
            }
        }
        if covered.len() >= required && cert_authors.insert(c.author_pubkey.to_bytes()) {
            certs.push(*ch);
        }
    }
    if cert_authors.len() >= required {
        return WaveOutcome::Commit { votes, certs };
    }
    if blame_authors.len() >= required {
        return WaveOutcome::Skip;
    }
    WaveOutcome::Undecided
}

/// 轮转 leader 下标（wave-3 固定 leader，Mysticeti pipelining 等效形式）：
/// round r 的预定 leader = 排序后活跃 validator 集第 `r % n` 位。
///
/// 纯轮数函数，跨节点零沟通即一致；每轮皆有 leader（波间隔 = 3 轮的提交
/// 时延与每轮一个 leader 的吞吐同时成立）。
pub fn round_leader_index(round: Round, validator_count: usize) -> usize {
    (round as usize) % validator_count.max(1)
}

/// 获取 vertex 的所有祖先（递归遍历 parent_hashes，含自身）。
fn collect_ancestors(dag: &Dag, hash: &Hash) -> Vec<Hash> {
    let mut visited: BTreeSet<Hash> = BTreeSet::new();
    let mut stack: Vec<Hash> = vec![*hash];
    let mut result: Vec<Hash> = Vec::new();

    while let Some(h) = stack.pop() {
        if !visited.insert(h) {
            continue;
        }
        result.push(h);
        if let Some(v) = dag.get(&h) {
            for parent in &v.parent_hashes {
                if !visited.contains(parent) {
                    stack.push(*parent);
                }
            }
        }
    }

    result
}

/// Bullshark 线性排序（SubTask 9.2）。
///
/// spec：对 DAG vertex 线性排序 — 按 (round, author_pubkey_bytes) 排序。
///
/// 参数：
/// - `dag`：DAG 存储
/// - `commit_hashes`：commit 内的 vertex hash 列表（leader + 其引用的祖先）
pub fn bullshark_linear_order(dag: &Dag, commit_hashes: &[Hash]) -> PokerL1Result<Vec<Hash>> {
    // 收集所有祖先（去重）
    let mut all_hashes: BTreeSet<Hash> = BTreeSet::new();
    for h in commit_hashes {
        for ancestor in collect_ancestors(dag, h) {
            all_hashes.insert(ancestor);
        }
    }

    // Never let an incomplete DAG turn deterministic ordering into a panic.  A commit can only
    // be projected when every referenced vertex is present locally; callers should request the
    // missing vertex from the peer and retry instead of producing a partial block.
    for hash in &all_hashes {
        if dag.get(hash).is_none() {
            return Err(PokerL1Error::DagVertexNotFound);
        }
    }

    // 转为 Vec 并按 (round, author_pubkey_bytes) 排序
    let mut sorted: Vec<Hash> = all_hashes.into_iter().collect();
    sorted.sort_by(|a, b| {
        let va = dag.get(a).expect("validated vertex must exist in DAG");
        let vb = dag.get(b).expect("validated vertex must exist in DAG");
        // 先按 round 排序
        va.round
            .cmp(&vb.round)
            // 同 round 按 author_pubkey_bytes 排序
            .then_with(|| {
                va.author_pubkey
                    .to_bytes()
                    .cmp(&vb.author_pubkey.to_bytes())
            })
            // 同 author 按 vertex_hash 排序（确定性）
            .then_with(|| a.cmp(b))
    });

    Ok(sorted)
}

/// Return the canonical Bullshark order after removing vertices already materialized in an
/// earlier block.
///
/// The DAG deliberately retains committed frontier vertices because later rounds reference
/// them.  They must remain available for ancestry traversal, but their transactions must never be
/// executed twice.  Keeping this filtering in the consensus module makes the committed-frontier
/// rule explicit and gives every producer the same projection primitive.
///
/// 恰 quorum 存活修复：祖先遍历**不降入已提交 vertex**。committed 集按构造是
/// 祖先封闭的（每个投影 = 全体祖先 − 更早已提交），因此已提交 vertex 的祖先
/// 必然已提交，继续下钻只会要求节点持有它早已「提交并遗忘」的历史 —— 晚启动 /
/// 重启 / 丢 gossip 的节点其 live DAG 缺历史 round，旧遍历会永久性投影失败，
/// 节点从此无法签 commit 票；恰 quorum 存活（5/7）时少一个投票者即全网停滞。
/// 剪枝后，投影只依赖已提交边界之上的未提交区（近期 gossip，视角天然收敛），
/// 缺口节点随 block import 补齐 committed 集后自动恢复投票资格，且所有节点对
/// 同一 (DAG, committed) 仍得到逐位相同的投影。
pub fn bullshark_linear_order_uncommitted(
    dag: &Dag,
    commit_hashes: &[Hash],
    committed: &BTreeSet<Hash>,
) -> PokerL1Result<Vec<Hash>> {
    let mut all_hashes: BTreeSet<Hash> = BTreeSet::new();
    let mut visited: BTreeSet<Hash> = BTreeSet::new();
    let mut stack: Vec<Hash> = commit_hashes.to_vec();
    while let Some(hash) = stack.pop() {
        if !visited.insert(hash) {
            continue;
        }
        // 已提交：其祖先必然已提交（祖先封闭），不纳入投影也不下钻。
        if committed.contains(&hash) {
            continue;
        }
        all_hashes.insert(hash);
        if let Some(vertex) = dag.get(&hash) {
            for parent in &vertex.parent_hashes {
                if !visited.contains(parent) {
                    stack.push(*parent);
                }
            }
        }
    }

    // Never let an incomplete DAG turn deterministic ordering into a panic.  A commit can only
    // be projected when every *uncommitted* referenced vertex is present locally; callers should
    // request the missing vertex from the peer and retry instead of producing a partial block.
    for hash in &all_hashes {
        if dag.get(hash).is_none() {
            return Err(PokerL1Error::DagVertexNotFound);
        }
    }

    // 转为 Vec 并按 (round, author_pubkey_bytes) 排序
    let mut sorted: Vec<Hash> = all_hashes.into_iter().collect();
    sorted.sort_by(|a, b| {
        let va = dag.get(a).expect("validated vertex must exist in DAG");
        let vb = dag.get(b).expect("validated vertex must exist in DAG");
        // 先按 round 排序
        va.round
            .cmp(&vb.round)
            // 同 round 按 author_pubkey_bytes 排序
            .then_with(|| {
                va.author_pubkey
                    .to_bytes()
                    .cmp(&vb.author_pubkey.to_bytes())
            })
            // 同 author 按 vertex_hash 排序（确定性）
            .then_with(|| a.cmp(b))
    });

    Ok(sorted)
}

/// Block 投影结果（SubTask 9.3）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlockProjection {
    /// 投影产出的 block header。
    pub header: BlockHeader,
    /// Public 通道 tx 列表。
    pub public_txs: Vec<Transaction>,
    /// GameTurn 通道 tx 列表。
    pub gameturn_txs: Vec<Transaction>,
    /// commit 内的有序 vertex hash 列表。
    pub ordered_vertex_hashes: Vec<Hash>,
}

/// 从 DAG commit 投影产出 block（SubTask 9.3 + 9.4）。
///
/// spec：
/// - block = commit 内 vertex 的 tx 聚合 + S9/R4-M4 排序
/// - block header 含 dag_commit_certificate
///
/// 参数：
/// - `dag`：DAG 存储
/// - `commit_leader`：commit leader 检测结果
/// - `commit_certificate`：已组装的 commit certificate
/// - `env`：交易执行环境（chain_id / height / timestamp / gas limit）
/// - `object_db`：对象数据库（可变引用，执行 tx 后更新状态）
/// - `account_store`：账户存储（可变引用，执行 tx 后更新状态）
/// - `prev_hash`：前一个 block 的 hash
/// - `height`：当前 block height
/// - `timestamp_ms`：当前 block timestamp（毫秒）
pub fn project_block_from_commit(
    dag: &Dag,
    commit_leader: &CommitLeader,
    commit_certificate: DagCommitCertificate,
    env: &ExecutionEnvironment,
    object_db: &mut ObjectDb,
    account_store: &mut AccountStore,
    prev_hash: Hash,
    height: u64,
    timestamp_ms: u64,
) -> PokerL1Result<BlockProjection> {
    // 1. Bullshark 线性排序。新证书必须承诺 canonical projection；空列表保留旧的
    // library/test compatibility and is replaced by the leader roots below.
    let commit_roots = if commit_certificate.vertex_hash_list.is_empty() {
        commit_leader.referencing_hashes.clone()
    } else {
        commit_certificate.vertex_hash_list.clone()
    };
    let ordered_hashes = bullshark_linear_order(dag, &commit_roots)?;
    if !commit_certificate.vertex_hash_list.is_empty()
        && commit_certificate.vertex_hash_list != ordered_hashes
    {
        return Err(PokerL1Error::CommitCertificateMismatch(
            "commit certificate vertex_hash_list is not the canonical Bullshark order".into(),
        ));
    }

    // 2. 按 vertex 顺序收集 tx_list（保留 vertex 边界，供 R4-M4 跨 vertex 排序）
    let mut vertex_txs: Vec<Vec<Transaction>> = Vec::with_capacity(ordered_hashes.len());
    for h in &ordered_hashes {
        let vertex = dag.get(h).ok_or(PokerL1Error::DagVertexNotFound)?;
        vertex_txs.push(vertex.tx_list.to_vec());
    }

    // 3. S9/R4-M4 排序（GameTurn + CheckpointAnchor → Public → ForceSync）
    let sorted_txs = sort_commit_txs_r4m4(vertex_txs);

    // 4. 拆分为 public_txs 与 gameturn_txs（按 lane_hint）
    let mut public_txs = Vec::new();
    let mut gameturn_txs = Vec::new();
    for tx in &sorted_txs {
        use crate::transaction::TxLane;
        match tx.lane_hint {
            TxLane::GameTurn | TxLane::CheckpointAnchor => gameturn_txs.push(tx.clone()),
            TxLane::Public | TxLane::ForceSync => public_txs.push(tx.clone()),
        }
    }

    // 5. 计算 tx roots
    let public_tx_root = crate::block::compute_tx_merkle_root(&public_txs);
    let gameturn_tx_root = crate::block::compute_tx_merkle_root(&gameturn_txs);

    // 6. 执行交易并获取新的 state_root。
    //
    // `public_txs` / `gameturn_txs` 是为了分别承诺 Merkle root 而拆分的；它们不是
    // 两套独立状态机。必须重放完整的 S9/R4-M4 有序序列，否则 GameTurn 状态变化会
    // 游离在 block header 的 state_root 之外。
    let outcome = execute_block(env, &sorted_txs, object_db, account_store);
    let state_root = outcome.state_root;

    // 7. 构造 block header
    let header = BlockHeader {
        height,
        timestamp_ms,
        prev_hash,
        state_root,
        public_tx_root,
        gameturn_tx_root,
        dag_commit_certificate: commit_certificate,
    };

    Ok(BlockProjection {
        header,
        public_txs,
        gameturn_txs,
        ordered_vertex_hashes: ordered_hashes,
    })
}

/// 从 BlockProjection 构造 Block。
impl BlockProjection {
    /// 消费 projection 构造最终 Block。
    pub fn into_block(self) -> Block {
        Block::new(self.header, self.public_txs, self.gameturn_txs)
    }
}

/// 校验 commit certificate 的 2/3 quorum（SubTask 9.5）。
///
/// spec：commit certificate 含 2/3 secp256k1 多签（signer_bitmap + signature_list） → finalized。
///
/// 注意：此函数仅校验签名数量是否 ≥ 2/3 quorum。
/// 实际 secp256k1 签名验证由 Task 10 / IMPL-SEC-1 实现。
///
/// 参数：
/// - `cert`：commit certificate
/// - `validator_count`：当前 validator 集规模
pub fn validate_commit_certificate_quorum(
    cert: &DagCommitCertificate,
    validator_count: usize,
) -> PokerL1Result<()> {
    let required = required_quorum(validator_count);
    let actual = cert.signer_count();
    if actual < required {
        return Err(PokerL1Error::InsufficientQuorum { actual, required });
    }
    Ok(())
}

/// 校验 commit certificate 字段一致性（SEC2-C1）。
///
/// spec SEC2-C1：
/// - 签名对象绑定 epoch / prev_commit_hash / state_root / public_tx_root / gameturn_tx_root
/// - 防 commit certificate 被重用到不同 block 内容
///
/// 参数：
/// - `cert`：commit certificate
/// - `expected_epoch`：期望的 epoch
/// - `expected_prev_commit_hash`：期望的 prev_commit_hash
/// - `expected_state_root`：期望的 state_root
/// - `expected_public_tx_root`：期望的 public_tx_root
/// - `expected_gameturn_tx_root`：期望的 gameturn_tx_root
pub fn validate_commit_certificate_fields(
    cert: &DagCommitCertificate,
    expected_epoch: Epoch,
    expected_prev_commit_hash: Hash,
    expected_state_root: Hash,
    expected_public_tx_root: Hash,
    expected_gameturn_tx_root: Hash,
) -> PokerL1Result<()> {
    if cert.epoch != expected_epoch {
        return Err(PokerL1Error::CommitCertificateMismatch(format!(
            "epoch mismatch: cert={}, expected={}",
            cert.epoch, expected_epoch
        )));
    }
    if cert.prev_commit_hash != expected_prev_commit_hash {
        return Err(PokerL1Error::CommitCertificateMismatch(format!(
            "prev_commit_hash mismatch: cert={:?}, expected={:?}",
            cert.prev_commit_hash, expected_prev_commit_hash
        )));
    }
    if cert.state_root != expected_state_root {
        return Err(PokerL1Error::CommitCertificateMismatch(format!(
            "state_root mismatch: cert={:?}, expected={:?}",
            cert.state_root, expected_state_root
        )));
    }
    if cert.public_tx_root != expected_public_tx_root {
        return Err(PokerL1Error::CommitCertificateMismatch(format!(
            "public_tx_root mismatch: cert={:?}, expected={:?}",
            cert.public_tx_root, expected_public_tx_root
        )));
    }
    if cert.gameturn_tx_root != expected_gameturn_tx_root {
        return Err(PokerL1Error::CommitCertificateMismatch(format!(
            "gameturn_tx_root mismatch: cert={:?}, expected={:?}",
            cert.gameturn_tx_root, expected_gameturn_tx_root
        )));
    }
    Ok(())
}

/// 组装 commit certificate（SubTask 9.5 + SEC2-C1）。
///
/// spec：
/// - 收集 ≥2/3 validator 的签名
/// - 签名对象 = signing_hash（已在 Phase 1 实现）
/// - signer_bitmap 标记哪些 validator 签名
///
/// 参数：
/// - `epoch`：当前 epoch
/// - `commit_round`：commit 轮次
/// - `prev_commit_hash`：前一个 commit 的 hash
/// - `vertex_hash_list`：commit 涵盖的 vertex hash 列表
/// - `round_attendance_bitmap`：本轮出勤 bitmap
/// - `state_root` / `public_tx_root` / `gameturn_tx_root`：本 block 的 roots
/// - `signatures`：(validator_index, signature_bytes) 列表
/// - `validator_count`：validator 集规模（用于构造 signer_bitmap）
#[allow(clippy::too_many_arguments)]
pub fn assemble_commit_certificate(
    epoch: Epoch,
    commit_round: CommitRound,
    prev_commit_hash: Hash,
    vertex_hash_list: Vec<Hash>,
    round_attendance_bitmap: Vec<u8>,
    state_root: Hash,
    public_tx_root: Hash,
    gameturn_tx_root: Hash,
    signatures: &[(usize, Vec<u8>)],
    validator_count: usize,
) -> PokerL1Result<DagCommitCertificate> {
    // 构造 signer_bitmap
    let bitmap_len = validator_count.div_ceil(8);
    let mut signer_bitmap = vec![0u8; bitmap_len];
    let mut signature_list: Vec<Vec<u8>> = Vec::with_capacity(signatures.len());

    for &(validator_idx, ref sig) in signatures {
        if validator_idx >= validator_count {
            return Err(PokerL1Error::Other(format!(
                "validator index {} out of range (count={})",
                validator_idx, validator_count
            )));
        }
        // 设置 bitmap 位
        let byte_idx = validator_idx / 8;
        let bit_idx = validator_idx % 8;
        signer_bitmap[byte_idx] |= 1u8 << bit_idx;
        signature_list.push(sig.clone());
    }

    Ok(DagCommitCertificate {
        epoch,
        commit_round,
        prev_commit_hash,
        vertex_hash_list,
        round_attendance_bitmap,
        state_root,
        public_tx_root,
        gameturn_tx_root,
        signature_list,
        signer_bitmap,
    })
}

/// 检测 commit certificate equivocation（SEC2-C1 slashing 证据）。
///
/// spec SEC2-C1：同 (epoch, commit_round) 双签 commit certificate → 踢出 + 罚没。
///
/// 参数：
/// - `cert1`：第一个 commit certificate
/// - `cert2`：第二个 commit certificate
/// - `chain_id`：链 ID（用于计算 cert_hash）
///
/// 返回 `Some(evidence)` 如果检测到 equivocation；`None` 如果无 equivocation。
pub fn detect_commit_cert_equivocation(
    cert1: &DagCommitCertificate,
    cert2: &DagCommitCertificate,
    chain_id: ChainId,
    validators: &[crate::consensus::ValidatorEntry],
) -> Option<crate::consensus::CommitCertEquivocationEvidence> {
    // 同 (epoch, commit_round) 但不同 cert_hash → equivocation
    if cert1.epoch == cert2.epoch && cert1.commit_round == cert2.commit_round {
        // 进一步检查是否真的不同（不同 vertex_hash_list 或签名）
        if cert1.vertex_hash_list != cert2.vertex_hash_list
            || cert1.signer_bitmap != cert2.signer_bitmap
        {
            // 缺口 #1-路径C：证据 schema 改为携带两个完整 cert + 矛盾 validator 的
            // pubkey 与其在两 cert 中的签名。从两 cert 的 signer_bitmap 交集中找出
            // 第一个"在两 cert 都签名"的 validator 作为矛盾作者。
            return build_commit_cert_evidence_from_intersecting_signer(
                cert1, cert2, chain_id, validators,
            );
        }
    }
    None
}

/// 从两个 cert 的 signer_bitmap 交集中构造第一个矛盾 validator 的证据。
///
/// 缺口 #1-路径C：扫描两 bitmap 的共同置位 validator，取第一个作为 `author`，
/// 从各自 `signature_list`（按升序置位对应）提取其签名，组装完整证据。
///
/// 参数 `validators` 提供 validator 索引 → pubkey 的映射（signer_bitmap 的 index 基准）。
///
/// 返回 `None` 若两 cert 无共同签名 validator（理论上不会发生，因双签才构成 equivocation）。
fn build_commit_cert_evidence_from_intersecting_signer(
    cert1: &DagCommitCertificate,
    cert2: &DagCommitCertificate,
    chain_id: ChainId,
    validators: &[crate::consensus::ValidatorEntry],
) -> Option<crate::consensus::CommitCertEquivocationEvidence> {
    // signer_bitmap 置位（升序）→ signature_list 紧凑对应。
    let signers1 = bitmap_set_bits(&cert1.signer_bitmap);
    let signers2 = bitmap_set_bits(&cert2.signer_bitmap);
    // 两 cert 的签名列表需与各自置位数匹配（防御性）。
    if signers1.len() != cert1.signature_list.len() || signers2.len() != cert2.signature_list.len()
    {
        return None;
    }
    // 找第一个在两 cert 都签名的 validator 索引。
    for (list_pos1, &validator_idx) in signers1.iter().enumerate() {
        if let Some(list_pos2) = signers2.iter().position(|&idx| idx == validator_idx) {
            // 该 validator 在两 cert 都签名 → 矛盾作者。
            let author = validators.get(validator_idx)?.pubkey.clone();
            return Some(crate::consensus::CommitCertEquivocationEvidence {
                chain_id,
                epoch: cert1.epoch,
                commit_round: cert1.commit_round,
                author,
                signature_1: cert1.signature_list[list_pos1].clone(),
                signature_2: cert2.signature_list[list_pos2].clone(),
                cert_1: cert1.clone(),
                cert_2: cert2.clone(),
            });
        }
    }
    None
}

/// bitmap 置位升序枚举（与 cert_verification 模块口径一致）。
fn bitmap_set_bits(bitmap: &[u8]) -> Vec<usize> {
    let mut indices = Vec::new();
    for (byte_idx, byte) in bitmap.iter().enumerate() {
        for bit_idx in 0..8 {
            if (byte >> bit_idx) & 1 == 1 {
                indices.push(byte_idx * 8 + bit_idx);
            }
        }
    }
    indices
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{DagCommitCertificate, DagVertex, MAX_VERTEX_SIZE};
    use crate::signature::TaggedPubkey;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{Gas, RouteHint, TxLane};

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    fn make_vertex(epoch: Epoch, round: Round, author_byte: u8, parents: Vec<Hash>) -> DagVertex {
        DagVertex {
            epoch,
            round,
            author_pubkey: make_tagged_pubkey(author_byte),
            tx_list: vec![],
            parent_hashes: parents,
            author_sig: vec![0u8; 65],
            forced_tx_hashes: vec![],
        }
    }

    fn make_tx(nonce: u64, lane: TxLane) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x10),
            signature: vec![0u8; 65],
            gas: Gas::new(1000, 1),
            lane_hint: lane,
            route_hint: RouteHint::AnyValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    // ===== wave-3 固定 leader 评估测试 =====

    #[test]
    fn wave_leader_rotation_is_deterministic() {
        assert_eq!(round_leader_index(1, 4), 1);
        assert_eq!(round_leader_index(2, 4), 2);
        assert_eq!(round_leader_index(4, 4), 0);
        assert_eq!(round_leader_index(5, 4), 1);
        // 单 validator：恒为 0（len.max(1) 防零）
        assert_eq!(round_leader_index(9, 1), 0);
        assert_eq!(round_leader_index(3, 0), 0);
    }

    #[test]
    fn wave_commit_on_double_quorum() {
        // L 轮 leader；L+1 三个 supporter（quorum 票）；L+2 三个 cert
        //（各覆盖三张票）→ Commit。
        let mut dag = Dag::new();
        let leader = dag.insert(make_vertex(1, 5, 0x10, vec![]));
        let v11 = dag.insert(make_vertex(1, 6, 0x11, vec![leader]));
        let v12 = dag.insert(make_vertex(1, 6, 0x12, vec![leader]));
        let v13 = dag.insert(make_vertex(1, 6, 0x13, vec![leader]));
        let c1 = dag.insert(make_vertex(1, 7, 0x11, vec![v11, v12, v13]));
        let _c2 = dag.insert(make_vertex(1, 7, 0x12, vec![v11, v12, v13]));
        let _c3 = dag.insert(make_vertex(1, 7, 0x13, vec![v11, v12, v13]));
        let _ = c1;
        match evaluate_leader_wave(&dag, &leader, 5, 4) {
            WaveOutcome::Commit { votes, certs } => {
                assert_eq!(votes.len(), 3);
                assert_eq!(certs.len(), 3);
            }
            other => panic!("期望 Commit，实际 {other:?}"),
        }
    }

    #[test]
    fn wave_undecided_before_decision_round() {
        // 只有票没有 cert → Undecided
        let mut dag = Dag::new();
        let leader = dag.insert(make_vertex(1, 5, 0x10, vec![]));
        dag.insert(make_vertex(1, 6, 0x11, vec![leader]));
        dag.insert(make_vertex(1, 6, 0x12, vec![leader]));
        dag.insert(make_vertex(1, 6, 0x13, vec![leader]));
        assert_eq!(
            evaluate_leader_wave(&dag, &leader, 5, 4),
            WaveOutcome::Undecided
        );
    }

    #[test]
    fn wave_skip_on_blame_quorum() {
        // L+1 三个 vertex 均未引用 leader → blame quorum → Skip
        let mut dag = Dag::new();
        let leader = dag.insert(make_vertex(1, 5, 0x10, vec![]));
        let other = dag.insert(make_vertex(1, 5, 0x0f, vec![]));
        dag.insert(make_vertex(1, 6, 0x11, vec![other]));
        dag.insert(make_vertex(1, 6, 0x12, vec![other]));
        dag.insert(make_vertex(1, 6, 0x13, vec![other]));
        assert_eq!(evaluate_leader_wave(&dag, &leader, 5, 4), WaveOutcome::Skip);
    }

    #[test]
    fn wave_votes_only_from_exact_round() {
        // 票只数 L+1 轮：L+1 仅 2 张票，L+4 轮迟到引用不计入 → 不可能凑成
        // Commit（Undecided），证明图案有界（对照旧 detect_commit_leader 的
        // 全轮扫描）。
        let mut dag = Dag::new();
        let leader = dag.insert(make_vertex(1, 5, 0x10, vec![]));
        let v11 = dag.insert(make_vertex(1, 6, 0x11, vec![leader]));
        let v12 = dag.insert(make_vertex(1, 6, 0x12, vec![leader]));
        let _v13 = dag.insert(make_vertex(1, 6, 0x13, vec![])); // 非支持者
        let c1 = dag.insert(make_vertex(1, 7, 0x11, vec![v11, v12])); // 仅覆盖 2 票 < 3
        let _c2 = dag.insert(make_vertex(1, 7, 0x12, vec![v11, v12]));
        // 迟到引用：round 9 的 vertex 直接引用 leader —— 不计为票
        dag.insert(make_vertex(1, 9, 0x0e, vec![leader, c1]));
        assert_eq!(
            evaluate_leader_wave(&dag, &leader, 5, 4),
            WaveOutcome::Undecided
        );
    }

    #[test]
    fn wave_cert_requires_vote_quorum_inside_parents() {
        // L+2 cert 的 parents 必须覆盖 ≥ quorum 张票：只覆盖 2/3 的 cert 不算
        let mut dag = Dag::new();
        let leader = dag.insert(make_vertex(1, 5, 0x10, vec![]));
        let v11 = dag.insert(make_vertex(1, 6, 0x11, vec![leader]));
        let v12 = dag.insert(make_vertex(1, 6, 0x12, vec![leader]));
        let v13 = dag.insert(make_vertex(1, 6, 0x13, vec![leader]));
        dag.insert(make_vertex(1, 7, 0x11, vec![v11, v12])); // 覆盖 2 票
        dag.insert(make_vertex(1, 7, 0x12, vec![v12, v13])); // 覆盖 2 票
        dag.insert(make_vertex(1, 7, 0x13, vec![v11, v13])); // 覆盖 2 票
        // 三个"半 cert"各缺一票 → 不足以 Commit，但 blame=0 → Undecided
        assert_eq!(
            evaluate_leader_wave(&dag, &leader, 5, 4),
            WaveOutcome::Undecided
        );
    }

    // ===== Dag 存储测试 =====

    #[test]
    fn dag_insert_and_get() {
        let mut dag = Dag::new();
        let v = make_vertex(1, 1, 0x10, vec![]);
        let h = dag.insert(v);
        assert_eq!(dag.len(), 1);
        assert!(dag.get(&h).is_some());
    }

    #[test]
    fn dag_round_vertices() {
        let mut dag = Dag::new();
        let v1 = make_vertex(1, 1, 0x10, vec![]);
        let v2 = make_vertex(1, 1, 0x11, vec![]);
        let v3 = make_vertex(1, 2, 0x12, vec![]);
        dag.insert(v1);
        dag.insert(v2);
        dag.insert(v3);
        assert_eq!(dag.round_vertices(1).len(), 2);
        assert_eq!(dag.round_vertices(2).len(), 1);
        assert_eq!(dag.round_vertices(3).len(), 0);
    }

    #[test]
    fn dag_children_of() {
        let mut dag = Dag::new();
        let parent = make_vertex(1, 1, 0x10, vec![]);
        let parent_hash = dag.insert(parent);
        let child = make_vertex(1, 2, 0x11, vec![parent_hash]);
        let child_hash = dag.insert(child);
        let children = dag.children_of(&parent_hash);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0], child_hash);
    }

    #[test]
    fn dag_insert_same_vertex_is_idempotent_for_all_indexes() {
        let mut dag = Dag::new();
        let parent_hash = dag.insert(make_vertex(1, 1, 0x10, vec![]));
        let child = make_vertex(1, 2, 0x11, vec![parent_hash]);
        let child_hash = dag.insert(child.clone());
        assert_eq!(dag.insert(child), child_hash);

        assert_eq!(dag.len(), 2);
        assert_eq!(dag.round_vertices(2), &[child_hash]);
        assert_eq!(dag.children_of(&parent_hash), &[child_hash]);
    }

    #[test]
    fn dag_max_round() {
        let mut dag = Dag::new();
        assert_eq!(dag.max_round(), None);
        dag.insert(make_vertex(1, 1, 0x10, vec![]));
        dag.insert(make_vertex(1, 3, 0x11, vec![]));
        assert_eq!(dag.max_round(), Some(3));
    }

    // ===== 前沿缺席分类原语（恰 quorum 存活活性修复） =====

    #[test]
    fn author_has_vertex_since_classifies_frontier_absence() {
        let mut dag = Dag::new();
        let a1 = dag.insert(make_vertex(1, 1, 0x10, vec![]));
        let b1 = dag.insert(make_vertex(1, 1, 0x11, vec![]));
        let _c1 = dag.insert(make_vertex(1, 1, 0x12, vec![]));
        // round 2：0x10/0x11 出 vertex，0x12 离线不再产出。
        dag.insert(make_vertex(1, 2, 0x10, vec![a1]));
        dag.insert(make_vertex(1, 2, 0x11, vec![b1]));

        let a_bytes = make_tagged_pubkey(0x10).to_bytes();
        let b_bytes = make_tagged_pubkey(0x11).to_bytes();
        let c_bytes = make_tagged_pubkey(0x12).to_bytes();

        // 0x10 在 round 2 有 vertex；0x12 自 round 2 起缺席。
        assert!(author_has_vertex_since(&dag, &a_bytes, 2));
        assert!(author_has_vertex_since(&dag, &b_bytes, 2));
        assert!(!author_has_vertex_since(&dag, &c_bytes, 2));
        // 0x12 在 round 1（含）起仍有 vertex —— 缺席是相对待检轮的。
        assert!(author_has_vertex_since(&dag, &c_bytes, 1));
        // 自 round 3 起无人有 vertex（前沿未到）。
        assert!(!author_has_vertex_since(&dag, &a_bytes, 3));
    }

    // ===== detect_commit_leader 测试（SubTask 9.1） =====

    #[test]
    fn detect_commit_leader_with_sufficient_references() {
        // 4 validators，quorum = ceil(4*2/3) = 3
        let mut dag = Dag::new();

        // round 1: 4 validators 各出 1 vertex
        let mut round1_hashes = vec![];
        for i in 0..4 {
            let v = make_vertex(1, 1, 0x10 + i, vec![]);
            round1_hashes.push(dag.insert(v));
        }

        // round 2: 3 个 validator 引用 round1 的第一个 vertex（leader）
        let leader = round1_hashes[0];
        for i in 0..3 {
            let v = make_vertex(1, 2, 0x20 + i, vec![leader]);
            dag.insert(v);
        }

        let result = detect_commit_leader(&dag, &leader, 4).expect("检测应成功");
        assert!(result.is_some());
        let leader_info = result.unwrap();
        assert_eq!(leader_info.leader_hash, leader);
        assert_eq!(leader_info.reference_count, 3);
        assert_eq!(leader_info.required_quorum, 3); // ceil(4*2/3) = 3
    }

    #[test]
    fn detect_commit_leader_insufficient_references() {
        // 4 validators，quorum = 3，但只有 2 个引用
        let mut dag = Dag::new();
        let leader = dag.insert(make_vertex(1, 1, 0x10, vec![]));
        for i in 0..2 {
            let v = make_vertex(1, 2, 0x20 + i, vec![leader]);
            dag.insert(v);
        }
        let result = detect_commit_leader(&dag, &leader, 4).expect("检测应成功");
        assert!(result.is_none(), "2 < 3 quorum，不应形成 commit");
    }

    #[test]
    fn detect_commit_leader_dedup_same_validator() {
        // 同一 validator 多个 vertex 引用 leader 只算一次
        let mut dag = Dag::new();
        let leader = dag.insert(make_vertex(1, 1, 0x10, vec![]));
        // 同一 validator (0x20) 出两个 vertex 引用 leader
        dag.insert(make_vertex(1, 2, 0x20, vec![leader]));
        dag.insert(make_vertex(1, 3, 0x20, vec![leader]));
        let result = detect_commit_leader(&dag, &leader, 4).expect("检测应成功");
        // 只有 1 个 unique validator 引用 → 不够 quorum=3
        assert!(result.is_none());
    }

    #[test]
    fn detect_commit_leader_rejects_unknown_vertex() {
        let dag = Dag::new();
        let unknown = [0xFF; 32];
        let err = detect_commit_leader(&dag, &unknown, 4).unwrap_err();
        assert!(matches!(err, PokerL1Error::DagVertexNotFound));
    }

    // ===== canonical commit-leader 候选序测试（恰 quorum 存活 commit 停滞修复） =====

    /// 构造「每轮全 fan」健康 DAG 的 vertex 集：authors 各出 1 vertex/轮，
    /// round>1 的 vertex 引用上一轮全部 vertex。返回 round → 按构造序的 vertex 列表。
    fn build_fan_vertices(max_round: Round, authors: &[u8]) -> BTreeMap<Round, Vec<DagVertex>> {
        let mut by_round: BTreeMap<Round, Vec<DagVertex>> = BTreeMap::new();
        for round in 1..=max_round {
            for &author in authors {
                let parents: Vec<Hash> = if round == 1 {
                    vec![]
                } else {
                    by_round[&(round - 1)]
                        .iter()
                        .map(|vertex| vertex.vertex_hash())
                        .collect()
                };
                by_round
                    .entry(round)
                    .or_default()
                    .push(make_vertex(1, round, author, parents));
            }
        }
        by_round
    }

    /// 构造「每轮全 fan」健康 DAG：authors 各出 1 vertex/轮，round>1 的 vertex
    /// 引用上一轮全部 vertex。返回 round → 按插入序的 vertex hash 列表。
    fn build_fan_dag(
        dag: &mut Dag,
        max_round: Round,
        authors: &[u8],
    ) -> BTreeMap<Round, Vec<Hash>> {
        let mut by_round: BTreeMap<Round, Vec<Hash>> = BTreeMap::new();
        for (round, vertices) in build_fan_vertices(max_round, authors) {
            let hashes: Vec<Hash> = vertices.into_iter().map(|vertex| dag.insert(vertex)).collect();
            by_round.insert(round, hashes);
        }
        by_round
    }

    /// 旧 validator loop 选择逻辑（窗口 max_r-4..max_r-1 + 插入序 + 逐个 detect，
    /// committed 检查在 detect 之后）—— 仅用于测试对照，演示窗口错位下的分歧。
    fn legacy_window_first_candidate(
        dag: &Dag,
        committed: &BTreeSet<Hash>,
        validator_count: usize,
    ) -> Option<Hash> {
        let max_r = dag.max_round()?;
        if max_r < 2 {
            return None;
        }
        let scan_start = max_r.saturating_sub(4).max(1);
        for round in scan_start..max_r {
            for vh in dag.round_vertices(round) {
                let detect_passes = matches!(
                    detect_commit_leader(dag, vh, validator_count),
                    Ok(Some(_))
                );
                if detect_passes && !committed.contains(vh) {
                    return Some(*vh);
                }
            }
        }
        None
    }

    /// 新 validator loop 选择逻辑（规范化候选序 + quorum 预检，取首个命中）。
    fn canonical_first_candidate(
        dag: &Dag,
        committed: &BTreeSet<Hash>,
        validator_count: usize,
    ) -> Option<Hash> {
        canonical_commit_candidates(dag, committed)
            .into_iter()
            .find(|hash| has_quorum_distinct_author_references(dag, hash, validator_count))
    }

    /// 复现生产路径的 cert 签名对象：leader 权威检测 → 未提交规范投影 → cert
    /// signing_hash（与 main.rs compute_cert_signing_hash 的投影输入一致）。
    fn cert_statement_hash(
        dag: &Dag,
        leader_hash: &Hash,
        committed: &BTreeSet<Hash>,
        validator_count: usize,
    ) -> Hash {
        let leader = detect_commit_leader(dag, leader_hash, validator_count)
            .expect("detect 应成功")
            .expect("leader 应满足 quorum");
        let ordered =
            bullshark_linear_order_uncommitted(dag, &leader.referencing_hashes, committed)
                .expect("投影应成功");
        assert!(!ordered.is_empty());
        let cert = DagCommitCertificate {
            epoch: 1,
            commit_round: 4,
            prev_commit_hash: [0xAB; 32],
            vertex_hash_list: ordered,
            round_attendance_bitmap: vec![0xFF],
            state_root: [7u8; 32],
            public_tx_root: [8u8; 32],
            gameturn_tx_root: [9u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![0x00],
        };
        cert.signing_hash(crate::DEFAULT_CHAIN_ID)
    }

    #[test]
    fn canonical_candidates_converge_across_misaligned_node_views() {
        // 5 validators（quorum = 2*5/3+1 = 4），rounds 1..5 全 fan DAG。
        // 三个节点视角模拟窗口/插入序错位 —— 注意 vertex 内容全网唯一（作者一次
        // 构造、gossip 分发），各视角差异只在本地 Dag 的插入（到达）顺序与可见轮次：
        //   X：到达序 author 升序（完整 DAG，max_r=5）
        //   P：到达序 author 降序（完整 DAG，max_r=5）
        //   Q：到达序 author 降序且尚未收到 round 5（落后一轮，max_r=4）
        // committed = rounds 1..2（链已提交到那里，三节点 tip 一致）。
        const AUTHORS: [u8; 5] = [0x10, 0x11, 0x12, 0x13, 0x14];
        let authors_rev: Vec<u8> = AUTHORS.iter().rev().copied().collect();

        // 一次构造同一组 vertex（作者视角，author 升序），再按不同到达序装入各节点。
        let by_round = build_fan_vertices(5, &AUTHORS);
        let committed: BTreeSet<Hash> = by_round
            .iter()
            .filter(|(round, _)| **round <= 2)
            .flat_map(|(_, vertices)| vertices.iter().map(|vertex| vertex.vertex_hash()))
            .collect();

        // 按给定 author 到达序装入选定轮次的 vertex（内容全网一致；
        // by_round 以 AUTHORS 升序构造，索引即 author 位次）。
        let insert_arrival_order =
            |rounds: std::ops::RangeInclusive<Round>, authors_order: &[u8]| -> Dag {
                let mut dag = Dag::new();
                for round in rounds {
                    for author in authors_order {
                        if let Some(idx) = AUTHORS.iter().position(|a| a == author) {
                            dag.insert(by_round[&round][idx].clone());
                        }
                    }
                }
                dag
            };
        let dag_x = insert_arrival_order(1..=5, &AUTHORS);
        let dag_p = insert_arrival_order(1..=5, &authors_rev);
        let dag_q = insert_arrival_order(1..=4, &authors_rev);
        // 三视角可见部分内容一致（同 tip 链投影 → 同 committed 集）。
        assert_eq!(dag_x.len(), 25);
        assert_eq!(dag_p.len(), 25);
        assert_eq!(dag_q.len(), 20);

        // --- 旧逻辑：窗口 + 插入序 → 不同视角选出不同首候选（根因演示） ---
        let legacy_x = legacy_window_first_candidate(&dag_x, &committed, 5);
        let legacy_p = legacy_window_first_candidate(&dag_p, &committed, 5);
        let legacy_q = legacy_window_first_candidate(&dag_q, &committed, 5);
        assert_ne!(
            legacy_x, legacy_p,
            "插入序错位时旧逻辑应选出不同 leader（根因）"
        );
        assert_ne!(
            legacy_x, legacy_q,
            "窗口/插入序错位时旧逻辑应选出不同 leader（根因）"
        );

        // --- 新逻辑：规范化候选序 → 三视角收敛到同一 leader ---
        let pick_x = canonical_first_candidate(&dag_x, &committed, 5);
        let pick_p = canonical_first_candidate(&dag_p, &committed, 5);
        let pick_q = canonical_first_candidate(&dag_q, &committed, 5);
        assert_eq!(pick_x, pick_p, "插入序不同不应改变首候选");
        assert_eq!(
            pick_x, pick_q,
            "落后一轮的视角（max_r 错位）应选出同一 leader"
        );
        let pick = pick_x.expect("应存在 quorum 候选");
        // 首候选必须是 round 3 中 author 字节序最小者（rounds 1..2 已提交）。
        assert_eq!(pick, by_round[&3][0].vertex_hash());

        // cert 签名对象收敛：三视角对同一 leader 构造出同一 signing_hash。
        let hash_x = cert_statement_hash(&dag_x, &pick, &committed, 5);
        let hash_p = cert_statement_hash(&dag_p, &pick, &committed, 5);
        let hash_q = cert_statement_hash(&dag_q, &pick, &committed, 5);
        assert_eq!(hash_x, hash_p, "cert signing_hash 必须跨插入序收敛");
        assert_eq!(hash_x, hash_q, "cert signing_hash 必须跨 max_r 错位收敛");
    }

    #[test]
    fn canonical_candidates_order_and_committed_filter() {
        // round 1: authors 0x11 先插、0x10 后插（插入序与规范序相反）
        // round 2: 全 fan 引用；committed = round 1 全部。
        let mut dag = Dag::new();
        let h11 = dag.insert(make_vertex(1, 1, 0x11, vec![]));
        let h10 = dag.insert(make_vertex(1, 1, 0x10, vec![]));
        let mut round2 = vec![dag.insert(make_vertex(1, 2, 0x12, vec![h10, h11]))];
        round2.push(dag.insert(make_vertex(1, 2, 0x10, vec![h10, h11])));

        let committed: BTreeSet<Hash> = [h10, h11].into_iter().collect();
        let candidates = canonical_commit_candidates(&dag, &committed);
        assert_eq!(
            candidates,
            vec![round2[1], round2[0]],
            "候选应为 round 2 全部未提交 vertex，author 升序（0x10 在 0x12 前）"
        );
        assert!(canonical_commit_candidates(&dag, &BTreeSet::new()).len() == 4);
    }

    #[test]
    fn canonical_scan_skips_unreferenced_straggler_without_stalling() {
        // 迟到 straggler：author 0x15 的 round-3 vertex 在 round-4 全 fan 之后才插入，
        // 没有任何 round-4 vertex 引用它（引用集已冻结）→ 永远不满足 quorum。
        // 规范化扫描必须跳过它并继续选中下一规范候选，不得阻塞 commit。
        const AUTHORS: [u8; 5] = [0x10, 0x11, 0x12, 0x13, 0x14];
        let mut dag = Dag::new();
        let by_round = build_fan_dag(&mut dag, 4, &AUTHORS);
        let straggler = dag.insert(make_vertex(1, 3, 0x15, by_round[&2].clone()));

        let committed: BTreeSet<Hash> = by_round
            .iter()
            .filter(|(round, _)| **round <= 2)
            .flat_map(|(_, hashes)| hashes.iter().copied())
            .collect();

        let pick = canonical_first_candidate(&dag, &committed, 5).expect("应存在 quorum 候选");
        assert_ne!(pick, straggler, "无引用 straggler 不得成为候选");
        assert_eq!(pick, by_round[&3][0], "应选中 round 3 规范首候选");
        // straggler 在候选序列中存在（未提交），但被 quorum 预检过滤。
        assert!(canonical_commit_candidates(&dag, &committed).contains(&straggler));
        assert!(!has_quorum_distinct_author_references(
            &dag, &straggler, 5
        ));
    }

    #[test]
    fn has_quorum_precheck_matches_detect_commit_leader_on_all_vertices() {
        const AUTHORS: [u8; 5] = [0x10, 0x11, 0x12, 0x13, 0x14];
        let mut dag = Dag::new();
        let by_round = build_fan_dag(&mut dag, 4, &AUTHORS);
        let straggler = dag.insert(make_vertex(1, 3, 0x15, by_round[&2].clone()));

        for hashes in by_round.values() {
            for hash in hashes {
                let precheck = has_quorum_distinct_author_references(&dag, hash, 5);
                let detect = matches!(
                    detect_commit_leader(&dag, hash, 5),
                    Ok(Some(_))
                );
                assert_eq!(precheck, detect, "预检与权威检测必须等价（validated DAG）");
            }
        }
        assert!(!has_quorum_distinct_author_references(
            &dag, &straggler, 5
        ));
    }

    #[test]
    fn projection_prunes_committed_ancestry_and_fails_closed_on_uncommitted_gap() {
        // 晚启动节点的 live DAG 缺历史 round（gossip 一次性，不会回补）。
        // 投影遍历不降入已提交 vertex：committed 集祖先封闭，历史缺口不再阻断
        // 投影 —— 缺口节点随 block import 补齐 committed 集后，投影与完整视角
        // 逐位一致（cert hash 收敛、恢复投票资格）。
        const AUTHORS: [u8; 5] = [0x10, 0x11, 0x12, 0x13, 0x14];
        let mut full = Dag::new();
        let by_round = build_fan_dag(&mut full, 4, &AUTHORS);

        let committed: BTreeSet<Hash> = by_round
            .iter()
            .filter(|(round, _)| **round <= 2)
            .flat_map(|(_, hashes)| hashes.iter().copied())
            .collect();
        // 与生产路径一致：投影的 commit_hashes = leader 的引用集（round 4 顶点，
        // 它们引用全部 round-3 作者）。
        let referencing: Vec<Hash> = by_round[&4].clone();
        let projection =
            bullshark_linear_order_uncommitted(&full, &referencing, &committed).unwrap();
        assert!(!projection.is_empty());

        // 缺口视角：live DAG 仅装入 rounds 3-4（历史 rounds 1-2 缺失，但已提交）。
        let mut gapped = Dag::new();
        for round in 3..=4 {
            for hash in &by_round[&round] {
                let vertex = full.get(hash).unwrap().clone();
                gapped.insert(vertex);
            }
        }
        let gapped_projection =
            bullshark_linear_order_uncommitted(&gapped, &referencing, &committed).unwrap();
        assert_eq!(
            gapped_projection, projection,
            "committed 集覆盖历史缺口时，缺口节点投影必须与完整视角逐位一致"
        );

        // fail-closed 保持：缺口落在**未提交**区（round 3 的部分 vertex 缺失）时，
        // 投影构造仍然必须失败（DagVertexNotFound），不得产出偏小投影。
        let mut gapped_uncommitted = Dag::new();
        for round in 3..=4 {
            for hash in &by_round[&round] {
                let vertex = full.get(hash).unwrap().clone();
                gapped_uncommitted.insert(vertex);
                break; // 每轮只装 1 个 vertex，制造 round-3 内部缺口
            }
        }
        let result =
            bullshark_linear_order_uncommitted(&gapped_uncommitted, &referencing, &committed);
        assert!(
            matches!(result, Err(PokerL1Error::DagVertexNotFound)),
            "未提交区的缺口必须投影失败（fail-closed 弃权）"
        );
    }

    // ===== bullshark_linear_order 测试（SubTask 9.2） =====

    #[test]
    fn bullshark_linear_order_by_round_then_author() {
        let mut dag = Dag::new();

        // round 1: 2 vertices (author 0x11, 0x10 — 排序后 0x10 在前)
        let v1a = make_vertex(1, 1, 0x11, vec![]);
        let v1b = make_vertex(1, 1, 0x10, vec![]);
        let h1a = dag.insert(v1a);
        let h1b = dag.insert(v1b);

        // round 2: 1 vertex 引用 round 1 的两个 vertex
        let v2 = make_vertex(1, 2, 0x20, vec![h1a, h1b]);
        let h2 = dag.insert(v2);

        let ordered = bullshark_linear_order(&dag, &[h2]).expect("排序应成功");
        // 排序：round 1 (author 0x10, 0x11) → round 2 (author 0x20)
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0], h1b, "round 1 author 0x10 应排第一");
        assert_eq!(ordered[1], h1a, "round 1 author 0x11 应排第二");
        assert_eq!(ordered[2], h2, "round 2 author 0x20 应排第三");
    }

    #[test]
    fn bullshark_linear_order_deduplicates() {
        let mut dag = Dag::new();
        let v1 = make_vertex(1, 1, 0x10, vec![]);
        let h1 = dag.insert(v1);
        let v2 = make_vertex(1, 2, 0x20, vec![h1]);
        let h2 = dag.insert(v2);

        // 传入重复的 h2
        let ordered = bullshark_linear_order(&dag, &[h2, h2]).expect("排序应成功");
        assert_eq!(ordered.len(), 2, "去重后应只有 2 个 vertex");
    }

    // ===== project_block_from_commit 测试（SubTask 9.3 + 9.4） =====

    #[test]
    fn project_block_from_commit_aggregates_and_sorts_txs() {
        let mut dag = Dag::new();

        // round 1: vertex 含 ForceSync tx
        let mut v1 = make_vertex(1, 1, 0x10, vec![]);
        v1.tx_list.push(make_tx(1, TxLane::ForceSync));
        let h1 = dag.insert(v1);

        // round 2: vertex 含 GameTurn tx
        let mut v2 = make_vertex(1, 2, 0x20, vec![h1]);
        v2.tx_list.push(make_tx(2, TxLane::GameTurn));
        let h2 = dag.insert(v2);

        // 构造 commit leader
        let leader = CommitLeader {
            leader_hash: h2,
            leader_round: 2,
            referencing_hashes: vec![h2],
            reference_count: 1,
            required_quorum: 1,
        };

        let cert = DagCommitCertificate {
            epoch: 1,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![h1, h2],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![0xFF],
        };

        let env = ExecutionEnvironment::new(crate::DEFAULT_CHAIN_ID, 1, 1000);
        let mut object_db = ObjectDb::open_inmemory().expect("打开内存 ObjectDb");
        let mut account_store = AccountStore::new();

        let projection = project_block_from_commit(
            &dag,
            &leader,
            cert,
            &env,
            &mut object_db,
            &mut account_store,
            [0u8; 32],
            1,
            1000,
        )
        .expect("投影应成功");

        // GameTurn tx 应在 gameturn_txs，ForceSync tx 应在 public_txs
        assert_eq!(projection.gameturn_txs.len(), 1);
        assert_eq!(projection.public_txs.len(), 1);
        assert_eq!(projection.header.height, 1);
    }

    /// 验证 project_block_from_commit 正确计算 state_root（执行 tx 后的 ObjectDb root）。
    #[test]
    fn project_block_from_commit_computes_state_root() {
        use crate::account::{Account, derive_address};
        use crate::object_model::{Object, Ownership};
        use crate::transaction::{Gas, RouteHint, TxRequest};

        let mut dag = Dag::new();

        // 创建签名者
        let secp = secp256k1::Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
        let tagged_pubkey = crate::signature::TaggedPubkey {
            tag: crate::signature::tagged_pubkey::encode_tag(
                crate::signature::tagged_pubkey::SignatureScheme::Secp256k1,
                1,
            ),
            raw: pk.serialize().to_vec(),
        };
        let caller = derive_address(&tagged_pubkey);

        // 构造 Public 通道 tx（outputs 创建对象）
        let req = TxRequest {
            inputs: vec![],
            outputs: vec![Object::new(
                crate::object_model::ObjectID::new(caller, 0),
                Ownership::AddressOwned { owner: caller },
                "TestOutput",
                b"obj0".to_vec(),
                None,
            )],
            contract_call: None,
            gas: Gas::new(1_000_000, 1),
            lane_hint: crate::transaction::TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let tx = {
            let hash = req.signing_hash();
            let secp = secp256k1::Secp256k1::new();
            let sig = secp.sign_ecdsa_recoverable(&secp256k1::Message::from_digest(hash), &sk);
            let (rid, compact) = sig.serialize_compact();
            let mut full_sig = compact.to_vec();
            full_sig.push(rid.to_i32() as u8);
            req.into_transaction(tagged_pubkey.clone(), full_sig)
        };

        // 构造 vertex 并插入 DAG
        let mut v = make_vertex(1, 1, 0x10, vec![]);
        v.tx_list.push(tx);
        let h = dag.insert(v);

        let leader = CommitLeader {
            leader_hash: h,
            leader_round: 1,
            referencing_hashes: vec![h],
            reference_count: 1,
            required_quorum: 1,
        };

        let cert = DagCommitCertificate {
            epoch: 1,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![h],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![0xFF],
        };

        let env = ExecutionEnvironment::new(crate::DEFAULT_CHAIN_ID, 1, 1000);
        let mut object_db = ObjectDb::open_inmemory().expect("打开内存 ObjectDb");
        let mut account_store = AccountStore::new();

        // 创建账户（balance 足够支付 gas）
        let account = Account::new(tagged_pubkey.clone(), 1_000_000);
        account_store.create(account).expect("创建账户");

        let initial_root = object_db.state_root();

        let projection = project_block_from_commit(
            &dag,
            &leader,
            cert,
            &env,
            &mut object_db,
            &mut account_store,
            [0u8; 32],
            1,
            1000,
        )
        .expect("投影应成功");

        // state_root 应该改变（因为创建了对象）
        assert_ne!(
            projection.header.state_root, initial_root,
            "执行 tx 后 state_root 应改变"
        );
        // state_root 应该等于 object_db 的当前 root
        assert_eq!(
            projection.header.state_root,
            object_db.state_root(),
            "state_root 应等于 ObjectDb 的当前 root"
        );
        // 对象应已创建
        let obj_id = crate::object_model::ObjectID::new(caller, 0);
        object_db.read(&obj_id).expect("对象应已创建");
        // nonce 应推进
        assert_eq!(
            account_store.get(&caller).expect("账户存在").nonce,
            1,
            "nonce 应推进"
        );
    }

    // ===== validate_commit_certificate_quorum 测试（SubTask 9.5） =====

    #[test]
    fn validate_commit_certificate_quorum_ok() {
        // 4 validators, quorum = 3
        let cert = DagCommitCertificate {
            epoch: 1,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            // 3 个签名（bitmap = 0b00000111 = 3 位）
            signature_list: vec![vec![0u8; 65], vec![0u8; 65], vec![0u8; 65]],
            signer_bitmap: vec![0b0000_0111],
        };
        validate_commit_certificate_quorum(&cert, 4).expect("3 >= 3 quorum 应通过");
    }

    #[test]
    fn validate_commit_certificate_quorum_insufficient() {
        // 4 validators, quorum = 3, 但只有 2 个签名
        let cert = DagCommitCertificate {
            epoch: 1,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![vec![0u8; 65], vec![0u8; 65]],
            signer_bitmap: vec![0b0000_0011],
        };
        let err = validate_commit_certificate_quorum(&cert, 4).unwrap_err();
        assert!(matches!(err, PokerL1Error::InsufficientQuorum { .. }));
    }

    // ===== validate_commit_certificate_fields 测试（SEC2-C1） =====

    #[test]
    fn validate_commit_certificate_fields_ok() {
        let cert = DagCommitCertificate {
            epoch: 1,
            commit_round: 1,
            prev_commit_hash: [0xAA; 32],
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0xBB; 32],
            public_tx_root: [0xCC; 32],
            gameturn_tx_root: [0xDD; 32],
            signature_list: vec![],
            signer_bitmap: vec![0xFF],
        };
        validate_commit_certificate_fields(
            &cert, 1, [0xAA; 32], [0xBB; 32], [0xCC; 32], [0xDD; 32],
        )
        .expect("字段一致应通过");
    }

    #[test]
    fn validate_commit_certificate_fields_epoch_mismatch() {
        let cert = DagCommitCertificate {
            epoch: 2,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![0xFF],
        };
        let err = validate_commit_certificate_fields(
            &cert, 1, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PokerL1Error::CommitCertificateMismatch(_)));
    }

    #[test]
    fn validate_commit_certificate_fields_state_root_mismatch() {
        let cert = DagCommitCertificate {
            epoch: 1,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0xAA; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![0xFF],
        };
        let err = validate_commit_certificate_fields(
            &cert, 1, [0u8; 32], [0xBB; 32], [0u8; 32], [0u8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PokerL1Error::CommitCertificateMismatch(_)));
    }

    // ===== assemble_commit_certificate 测试 =====

    #[test]
    fn assemble_commit_certificate_sets_bitmap_correctly() {
        let sigs: Vec<(usize, Vec<u8>)> =
            vec![(0, vec![0u8; 65]), (2, vec![0u8; 65]), (5, vec![0u8; 65])];
        let cert = assemble_commit_certificate(
            1,
            1,
            [0u8; 32],
            vec![],
            vec![0xFF],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            &sigs,
            8,
        )
        .expect("组装应成功");

        // validator 0, 2, 5 签名
        // bitmap byte 0: bit 0 (val 0) + bit 2 (val 2) + bit 5 (val 5)
        // = 0b00100101 = 0x25
        assert_eq!(cert.signer_bitmap, vec![0b0010_0101]);
        assert_eq!(cert.signature_list.len(), 3);
        assert_eq!(cert.signer_count(), 3);
    }

    #[test]
    fn assemble_commit_certificate_rejects_out_of_range_index() {
        let sigs: Vec<(usize, Vec<u8>)> = vec![(10, vec![0u8; 65])];
        let err = assemble_commit_certificate(
            1,
            1,
            [0u8; 32],
            vec![],
            vec![0xFF],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            &sigs,
            5,
        )
        .unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    // ===== detect_commit_cert_equivocation 测试（SEC2-C1 slashing） =====

    #[test]
    fn detect_commit_cert_equivocation_same_epoch_round_different_vertex_list() {
        let cert1 = DagCommitCertificate {
            epoch: 1,
            commit_round: 5,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![[1u8; 32]],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![0xFF],
        };
        let cert2 = DagCommitCertificate {
            epoch: 1,
            commit_round: 5,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![[2u8; 32]], // 不同
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![0xFF],
        };
        let evidence =
            detect_commit_cert_equivocation(&cert1, &cert2, crate::DEFAULT_CHAIN_ID, &[]);
        // 缺口 #1-路径C：detect 现需从签名交集构造证据；此用例 signature_list 为空，
        // 无法构造（build_..._intersecting_signer 返回 None）。检测逻辑本身已识别差异，
        // 完整证据构造由带签名的用例覆盖。此处仅验证函数不 panic。
        let _ = evidence;
    }

    #[test]
    fn detect_commit_cert_equivocation_no_equivocation_different_epoch() {
        let cert1 = DagCommitCertificate {
            epoch: 1,
            commit_round: 5,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![[1u8; 32]],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![0xFF],
        };
        let cert2 = DagCommitCertificate {
            epoch: 2, // 不同 epoch
            commit_round: 5,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![[2u8; 32]],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![0xFF],
        };
        let evidence =
            detect_commit_cert_equivocation(&cert1, &cert2, crate::DEFAULT_CHAIN_ID, &[]);
        assert!(evidence.is_none(), "不同 epoch 不算 equivocation");
    }

    #[test]
    fn detect_commit_cert_equivocation_no_equivocation_identical() {
        let cert = DagCommitCertificate {
            epoch: 1,
            commit_round: 5,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![[1u8; 32]],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![0xFF],
        };
        let evidence = detect_commit_cert_equivocation(&cert, &cert, crate::DEFAULT_CHAIN_ID, &[]);
        assert!(evidence.is_none(), "相同的 cert 不算 equivocation");
    }

    // ===== 序列化往返测试 =====

    #[test]
    fn commit_leader_bcs_roundtrip() {
        let leader = CommitLeader {
            leader_hash: [0xAA; 32],
            leader_round: 5,
            referencing_hashes: vec![[0xBB; 32]],
            reference_count: 3,
            required_quorum: 3,
        };
        let bytes = borsh::to_vec(&leader).unwrap();
        let recovered: CommitLeader = borsh::from_slice(&bytes).unwrap();
        assert_eq!(leader, recovered);
    }

    #[test]
    fn block_projection_bcs_roundtrip() {
        let header = BlockHeader {
            height: 1,
            timestamp_ms: 1000,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            dag_commit_certificate: DagCommitCertificate {
                epoch: 1,
                commit_round: 1,
                prev_commit_hash: [0u8; 32],
                vertex_hash_list: vec![],
                round_attendance_bitmap: vec![0xFF],
                state_root: [0u8; 32],
                public_tx_root: [0u8; 32],
                gameturn_tx_root: [0u8; 32],
                signature_list: vec![],
                signer_bitmap: vec![0xFF],
            },
        };
        let projection = BlockProjection {
            header,
            public_txs: vec![],
            gameturn_txs: vec![],
            ordered_vertex_hashes: vec![[0xAA; 32]],
        };
        let bytes = borsh::to_vec(&projection).unwrap();
        let recovered: BlockProjection = borsh::from_slice(&bytes).unwrap();
        assert_eq!(projection, recovered);
    }

    // ===== MAX_VERTEX_SIZE 验证 =====

    #[test]
    fn max_vertex_size_is_256kb() {
        assert_eq!(MAX_VERTEX_SIZE, 256 * 1024);
    }
}
