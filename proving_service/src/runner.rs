//! `HandRunner` —— 驱动真实合约 dispatch + host proof verification 的覆盖片段。
//!
//! 复用 `poker_l1` 的 dispatch 产生 pre/post 快照（状态转移正确性来自合约），
//! 每步把 `ProveTask` 喂给 `Orchestrator`（prove + 立即 verify），最后校验整条
//! 未外部锚定的本地 state_root 连续性，并确认 descriptor-only 聚合保持 fail-closed。
//!
//! ## 当前编排的序列
//!
//! 为聚焦"证明管线"（而非 Mental Poker 密码学），runner 编排一条由**简单参数
//! 方法**组成的真实牌局片段，全部经 dispatch 真实执行：
//!
//! ```text
//! create_table
//!   → join_table × N
//!   → addon（某玩家）
//!   → rebuy（某玩家）
//!   → leave_table（某玩家）
//! ```
//!
//! 覆盖 lifecycle + funds 的 6 步方法片段，每步产出真实 ProveTask 并证明。
//! 这不是完整一手牌：没有 start_hand、下注轮结束、settlement 或可信递归聚合。
//! `kick_player` 在 WAITING 下可能内部触发 reset/version 多步变化，也不纳入此单步
//! AIR 成功路径。
//!
//! ## 关于完整 shuffle/reveal/reconstruct 牌局
//!
//! Mental Poker 的 crypto 阶段（`join_and_shuffle`/`submit_shuffle_v2`/
//! `submit_player_reveal_tokens`/`submit_reconstruct_deck`/`leave_with_proof`）
//! 需要构造合法的 BLS/ElGamal 密文与 ZK proof（`ElGamalCiphertext`/`DLEqProof`/
//! `ZKShuffleProof`）。即便合约 `config` 默认 skip ZK 验证，仍需结构合法的密文
//! 数据。Orchestrator 已为这 5 个方法接线 trace 构造（见
//! `poker_texas_air::orchestrator`），待 crypto 数据构造器就绪后即可纳入 runner。

use blstrs::G1Projective;
use borsh::BorshSerialize;
use group::Group;

use poker_l1::Address;
use poker_l1::object_model::ObjectID;
use poker_l1::vm::contracts::texas_poker::dispatch::{
    AddonArgs, CreateTableArgs, JoinTableArgs, LeaveTableArgs, RebuyArgs, selectors,
};
use poker_l1::vm::contracts::texas_poker::types::{TableConfig, TexasPokerTable};
use poker_protocol::crypto::types::ECPoint;

use crate::contracts::TexasPokerPlugin;
use crate::plugin::{ContractPlugin, PluginError};
use crate::{ServiceError, ServiceResult};

/// Runner 覆盖片段的产出摘要。
#[derive(Debug, Clone)]
pub struct HandReport {
    /// 每步的方法名 + 是否 prove 成功。
    pub steps: Vec<(&'static str, bool)>,
    /// state_root 链校验是否通过。
    pub chain_ok: bool,
    /// descriptor-only 聚合入口是否意外成功（当前预期为 `Some(false)`）。
    pub aggregate_ok: Option<bool>,
    /// 最终统计。
    pub stats: crate::PluginStats,
}

/// HandRunner：驱动 texas_poker 插件跑通预设 VM→host-verifier 覆盖片段。
pub struct HandRunner {
    /// 玩家地址（2 个）。
    players: [Address; 2],
    /// 创建者地址。
    creator: Address,
}

impl Default for HandRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl HandRunner {
    /// 构造 runner（2 个测试玩家）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            players: [[0x10; 20], [0x20; 20]],
            creator: [0xAA; 20],
        }
    }

    /// 跑通预设 VM→host-verifier 覆盖片段：返回 (plugin, report)。
    ///
    /// plugin 保留最终状态，可供进一步观察；生产聚合入口当前应保持 fail-closed。
    ///
    /// # Errors
    ///
    /// 任一 dispatch 或 prove 失败则返回错误。
    pub fn run(self) -> ServiceResult<(TexasPokerPlugin, HandReport)> {
        // ===== Step 0: create_table（创建新桌台，初始化 plugin）=====
        let placeholder = make_placeholder_table(self.creator);
        let mut plugin = TexasPokerPlugin::new(placeholder);
        let mut steps: Vec<(&'static str, bool)> = Vec::new();

        let create_args = CreateTableArgs {
            name: "runner_table".into(),
            max_players: 6,
            small_blind: 50,
            big_blind: 100,
        };
        dispatch_and_prove(
            &mut plugin,
            self.creator,
            &selectors::create_table(),
            &create_args,
            "create_table",
            &mut steps,
        )?;

        // ===== Step 1-2: join_table × 2 =====
        for (idx, &player) in self.players.iter().enumerate() {
            let join_args = JoinTableArgs {
                player,
                buy_in: 1_000,
                pk: dummy_pk(idx as u8),
            };
            dispatch_and_prove(
                &mut plugin,
                player,
                &selectors::join_table(),
                &join_args,
                "join_table",
                &mut steps,
            )?;
        }

        // ===== Step 3: addon（玩家 0 加 200 到 pending）=====
        let addon_args = AddonArgs {
            seat_index: 0,
            amount: 200,
        };
        dispatch_and_prove(
            &mut plugin,
            self.players[0],
            &selectors::addon(),
            &addon_args,
            "addon",
            &mut steps,
        )?;

        // ===== Step 4: rebuy（玩家 1 立即加 300 到 stack）=====
        let rebuy_args = RebuyArgs {
            seat_index: 1,
            amount: 300,
        };
        dispatch_and_prove(
            &mut plugin,
            self.players[1],
            &selectors::rebuy(),
            &rebuy_args,
            "rebuy",
            &mut steps,
        )?;

        // ===== Step 5: leave_table（玩家 0 离场，WAITING 态允许）=====
        let leave_args = LeaveTableArgs { seat_index: 0 };
        dispatch_and_prove(
            &mut plugin,
            self.players[0],
            &selectors::leave_table(),
            &leave_args,
            "leave_table",
            &mut steps,
        )?;

        // ===== 校验 state_root 链 + 尝试聚合 =====
        let chain_ok = plugin.verify_chain().is_ok();
        let aggregate_ok = if plugin.proven().len() >= 2 {
            match plugin.aggregate() {
                Ok(()) => {
                    return Err(ServiceError::Runner(
                        "untrusted descriptor aggregator unexpectedly succeeded".into(),
                    ));
                }
                Err(PluginError::UntrustedAggregationDisabled) => Some(false),
                Err(error) => {
                    return Err(ServiceError::Runner(format!(
                        "descriptor aggregator returned an unexpected error: {error}"
                    )));
                }
            }
        } else {
            None
        };

        let stats = plugin.stats();
        Ok((
            plugin,
            HandReport {
                steps,
                chain_ok,
                aggregate_ok,
                stats,
            },
        ))
    }
}

// ===== 内部辅助 =====

/// 执行一步 dispatch + （若有 prove_task）prove，记录到 steps。
fn dispatch_and_prove<A: BorshSerialize>(
    plugin: &mut TexasPokerPlugin,
    caller: Address,
    selector: &[u8; 32],
    args: &A,
    name: &'static str,
    steps: &mut Vec<(&'static str, bool)>,
) -> ServiceResult<()> {
    let args_bytes = borsh::to_vec(args)
        .map_err(|e| ServiceError::Runner(format!("borsh encode {name}: {e}")))?;
    let outcome = plugin
        .dispatch(caller, selector, &args_bytes)
        .map_err(|error| ServiceError::Runner(format!("{name} dispatch: {error}")))?;
    if let Some(task) = &outcome.prove_task {
        plugin
            .prove_task(task)
            .map_err(|error| ServiceError::Runner(format!("{name} prove/verify: {error}")))?;
        steps.push((name, true));
    } else {
        // 无 prove_task（如 tick）—— 记录为成功但不计 prove
        steps.push((name, true));
    }
    Ok(())
}

/// 构造占位桌台（create_table 会在其上覆写真实配置）。
fn make_placeholder_table(creator: Address) -> TexasPokerTable {
    let id = ObjectID::new([0xFF; 20], 0);
    let mut table = TexasPokerTable::new(id, "placeholder".into(), creator, 6, 50, 100);
    // 默认 config（skip 所有 ZK）便于流程跑通
    table.config = TableConfig::default();
    table
}

/// 构造测试用占位公钥（join_table 用；skip 模式下不参与真实 ZK 验证）。
///
/// `idx` 为玩家序号；用 generator 的倍数产生**互不相同**的点，避免触发
/// "pk already registered"。
fn dummy_pk(idx: u8) -> ECPoint {
    let g = G1Projective::generator();
    let pk = match idx {
        0 => g,
        _ => {
            // g * (idx + 1) —— 通过反复自加实现（避免构造 Scalar）
            let mut p = g;
            for _ in 0..idx {
                p += g;
            }
            p
        }
    };
    ECPoint(pk)
}
