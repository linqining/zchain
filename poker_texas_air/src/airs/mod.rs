//! Method AIRs — 21 个方法各自专用 AIR。
//!
//! ## 分类
//!
//! - [`lifecycle`] — A 档：6 个表台生命周期方法
//! - [`actions`] — B 档：7 个玩家动作方法
//! - [`funds`] — B+ 档：2 个资金动作方法（addon/rebuy）
//! - [`crypto`] — C 档：5 个密码学协议方法
//!
//! ## 通用模板
//!
//! 所有 AIR 共享 [`common`] 模块的通用列布局与约束工具。

pub mod actions;
pub mod common;
pub mod crypto;
pub mod funds;
pub mod lifecycle;

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::FrameworkEval;

use crate::method_kind::MethodKind;

/// Verifier-trusted statement shared by every Texas Poker AIR.
///
/// This value is deliberately separate from the proof object.  A verifier must
/// reconstruct it from the L1 task/state it trusts; accepting these fields from
/// the prover would let the prover choose a different transition statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AirStatement {
    /// Method whose transition is being proved.
    pub kind: MethodKind,
    /// Domain-separated 124-bit projection of the full pre-state commitment.
    pub pre_state_root: [M31; 4],
    /// Domain-separated 124-bit projection of the full post-state commitment.
    pub post_state_root: [M31; 4],
    /// Table identifier.
    pub table_id: u64,
    /// Hand sequence number.
    pub hand_id: u32,
    /// Call sequence number.
    pub call_seq: u32,
    /// Version before execution.
    pub pre_version: u64,
    /// Version after execution.
    pub post_version: u64,
}

/// AIRs that expose a verifier-trusted Texas Poker statement.
///
/// `verify_method` uses this trait to bind the trace to public inputs supplied
/// independently by the verifier.  The proof-carried AIR value is never used as
/// the source of truth.
pub trait TexasAir: FrameworkEval + Clone + Sync {
    /// Return the common statement compiled into this AIR instance.
    fn statement(&self) -> AirStatement;

    /// Number of original trace columns expected by this AIR.
    fn trace_num_columns(&self) -> usize;
}

macro_rules! impl_texas_air {
    ($ty:path, $kind:expr) => {
        impl TexasAir for $ty {
            fn statement(&self) -> AirStatement {
                AirStatement {
                    kind: $kind,
                    pre_state_root: self.pre_state_root,
                    post_state_root: self.post_state_root,
                    table_id: self.table_id,
                    hand_id: self.hand_id,
                    call_seq: self.call_seq,
                    pre_version: self.pre_version,
                    post_version: self.post_version,
                }
            }

            fn trace_num_columns(&self) -> usize {
                Self::num_columns()
            }
        }
    };
}

impl_texas_air!(
    lifecycle::create_table::CreateTableAir,
    MethodKind::CreateTable
);
impl_texas_air!(lifecycle::join_table::JoinTableAir, MethodKind::JoinTable);
impl_texas_air!(
    lifecycle::leave_table::LeaveTableAir,
    MethodKind::LeaveTable
);
impl_texas_air!(lifecycle::start_hand::StartHandAir, MethodKind::StartHand);
impl_texas_air!(lifecycle::tick::TickAir, MethodKind::Tick);
impl_texas_air!(
    lifecycle::reset_for_next_hand::ResetForNextHandAir,
    MethodKind::ResetForNextHand
);
impl_texas_air!(actions::fold::FoldAir, MethodKind::Fold);
impl_texas_air!(actions::check::CheckAir, MethodKind::Check);
impl_texas_air!(actions::call::CallAir, MethodKind::Call);
impl_texas_air!(actions::raise::RaiseAir, MethodKind::Raise);
impl_texas_air!(actions::bet::BetAir, MethodKind::Bet);
impl_texas_air!(actions::auto_fold::AutoFoldAir, MethodKind::AutoFold);
impl_texas_air!(actions::force_fold::ForceFoldAir, MethodKind::ForceFold);
impl_texas_air!(actions::kick_player::KickPlayerAir, MethodKind::KickPlayer);
impl_texas_air!(funds::addon::AddonAir, MethodKind::Addon);
impl_texas_air!(funds::rebuy::RebuyAir, MethodKind::Rebuy);
impl_texas_air!(
    crypto::join_and_shuffle::JoinAndShuffleAir,
    MethodKind::JoinAndShuffle
);
impl_texas_air!(
    crypto::leave_with_proof::LeaveWithProofAir,
    MethodKind::LeaveWithProof
);
impl_texas_air!(
    crypto::submit_shuffle_v2::SubmitShuffleV2Air,
    MethodKind::SubmitShuffleV2
);
impl_texas_air!(
    crypto::submit_player_reveal_tokens::SubmitPlayerRevealTokensAir,
    MethodKind::SubmitPlayerRevealTokens
);
impl_texas_air!(
    crypto::submit_reconstruct_deck::SubmitReconstructDeckAir,
    MethodKind::SubmitReconstructDeck
);
