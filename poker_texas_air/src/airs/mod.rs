//! Method AIRs — 22 个已启用的专用 AIR。
//!
//! ## 分类
//!
//! - [`lifecycle`] — A 档：6 个表台生命周期方法
//! - [`actions`] — B 档：9 个已启用玩家动作方法
//! - [`funds`] — B+ 档：2 个资金动作方法（addon/rebuy）
//! - [`crypto`] — C 档：5 个密码学协议方法
//!
//! VM 另注册 `fold_with_proof`，该 selector 尚无可信 AIR statement，生产
//! Orchestrator 会在 proof 构造前拒绝。
//!
//! ## 通用模板
//!
//! 所有 AIR 共享 [`common`] 模块的通用列布局与约束工具。

pub mod actions;
pub mod bound;
pub mod common;
pub mod crypto;
pub mod funds;
pub mod lifecycle;

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::FrameworkEval;

use crate::error::TexasAirResult;
use crate::method_kind::MethodKind;
use crate::public_inputs::TexasPublicInputs;

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
/// `verify_method_against` uses this trait to bind the trace to public inputs
/// supplied independently by the verifier. The proof-carried AIR value is never
/// used as the source of truth. This trait alone does not authenticate task
/// provenance or replay full VM dispatch; the receipt path adds those checks in
/// the Orchestrator (with provenance still supplied by an external anchor).
pub trait TexasAir: FrameworkEval + Clone + Sync {
    /// Return the common statement compiled into this AIR instance.
    fn statement(&self) -> AirStatement;

    /// Number of original trace columns expected by this AIR.
    fn trace_num_columns(&self) -> usize;

    /// Validate method-specific AIR constants and the complete trusted row
    /// against canonical pre/post table images supplied by the verifier.
    ///
    /// Most legacy AIRs still use the default no-op. Production betting AIRs
    /// override this hook so a prover cannot pair valid state roots with an
    /// unrelated, self-consistent business row. The Orchestrator additionally
    /// replays full VM dispatch for every enabled method before issuing a receipt.
    fn validate_public_inputs(&self, _public_inputs: &TexasPublicInputs) -> TexasAirResult<()> {
        Ok(())
    }
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

macro_rules! impl_validated_texas_air {
    ($ty:path, $kind:expr, $validator:path) => {
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

            fn validate_public_inputs(
                &self,
                public_inputs: &TexasPublicInputs,
            ) -> TexasAirResult<()> {
                $validator(self, public_inputs)
            }
        }
    };
}

impl_validated_texas_air!(
    lifecycle::create_table::CreateTableAir,
    MethodKind::CreateTable,
    lifecycle::create_table::validate_public_inputs
);
impl_validated_texas_air!(
    lifecycle::join_table::JoinTableAir,
    MethodKind::JoinTable,
    lifecycle::validation::validate_join_table
);
impl_validated_texas_air!(
    lifecycle::leave_table::LeaveTableAir,
    MethodKind::LeaveTable,
    lifecycle::validation::validate_leave_table
);
impl_validated_texas_air!(
    lifecycle::start_hand::StartHandAir,
    MethodKind::StartHand,
    lifecycle::validation::validate_start_hand
);
impl_validated_texas_air!(
    lifecycle::tick::TickAir,
    MethodKind::Tick,
    lifecycle::tick::validate_public_inputs
);
impl_validated_texas_air!(
    lifecycle::reset_for_next_hand::ResetForNextHandAir,
    MethodKind::ResetForNextHand,
    lifecycle::validation::validate_reset_for_next_hand
);
impl_validated_texas_air!(
    actions::fold::FoldAir,
    MethodKind::Fold,
    actions::validation::validate_fold
);
impl_validated_texas_air!(
    actions::check::CheckAir,
    MethodKind::Check,
    actions::validation::validate_check
);
impl_validated_texas_air!(
    actions::call::CallAir,
    MethodKind::Call,
    actions::validation::validate_call
);
impl_validated_texas_air!(
    actions::raise::RaiseAir,
    MethodKind::Raise,
    actions::validation::validate_raise
);
impl_validated_texas_air!(
    actions::bet::BetAir,
    MethodKind::Bet,
    actions::validation::validate_bet
);
impl_validated_texas_air!(
    actions::auto_fold::AutoFoldAir,
    MethodKind::AutoFold,
    actions::validation::validate_auto_fold
);
impl_validated_texas_air!(
    actions::force_fold::ForceFoldAir,
    MethodKind::ForceFold,
    actions::validation::validate_force_fold
);
impl_texas_air!(actions::kick_player::KickPlayerAir, MethodKind::KickPlayer);
impl_validated_texas_air!(
    actions::request_leave_after_hand::RequestLeaveAfterHandAir,
    MethodKind::RequestLeaveAfterHand,
    actions::validation::validate_request_leave_after_hand
);
impl_validated_texas_air!(
    funds::addon::AddonAir,
    MethodKind::Addon,
    funds::validation::validate_addon
);
impl_validated_texas_air!(
    funds::rebuy::RebuyAir,
    MethodKind::Rebuy,
    funds::validation::validate_rebuy
);
impl_texas_air!(
    crypto::join_and_shuffle::JoinAndShuffleAir,
    MethodKind::JoinAndShuffle
);
impl_texas_air!(
    crypto::leave_with_proof::LeaveWithProofAir,
    MethodKind::LeaveWithProof
);
impl_validated_texas_air!(
    crypto::submit_shuffle_v2::SubmitShuffleV2Air,
    MethodKind::SubmitShuffleV2,
    crypto::submit_shuffle_v2::validate_public_inputs
);
impl_texas_air!(
    crypto::submit_player_reveal_tokens::SubmitPlayerRevealTokensAir,
    MethodKind::SubmitPlayerRevealTokens
);
impl_validated_texas_air!(
    crypto::submit_reconstruct_deck::SubmitReconstructDeckAir,
    MethodKind::SubmitReconstructDeck,
    crypto::submit_reconstruct_deck::validate_public_inputs
);
