//! Poker 合约示例与业务逻辑（Task 16）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 16.1**：minimal Rust 合约模板（见 [`examples`] 模块）
//! - **SubTask 16.2 / 16.3**：Game 创建 / 修改合约示例（见 [`examples`] 模块）
//! - **SubTask 16.4**：poker settle 台费逻辑（见 [`settle`] 模块）
//! - **SubTask 16.5**：HandStarted 按 execution_mode 分支（见 [`hand_started`] 模块）
//! - **SubTask 16.6**：force_advance fold/check 规则（见 [`force_advance`] 模块）
//!
//! # 设计说明
//!
//! 由于 BPF 工具链（`bpf-tools` / `rust-bpf-linker`）在开发环境不可用，
//! 本模块采用"纯 Rust 业务逻辑 + 合约源码模板"双层设计：
//!
//! 1. **业务逻辑层**（`settle` / `hand_started` / `force_advance`）：纯 Rust 函数，
//!    可独立单元测试，验证协议层规则的正确性。这些函数对应合约在 VM 内执行
//!    时会调用的核心逻辑，合约 entrypoint 解析输入后调用这些函数。
//!
//! 2. **合约源码模板**（`examples`）：Rust 源码示例，文档化合约如何通过
//!    syscall（`object_read` / `object_write` / `object_create` / `emit_event`）
//!    与链交互。这些模板可用 `solana-bpf-tools` 编译为 `.so` 字节码后部署。
//!
//! 这种分层符合 spec 第 689-693 行的约束："规则由协议层定义，合约可覆盖"——
//! 协议层规则在 `force_advance` 模块实现，合约层可调用或覆盖。

pub mod ack_protocol;
pub mod censor_detection;
pub mod challenge_delta;
pub mod checkpoint_anchor;
pub mod checkpoint_skip;
pub mod delegated_escape;
pub mod examples;
pub mod forfeit;
pub mod force_advance;
pub mod force_checkin;
pub mod force_checkpoint;
pub mod force_settle;
pub mod hand_started;
pub mod request_da;
pub mod revert;
pub mod settle;
pub mod types;

pub use ack_protocol::{
    apply_refuse_ack, apply_request_ack, check_ack_deadline_expired, clear_expired_pending_acks,
    clear_pending_ack, RefuseAckReason, RefuseAckTx, RequestAckTx,
};
pub use censor_detection::{
    compute_replica_set, gossipsub_mesh_size, is_witness_in_replica_set,
    CensorshipWitnessEvidence, FalseWitnessEvidence, DEFAULT_GOSSIPSUB_MESH_SIZE,
    FALSE_WITNESS_SLASH_PERCENTAGE, MIN_CANDIDATE_VALIDATORS_FOR_REPLICA,
};
pub use checkpoint_anchor::{
    apply_checkpoint_anchor, verify_checkpoint_anchor, AckSignature, CheckpointAnchorTx,
    OptOutAckProof,
};
pub use checkpoint_skip::{
    apply_checkpoint_skip, verify_segment_chain, CheckpointSkipTx, SegmentContinuityProof, StateProof,
};
pub use delegated_escape::{
    apply_revoke_delegated_escape, compute_next_credential_nonce,
    consume_delegated_escape_authorization, DelegatedEscapeAuthorization,
    RevokeDelegatedEscapeTx,
};
pub use force_checkin::{
    apply_designated_operator_check_exemption, apply_force_checkin,
    determine_force_checkin_scenario, is_designated_operator_exemption_exhausted,
    should_exempt_current_turn_player, validate_force_checkin_game_id, ForceCheckinInput,
    ForceCheckinOutcome, ForfeitDecision, ForfeitReason, ForceCheckinScenario, RecoveryStage,
    DEFAULT_DESIGNATED_OPERATOR_CHECK_EXEMPTION_LIMIT, DEFAULT_RECOVERY_WINDOW_BLOCKS,
};
pub use force_checkpoint::{
    apply_force_checkpoint, compute_force_checkpoint_deposit, AssignedValidatorFailureProof,
    ForceCheckpointTx, MultiReplicaReceipt, NonInclusionProof, RoundRangeNonInclusionProof,
    VertexInfo,
};
pub use force_advance::{apply_force_advance, force_advance_action, ForceAdvanceError, ForceAdvanceInput};
pub use hand_started::{hand_started_branch, HandStartedError, HandStartedInput};
pub use revert::{
    apply_force_revert, apply_request_revert, ForceRevertTx, RequestRevertTx, RevertOutcome,
    RevertReason,
};
pub use challenge_delta::{
    apply_challenge_delta, compute_challenge_delta_outcome, compute_challenger_deposit,
    compute_challenger_reward, hash_state_delta, validate_challenge_deposit_ratio,
    validate_challenge_reward_ratio, ChallengeDeltaOutcome, ChallengeDeltaTx,
    DEFAULT_CHALLENGE_DEPOSIT_RATIO, DEFAULT_CHALLENGE_REWARD_RATIO, MAX_CHALLENGE_DEPOSIT_RATIO,
    MAX_CHALLENGE_REWARD_RATIO, MIN_CHALLENGE_DEPOSIT_RATIO, MIN_CHALLENGE_REWARD_RATIO,
};
pub use request_da::{apply_request_da, is_request_da_appropriate, RequestDaOutcome, RequestDaTx};
pub use force_settle::{apply_force_settle, is_force_settle_allowed, ForceSettleOutcome, ForceSettleTx};
pub use forfeit::{
    apply_forfeit, apply_forfeit_refund, compute_designated_operator_bond,
    compute_forfeit_deposit, compute_forfeit_distribution, validate_designated_operator_bond,
    validate_forfeit_deposit_ratio, ForfeitDistribution, ForfeitOutcome, RefundOutcome,
    DEFAULT_FORFEIT_DEPOSIT_RATIO, MAX_FORFEIT_DEPOSIT_RATIO, MIN_FORFEIT_DEPOSIT_RATIO,
};
pub use settle::{compute_rake, settle_hand, RakeConfig, SettleError, SettleResult};
pub use types::{
    BettingRound, GameAction, GameContract, GamePhase, HandState, PlayerStack,
};
