//! Restart-safe proving-service package for one Texas transition proof set.
//!
//! The package stores the complete canonical task beside the bounded Stwo
//! method archive and, for composite methods, the required four-stage component
//! archive. Verification never trusts proof-carried AIR metadata: it replays the
//! task through [`poker_texas_air::orchestrator::Orchestrator`] and reconstructs
//! every trusted statement before decoding the proofs.

use borsh::{BorshDeserialize, BorshSerialize};
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::types::TexasPokerTable;
use poker_texas_air::airs::composition::{
    ArchivedCompositionProofBundle, supports_composite_proof,
};
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::proof_archive::ArchivedMethodProof;
use poker_texas_air::prove_task::{MethodInput, ProveTask};

use crate::repository::StoredProofMetadata;
use crate::{ServiceError, ServiceResult};

/// Current proving-service proof package schema.
pub const SERVICE_PROOF_PACKAGE_VERSION: u8 = 3;
const LEGACY_SERVICE_PROOF_PACKAGE_VERSION: u8 = 2;
/// Maximum accepted task-plus-proof package size.
pub const MAX_SERVICE_PROOF_PACKAGE_BYTES: usize = 128 * 1024 * 1024;

/// Exact transient-input layout persisted by service proof package v2.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
enum LegacyMethodInputV2 {
    SeatOnly {
        seat_index: u8,
    },
    Raise {
        seat_index: u8,
        total_bet: u64,
    },
    Bet {
        seat_index: u8,
        amount: u64,
    },
    Funds {
        seat_index: u8,
        amount: u64,
    },
    Kick {
        seat_index: u8,
        reason: u8,
    },
    Join {
        player: [u8; 20],
        buy_in: u64,
    },
    CreateTable {
        name: String,
        max_players: u8,
        small_blind: u64,
        big_blind: u64,
    },
    JoinAndShuffle {
        seat_index: u8,
        player: [u8; 20],
        buy_in: u64,
        raw_args: Vec<u8>,
    },
    LeaveWithProof {
        seat_index: u8,
        raw_args: Vec<u8>,
    },
    SubmitShuffleV2 {
        seat_index: u8,
        raw_args: Vec<u8>,
    },
    SubmitPlayerRevealTokens {
        seat_index: u8,
        raw_args: Vec<u8>,
    },
    SubmitReconstructDeck {
        seat_index: u8,
        raw_args: Vec<u8>,
    },
    RequestLeaveAfterHand {
        seat_index: u8,
    },
    FoldWithProof {
        seat_index: u8,
        raw_args: Vec<u8>,
    },
    Empty,
}

impl LegacyMethodInputV2 {
    fn matches_current(&self, current: &MethodInput, canonical_args: &[u8]) -> bool {
        match (self, current) {
            (Self::SeatOnly { seat_index: a }, MethodInput::SeatOnly { seat_index: b }) => a == b,
            (
                Self::Raise {
                    seat_index: a,
                    total_bet: x,
                },
                MethodInput::Raise {
                    seat_index: b,
                    total_bet: y,
                },
            ) => a == b && x == y,
            (
                Self::Bet {
                    seat_index: a,
                    amount: x,
                },
                MethodInput::Bet {
                    seat_index: b,
                    amount: y,
                },
            )
            | (
                Self::Funds {
                    seat_index: a,
                    amount: x,
                },
                MethodInput::Funds {
                    seat_index: b,
                    amount: y,
                },
            ) => a == b && x == y,
            (
                Self::Kick {
                    seat_index: a,
                    reason: x,
                },
                MethodInput::Kick {
                    seat_index: b,
                    reason: y,
                },
            ) => a == b && x == y,
            (
                Self::Join {
                    player: a,
                    buy_in: x,
                },
                MethodInput::Join {
                    player: b,
                    buy_in: y,
                },
            ) => a == b && x == y,
            (
                Self::CreateTable {
                    name: a,
                    max_players: b,
                    small_blind: c,
                    big_blind: d,
                },
                MethodInput::CreateTable {
                    name: w,
                    max_players: x,
                    small_blind: y,
                    big_blind: z,
                },
            ) => a == w && b == x && c == y && d == z,
            (
                Self::JoinAndShuffle {
                    seat_index: a,
                    player: b,
                    buy_in: c,
                    raw_args,
                },
                MethodInput::JoinAndShuffle {
                    seat_index: x,
                    player: y,
                    buy_in: z,
                },
            ) => a == x && b == y && c == z && raw_args == canonical_args,
            (
                Self::LeaveWithProof {
                    seat_index: a,
                    raw_args,
                },
                MethodInput::LeaveWithProof { seat_index: b },
            )
            | (
                Self::SubmitShuffleV2 {
                    seat_index: a,
                    raw_args,
                },
                MethodInput::SubmitShuffleV2 { seat_index: b },
            )
            | (
                Self::SubmitPlayerRevealTokens {
                    seat_index: a,
                    raw_args,
                },
                MethodInput::SubmitPlayerRevealTokens { seat_index: b },
            )
            | (
                Self::SubmitReconstructDeck {
                    seat_index: a,
                    raw_args,
                },
                MethodInput::SubmitReconstructDeck { seat_index: b },
            )
            | (
                Self::FoldWithProof {
                    seat_index: a,
                    raw_args,
                },
                MethodInput::FoldWithProof { seat_index: b },
            ) => a == b && raw_args == canonical_args,
            (
                Self::RequestLeaveAfterHand { seat_index: a },
                MethodInput::RequestLeaveAfterHand { seat_index: b },
            ) => a == b,
            (Self::Empty, MethodInput::Empty) => true,
            _ => false,
        }
    }
}

/// Durable package required to reverify one completed proving job.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ServiceProofPackage {
    version: u8,
    task: ProveTask,
    archive: ArchivedMethodProof,
    composition_archive: Option<ArchivedCompositionProofBundle>,
}

/// Exact v2 durable layout retained only for fail-closed migration.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyProveTaskV2 {
    method_kind: MethodKind,
    method_input: LegacyMethodInputV2,
    context: DispatchContext,
    selector: [u8; 32],
    raw_args: Vec<u8>,
    pre_table: TexasPokerTable,
    post_table: TexasPokerTable,
    table_id: u64,
    hand_id: u32,
    call_seq: u32,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyServiceProofPackageV2 {
    version: u8,
    task: LegacyProveTaskV2,
    archive: ArchivedMethodProof,
    composition_archive: Option<ArchivedCompositionProofBundle>,
}

impl LegacyProveTaskV2 {
    fn into_current(self) -> ServiceResult<ProveTask> {
        if self.selector != self.method_kind.selector() {
            return Err(ServiceError::Prover(
                "legacy proof package task selector/method mismatch".into(),
            ));
        }
        let (method_tag, canonical_args) =
            poker_l1::vm::contracts::texas_poker::dispatch::canonical_command_parts(
                &self.selector,
                &self.raw_args,
            )
            .map_err(|error| {
                ServiceError::Prover(format!(
                    "legacy proof package canonical command migration: {error}"
                ))
            })?;
        if method_tag != self.method_kind as u8 {
            return Err(ServiceError::Prover(
                "legacy proof package task tag mismatch".into(),
            ));
        }
        let derived_input = poker_l1::vm::contracts::texas_poker::dispatch::derive_method_input(
            method_tag,
            &canonical_args,
        )
        .map_err(|error| {
            ServiceError::Prover(format!(
                "legacy proof package typed input migration: {error}"
            ))
        })?;
        if !self
            .method_input
            .matches_current(&derived_input, &canonical_args)
        {
            return Err(ServiceError::Prover(
                "legacy proof package carries mismatched duplicate method input".into(),
            ));
        }
        Ok(ProveTask::new(
            self.method_kind,
            self.context,
            canonical_args,
            self.pre_table,
            self.post_table,
            self.table_id,
            self.hand_id,
            self.call_seq,
        ))
    }
}

impl ServiceProofPackage {
    /// Construct a package from the exact replayed task and verified proof archive.
    ///
    /// # Errors
    ///
    /// Returns an error when archive validation fails.
    pub fn new(
        task: ProveTask,
        archive: ArchivedMethodProof,
        composition_archive: Option<ArchivedCompositionProofBundle>,
    ) -> ServiceResult<Self> {
        let package = Self {
            version: SERVICE_PROOF_PACKAGE_VERSION,
            task,
            archive,
            composition_archive,
        };
        package.validate()?;
        Ok(package)
    }

    /// Strictly decode one complete Borsh package.
    ///
    /// # Errors
    ///
    /// Returns an error for empty/oversized input, trailing bytes, an unsupported
    /// version, or an invalid embedded archive.
    pub fn from_bytes(bytes: &[u8]) -> ServiceResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_SERVICE_PROOF_PACKAGE_BYTES {
            return Err(ServiceError::Prover(
                "invalid proving-service proof package length".into(),
            ));
        }
        let package = match bytes.first().copied() {
            Some(SERVICE_PROOF_PACKAGE_VERSION) => {
                Self::try_from_slice(bytes).map_err(|error| {
                    ServiceError::Prover(format!("decode proving-service proof package: {error}"))
                })?
            }
            Some(LEGACY_SERVICE_PROOF_PACKAGE_VERSION) => {
                let legacy =
                    LegacyServiceProofPackageV2::try_from_slice(bytes).map_err(|error| {
                        ServiceError::Prover(format!(
                            "decode legacy proving-service proof package v2: {error}"
                        ))
                    })?;
                if legacy.version != LEGACY_SERVICE_PROOF_PACKAGE_VERSION {
                    return Err(ServiceError::Prover(
                        "legacy proving-service package version mismatch".into(),
                    ));
                }
                Self {
                    version: SERVICE_PROOF_PACKAGE_VERSION,
                    task: legacy.task.into_current()?,
                    archive: legacy.archive,
                    composition_archive: legacy.composition_archive,
                }
            }
            Some(version) => {
                return Err(ServiceError::Prover(format!(
                    "unsupported proving-service proof package version {version}"
                )));
            }
            None => unreachable!("empty package rejected above"),
        };
        package.validate()?;
        Ok(package)
    }

    /// Encode this package as canonical Borsh bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or encoding fails, or the encoded value
    /// exceeds the service package limit.
    pub fn to_bytes(&self) -> ServiceResult<Vec<u8>> {
        self.validate()?;
        let bytes = borsh::to_vec(self).map_err(|error| {
            ServiceError::Prover(format!("encode proving-service proof package: {error}"))
        })?;
        if bytes.len() > MAX_SERVICE_PROOF_PACKAGE_BYTES {
            return Err(ServiceError::Prover(
                "proving-service proof package exceeds size limit".into(),
            ));
        }
        Ok(bytes)
    }

    /// Exact canonical task that defines the proof statement.
    #[must_use]
    pub const fn task(&self) -> &ProveTask {
        &self.task
    }

    /// Bounded Stwo method-proof archive.
    #[must_use]
    pub const fn archive(&self) -> &ArchivedMethodProof {
        &self.archive
    }

    /// Optional four-stage component-proof bundle required by composite methods.
    #[must_use]
    pub const fn composition_archive(&self) -> Option<&ArchivedCompositionProofBundle> {
        self.composition_archive.as_ref()
    }

    /// Consume the package into its task and archive.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ProveTask,
        ArchivedMethodProof,
        Option<ArchivedCompositionProofBundle>,
    ) {
        (self.task, self.archive, self.composition_archive)
    }

    fn validate(&self) -> ServiceResult<()> {
        if self.version != SERVICE_PROOF_PACKAGE_VERSION {
            return Err(ServiceError::Prover(format!(
                "unsupported proving-service proof package version {}",
                self.version
            )));
        }
        self.archive
            .validate()
            .map_err(|error| ServiceError::Prover(error.to_string()))?;
        if self.task.method_kind != self.archive.method_kind() {
            return Err(ServiceError::Prover(
                "proof package task/archive method mismatch".into(),
            ));
        }
        match (
            supports_composite_proof(self.task.method_kind),
            self.composition_archive.as_ref(),
        ) {
            (true, Some(bundle)) => bundle
                .validate()
                .map_err(|error| ServiceError::Prover(error.to_string()))?,
            (true, None) => {
                return Err(ServiceError::Prover(
                    "composite proof package is missing its four-stage STARK proof bundle".into(),
                ));
            }
            (false, None) => {}
            (false, Some(_)) => {
                return Err(ServiceError::Prover(
                    "non-composite proof package carries an unexpected component bundle".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Reconstruct the compact journal metadata for a canonical proof task.
pub(crate) fn stored_proof_metadata(task: &ProveTask) -> ServiceResult<StoredProofMetadata> {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};

    let task_bytes = borsh::to_vec(task)
        .map_err(|error| ServiceError::Prover(format!("encode proved task: {error}")))?;
    let pre_state_root = poker_texas_air::state_root::compute_state_root(&task.pre_table)
        .map_err(|error| ServiceError::Prover(error.to_string()))?;
    let post_state_root = poker_texas_air::state_root::compute_state_root(&task.post_table)
        .map_err(|error| ServiceError::Prover(error.to_string()))?;
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"zchain.proving_service.task.v2");
    hasher.update(&task_bytes);
    let mut task_digest = [0u8; 32];
    hasher
        .finalize_variable(&mut task_digest)
        .expect("32 <= 64");
    Ok(StoredProofMetadata {
        task_digest,
        pre_state_root: pre_state_root.field().to_bytes_be(),
        post_state_root: post_state_root.field().to_bytes_be(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_l1::object_model::ObjectID;
    use poker_l1::signature::TaggedPubkey;
    use poker_l1::vm::contracts::texas_poker::dispatch::{self as texas_dispatch, SeatIndexArgs};
    use poker_l1::vm::contracts::texas_poker::types::SeatStatus;

    fn table(name: &str) -> TexasPokerTable {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0x55; 20], 7),
            name.into(),
            [0xAA; 20],
            6,
            50,
            100,
        );
        table.seats[2].player = [0x11; 20];
        table.seats[2].set_status(SeatStatus::Active);
        table
    }

    fn context() -> DispatchContext {
        DispatchContext {
            caller: [0x11; 20],
            caller_pubkey: TaggedPubkey {
                tag: 0,
                raw: vec![0x22; 32],
            },
            chain_id: 1,
            block_height: 2,
            block_timestamp: 3,
        }
    }

    fn legacy_fold_task() -> LegacyProveTaskV2 {
        LegacyProveTaskV2 {
            method_kind: MethodKind::Fold,
            method_input: LegacyMethodInputV2::SeatOnly { seat_index: 2 },
            context: context(),
            selector: texas_dispatch::selectors::fold(),
            raw_args: borsh::to_vec(&SeatIndexArgs { seat_index: 2 }).unwrap(),
            pre_table: table("pre"),
            post_table: table("post"),
            table_id: 7,
            hand_id: 8,
            call_seq: 9,
        }
    }

    #[test]
    fn legacy_v2_task_migrates_to_single_canonical_command() {
        let current = legacy_fold_task().into_current().unwrap();
        assert_eq!(current.method_kind, MethodKind::Fold);
        assert_eq!(current.selector(), texas_dispatch::selectors::fold());
        assert_eq!(
            current.method_input().unwrap(),
            MethodInput::SeatOnly { seat_index: 2 }
        );
        assert_eq!(
            current.canonical_command_bytes().unwrap(),
            borsh::to_vec(&(MethodKind::Fold as u8, current.raw_args.clone())).unwrap()
        );
    }

    #[test]
    fn legacy_v2_task_rejects_mismatched_duplicate_input() {
        let mut legacy = legacy_fold_task();
        legacy.method_input = LegacyMethodInputV2::SeatOnly { seat_index: 3 };
        assert!(legacy.into_current().is_err());
    }
}
