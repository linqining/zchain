//! Transferable two-part proof packages for poker cryptographic calls.
//!
//! A package contains both halves required to accept a crypto-bearing Texas
//! Poker transition:
//!
//! 1. the Stwo method proof for the state transition and AIR digest columns;
//! 2. the complete canonical poker-precompile request, including the
//!    Bayer--Groth shuffle or Reconstruction V3 slot-OR proof.
//!
//! The package does **not** carry a trusted AIR or trusted public inputs.
//! Verification requires the independently authenticated [`ProveTask`], replays
//! its VM dispatch, rebuilds the canonical request/AIR/public inputs, verifies
//! the native crypto proof, and finally verifies the Stwo proof. This prevents
//! either half from being detached, substituted, or replayed in another call
//! scope.

use bincode::Options;
use poker_protocol::precompile::{
    build_bls12381_reconstruction_v3_request, build_bls12381_shuffle_request,
};
use poker_protocol::precompile_abi::{
    RECONSTRUCTION_V3_ABI_VERSION, ReconstructionV3VerifyRequest, SHUFFLE_ABI_VERSION,
    ShuffleVerifyRequest, TranscriptId,
};
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;

use crate::airs::crypto::submit_reconstruct_deck::{
    SubmitReconstructDeckAir, SubmitReconstructDeckInput, SubmitReconstructDeckRow,
};
use crate::airs::crypto::submit_shuffle_v2::{
    SubmitShuffleV2Air, SubmitShuffleV2Input, SubmitShuffleV2Row,
};
use crate::deck_commitment::deck_commitment;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::orchestrator::validate_full_dispatch_task;
use crate::precompile_binding::{
    PokerPrecompileId, PrecompileCallBinding, precompile_call_context,
};
use crate::proof_archive::ArchivedMethodProof;
use crate::prove_task::{MethodInput, ProveTask};
use crate::prover::{MethodProof, prove_method};
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::{StateRoot, state_root_to_air_limbs, table_state_preimage};
use crate::trace_gen::generic_trace::{MIN_LOG_SIZE, gen_method_trace};
use crate::verified_chain::{VerificationReceipt, verify_method_against_and_issue_receipt};

/// Wire-format magic for a stage-3 dual proof package.
pub const DUAL_PROOF_MAGIC: [u8; 8] = *b"ZPDUAL03";
/// Current dual-proof envelope version.
pub const DUAL_PROOF_VERSION: u8 = 1;
/// Maximum accepted serialized Stwo proof size.
pub const MAX_STARK_PROOF_BYTES: usize = 64 * 1024 * 1024;
/// Maximum accepted canonical poker-precompile request size.
pub const MAX_CRYPTO_REQUEST_BYTES: usize = 4 * 1024 * 1024;

const HEADER_LEN: usize = 8 + 4 + 4 + 4;

/// Untrusted transport envelope containing both proof halves.
///
/// Fields are private so locally constructed values use the same invariants as
/// decoded wire data. None of these fields is trusted during verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualProofBundle {
    version: u8,
    method_kind: MethodKind,
    precompile_id: PokerPrecompileId,
    abi_version: u8,
    stark_proof_bytes: Vec<u8>,
    crypto_request_bytes: Vec<u8>,
}

impl DualProofBundle {
    /// Envelope version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Method selector claimed by the untrusted envelope.
    #[must_use]
    pub const fn method_kind(&self) -> MethodKind {
        self.method_kind
    }

    /// Poker precompile claimed by the untrusted envelope.
    #[must_use]
    pub const fn precompile_id(&self) -> PokerPrecompileId {
        self.precompile_id
    }

    /// Canonical poker request ABI version claimed by the envelope.
    #[must_use]
    pub const fn abi_version(&self) -> u8 {
        self.abi_version
    }

    /// Serialized Stwo proof bytes.
    #[must_use]
    pub fn stark_proof_bytes(&self) -> &[u8] {
        &self.stark_proof_bytes
    }

    /// Complete canonical poker-precompile request bytes.
    #[must_use]
    pub fn crypto_request_bytes(&self) -> &[u8] {
        &self.crypto_request_bytes
    }

    /// Encode the envelope using fixed-width little-endian lengths.
    ///
    /// # Errors
    ///
    /// Rejects a payload exceeding the configured proof or request limit.
    pub fn encode(&self) -> TexasAirResult<Vec<u8>> {
        validate_lengths(
            self.stark_proof_bytes.len(),
            self.crypto_request_bytes.len(),
        )?;
        let proof_len = u32::try_from(self.stark_proof_bytes.len()).map_err(|_| {
            TexasAirError::SerializationError("dual proof length exceeds u32".into())
        })?;
        let request_len = u32::try_from(self.crypto_request_bytes.len()).map_err(|_| {
            TexasAirError::SerializationError("crypto request length exceeds u32".into())
        })?;
        let mut out = Vec::with_capacity(
            HEADER_LEN + self.stark_proof_bytes.len() + self.crypto_request_bytes.len(),
        );
        out.extend_from_slice(&DUAL_PROOF_MAGIC);
        out.extend_from_slice(&[
            self.version,
            self.method_kind as u8,
            self.precompile_id as u8,
            self.abi_version,
        ]);
        out.extend_from_slice(&proof_len.to_le_bytes());
        out.extend_from_slice(&request_len.to_le_bytes());
        out.extend_from_slice(&self.stark_proof_bytes);
        out.extend_from_slice(&self.crypto_request_bytes);
        Ok(out)
    }

    /// Strictly decode a dual-proof envelope.
    ///
    /// Unknown versions/selectors, invalid method/precompile combinations,
    /// oversized fields, truncation, and trailing bytes are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`TexasAirError::SerializationError`] for malformed wire data.
    pub fn decode(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(wire_error("dual proof header is truncated"));
        }
        if bytes[..8] != DUAL_PROOF_MAGIC {
            return Err(wire_error("dual proof magic mismatch"));
        }
        let version = bytes[8];
        if version != DUAL_PROOF_VERSION {
            return Err(wire_error(format!(
                "unsupported dual proof version {version}"
            )));
        }
        let method_kind = MethodKind::from_u8(bytes[9])
            .ok_or_else(|| wire_error("unknown dual proof method kind"))?;
        let precompile_id = match bytes[10] {
            1 => PokerPrecompileId::Shuffle,
            2 => PokerPrecompileId::DleqLeave,
            3 => PokerPrecompileId::ReconstructionV3,
            4 => PokerPrecompileId::RevealToken,
            _ => return Err(wire_error("unknown poker precompile id")),
        };
        let abi_version = bytes[11];
        validate_route(method_kind, precompile_id, abi_version)?;
        let proof_len = u32::from_le_bytes(bytes[12..16].try_into().expect("fixed slice")) as usize;
        let request_len =
            u32::from_le_bytes(bytes[16..20].try_into().expect("fixed slice")) as usize;
        validate_lengths(proof_len, request_len)?;
        let expected_len = HEADER_LEN
            .checked_add(proof_len)
            .and_then(|len| len.checked_add(request_len))
            .ok_or_else(|| wire_error("dual proof total length overflow"))?;
        if bytes.len() != expected_len {
            return Err(wire_error(format!(
                "dual proof length mismatch: header declares {expected_len}, received {}",
                bytes.len()
            )));
        }
        let proof_end = HEADER_LEN + proof_len;
        Ok(Self {
            version,
            method_kind,
            precompile_id,
            abi_version,
            stark_proof_bytes: bytes[HEADER_LEN..proof_end].to_vec(),
            crypto_request_bytes: bytes[proof_end..].to_vec(),
        })
    }
}

/// Result of verifying both halves against an independently supplied task.
///
/// Private fields ensure this acceptance object can only be issued by the
/// verifier path in this module.
#[derive(Debug, Clone)]
pub struct VerifiedDualProof {
    receipt: VerificationReceipt,
    precompile_binding: PrecompileCallBinding,
}

impl VerifiedDualProof {
    /// Native-verifier receipt for the accepted Stwo method proof.
    #[must_use]
    pub const fn receipt(&self) -> &VerificationReceipt {
        &self.receipt
    }

    /// Independently reverified binding for the accepted crypto request.
    #[must_use]
    pub const fn precompile_binding(&self) -> &PrecompileCallBinding {
        &self.precompile_binding
    }
}

/// Build both proof halves for a shuffle or reconstruction task.
///
/// The task is replayed before proof generation. Other method kinds are
/// rejected because they do not yet have a stage-3 poker-precompile binding.
///
/// # Errors
///
/// Returns an error when VM replay, crypto verification, trace generation,
/// Stwo proving, or serialization fails.
pub fn prove_dual_proof(task: &ProveTask) -> TexasAirResult<DualProofBundle> {
    match prepare(task, None)? {
        PreparedMethod::Shuffle {
            air,
            mut public_inputs,
            row,
            request_bytes,
            ..
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let trace = gen_method_trace(
                SubmitShuffleV2Air::num_columns(),
                &row_values,
                &SubmitShuffleV2Row::padding().to_vec(),
            )?;
            let proof = prove_method(
                &trace,
                air,
                SubmitShuffleV2Air::num_columns(),
                public_inputs,
            )?;
            bundle_from_stark(
                MethodKind::SubmitShuffleV2,
                PokerPrecompileId::Shuffle,
                SHUFFLE_ABI_VERSION,
                &proof.stark_proof,
                request_bytes,
            )
        }
        PreparedMethod::Reconstruction {
            air,
            mut public_inputs,
            row,
            request_bytes,
            ..
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let trace = gen_method_trace(
                SubmitReconstructDeckAir::num_columns(),
                &row_values,
                &SubmitReconstructDeckRow::padding().to_vec(),
            )?;
            let proof = prove_method(
                &trace,
                air,
                SubmitReconstructDeckAir::num_columns(),
                public_inputs,
            )?;
            bundle_from_stark(
                MethodKind::SubmitReconstructDeck,
                PokerPrecompileId::ReconstructionV3,
                RECONSTRUCTION_V3_ABI_VERSION,
                &proof.stark_proof,
                request_bytes,
            )
        }
    }
}

/// Repackage an already archived, natively verified method proof as a dual
/// proof without running the prover again.
///
/// The canonical precompile request is rebuilt from `task`; the archive only
/// supplies the serialized Stwo half and is never trusted for method metadata.
/// This is the bridge used by proving-service outer aggregation after restart.
pub fn dual_proof_from_archived(
    task: &ProveTask,
    archive: &ArchivedMethodProof,
) -> TexasAirResult<DualProofBundle> {
    if archive.method_kind() != task.method_kind {
        return Err(TexasAirError::SpecViolation(
            "archived dual proof method kind does not match task".into(),
        ));
    }
    let prepared = prepare(task, None)?;
    let (method_kind, precompile_id, abi_version, request_bytes, num_columns, log_size) =
        match prepared {
            PreparedMethod::Shuffle {
                request_bytes, air, ..
            } => (
                MethodKind::SubmitShuffleV2,
                PokerPrecompileId::Shuffle,
                SHUFFLE_ABI_VERSION,
                request_bytes,
                SubmitShuffleV2Air::num_columns(),
                air.log_size,
            ),
            PreparedMethod::Reconstruction {
                request_bytes, air, ..
            } => (
                MethodKind::SubmitReconstructDeck,
                PokerPrecompileId::ReconstructionV3,
                RECONSTRUCTION_V3_ABI_VERSION,
                request_bytes,
                SubmitReconstructDeckAir::num_columns(),
                air.log_size,
            ),
        };
    if archive.num_columns()? != num_columns || archive.log_size() != log_size {
        return Err(TexasAirError::SpecViolation(
            "archived dual proof trace shape does not match canonical task".into(),
        ));
    }
    let stark = archive.decode_stark()?;
    bundle_from_stark(
        method_kind,
        precompile_id,
        abi_version,
        &stark,
        request_bytes,
    )
}

/// Verify both proof halves against an independently authenticated task.
///
/// Verification never falls back to package-carried AIR or public inputs:
/// those values are reconstructed from `task` after a complete VM replay.
///
/// # Errors
///
/// Returns an error if either proof half is invalid or if any method, ABI,
/// request, digest, state, seat, table, hand, call, version, or dispatch scope
/// binding differs.
pub fn verify_dual_proof(
    task: &ProveTask,
    bundle: &DualProofBundle,
) -> TexasAirResult<VerifiedDualProof> {
    if bundle.version != DUAL_PROOF_VERSION {
        return Err(wire_error("unsupported in-memory dual proof version"));
    }
    if bundle.method_kind != task.method_kind {
        return Err(TexasAirError::SpecViolation(
            "dual proof method kind does not match trusted task".into(),
        ));
    }
    validate_route(bundle.method_kind, bundle.precompile_id, bundle.abi_version)?;

    match prepare(task, Some(&bundle.crypto_request_bytes))? {
        PreparedMethod::Shuffle {
            air,
            mut public_inputs,
            row,
            binding,
            ..
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let stark_proof = decode_stark(&bundle.stark_proof_bytes)?;
            let proof = MethodProof {
                stark_proof,
                air: air.clone(),
                log_size: air.log_size,
                num_columns: SubmitShuffleV2Air::num_columns(),
                public_inputs: public_inputs.clone(),
            };
            let receipt = verify_method_against_and_issue_receipt(proof, air, &public_inputs)?;
            Ok(VerifiedDualProof {
                receipt,
                precompile_binding: binding,
            })
        }
        PreparedMethod::Reconstruction {
            air,
            mut public_inputs,
            row,
            binding,
            ..
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let stark_proof = decode_stark(&bundle.stark_proof_bytes)?;
            let proof = MethodProof {
                stark_proof,
                air: air.clone(),
                log_size: air.log_size,
                num_columns: SubmitReconstructDeckAir::num_columns(),
                public_inputs: public_inputs.clone(),
            };
            let receipt = verify_method_against_and_issue_receipt(proof, air, &public_inputs)?;
            Ok(VerifiedDualProof {
                receipt,
                precompile_binding: binding,
            })
        }
    }
}

enum PreparedMethod {
    Shuffle {
        air: SubmitShuffleV2Air,
        public_inputs: TexasPublicInputs,
        row: SubmitShuffleV2Row,
        binding: PrecompileCallBinding,
        request_bytes: Vec<u8>,
    },
    Reconstruction {
        air: SubmitReconstructDeckAir,
        public_inputs: TexasPublicInputs,
        row: SubmitReconstructDeckRow,
        binding: PrecompileCallBinding,
        request_bytes: Vec<u8>,
    },
}

fn prepare(task: &ProveTask, supplied_request: Option<&[u8]>) -> TexasAirResult<PreparedMethod> {
    validate_full_dispatch_task(task)?;
    let pre_image = table_state_preimage(&task.pre_table)?;
    let post_image = table_state_preimage(&task.post_table)?;
    let pre_root = StateRoot(starknet_crypto::poseidon_hash_many(&pre_image));
    let post_root = StateRoot(starknet_crypto::poseidon_hash_many(&post_image));
    let mut public_inputs = TexasPublicInputs {
        pre_image,
        post_image,
        pre_state_root: pre_root,
        post_state_root: post_root,
        kind: task.method_kind,
        table_id: task.table_id,
        hand_id: task.hand_id,
        call_seq: task.call_seq,
        pre_version: task.pre_table.version,
        post_version: task.post_table.version,
        dispatch_call_digest: [0u8; 32],
        dispatch_call: None,
        precompile_binding: None,
        expected_trace_row: None,
    };
    public_inputs.bind_dispatch_call(task.context.clone(), task.selector, task.raw_args.clone())?;

    match task.method_kind {
        MethodKind::SubmitShuffleV2 => {
            let MethodInput::SubmitShuffleV2 {
                seat_index,
                raw_args,
            } = &task.method_input
            else {
                return Err(TexasAirError::SpecViolation(
                    "submit_shuffle_v2 task has the wrong MethodInput variant".into(),
                ));
            };
            let args: poker_l1::vm::contracts::texas_poker::dispatch::SubmitShuffleV2Args =
                borsh::from_slice(raw_args).map_err(|error| {
                    TexasAirError::SerializationError(format!(
                        "submit_shuffle_v2 raw args borsh: {error}"
                    ))
                })?;
            if args.seat_index != *seat_index {
                return Err(TexasAirError::SpecViolation(
                    "submit_shuffle_v2 seat differs between task fields".into(),
                ));
            }
            let aggregated_pk = task
                .pre_table
                .deck_state
                .aggregated_pk
                .as_ref()
                .ok_or_else(|| {
                    TexasAirError::SpecViolation(
                        "submit_shuffle_v2 requires an aggregated public key".into(),
                    )
                })?;
            let call_context = call_context(task, *seat_index, &public_inputs);
            let expected_request = build_bls12381_shuffle_request(
                b"zk_shuffle_proof_v2",
                &call_context,
                TranscriptId::FiatShamirSha3,
                &aggregated_pk.0,
                &task.pre_table.deck_state.encrypted,
                &args.output_cards,
                &args.shuffle_proof,
            )
            .map_err(|error| {
                TexasAirError::SpecViolation(format!(
                    "submit_shuffle_v2 request construction failed: {error}"
                ))
            })?;
            let expected_bytes = expected_request.encode().map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "submit_shuffle_v2 request encoding failed: {error}"
                ))
            })?;
            let request_bytes = require_expected_request(supplied_request, expected_bytes)?;
            let request = ShuffleVerifyRequest::decode(&request_bytes).map_err(|error| {
                TexasAirError::SpecViolation(format!(
                    "shuffle request canonical decode failed: {error}"
                ))
            })?;
            let binding = PrecompileCallBinding::verify_shuffle(&request)?;
            let input = SubmitShuffleV2Input {
                seat_index: *seat_index,
                new_deck_commitment: deck_commitment(&task.post_table),
                // Admission is determined by the pre-dispatch shuffle phase. The final shuffler
                // legitimately drives the post-state to NONE after `advance_shuffle`.
                shuffle_phase: task.pre_table.shuffle_state.phase,
                precompile: binding.air_binding(),
            };
            let row = SubmitShuffleV2Row::active(
                &input,
                state_root_to_air_limbs(pre_root),
                state_root_to_air_limbs(post_root),
                task.table_id,
                task.hand_id,
                task.call_seq,
                task.pre_table.version,
                task.post_table.version,
                task.post_table.shuffle_state.completed_players.len() as u8,
            );
            let air = SubmitShuffleV2Air {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: state_root_to_air_limbs(pre_root),
                post_state_root: state_root_to_air_limbs(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: task.pre_table.version,
                post_version: task.post_table.version,
            };
            public_inputs.precompile_binding = Some(binding.clone());
            Ok(PreparedMethod::Shuffle {
                air,
                public_inputs,
                row,
                binding,
                request_bytes,
            })
        }
        MethodKind::SubmitReconstructDeck => {
            let MethodInput::SubmitReconstructDeck {
                seat_index,
                raw_args,
            } = &task.method_input
            else {
                return Err(TexasAirError::SpecViolation(
                    "submit_reconstruct_deck task has the wrong MethodInput variant".into(),
                ));
            };
            let args: poker_l1::vm::contracts::texas_poker::dispatch::SubmitReconstructDeckArgs =
                borsh::from_slice(raw_args).map_err(|error| {
                    TexasAirError::SerializationError(format!(
                        "submit_reconstruct_deck raw args borsh: {error}"
                    ))
                })?;
            if args.seat_index != *seat_index {
                return Err(TexasAirError::SpecViolation(
                    "submit_reconstruct_deck seat differs between task fields".into(),
                ));
            }
            let call_context = call_context(task, *seat_index, &public_inputs);
            let expected_request = build_bls12381_reconstruction_v3_request(
                poker_protocol::zk_shuffle::reconstruction::RECONSTRUCTION_V3_PROOF_LABEL,
                &call_context,
                TranscriptId::FiatShamirSha3,
                &args.statement,
                &args.proof,
            )
            .map_err(|error| {
                TexasAirError::SpecViolation(format!(
                    "submit_reconstruct_deck request construction failed: {error}"
                ))
            })?;
            let expected_bytes = expected_request.encode().map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "submit_reconstruct_deck request encoding failed: {error}"
                ))
            })?;
            let request_bytes = require_expected_request(supplied_request, expected_bytes)?;
            let request =
                ReconstructionV3VerifyRequest::decode(&request_bytes).map_err(|error| {
                    TexasAirError::SpecViolation(format!(
                        "reconstruction V3 request canonical decode failed: {error}"
                    ))
                })?;
            let binding = PrecompileCallBinding::verify_reconstruction_v3(&request)?;
            let input = SubmitReconstructDeckInput {
                seat_index: *seat_index,
                reconstruct_phase: task.pre_table.reconstruct_state.phase,
                precompile: binding.air_binding(),
            };
            let row = SubmitReconstructDeckRow::active(
                &input,
                state_root_to_air_limbs(pre_root),
                state_root_to_air_limbs(post_root),
                task.table_id,
                task.hand_id,
                task.call_seq,
                task.pre_table.version,
                task.post_table.version,
                task.post_table.reconstruct_state.player_decks.len() as u8,
            );
            let air = SubmitReconstructDeckAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: state_root_to_air_limbs(pre_root),
                post_state_root: state_root_to_air_limbs(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: task.pre_table.version,
                post_version: task.post_table.version,
            };
            public_inputs.precompile_binding = Some(binding.clone());
            Ok(PreparedMethod::Reconstruction {
                air,
                public_inputs,
                row,
                binding,
                request_bytes,
            })
        }
        other => Err(TexasAirError::NotImplemented(format!(
            "{} has no stage-3 dual proof package",
            other.method_name()
        ))),
    }
}

fn call_context(task: &ProveTask, seat_index: u8, pi: &TexasPublicInputs) -> Vec<u8> {
    precompile_call_context(
        task.method_kind,
        seat_index,
        pi.table_id,
        pi.hand_id,
        pi.call_seq,
        pi.pre_version,
        pi.post_version,
        pi.pre_state_root,
        pi.post_state_root,
        pi.dispatch_call_digest,
    )
}

fn require_expected_request(supplied: Option<&[u8]>, expected: Vec<u8>) -> TexasAirResult<Vec<u8>> {
    if let Some(bytes) = supplied {
        if bytes != expected {
            return Err(TexasAirError::SpecViolation(
                "dual proof crypto request does not match the canonical trusted task request"
                    .into(),
            ));
        }
        Ok(bytes.to_vec())
    } else {
        Ok(expected)
    }
}

fn bundle_from_stark(
    method_kind: MethodKind,
    precompile_id: PokerPrecompileId,
    abi_version: u8,
    stark_proof: &StarkProof<Poseidon252MerkleHasher>,
    crypto_request_bytes: Vec<u8>,
) -> TexasAirResult<DualProofBundle> {
    let stark_proof_bytes = bincode_options()
        .serialize(stark_proof)
        .map_err(|error| wire_error(format!("Stwo proof serialization failed: {error}")))?;
    validate_lengths(stark_proof_bytes.len(), crypto_request_bytes.len())?;
    Ok(DualProofBundle {
        version: DUAL_PROOF_VERSION,
        method_kind,
        precompile_id,
        abi_version,
        stark_proof_bytes,
        crypto_request_bytes,
    })
}

fn decode_stark(bytes: &[u8]) -> TexasAirResult<StarkProof<Poseidon252MerkleHasher>> {
    if bytes.is_empty() || bytes.len() > MAX_STARK_PROOF_BYTES {
        return Err(wire_error("invalid serialized Stwo proof length"));
    }
    bincode_options()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|error| wire_error(format!("Stwo proof decoding failed: {error}")))
}

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_STARK_PROOF_BYTES as u64)
}

fn validate_route(
    method_kind: MethodKind,
    precompile_id: PokerPrecompileId,
    abi_version: u8,
) -> TexasAirResult<()> {
    let valid = matches!(
        (method_kind, precompile_id, abi_version),
        (
            MethodKind::SubmitShuffleV2,
            PokerPrecompileId::Shuffle,
            SHUFFLE_ABI_VERSION
        ) | (
            MethodKind::SubmitReconstructDeck,
            PokerPrecompileId::ReconstructionV3,
            RECONSTRUCTION_V3_ABI_VERSION
        )
    );
    if !valid {
        return Err(wire_error(
            "dual proof method/precompile/ABI route is not supported",
        ));
    }
    Ok(())
}

fn validate_lengths(proof_len: usize, request_len: usize) -> TexasAirResult<()> {
    if proof_len == 0 || proof_len > MAX_STARK_PROOF_BYTES {
        return Err(wire_error(format!(
            "Stwo proof length {proof_len} is outside 1..={MAX_STARK_PROOF_BYTES}"
        )));
    }
    if request_len == 0 || request_len > MAX_CRYPTO_REQUEST_BYTES {
        return Err(wire_error(format!(
            "crypto request length {request_len} is outside 1..={MAX_CRYPTO_REQUEST_BYTES}"
        )));
    }
    Ok(())
}

fn wire_error(message: impl Into<String>) -> TexasAirError {
    TexasAirError::SerializationError(message.into())
}
