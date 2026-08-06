//! Four-proof bundle for one canonical composite Texas Poker transition.

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::fields::m31::M31;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;

use super::air::{
    BetCollectionAir, ComponentTexasAir, RoundAdvanceAir, SeatUpdateAir, SettlementAir,
};
use super::{
    CompositeTransitionPlan, StageKind, derive_composite_transition_plan_from_task,
    supports_composite_proof,
};
use crate::airs::TexasAir;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::prover::{MethodProof, prove_method};
use crate::public_inputs::TexasPublicInputs;
use crate::trace_gen::generic_trace::{MIN_LOG_SIZE, gen_method_trace};
use crate::verifier::verify_method_against;

/// Durable composition-proof bundle schema version.
pub const COMPOSITION_PROOF_BUNDLE_VERSION: u8 = 1;

const MAX_COMPONENT_STARK_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMPOSITION_BUNDLE_BYTES: usize = 4 * MAX_COMPONENT_STARK_BYTES + 64 * 1024;

/// One independently committed STARK proof inside a four-stage bundle.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedComponentProof {
    stage_kind: StageKind,
    log_size: u32,
    num_columns: u32,
    stark_proof_bytes: Vec<u8>,
}

impl ArchivedComponentProof {
    /// Component discriminator committed by this proof envelope.
    #[must_use]
    pub const fn stage_kind(&self) -> StageKind {
        self.stage_kind
    }

    /// Number of original trace columns committed by this proof envelope.
    pub fn num_columns(&self) -> TexasAirResult<usize> {
        usize::try_from(self.num_columns).map_err(|_| {
            TexasAirError::SerializationError(
                "component proof column count does not fit usize".into(),
            )
        })
    }

    fn from_stark(
        stage_kind: StageKind,
        log_size: u32,
        num_columns: usize,
        proof: &StarkProof<Poseidon252MerkleHasher>,
    ) -> TexasAirResult<Self> {
        let num_columns = u32::try_from(num_columns).map_err(|_| {
            TexasAirError::SerializationError("component column count exceeds u32".into())
        })?;
        let stark_proof_bytes = bincode_options().serialize(proof).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "component Stwo proof serialization failed: {error}"
            ))
        })?;
        let archive = Self {
            stage_kind,
            log_size,
            num_columns,
            stark_proof_bytes,
        };
        archive.validate()?;
        Ok(archive)
    }

    fn decode_stark(&self) -> TexasAirResult<StarkProof<Poseidon252MerkleHasher>> {
        self.validate()?;
        bincode_options()
            .reject_trailing_bytes()
            .deserialize(&self.stark_proof_bytes)
            .map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "component Stwo proof decoding failed: {error}"
                ))
            })
    }

    fn validate(&self) -> TexasAirResult<()> {
        if self.log_size != MIN_LOG_SIZE || self.num_columns == 0 {
            return Err(TexasAirError::SerializationError(
                "invalid component proof trace shape".into(),
            ));
        }
        if self.stark_proof_bytes.is_empty()
            || self.stark_proof_bytes.len() > MAX_COMPONENT_STARK_BYTES
        {
            return Err(TexasAirError::SerializationError(
                "invalid component Stwo proof length".into(),
            ));
        }
        Ok(())
    }
}

/// Four independent STARK proofs linked by one canonical transition-plan digest.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCompositionProofBundle {
    version: u8,
    method_kind: MethodKind,
    table_id: u64,
    hand_id: u32,
    call_seq: u32,
    plan_digest: [u8; 32],
    stages: [ArchivedComponentProof; 4],
}

impl ArchivedCompositionProofBundle {
    /// Composite plan digest shared by every child proof.
    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    /// Child proofs in SeatUpdate, BetCollection, RoundAdvance, Settlement order.
    #[must_use]
    pub const fn stages(&self) -> &[ArchivedComponentProof; 4] {
        &self.stages
    }

    /// Validate the bounded archive envelope without trusting proof-carried task scope.
    ///
    /// Full verification must still call [`verify_composition_bundle`] with the canonical task.
    pub fn validate(&self) -> TexasAirResult<()> {
        self.validate_envelope()
    }

    /// Encode the complete bounded bundle as canonical Borsh bytes.
    pub fn to_bytes(&self) -> TexasAirResult<Vec<u8>> {
        self.validate_envelope()?;
        borsh::to_vec(self).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "composition proof bundle Borsh encoding failed: {error}"
            ))
        })
    }

    /// Decode a complete bounded bundle and reject trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_COMPOSITION_BUNDLE_BYTES {
            return Err(TexasAirError::SerializationError(
                "invalid composition proof bundle length".into(),
            ));
        }
        let bundle = Self::try_from_slice(bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "composition proof bundle Borsh decoding failed: {error}"
            ))
        })?;
        bundle.validate_envelope()?;
        Ok(bundle)
    }

    fn validate_envelope(&self) -> TexasAirResult<()> {
        if self.version != COMPOSITION_PROOF_BUNDLE_VERSION
            || !supports_composite_proof(self.method_kind)
        {
            return Err(TexasAirError::SerializationError(
                "unsupported composition proof bundle envelope".into(),
            ));
        }
        for (index, stage) in self.stages.iter().enumerate() {
            stage.validate()?;
            if usize::from(stage.stage_kind as u8) != index {
                return Err(TexasAirError::SerializationError(
                    "component proofs are not in canonical stage order".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Prove and independently verify all four components for a supported task.
///
/// Methods outside the composition pipeline return `Ok(None)`. Supported methods always return
/// four proofs, including deterministic inactive proofs for stages not executed by that dispatch.
pub fn prove_composition_bundle(
    task: &crate::prove_task::ProveTask,
) -> TexasAirResult<Option<ArchivedCompositionProofBundle>> {
    if !supports_composite_proof(task.method_kind) {
        return Ok(None);
    }
    let plan = derive_composite_transition_plan_from_task(task)?;
    let base = base_public_inputs(task)?;
    let airs = build_airs(&plan, &base);
    let ((seat_update, bet_collection), (round_advance, settlement)) = rayon::join(
        || {
            rayon::join(
                || prove_stage(StageKind::SeatUpdate, airs.0, &base),
                || prove_stage(StageKind::BetCollection, airs.1, &base),
            )
        },
        || {
            rayon::join(
                || prove_stage(StageKind::RoundAdvance, airs.2, &base),
                || prove_stage(StageKind::Settlement, airs.3, &base),
            )
        },
    );
    let stages = [seat_update?, bet_collection?, round_advance?, settlement?];
    let bundle = ArchivedCompositionProofBundle {
        version: COMPOSITION_PROOF_BUNDLE_VERSION,
        method_kind: task.method_kind,
        table_id: task.table_id,
        hand_id: task.hand_id,
        call_seq: task.call_seq,
        plan_digest: plan.plan_digest,
        stages,
    };
    bundle.validate_envelope()?;
    Ok(Some(bundle))
}

/// Reconstruct a canonical task and verify every independent component proof and stage link.
pub fn verify_composition_bundle(
    task: &crate::prove_task::ProveTask,
    bundle: &ArchivedCompositionProofBundle,
) -> TexasAirResult<()> {
    bundle.validate_envelope()?;
    if bundle.method_kind != task.method_kind
        || bundle.table_id != task.table_id
        || bundle.hand_id != task.hand_id
        || bundle.call_seq != task.call_seq
    {
        return Err(TexasAirError::SpecViolation(
            "composition proof bundle scope does not match canonical task".into(),
        ));
    }
    let plan = derive_composite_transition_plan_from_task(task)?;
    plan.validate_composition()?;
    if bundle.plan_digest != plan.plan_digest {
        return Err(TexasAirError::SpecViolation(
            "composition proof bundle plan digest mismatch".into(),
        ));
    }
    let base = base_public_inputs(task)?;
    let airs = build_airs(&plan, &base);
    let ((seat_update, bet_collection), (round_advance, settlement)) = rayon::join(
        || {
            rayon::join(
                || verify_stage(&bundle.stages[0], StageKind::SeatUpdate, airs.0, &base),
                || verify_stage(&bundle.stages[1], StageKind::BetCollection, airs.1, &base),
            )
        },
        || {
            rayon::join(
                || verify_stage(&bundle.stages[2], StageKind::RoundAdvance, airs.2, &base),
                || verify_stage(&bundle.stages[3], StageKind::Settlement, airs.3, &base),
            )
        },
    );
    seat_update?;
    bet_collection?;
    round_advance?;
    settlement
}

fn base_public_inputs(task: &crate::prove_task::ProveTask) -> TexasAirResult<TexasPublicInputs> {
    let mut public_inputs = TexasPublicInputs::from_tables(
        &task.pre_table,
        &task.post_table,
        task.method_kind,
        task.table_id,
        task.hand_id,
        task.call_seq,
    )?;
    public_inputs.bind_dispatch_call(task.context.clone(), task.selector, task.raw_args.clone())?;
    Ok(public_inputs)
}

fn build_airs(
    plan: &CompositeTransitionPlan,
    public_inputs: &TexasPublicInputs,
) -> (
    SeatUpdateAir,
    BetCollectionAir,
    RoundAdvanceAir,
    SettlementAir,
) {
    (
        SeatUpdateAir::new(
            MIN_LOG_SIZE,
            plan.method_kind,
            public_inputs,
            plan.seat_update.clone(),
            plan.link(StageKind::SeatUpdate).clone(),
        ),
        BetCollectionAir::new(
            MIN_LOG_SIZE,
            plan.method_kind,
            public_inputs,
            plan.bet_collection.clone(),
            plan.link(StageKind::BetCollection).clone(),
        ),
        RoundAdvanceAir::new(
            MIN_LOG_SIZE,
            plan.method_kind,
            public_inputs,
            plan.round_advance.clone(),
            plan.link(StageKind::RoundAdvance).clone(),
        ),
        SettlementAir::new(
            MIN_LOG_SIZE,
            plan.method_kind,
            public_inputs,
            plan.settlement.clone(),
            plan.link(StageKind::Settlement).clone(),
        ),
    )
}

fn stage_public_inputs<A: TexasAir>(
    base: &TexasPublicInputs,
    air: &A,
    row: &[M31],
) -> TexasAirResult<TexasPublicInputs> {
    let mut public_inputs = base.clone();
    public_inputs.expected_trace_row = None;
    public_inputs.component = air.statement().component;
    public_inputs.bind_expected_trace_row(row)?;
    Ok(public_inputs)
}

fn prove_stage<A: ComponentTexasAir>(
    stage_kind: StageKind,
    air: A,
    base: &TexasPublicInputs,
) -> TexasAirResult<ArchivedComponentProof> {
    let row = air.canonical_row();
    let public_inputs = stage_public_inputs(base, &air, &row)?;
    let padding = vec![M31::from(0u32); row.len()];
    let trace = gen_method_trace(row.len(), &row, &padding)?;
    let proof = prove_method(&trace, air.clone(), row.len(), public_inputs.clone())?;
    let archive = ArchivedComponentProof::from_stark(
        stage_kind,
        proof.log_size,
        proof.num_columns,
        &proof.stark_proof,
    )?;
    verify_method_against(proof, air, &public_inputs)?;
    Ok(archive)
}

fn verify_stage<A: ComponentTexasAir>(
    archive: &ArchivedComponentProof,
    stage_kind: StageKind,
    air: A,
    base: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let row = air.canonical_row();
    if archive.stage_kind != stage_kind
        || archive.log_size != air.log_size()
        || archive.num_columns()? != row.len()
        || row.len() != air.trace_num_columns()
    {
        return Err(TexasAirError::SerializationError(
            "component proof shape does not match canonical AIR".into(),
        ));
    }
    let public_inputs = stage_public_inputs(base, &air, &row)?;
    let proof = MethodProof {
        stark_proof: archive.decode_stark()?,
        air: air.clone(),
        log_size: air.log_size(),
        num_columns: row.len(),
        public_inputs: public_inputs.clone(),
    };
    verify_method_against(proof, air, &public_inputs)
}

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_COMPONENT_STARK_BYTES as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(stage_kind: StageKind, num_columns: usize) -> ArchivedComponentProof {
        ArchivedComponentProof {
            stage_kind,
            log_size: MIN_LOG_SIZE,
            num_columns: u32::try_from(num_columns).unwrap(),
            stark_proof_bytes: vec![1],
        }
    }

    fn envelope() -> ArchivedCompositionProofBundle {
        ArchivedCompositionProofBundle {
            version: COMPOSITION_PROOF_BUNDLE_VERSION,
            method_kind: MethodKind::Check,
            table_id: 7,
            hand_id: 3,
            call_seq: 9,
            plan_digest: [4; 32],
            stages: [
                stage(
                    StageKind::SeatUpdate,
                    super::super::seat_update::NUM_COLUMNS,
                ),
                stage(
                    StageKind::BetCollection,
                    super::super::bet_collection::NUM_COLUMNS,
                ),
                stage(
                    StageKind::RoundAdvance,
                    super::super::round_advance::NUM_COLUMNS,
                ),
                stage(StageKind::Settlement, super::super::settlement::NUM_COLUMNS),
            ],
        }
    }

    #[test]
    fn archive_roundtrip_preserves_canonical_stage_order() {
        let bundle = envelope();
        let bytes = bundle.to_bytes().unwrap();
        let decoded = ArchivedCompositionProofBundle::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn archive_rejects_reordered_or_duplicated_stages() {
        let mut bundle = envelope();
        bundle.stages.swap(0, 1);
        assert!(bundle.to_bytes().is_err());
        let mut bundle = envelope();
        bundle.stages[3].stage_kind = StageKind::RoundAdvance;
        assert!(bundle.to_bytes().is_err());
    }
}
