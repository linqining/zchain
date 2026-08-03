//! # RecursivePublicInputs — L2 proof 的公开输入
//!
//! 详见 `.trae/documents/stwo_phase5_verifier_air_design.md` §8.3。
//!
//! L2 proof 的 public inputs 必须包含 L1 proof 的所有公开承诺，否则 prover 可以伪造。
//! 这些字段通过 channel mix 绑定到 L2 Fiat-Shamir transcript，可阻止 proof 被事后重标记；
//! 但 transcript binding 本身不等价于 verifier AIR 已验证对应 L1 proof。

use starknet_ff::FieldElement as FieldElement252;
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::line::LinePoly;

mod circle_point_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use stwo::core::circle::CirclePoint;
    use stwo::core::fields::qm31::SecureField;

    pub fn serialize<S>(point: &CirclePoint<SecureField>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (point.x, point.y).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<CirclePoint<SecureField>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (x, y) = <(SecureField, SecureField)>::deserialize(deserializer)?;
        Ok(CirclePoint { x, y })
    }
}

/// 递归证明内固定执行的 L1 verifier 程序。
///
/// 递归 verifier 不能接受 prover 自报的 component layout 或 transcript schedule；每个
/// 变体必须在代码中固定 commitments、interaction 消息、mask points 和 composition AIR。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RecursiveVerifierProgram {
    /// `prove_cpu_trace` / `verify_cpu_proof` 的单组件、无 interaction CPU verifier。
    #[default]
    CpuV1,
    /// One fixed, no-interaction component whose original columns are sampled only at offset 0.
    ///
    /// This is the protocol shape used by the Texas method AIRs: application public inputs are
    /// mixed before the trace commitments and every row is bound to one verifier-reconstructed
    /// business row.  The application wrapper must independently reconstruct the component and
    /// evaluate its composition claim; the recursive AIR proves the common PCS/Merkle/FRI part.
    ReplicatedRowV1,
}

impl RecursiveVerifierProgram {
    const fn transcript_id(self) -> u32 {
        match self {
            Self::CpuV1 => 1,
            Self::ReplicatedRowV1 => 2,
        }
    }
}

/// A canonical operation mixed into the L1 Poseidon252 transcript before commitments.
///
/// Application statements cannot be represented by a digest chosen by the prover: the exact
/// typed channel operations are carried in the recursive public inputs and replayed by the fixed
/// verifier program.  An application verifier must reconstruct this list from independently
/// trusted public inputs and require exact equality before accepting the recursive proof.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RecursiveStatementOp {
    /// [`Channel::mix_u32s`] with a length-delimited payload.
    MixU32s(Vec<u32>),
    /// [`Channel::mix_felts`] with a length-delimited payload.
    MixFelts(Vec<SecureField>),
    /// [`Channel::mix_u64`].
    MixU64(u64),
}

impl RecursiveStatementOp {
    /// Apply this operation to a transcript channel.
    pub fn apply(&self, channel: &mut impl Channel) {
        match self {
            Self::MixU32s(values) => channel.mix_u32s(values),
            Self::MixFelts(values) => channel.mix_felts(values),
            Self::MixU64(value) => channel.mix_u64(*value),
        }
    }

    fn mix_into_outer(&self, channel: &mut impl Channel) {
        match self {
            Self::MixU32s(values) => {
                channel.mix_u32s(&[1]);
                mix_len(channel, values.len());
                channel.mix_u32s(values);
            }
            Self::MixFelts(values) => {
                channel.mix_u32s(&[2]);
                mix_len(channel, values.len());
                channel.mix_felts(values);
            }
            Self::MixU64(value) => {
                channel.mix_u32s(&[3]);
                channel.mix_u64(*value);
            }
        }
    }
}

/// Channel adapter that records an application's exact statement transcript while preserving
/// normal Poseidon252 semantics.
///
/// It lets downstream crates reuse their existing `mix_into<C: Channel>` implementation without
/// duplicating its serialization schedule. Draw operations are delegated but are not recorded;
/// statement construction is expected to contain only mix operations.
#[derive(Debug, Clone, Default)]
pub struct RecursiveStatementRecorder {
    channel: Poseidon252Channel,
    operations: Vec<RecursiveStatementOp>,
}

impl RecursiveStatementRecorder {
    /// Finish recording and return the canonical operation sequence.
    #[must_use]
    pub fn into_operations(self) -> Vec<RecursiveStatementOp> {
        self.operations
    }

    /// Borrow the recorded operation sequence.
    #[must_use]
    pub fn operations(&self) -> &[RecursiveStatementOp] {
        &self.operations
    }
}

impl Channel for RecursiveStatementRecorder {
    const BYTES_PER_HASH: usize = Poseidon252Channel::BYTES_PER_HASH;

    fn verify_pow_nonce(&self, n_bits: u32, nonce: u64) -> bool {
        self.channel.verify_pow_nonce(n_bits, nonce)
    }

    fn mix_felts(&mut self, felts: &[SecureField]) {
        self.operations
            .push(RecursiveStatementOp::MixFelts(felts.to_vec()));
        self.channel.mix_felts(felts);
    }

    fn mix_u32s(&mut self, data: &[u32]) {
        self.operations
            .push(RecursiveStatementOp::MixU32s(data.to_vec()));
        self.channel.mix_u32s(data);
    }

    fn mix_u64(&mut self, value: u64) {
        self.operations.push(RecursiveStatementOp::MixU64(value));
        self.channel.mix_u64(value);
    }

    fn draw_secure_felt(&mut self) -> SecureField {
        self.channel.draw_secure_felt()
    }

    fn draw_secure_felts(&mut self, n_felts: usize) -> Vec<SecureField> {
        self.channel.draw_secure_felts(n_felts)
    }

    fn draw_u32s(&mut self) -> Vec<u32> {
        self.channel.draw_u32s()
    }
}

/// 单棵 L1 commitment tree 的 verifier 元数据。
///
/// `column_log_sizes` 使用提交前的多项式 log degree；Stwo verifier 会为每列加上
/// `config.fri_config.log_blowup_factor`，再结合 `config.lifting_log_size` 得到 Merkle
/// tree height。列顺序必须与 prover 调用 `tree_builder.extend_evals` 的顺序一致。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecursiveTreeMetadata {
    /// 该 commitment tree 中各列的多项式 log degree。
    pub column_log_sizes: Vec<u32>,
}

impl RecursiveTreeMetadata {
    /// 创建一棵 commitment tree 的元数据。
    #[must_use]
    pub const fn new(column_log_sizes: Vec<u32>) -> Self {
        Self { column_log_sizes }
    }

    /// 返回 Stwo Merkle verifier 实际使用的扩展列 log sizes。
    #[must_use]
    pub fn extended_column_log_sizes(&self, config: PcsConfig) -> Option<Vec<u32>> {
        self.column_log_sizes
            .iter()
            .map(|log_size| log_size.checked_add(config.fri_config.log_blowup_factor))
            .collect()
    }

    /// 返回 Stwo Merkle verifier 实际使用的 tree height。
    #[must_use]
    pub fn tree_height(&self, config: PcsConfig) -> Option<u32> {
        let max_column_log_size = self
            .extended_column_log_sizes(config)?
            .into_iter()
            .max()
            .unwrap_or_default();
        let height = config.lifting_log_size.unwrap_or(max_column_log_size);
        (max_column_log_size <= height).then_some(height)
    }
}

/// L2 proof 的公开输入。
///
/// 包含 L1 proof 的所有公开承诺，作为 L2 verifier 的输入。
/// 任何字段被篡改都会导致 L2 proof 验证失败（因为 channel mix）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecursivePublicInputs {
    /// 固定的 L1 verifier 程序；禁止 prover 自报 transcript/component schema。
    pub verifier_program: RecursiveVerifierProgram,

    /// Exact application-statement transcript prefix mixed before L1 commitments.
    ///
    /// `CpuV1` requires this list to be empty. `ReplicatedRowV1` requires the application wrapper
    /// to reconstruct it from trusted public inputs and compare it byte-for-byte.
    pub statement_transcript: Vec<RecursiveStatementOp>,

    /// L1 proof 的 Merkle roots（所有 trees 的 commitments）。
    ///
    /// 包括 preprocessed trace root（通常为空）、original trace root、
    /// interaction trace root、composition commitment root。
    pub l1_commitments: Vec<FieldElement252>,

    /// 每棵 L1 commitment tree 的列 log-size 元数据。
    ///
    /// 必须与 `l1_commitments`、L1 proof 的 `decommitments` 和 `queried_values` 一一对应。
    /// tree 0 是 preprocessed tree；最后一棵通常是 split composition tree。
    pub l1_tree_metadata: Vec<RecursiveTreeMetadata>,

    /// L1 proof 的 OODS（Out-Of-Domain Sampling）point。
    ///
    /// 由 L1 verifier 在 commit phase 通过 `CirclePoint::get_random_point(channel)` 抽取。
    #[serde(with = "circle_point_serde")]
    pub oods_point: CirclePoint<SecureField>,

    /// L1 composition constraints 的 transcript 随机线性组合系数。
    ///
    /// `CpuV1` verifier 在 original trace commitment 后从 Poseidon252 channel 抽取该值；
    /// Composition Eval AIR 使用它按 Stwo 的顺序累计全部 `CpuAir` constraint quotients。
    pub composition_random_coeff: SecureField,

    /// L1 proof 的 composition polynomial 在 OODS point 处的 claimed evaluation。
    ///
    /// 来自 L1 proof 的 `sampled_values`，由 L1 prover 提供并经 L1 verifier 验证。
    pub composition_oods_eval: SecureField,

    /// L1 PCS quotient batching 的 transcript 随机系数。
    ///
    /// 该值在 sampled values 混入 channel 后抽取，并用于构造 FRI first-layer answers。
    pub fri_quotient_random_coeff: SecureField,

    /// L1 FRI first layer 的 Merkle root。
    pub fri_first_layer_commitment: FieldElement252,

    /// L1 FRI inner layers 的全部 Merkle roots，按 transcript mix 顺序排列。
    pub fri_inner_layer_commitments: Vec<FieldElement252>,

    /// L1 FRI last layer polynomial。
    ///
    /// 作为 L1 FRI 的最终 layer，verifier 直接检查 `query_eval == last_layer_poly.eval_at_point(x)`。
    pub fri_last_layer_poly: LinePoly,

    /// L1 composition polynomial 的 max log degree bound。
    pub max_log_degree_bound: u32,

    /// L1 proof 的 PcsConfig（包含 FriConfig + log_blowup_factor 等）。
    pub config: PcsConfig,

    /// L1 proof 的 query positions（用于 Merkle Path 验证）。
    pub query_positions: Vec<usize>,

    /// L1 trace 的 log size（用于 Merkle Path 验证）。
    pub log_size: u32,

    /// L1 FRI 的 query point x 坐标（从 L1 transcript 提取，非硬编码）。
    ///
    /// v5.2 soundness fix：此前 `gen_fri_verifier_trace` 硬编码 `query_x = 1`，
    /// 允许恶意 prover 选择在 x=1 处通过但其他点失败的伪造多项式。
    /// 此字段存储从 L1 proof 的 Fiat-Shamir transcript 重新推导的真实 query point。
    pub fri_query_x: SecureField,

    /// L1 FRI last layer 在 `fri_query_x` 处的 claimed evaluation。
    ///
    /// 与 `fri_query_x` 一起作为 L2 公开输入，经 channel mix 绑定到 L2 proof。
    /// L2 FRI Verifier AIR 约束 `query_eval_in_trace == fri_query_eval`。
    pub fri_query_eval: SecureField,
}

impl RecursivePublicInputs {
    /// Fiat–Shamir transcript domain separator for the complete recursive statement.
    const TRANSCRIPT_DOMAIN: [u32; 4] = [0x504f_4b52, 0x4543_5552, 0x5349_5645, 1];

    /// 创建新的 RecursivePublicInputs。
    #[must_use]
    pub const fn new(
        l1_commitments: Vec<FieldElement252>,
        oods_point: CirclePoint<SecureField>,
        composition_oods_eval: SecureField,
        fri_first_layer_commitment: FieldElement252,
        fri_last_layer_poly: LinePoly,
        max_log_degree_bound: u32,
        config: PcsConfig,
        query_positions: Vec<usize>,
        log_size: u32,
        fri_query_x: SecureField,
        fri_query_eval: SecureField,
    ) -> Self {
        Self {
            verifier_program: RecursiveVerifierProgram::CpuV1,
            statement_transcript: Vec::new(),
            l1_commitments,
            l1_tree_metadata: Vec::new(),
            oods_point,
            composition_random_coeff: SecureField::from_u32_unchecked(0, 0, 0, 0),
            composition_oods_eval,
            fri_quotient_random_coeff: SecureField::from_u32_unchecked(0, 0, 0, 0),
            fri_first_layer_commitment,
            fri_inner_layer_commitments: Vec::new(),
            fri_last_layer_poly,
            max_log_degree_bound,
            config,
            query_positions,
            log_size,
            fri_query_x,
            fri_query_eval,
        }
    }

    /// 附加完整的 L1 tree 与 FRI layer 元数据。
    #[must_use]
    pub fn with_verifier_metadata(
        mut self,
        l1_tree_metadata: Vec<RecursiveTreeMetadata>,
        fri_inner_layer_commitments: Vec<FieldElement252>,
    ) -> Self {
        self.l1_tree_metadata = l1_tree_metadata;
        self.fri_inner_layer_commitments = fri_inner_layer_commitments;
        self
    }

    /// 附加由固定 verifier transcript 派生的随机挑战。
    #[must_use]
    pub const fn with_verifier_challenges(
        mut self,
        composition_random_coeff: SecureField,
        fri_quotient_random_coeff: SecureField,
    ) -> Self {
        self.composition_random_coeff = composition_random_coeff;
        self.fri_quotient_random_coeff = fri_quotient_random_coeff;
        self
    }

    /// Select a verifier program and bind its exact pre-commitment statement transcript.
    #[must_use]
    pub fn with_statement_transcript(
        mut self,
        verifier_program: RecursiveVerifierProgram,
        statement_transcript: Vec<RecursiveStatementOp>,
    ) -> Self {
        self.verifier_program = verifier_program;
        self.statement_transcript = statement_transcript;
        self
    }

    /// Replay the application statement prefix into an L1 Poseidon transcript.
    pub fn replay_statement_transcript(&self, channel: &mut impl Channel) {
        for operation in &self.statement_transcript {
            operation.apply(channel);
        }
    }

    /// 获取 L1 FRI config。
    #[must_use]
    pub const fn fri_config(&self) -> FriConfig {
        self.config.fri_config
    }

    /// Mix the complete recursive statement into a Fiat–Shamir channel.
    ///
    /// Variable-length fields are length-prefixed, `usize` query positions are encoded as
    /// architecture-independent `u64`, and felt252 commitments are mixed without truncation.
    /// Prover and verifier must call this method before committing/verifying the L2 trace.
    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u32s(&Self::TRANSCRIPT_DOMAIN);
        channel.mix_u32s(&[self.verifier_program.transcript_id()]);
        mix_len(channel, self.statement_transcript.len());
        for operation in &self.statement_transcript {
            operation.mix_into_outer(channel);
        }
        self.config.mix_into(channel);
        channel.mix_u32s(&[self.max_log_degree_bound]);
        channel.mix_felts(&[
            self.composition_random_coeff,
            self.composition_oods_eval,
            self.fri_quotient_random_coeff,
        ]);
        channel.mix_felts(&[self.oods_point.x, self.oods_point.y]);

        mix_len(channel, self.l1_commitments.len());
        for commitment in &self.l1_commitments {
            mix_felt252(channel, commitment);
        }

        mix_len(channel, self.l1_tree_metadata.len());
        for tree in &self.l1_tree_metadata {
            mix_len(channel, tree.column_log_sizes.len());
            channel.mix_u32s(&tree.column_log_sizes);
        }
        mix_felt252(channel, &self.fri_first_layer_commitment);
        mix_len(channel, self.fri_inner_layer_commitments.len());
        for commitment in &self.fri_inner_layer_commitments {
            mix_felt252(channel, commitment);
        }

        mix_len(channel, self.fri_last_layer_poly.len());
        channel.mix_felts(&self.fri_last_layer_poly[..]);

        mix_len(channel, self.query_positions.len());
        for &position in &self.query_positions {
            channel.mix_u64(
                u64::try_from(position)
                    .expect("query position must fit the transcript u64 encoding"),
            );
        }
        channel.mix_u32s(&[self.log_size]);
        channel.mix_felts(&[self.fri_query_x, self.fri_query_eval]);
    }
}

fn mix_len(channel: &mut impl Channel, len: usize) {
    channel.mix_u64(u64::try_from(len).expect("public input length must fit u64"));
}

fn mix_felt252(channel: &mut impl Channel, value: &FieldElement252) {
    let bytes = value.to_bytes_be();
    let words: [u32; 8] = std::array::from_fn(|i| {
        let offset = i * 4;
        u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    });
    channel.mix_u32s(&words);
}

impl Default for RecursivePublicInputs {
    fn default() -> Self {
        Self::new(
            Vec::new(),
            CirclePoint::zero(),
            SecureField::from(0u32),
            FieldElement252::ZERO,
            LinePoly::new(vec![SecureField::from(0u32)]),
            0,
            PcsConfig::default(),
            Vec::new(),
            0,
            SecureField::from(0u32),
            SecureField::from(0u32),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use stwo::core::channel::Blake2sChannel;

    #[test]
    fn test_recursive_public_inputs_new() {
        let inputs = RecursivePublicInputs::new(
            Vec::new(),
            CirclePoint::zero(),
            SecureField::zero(),
            FieldElement252::ZERO,
            LinePoly::new(vec![SecureField::zero()]),
            10,
            PcsConfig::default(),
            Vec::new(),
            10,
            SecureField::zero(),
            SecureField::zero(),
        );
        assert_eq!(inputs.l1_commitments.len(), 0);
        assert_eq!(inputs.max_log_degree_bound, 10);
        assert_eq!(inputs.log_size, 10);
        assert_eq!(inputs.fri_query_x, SecureField::zero());
        assert_eq!(inputs.fri_query_eval, SecureField::zero());
        assert_eq!(
            inputs.fri_config().log_blowup_factor,
            PcsConfig::default().fri_config.log_blowup_factor
        );
    }

    fn transcript_challenge(inputs: &RecursivePublicInputs) -> SecureField {
        let mut channel = Blake2sChannel::default();
        inputs.mix_into(&mut channel);
        channel.draw_secure_felt()
    }

    #[test]
    fn recursive_transcript_binds_commitments_queries_and_log_size() {
        let baseline = RecursivePublicInputs::default();
        let expected = transcript_challenge(&baseline);

        let mut changed_l1_commitments = baseline.clone();
        changed_l1_commitments.l1_commitments = vec![FieldElement252::ONE];
        assert_ne!(expected, transcript_challenge(&changed_l1_commitments));

        let mut changed_fri_commitment = baseline.clone();
        changed_fri_commitment.fri_first_layer_commitment = FieldElement252::ONE;
        assert_ne!(expected, transcript_challenge(&changed_fri_commitment));

        let mut changed_tree_metadata = baseline.clone();
        changed_tree_metadata.l1_tree_metadata = vec![RecursiveTreeMetadata::new(vec![7, 8])];
        assert_ne!(expected, transcript_challenge(&changed_tree_metadata));

        let mut changed_inner_commitments = baseline.clone();
        changed_inner_commitments.fri_inner_layer_commitments = vec![FieldElement252::ONE];
        assert_ne!(expected, transcript_challenge(&changed_inner_commitments));

        let mut changed_queries = baseline.clone();
        changed_queries.query_positions = vec![0];
        assert_ne!(expected, transcript_challenge(&changed_queries));

        let mut changed_composition_coeff = baseline.clone();
        changed_composition_coeff.composition_random_coeff = SecureField::from(1u32);
        assert_ne!(expected, transcript_challenge(&changed_composition_coeff));

        let mut changed_fri_coeff = baseline.clone();
        changed_fri_coeff.fri_quotient_random_coeff = SecureField::from(1u32);
        assert_ne!(expected, transcript_challenge(&changed_fri_coeff));

        let mut changed_log_size = baseline;
        changed_log_size.log_size = 1;
        assert_ne!(expected, transcript_challenge(&changed_log_size));
    }

    #[test]
    fn statement_recorder_replays_exact_poseidon_transcript() {
        let mut recorder = RecursiveStatementRecorder::default();
        recorder.mix_u32s(&[1, 2, 3]);
        recorder.mix_felts(&[SecureField::from(4u32)]);
        recorder.mix_u64(5);
        let recorded_draw = recorder.draw_secure_felt();
        let operations = recorder.into_operations();

        let mut replay = Poseidon252Channel::default();
        for operation in &operations {
            operation.apply(&mut replay);
        }
        assert_eq!(recorded_draw, replay.draw_secure_felt());

        let mut inputs = RecursivePublicInputs::default();
        inputs =
            inputs.with_statement_transcript(RecursiveVerifierProgram::ReplicatedRowV1, operations);
        let expected = transcript_challenge(&inputs);
        inputs.statement_transcript[0] = RecursiveStatementOp::MixU32s(vec![1, 2, 4]);
        assert_ne!(expected, transcript_challenge(&inputs));
    }
}
