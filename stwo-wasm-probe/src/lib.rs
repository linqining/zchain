//! M4-ACC-5 探针：stwo 2.3 验证器进 wasm32 的可行性与延迟量级。
//!
//! Demo AIR 结构对齐 poker_texas_air 的 canonical AIR（三棵承诺树 + 同一套 PCS
//! 参数），但约束体量参数化（n_scope/n_trace），用于扫描列数敏感度并外推
//! canonical 规模。证明由原生（nightly + prover feature）离线生成；wasm 侧只编译
//! 验证路径。
//!
//! 双哈希器：canonical 实际用 Poseidon252（stwo 2.3 在 wasm32 上 cfg 掉该模块，
//! 见报告）；Blake2s 为 wasm 可用路径，用于实测 + 按 native 比值外推 Poseidon。
//!
//! 结构参照（只读）：poker_texas_air/src/texas_canonical_air.rs
//!   prove_canonical_tagged_batch (L9267) / verify_canonical_stark (L9444)。

use serde::{Deserialize, Serialize};
use stwo::core::channel::Channel;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::{QM31, SecureField};
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::core::verifier::{verify, VerificationError};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    relation, EvalAtRow, FrameworkComponent, FrameworkEval, Relation, RelationEntry,
    TraceLocationAllocator,
};

/// 与 poker canonical 协议一致的 PCS 配置（poker_texas_air/src/prover_context.rs L43）：
/// 10 PoW bits + 30 FRI queries，log_blowup_factor = 1，fold_step = 1。
pub fn protocol_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 10,
        fri_config: FriConfig::new(0, 1, 30, 1),
        lifting_log_size: None,
    }
}

/// case 里用 u8 标识哈希器（Fiat–Shamir 信道与 Merle 承诺必须配对使用）。
pub const HASHER_POSEIDON252: u8 = 0;
pub const HASHER_BLAKE2S: u8 = 1;

/// scope（preprocessed）树里的选择子列 id（对齐 canonical 的 scoped_active 模式）。
pub fn preprocessed_col_id() -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: "probe_scope_selector".into(),
    }
}

/// 字节查找列数：28 对 + 1 张 256 项表 = 29 个 LogUp QM31 交互列
/// （对齐 canonical 的 RANGE_INTERACTION_COLUMNS = 29 → tree2 = 116 base 列）。
pub const N_BYTE_COLS: usize = 56;
pub const N_INTERACTION_QM31_COLS: usize = 29;

/// 与 canonical 交互树等宽（QM31 base 拆分后）的列数。
pub const N_INTERACTION_BASE_COLS: usize = N_INTERACTION_QM31_COLS * 4;

// relation arity 1，对齐 canonical 的 `relation!(CanonicalRange8, 1)`。
relation!(ProbeRange8, 1);

/// Demo AIR：结构对齐 canonical（1 个 scope 选择子 + 56 字节列 + 表列 + 填充列），
/// 约束为选择子绑定 + 布尔性 + LogUp 范围查找。
#[derive(Debug, Clone)]
pub struct ProbeAir {
    pub log_size: u32,
    pub n_trace: usize,
    pub range: ProbeRange8,
}

impl FrameworkEval for ProbeAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    // 对齐 canonical：self.log_size + 1。
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = M31::from(1u32).into();
        let zero: E::F = M31::from(0u32).into();

        // scope 选择子列（tree0 第 0 列，内容与 canonical 的 scoped_active 同模式）。
        let scoped_active = eval.get_preprocessed_column(preprocessed_col_id().clone());
        let gate = eval.next_trace_mask();
        // 选择子绑定（对齐 canonical `active - scoped_active`）。
        eval.add_constraint(gate.clone() - scoped_active);
        // 布尔性（对齐 canonical `active * (active - one)` 的简化形）。
        eval.add_constraint(gate.clone() * (gate.clone() - one.clone()));

        // 56 个字节列 → 56 个 arity-1 查找（framework 两两批成 28 个交互列）。
        let mut bytes = Vec::with_capacity(N_BYTE_COLS);
        for _ in 0..N_BYTE_COLS {
            bytes.push(eval.next_trace_mask());
        }
        for byte in &bytes {
            eval.add_to_relation(RelationEntry::new(
                &self.range,
                E::EF::from(gate.clone()),
                &[byte.clone()],
            ));
        }

        // 256 项表的负重列（mult/tval，对齐 canonical 的 multiplicity/table_values）。
        let mult = eval.next_trace_mask();
        let tval = eval.next_trace_mask();
        eval.add_to_relation(RelationEntry::new(
            &self.range,
            E::EF::from(zero.clone() - mult.clone()),
            &[tval.clone()],
        ));
        // 56 查找 + 1 表 = 57 frac：前 28 批两两合并、最后 1 个单列
        // （对齐 canonical 的 finalize_logup_in_pairs 与 range_interaction 列结构）。
        eval.finalize_logup_in_pairs();

        // 填充列：布尔性约束，撑起目标列数（校准 canonical 的巨宽 trace）。
        // 固定列：gate(1) + bytes(56) + mult(1) + tval(1) = 3 + N_BYTE_COLS。
        let n_fixed = 3 + N_BYTE_COLS;
        assert!(self.n_trace >= n_fixed, "n_trace too small for demo layout");
        for _ in 0..(self.n_trace - n_fixed) {
            let c = eval.next_trace_mask();
            eval.add_constraint(c.clone() * (c.clone() - one.clone()));
        }
        eval
    }
}

/// 探针用例参数 + 序列化的 StarkProof（bincode）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeCase {
    pub version: u32,
    pub hasher: u8,
    pub log_size: u32,
    pub n_scope: usize,
    pub n_trace: usize,
    pub n_interaction_base_cols: usize,
    /// range_sum（QM31 的 4 个 M31 limb，u32 原始表示）。
    pub range_claimed: [u32; 4],
    pub stark_proof: Vec<u8>,
}

/// Fiat–Shamir 前置混合：prover 与 verifier 必须完全一致。
/// 对齐 canonical 的 mix_scope（把公共参数混入信道）。
pub fn mix_params<C: Channel>(channel: &mut C, log_size: u32, n_scope: usize, n_trace: usize) {
    channel.mix_felts(&[
        QM31::from(M31::from(0x7072_0be5u32)), // "probe" magic
        QM31::from(M31::from(log_size)),
        QM31::from(M31::from(n_scope as u32)),
        QM31::from(M31::from(n_trace as u32)),
    ]);
}

// ===== 以下仅原生（native-prover）：离线出证与基准 =====
#[cfg(feature = "native-prover")]
pub mod prover_path {
    use super::*;
    use stwo::core::poly::circle::CanonicCoset;
    #[cfg(not(target_arch = "wasm32"))]
    use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
    use stwo::prover::backend::simd::column::BaseColumn;
    use stwo::prover::backend::simd::m31::{N_LANES, PackedBaseField};
    use stwo::prover::backend::simd::qm31::PackedSecureField;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
    use stwo::prover::poly::{BitReversedOrder, NaturalOrder};
    use stwo::prover::pcs::CommitmentSchemeProver;
    use stwo::prover::{prove, ProvingError};
    use stwo_constraint_framework::LogupTraceGenerator;

    /// 确定性 scope 列内容：第 j 列第 r 行 = (j*100003 + r*7 + 1) mod (2^31-1)；
    /// 第 0 列固定全 1（scope 选择子）。
    pub fn scope_value(j: usize, r: usize) -> M31 {
        if j == 0 {
            return M31::from(1u32);
        }
        let v = ((j as u64 * 100_003 + r as u64 * 7 + 1) % 0x7fff_ffff) as u32;
        M31::from(v)
    }

    /// 确定性 trace 内容（列主序）：
    /// col0 = gate（全 1，绑定 scope 选择子）；col1..=56 字节；col57 mult；col58 tval；
    /// 其余为 0/1 填充。
    pub fn build_trace(log_size: u32, n_trace: usize) -> Vec<Vec<M31>> {
        let n_rows = 1usize << log_size;
        let mut cols = vec![vec![M31::from(0u32); n_rows]; n_trace];
        for r in 0..n_rows {
            cols[0][r] = M31::from(1u32); // gate
            for j in 0..N_BYTE_COLS {
                cols[1 + j][r] = M31::from(((r * 7 + j * 31) % 256) as u32);
            }
            let mult_col = 1 + N_BYTE_COLS;
            let tval_col = mult_col + 1;
            if r < 256 {
                cols[mult_col][r] = M31::from(1u32);
                cols[tval_col][r] = M31::from(r as u32);
            }
            for j in (tval_col + 1)..n_trace {
                cols[j][r] = M31::from(((r + j) % 2) as u32);
            }
        }
        cols
    }

    fn to_circle_evals(
        log_size: u32,
        cols: &[Vec<M31>],
    ) -> Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> {
        let domain = CanonicCoset::new(log_size).circle_domain();
        cols.iter()
            .map(|col| {
                let base_col = BaseColumn::from_cpu(col.as_slice());
                CircleEvaluation::<SimdBackend, M31, NaturalOrder>::new(domain, base_col)
                    .bit_reverse()
            })
            .collect()
    }

    fn bitrev_permutation(log_size: u32) -> Vec<usize> {
        let n = 1usize << log_size;
        let mut permutation = vec![0usize; n];
        for (i, p) in permutation.iter_mut().enumerate() {
            let mut r = 0usize;
            let mut j = i;
            for _ in 0..log_size {
                r <<= 1;
                r |= j & 1;
                j >>= 1;
            }
            *p = r;
        }
        permutation
    }

    fn bitrev(log_size: u32, column: &[M31]) -> Vec<M31> {
        let permutation = bitrev_permutation(log_size);
        permutation.iter().map(|&r| column[r]).collect()
    }

    fn pack_vec(log_size: u32, column: &[M31], vector_row: usize) -> PackedBaseField {
        let n_rows = 1usize << log_size;
        let bitrevved = bitrev(log_size, column);
        let mut values = [M31::from(0u32); N_LANES];
        for (lane, value) in values.iter_mut().enumerate() {
            let row = vector_row * N_LANES + lane;
            *value = if row < n_rows { bitrevved[row] } else { M31::from(0u32) };
        }
        PackedBaseField::from_array(values)
    }

    /// 交互 trace（对齐 canonical_range_interaction：28 对 + 1 表列）。
    fn range_interaction(
        log_size: u32,
        cols: &[Vec<M31>],
        range: &ProbeRange8,
    ) -> (Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>>, SecureField) {
        let gate_col = &cols[0];
        let mult_col = 1 + N_BYTE_COLS;
        let tval_col = mult_col + 1;
        let mut generator = LogupTraceGenerator::new(log_size);
        for pair in 0..(N_BYTE_COLS / 2) {
            let mut col = generator.new_col();
            for vector_row in 0..(1usize << (log_size - N_LANES.ilog2())) {
                let gate = pack_vec(log_size, gate_col, vector_row);
                let d0: PackedSecureField =
                    range.combine(&[pack_vec(log_size, &cols[1 + 2 * pair], vector_row)]);
                let d1: PackedSecureField =
                    range.combine(&[pack_vec(log_size, &cols[1 + 2 * pair + 1], vector_row)]);
                let gate_secure = PackedSecureField::from(gate);
                col.write_frac(vector_row, gate_secure * (d0 + d1), d0 * d1);
            }
            col.finalize_col();
        }
        {
            let mut col = generator.new_col();
            for vector_row in 0..(1usize << (log_size - N_LANES.ilog2())) {
                let multiplicity_packed = pack_vec(log_size, &cols[mult_col], vector_row);
                let d: PackedSecureField =
                    range.combine(&[pack_vec(log_size, &cols[tval_col], vector_row)]);
                let numerator = -PackedSecureField::from(multiplicity_packed);
                col.write_frac(vector_row, numerator, d);
            }
            col.finalize_col();
        }
        generator.finalize_last()
    }

    /// 生成证明用例（原生）。返回 (case, 提交的各树列数)。
    pub fn prove_case(
        log_size: u32,
        n_scope: usize,
        n_trace: usize,
        hasher: u8,
    ) -> Result<(ProbeCase, Vec<Vec<u32>>), String> {
        assert!(log_size >= 8, "demo 需要 log_size ≥ 8（256 项查找表）");
        #[cfg(not(target_arch = "wasm32"))]
        if hasher == HASHER_POSEIDON252 {
            return prove_case_impl::<Poseidon252MerkleChannel>(
                log_size,
                n_scope,
                n_trace,
                hasher,
                HASHER_POSEIDON252,
            )
            .expect("prove_case_impl returned None");
        }
        if hasher == HASHER_BLAKE2S {
            prove_case_impl::<Blake2sMerkleChannel>(log_size, n_scope, n_trace, hasher, HASHER_BLAKE2S)
                .expect("prove_case_impl returned None")
        } else {
            Err("unknown hasher".into())
        }
    }

    fn prove_case_impl<MC>(
        log_size: u32,
        n_scope: usize,
        n_trace: usize,
        hasher_tag: u8,
        expected: u8,
    ) -> Option<Result<(ProbeCase, Vec<Vec<u32>>), String>>
    where
        MC: stwo::core::channel::MerkleChannel,
        MC::C: Channel,
        SimdBackend: stwo::prover::backend::BackendForChannel<MC>,
        StarkProof<MC::H>: serde::Serialize,
    {
        if hasher_tag != expected {
            return None;
        }
        let config = protocol_pcs_config();
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(log_size + config.fri_config.log_blowup_factor).half_coset(),
        );
        let mut channel = MC::C::default();
        mix_params(&mut channel, log_size, n_scope, n_trace);
        let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);

        // tree0：scope（P 列；第 0 列 = 全 1 选择子）。
        let scope_cols: Vec<Vec<M31>> = (0..n_scope)
            .map(|j| (0..(1usize << log_size)).map(|r| scope_value(j, r)).collect())
            .collect();
        let mut committed_log_sizes: Vec<Vec<u32>> = Vec::new();
        {
            let mut b = scheme.tree_builder();
            b.extend_evals(to_circle_evals(log_size, &scope_cols));
            b.commit(&mut channel);
            committed_log_sizes.push(vec![log_size; n_scope]);
        }

        // tree1：trace（N 列）。
        let trace_cols = build_trace(log_size, n_trace);
        {
            let mut b = scheme.tree_builder();
            b.extend_evals(to_circle_evals(log_size, &trace_cols));
            b.commit(&mut channel);
            committed_log_sizes.push(vec![log_size; n_trace]);
        }

        // tree2：LogUp 交互（29 QM31 → base 拆分）。
        let range = ProbeRange8::draw(&mut channel);
        let (interaction, range_sum) = range_interaction(log_size, &trace_cols, &range);
        channel.mix_felts(&[range_sum]);
        let n_interaction_base_cols = interaction.len();
        {
            let mut b = scheme.tree_builder();
            b.extend_evals(interaction);
            b.commit(&mut channel);
            committed_log_sizes.push(vec![log_size; n_interaction_base_cols]);
        }

        let ids = vec![preprocessed_col_id()];
        let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
        let component = FrameworkComponent::new(
            &mut allocator,
            ProbeAir {
                log_size,
                n_trace,
                range,
            },
            range_sum,
        );
        let proof = match prove(&[&component], &mut channel, scheme) {
            Ok(p) => p,
            Err(e) => return Some(Err(e.to_string())),
        };
        let range_claimed = range_sum.to_m31_array().map(|limb| limb.0);
        let stark_proof = match bincode::serialize(&proof) {
            Ok(b) => b,
            Err(e) => return Some(Err(format!("bincode serialize: {e}"))),
        };
        Some(Ok((
            ProbeCase {
                version: 2,
                hasher: hasher_tag,
                log_size,
                n_scope,
                n_trace,
                n_interaction_base_cols,
                range_claimed,
                stark_proof,
            },
            committed_log_sizes,
        )))
    }

    /// canonical verify 特有的额外开销：用 SimdBackend 重建并提交 scope 承诺
    /// （对齐 verify_canonical_stark L9453-9474：simd_twiddles + tree_builder + commit）。
    /// 返回 (twiddles_ms, tree_build_commit_ms)。
    pub fn scope_recommit_timings(
        log_size: u32,
        n_scope: usize,
        hasher: u8,
    ) -> Result<(f64, f64), String> {
        #[cfg(not(target_arch = "wasm32"))]
        if hasher == HASHER_POSEIDON252 {
            return scope_recommit_impl::<Poseidon252MerkleChannel>(log_size, n_scope);
        }
        if hasher == HASHER_BLAKE2S {
            scope_recommit_impl::<Blake2sMerkleChannel>(log_size, n_scope)
        } else {
            Err("unknown hasher".into())
        }
    }

    fn scope_recommit_impl<MC>(log_size: u32, n_scope: usize) -> Result<(f64, f64), String>
    where
        MC: stwo::core::channel::MerkleChannel,
        MC::C: Channel,
        SimdBackend: stwo::prover::backend::BackendForChannel<MC>,
    {
        let config = protocol_pcs_config();
        // 注意：std::time::Instant 在 wasm32-unknown-unknown 上 panic（无时钟 syscall），
        // wasm 上内部耗时返回 0，由 node 胶水测墙钟。
        #[cfg(not(target_arch = "wasm32"))]
        let t0 = std::time::Instant::now();
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(log_size + config.fri_config.log_blowup_factor).half_coset(),
        );
        #[cfg(not(target_arch = "wasm32"))]
        let twiddles_ms = t0.elapsed().as_secs_f64() * 1e3;
        #[cfg(target_arch = "wasm32")]
        let twiddles_ms = 0.0;

        let scope_cols: Vec<Vec<M31>> = (0..n_scope)
            .map(|j| (0..(1usize << log_size)).map(|r| scope_value(j, r)).collect())
            .collect();
        #[cfg(not(target_arch = "wasm32"))]
        let t1 = std::time::Instant::now();
        let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);
        let mut b = scheme.tree_builder();
        let evals = to_circle_evals(log_size, &scope_cols);
        b.extend_evals(evals);
        let mut channel = MC::C::default();
        b.commit(&mut channel);
        #[cfg(not(target_arch = "wasm32"))]
        let commit_ms = t1.elapsed().as_secs_f64() * 1e3;
        #[cfg(target_arch = "wasm32")]
        let commit_ms = 0.0;
        Ok((twiddles_ms, commit_ms))
    }
}

// ===== 验证路径（wasm / 通用） =====

/// 验证一个用例。成功返回 Ok(())，失败返回错误描述。
/// 注意：HASHER_POSEIDON252 在 wasm32 上不可达——stwo 2.3 将 Poseidon252
/// channel/merkle 模块 `#[cfg(not(target_arch = "wasm32"))]` 整体排除（见报告）。
#[allow(unused_variables)]
pub fn verify_case(case: &ProbeCase) -> Result<(), String> {
    #[cfg(not(target_arch = "wasm32"))]
    if case.hasher == HASHER_POSEIDON252 {
        return verify_case_impl::<PoseidonVerifierTypes>(case);
    }
    if case.hasher == HASHER_BLAKE2S {
        verify_case_impl::<Blake2sVerifierTypes>(case)
    } else {
        Err("unknown hasher (or hasher unavailable on this target)".into())
    }
}

/// 把 Poseidon/Blake2s 两条 verifier 类型路径统一成 trait，wasm 侧按 case.hasher 分发。
trait VerifierTypes {
    type MC: stwo::core::channel::MerkleChannel;
    fn deserialize_proof(
        bytes: &[u8],
    ) -> Result<StarkProof<<Self::MC as stwo::core::channel::MerkleChannel>::H>, String>;
}

#[cfg(not(target_arch = "wasm32"))]
struct PoseidonVerifierTypes;
#[cfg(not(target_arch = "wasm32"))]
impl VerifierTypes for PoseidonVerifierTypes {
    type MC = Poseidon252MerkleChannel;
    fn deserialize_proof(
        bytes: &[u8],
    ) -> Result<StarkProof<<Self::MC as stwo::core::channel::MerkleChannel>::H>, String> {
        bincode::deserialize(bytes).map_err(|e| format!("proof deserialize: {e}"))
    }
}

struct Blake2sVerifierTypes;
impl VerifierTypes for Blake2sVerifierTypes {
    type MC = Blake2sMerkleChannel;
    fn deserialize_proof(
        bytes: &[u8],
    ) -> Result<StarkProof<<Self::MC as stwo::core::channel::MerkleChannel>::H>, String> {
        bincode::deserialize(bytes).map_err(|e| format!("proof deserialize: {e}"))
    }
}

fn verify_case_impl<V: VerifierTypes>(case: &ProbeCase) -> Result<(), String> {
    type McOf<V> = <V as VerifierTypes>::MC;
    let proof: StarkProof<<McOf<V> as stwo::core::channel::MerkleChannel>::H> =
        V::deserialize_proof(&case.stark_proof)?;
    if proof.commitments.len() < 3 {
        return Err(format!(
            "expect 3 commitments, got {}",
            proof.commitments.len()
        ));
    }
    let config = protocol_pcs_config();
    let mut channel =
        <<V as VerifierTypes>::MC as stwo::core::channel::MerkleChannel>::C::default();
    mix_params(&mut channel, case.log_size, case.n_scope, case.n_trace);
    let mut scheme = CommitmentSchemeVerifier::<V::MC>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![case.log_size; case.n_scope],
        &mut channel,
    );
    scheme.commit(
        proof.commitments[1],
        &vec![case.log_size; case.n_trace],
        &mut channel,
    );
    let range = ProbeRange8::draw(&mut channel);
    let claimed = SecureField::from_m31_array(case.range_claimed.map(M31::from));
    channel.mix_felts(&[claimed]);
    scheme.commit(
        proof.commitments[2],
        &vec![case.log_size; case.n_interaction_base_cols],
        &mut channel,
    );
    let ids = vec![preprocessed_col_id()];
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        ProbeAir {
            log_size: case.log_size,
            n_trace: case.n_trace,
            range,
        },
        claimed,
    );
    verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|e: VerificationError| e.to_string())
}

// Poseidon 通道只在非 wasm32 存在（stwo 2.3 cfg 门），wasm 上只暴露 Blake2s。
#[cfg(not(target_arch = "wasm32"))]
use stwo::core::channel::Poseidon252Channel;
#[cfg(not(target_arch = "wasm32"))]
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;

// ===== wasm C ABI（node 胶水直连，无 wasm-bindgen 依赖） =====
#[cfg(target_arch = "wasm32")]
pub mod abi {
    use super::*;
    use std::cell::RefCell;
    use std::slice;

    thread_local! {
        static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
    }

    fn set_err(msg: String) {
        LAST_ERROR.with(|e| *e.borrow_mut() = msg);
    }

    #[no_mangle]
    pub extern "C" fn probe_alloc(len: usize) -> *mut u8 {
        let mut buf = Vec::<u8>::with_capacity(len);
        let ptr = buf.as_mut_ptr();
        core::mem::forget(buf);
        ptr
    }

    /// # Safety
    /// ptr 必须来自 probe_alloc 且 len 一致。
    #[no_mangle]
    pub unsafe extern "C" fn probe_free(ptr: *mut u8, len: usize) {
        if !ptr.is_null() {
            drop(Vec::from_raw_parts(ptr, 0, len));
        }
    }

    /// 返回 0 = 验证通过；<0 = 失败（-1 输入反序列化失败，-2 约束/FRI 验证失败，-3 其他）。
    ///
    /// # Safety
    /// ptr/len 指向 bincode 编码的 ProbeCase。
    #[no_mangle]
    pub unsafe extern "C" fn probe_verify(ptr: *const u8, len: usize) -> i32 {
        let bytes = match std::panic::catch_unwind(|| unsafe { slice::from_raw_parts(ptr, len) }) {
            Ok(b) => b,
            Err(_) => {
                set_err("bad pointer".into());
                return -3;
            }
        };
        let case: ProbeCase = match bincode::deserialize(bytes) {
            Ok(c) => c,
            Err(e) => {
                set_err(format!("case deserialize: {e}"));
                return -1;
            }
        };
        match super::verify_case(&case) {
            Ok(()) => 0,
            Err(msg) => {
                set_err(msg);
                -2
            }
        }
    }

    /// 把最近一次错误消息拷到调用方缓冲，返回拷贝长度。
    ///
    /// # Safety
    /// ptr/cap 指向调用方可写缓冲。
    #[no_mangle]
    pub unsafe extern "C" fn probe_last_error(ptr: *mut u8, cap: usize) -> usize {
        let msg = LAST_ERROR.with(|e| e.borrow().clone());
        let bytes = msg.as_bytes();
        let n = bytes.len().min(cap);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, n);
        }
        n
    }

    /// canonical verify 的 scope 重建承诺步骤（SimdBackend tree_builder+commit）
    /// 在 wasm32 上的延迟。返回 0 成功（结果毫秒写入 out：2×f64），-1 失败。
    ///
    /// # Safety
    /// out 指向 ≥16 字节可写缓冲。
    #[cfg(feature = "native-prover")]
    #[no_mangle]
    pub unsafe extern "C" fn probe_scope_commit(
        log_size: u32,
        n_scope: usize,
        out: *mut f64,
    ) -> i32 {
        use super::prover_path::scope_recommit_timings;
        match scope_recommit_timings(log_size, n_scope, HASHER_BLAKE2S) {
            Ok((twiddles_ms, commit_ms)) => {
                unsafe {
                    *out = twiddles_ms;
                    *out.add(1) = commit_ms;
                }
                0
            }
            Err(_) => -1,
        }
    }
}
