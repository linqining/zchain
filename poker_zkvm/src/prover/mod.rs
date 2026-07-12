//! 端到端 prover（Phase 7 — Task 7.1 / 7.2 / 7.3 实现）。
//!
//! 严格遵循 spec.md L689-696（v1.4 FROZEN）：
//! - [`prove`] — 端到端证明生成：ELF → 执行 → trace → CCS 实例 → Hypernova 折叠 → 压缩 → 上链 proof
//! - [`ProverConfig`] — prover 配置（batch_size / max_n_vars / proof_size_limit 等）
//! - [`ZkPublicIo`] — 公共输入输出（poker_zkvm 本地版本，Phase 11 与 poker_l1 对齐）
//!
//! ## 子模块
//!
//! - [`spartan`] — Spartan 压缩 stub（Phase 12 实现）
//! - [`groth16_compress`] — Groth16 压缩 stub（Phase 12 实现）
//!
//! ## 关键设计决策
//!
//! - **trace padding**：追加 dummy NOP Step 使 `trace.len() % batch_size == 0`，保证 CCS 结构一致
//! - **x_c = r_x_l**：MVP 简化 — CCCCS 的 x_c 使用与 LCCCS 相同的 r_x_l
//! - **proof 序列化 stub**：简单二进制编码，Phase 5.5 替换为 spec 规范格式
//! - **Spartan/Groth16 stub**：返回 Phase pending 错误，完整 SNARK 实现留待 Phase 12
//! - **num_vars 须为 2 的幂**：IPA PCS 要求 witness 长度为 2^m。当前 MVP 要求
//!   `batch_size + 1` 为 2 的幂（如 batch_size = 3 → num_vars = 4 = 2^2）。
//!   Phase 5 增强版将在 CCS 构造时自动 padding 到 2 的幂。

pub mod groth16_compress;
pub mod spartan;

use ark_serialize::CanonicalSerialize;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::ccs::Fr as ZkvmFr;
use crate::compiler::elf_validator::validate_elf;
use crate::constraints::compile_trace_to_ccs;
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::fold::fold_loop::{fold_loop, HypernovaProof};
use crate::isa::executor::{execute_elf_with_config, ZkvmExecutionConfig};
use crate::isa::Instruction;
use crate::pcs::ipa::{IpaPcs, MAX_N_VARS};
use crate::pcs::{MultilinearPoly, Pcs};
use crate::syscalls::StubHostState;
use crate::trace::{Step, Trace};
use crate::transcript::{Transcript, HYPERNOVA_FOLD_DOMAIN_TAG};

/// 上链 proof 字节数上限（spec L692 — 64KB）。
///
/// 超出此大小的 proof 须触发 CycleFold 递归压缩（Stage 3）。
/// batch_size=256 时单实例 proof（≤256 步）~48KB < 64KB，可直接上链。
pub const MAX_ZKVM_PROOF_SIZE: usize = 64 * 1024;

/// 最大递归深度（spec L565 / L694 — 16 层）。
///
/// CycleFold 递归聚合的深度上限，防无限递归。
pub const MAX_RECURSION_DEPTH: u32 = 16;

/// Prover 配置（spec L689-696）。
///
/// 控制 prove() 的 batching / PCS 上限 / proof 大小限制 / 递归深度等参数。
#[derive(Clone, Debug)]
pub struct ProverConfig {
    /// 每 batch 步数（默认 256，[`crate::constraints::ZKVM_BATCH_SIZE`] = 1024 为 spec 上限）。
    ///
    /// Stage 1.1 padding 保证 `num_vars`/`num_rows` 为 2 的幂，不再需要 `batch_size + 1` 为 2 的幂。
    /// batch_size=256 时单实例 proof（≤256 步）~48KB < 64KB 上链限制。
    pub batch_size: usize,
    /// IPA PCS 最大变量数（N = 2^max_n_vars ≤ 2^24）。
    pub max_n_vars: usize,
    /// proof 字节数上限（默认 [`MAX_ZKVM_PROOF_SIZE`]）。
    pub proof_size_limit: usize,
    /// CycleFold 递归深度上限（默认 [`MAX_RECURSION_DEPTH`]）。
    pub max_recursion_depth: u32,
    /// VRF 派生 seed（spec L221）。
    pub randomness_seed: ZkvmFr,
    /// host 初始承诺（spec L222）。
    pub initial_commitment: ZkvmFr,
    /// host 终止承诺（spec L222）。
    pub final_commitment: ZkvmFr,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            // batch_size=256：Stage 1.1 padding 保证 num_vars/num_rows 为 2 的幂，
            // 不再需要 batch_size+1 为 2 的幂。
            // 单实例 proof（≤256 步）~48KB < 64KB 上链限制。
            // 多步 proof（如 1000 步→4 batches→3 fold steps）~245KB，需 CycleFold 压缩至 64KB（Stage 3）。
            batch_size: 256,
            max_n_vars: 20,
            proof_size_limit: MAX_ZKVM_PROOF_SIZE,
            max_recursion_depth: MAX_RECURSION_DEPTH,
            randomness_seed: ZkvmFr::zero(),
            initial_commitment: ZkvmFr::zero(),
            final_commitment: ZkvmFr::zero(),
        }
    }
}

impl ProverConfig {
    /// 校验配置参数合法性。
    ///
    /// # 错误
    /// - `batch_size == 0`
    /// - `max_n_vars > MAX_N_VARS`（24）
    /// - `proof_size_limit == 0`
    pub fn validate(&self) -> Result<(), ZkvmError> {
        if self.batch_size == 0 {
            return Err(ZkvmError::Other(
                "ProverConfig: batch_size 须 > 0".to_string(),
            ));
        }
        if self.max_n_vars > MAX_N_VARS {
            return Err(ZkvmError::Other(format!(
                "ProverConfig: max_n_vars {} 超过上限 {MAX_N_VARS}",
                self.max_n_vars
            )));
        }
        if self.proof_size_limit == 0 {
            return Err(ZkvmError::Other(
                "ProverConfig: proof_size_limit 须 > 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// ZKVM 公共输入输出（poker_zkvm 本地版本，spec L59）。
///
/// Phase 11 集成时与 poker_l1 版本对齐。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkPublicIo {
    /// 程序输入
    pub input: Vec<u8>,
    /// 程序输出（`commit_output` 写入）
    pub output: Vec<u8>,
    /// VRF 派生 seed
    pub randomness_seed: ZkvmFr,
    /// host 初始承诺
    pub initial_commitment: ZkvmFr,
    /// host 终止承诺
    pub final_commitment: ZkvmFr,
    /// `emit_event` 产生的事件哈希列表
    pub event_hashes: Vec<ZkvmFr>,
}

impl ZkPublicIo {
    /// 序列化为简单二进制格式（length-prefixed）。
    ///
    /// 格式：
    /// - input_len(4B LE) || input
    /// - output_len(4B LE) || output
    /// - randomness_seed(32B)
    /// - initial_commitment(32B)
    /// - final_commitment(32B)
    /// - event_count(4B LE) || event_hashes(32B × count)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.input.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.input);
        out.extend_from_slice(&(self.output.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.output);
        out.extend_from_slice(&self.randomness_seed.to_canonical_bytes());
        out.extend_from_slice(&self.initial_commitment.to_canonical_bytes());
        out.extend_from_slice(&self.final_commitment.to_canonical_bytes());
        out.extend_from_slice(&(self.event_hashes.len() as u32).to_le_bytes());
        for h in &self.event_hashes {
            out.extend_from_slice(&h.to_canonical_bytes());
        }
        out
    }

    /// 从简单二进制格式反序列化。
    ///
    /// # 错误
    /// - `InvalidZkProofFormat` — 长度不足 / 字段长度越界
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkvmError> {
        let mut pos = 0usize;

        let input = read_length_prefixed(bytes, &mut pos)?;
        let output = read_length_prefixed(bytes, &mut pos)?;

        let randomness_seed = read_field(bytes, &mut pos)?;
        let initial_commitment = read_field(bytes, &mut pos)?;
        let final_commitment = read_field(bytes, &mut pos)?;

        let event_count = read_u32_le(bytes, &mut pos)? as usize;
        let mut event_hashes = Vec::with_capacity(event_count);
        for _ in 0..event_count {
            event_hashes.push(read_field(bytes, &mut pos)?);
        }

        Ok(Self {
            input,
            output,
            randomness_seed,
            initial_commitment,
            final_commitment,
            event_hashes,
        })
    }
}

/// 读取 length-prefixed 字节向量。
fn read_length_prefixed(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, ZkvmError> {
    let len = read_u32_le(bytes, pos)? as usize;
    let end = pos.checked_add(len).ok_or_else(|| {
        ZkvmError::InvalidZkProofFormat("ZkPublicIo: length overflow".to_string())
    })?;
    if end > bytes.len() {
        return Err(ZkvmError::InvalidZkProofFormat(
            "ZkPublicIo: data too short".to_string(),
        ));
    }
    let data = bytes[*pos..end].to_vec();
    *pos = end;
    Ok(data)
}

/// 读取 32B 域元素。
fn read_field(bytes: &[u8], pos: &mut usize) -> Result<ZkvmFr, ZkvmError> {
    let end = pos.checked_add(32).ok_or_else(|| {
        ZkvmError::InvalidZkProofFormat("ZkPublicIo: field overflow".to_string())
    })?;
    if end > bytes.len() {
        return Err(ZkvmError::InvalidZkProofFormat(
            "ZkPublicIo: field data too short".to_string(),
        ));
    }
    let field = ZkvmFr::from_canonical_bytes(&bytes[*pos..end])?;
    *pos = end;
    Ok(field)
}

/// 读取 4B LE u32。
fn read_u32_le(bytes: &[u8], pos: &mut usize) -> Result<u32, ZkvmError> {
    let end = pos.checked_add(4).ok_or_else(|| {
        ZkvmError::InvalidZkProofFormat("ZkPublicIo: u32 overflow".to_string())
    })?;
    if end > bytes.len() {
        return Err(ZkvmError::InvalidZkProofFormat(
            "ZkPublicIo: u32 data too short".to_string(),
        ));
    }
    let val = u32::from_le_bytes([bytes[*pos], bytes[*pos + 1], bytes[*pos + 2], bytes[*pos + 3]]);
    *pos = end;
    Ok(val)
}

/// proof 序列化 magic 头。
const PROOF_MAGIC: &[u8; 4] = b"HYPN";

/// proof 序列化版本号（v3 = 完整 verifier 版本，含 fold_steps + ccs_commitment + public_io_commitment；
/// v2 = 含 CCS 序列化，已废弃；v1 不含 CCS，已废弃）。
const PROOF_VERSION: u8 = 3;

/// proof 反序列化/DoS 总长度上限（512KB）。
///
/// 用途：`deserialize_proof` 在分配内存前先校验总长度，防止 OOM DoS。
/// 与 [`MAX_ZKVM_PROOF_SIZE`]（64KB 上链限制）的区别：
/// - 本常量 = 压缩前 proof 的反序列化上限（含所有 fold 步骤数据）
/// - [`MAX_ZKVM_PROOF_SIZE`] = 压缩后上链 proof 上限
///
/// batch_size=256 时多步 proof 大小参考：
/// - 100 步 → 1 batch → 单实例 ~48KB
/// - 500 步 → 2 batches → 1 fold step ~80KB
/// - 1000 步 → 4 batches → 3 fold steps ~245KB
///
/// 均远小于 512KB 限制。CycleFold 压缩（Stage 3）后可恢复至 64KB 上链。
pub const MAX_PROOF_TOTAL_SIZE: usize = 512 * 1024;

/// 计算 public_io 的承诺哈希（Blake2b-256，带域分离前缀）。
///
/// 用于将 proof 与 public_io 绑定，防止恶意 prover 替换 public_io（重放攻击）。
/// prover 在 transcript 初始化时 absorb 此哈希，verifier 重放时校验 `hash_public_io(public_io) == proof.public_io_commitment`。
///
/// # 格式
/// `Blake2b-256(b"poker_zkvm_public_io" || public_io.to_bytes())`
pub fn hash_public_io(public_io: &ZkPublicIo) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
    hasher.update(b"poker_zkvm_public_io");
    hasher.update(&public_io.to_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("Blake2bVar finalize 不应失败");
    out
}

/// 序列化 Lcccs 到输出缓冲（ccs_ref + u_l + x_l + trace_l + r_x_l + v_l）。
fn serialize_lcccs(lcccs: &crate::fold::lcccs::Lcccs, out: &mut Vec<u8>) -> Result<(), ZkvmError> {
    let ccs_bytes = lcccs.ccs_ref.to_bytes();
    out.extend_from_slice(&(ccs_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&ccs_bytes);

    out.extend_from_slice(&lcccs.u_l.to_canonical_bytes());

    out.extend_from_slice(&(lcccs.x_l.len() as u32).to_le_bytes());
    for x in &lcccs.x_l {
        out.extend_from_slice(&x.to_canonical_bytes());
    }
    out.extend_from_slice(&(lcccs.trace_l.len() as u32).to_le_bytes());
    for t in &lcccs.trace_l {
        out.extend_from_slice(&t.to_canonical_bytes());
    }
    out.extend_from_slice(&(lcccs.r_x_l.len() as u32).to_le_bytes());
    for r in &lcccs.r_x_l {
        out.extend_from_slice(&r.to_canonical_bytes());
    }
    out.extend_from_slice(&(lcccs.v_l.len() as u32).to_le_bytes());
    for v in &lcccs.v_l {
        out.extend_from_slice(&v.to_canonical_bytes());
    }
    Ok(())
}

/// 序列化 SumcheckProof 到输出缓冲（outer_round_polys + v_pp + inner_round_polys）。
fn serialize_sumcheck(
    sc: &crate::fold::sumcheck::SumcheckProof,
    out: &mut Vec<u8>,
) -> Result<(), ZkvmError> {
    out.extend_from_slice(&(sc.outer_round_polys.len() as u32).to_le_bytes());
    for round in &sc.outer_round_polys {
        out.extend_from_slice(&(round.len() as u32).to_le_bytes());
        for e in round {
            out.extend_from_slice(&e.to_canonical_bytes());
        }
    }
    out.extend_from_slice(&(sc.v_pp.len() as u32).to_le_bytes());
    for v in &sc.v_pp {
        out.extend_from_slice(&v.to_canonical_bytes());
    }
    out.extend_from_slice(&(sc.inner_round_polys.len() as u32).to_le_bytes());
    for round in &sc.inner_round_polys {
        out.extend_from_slice(&(round.len() as u32).to_le_bytes());
        for e in round {
            out.extend_from_slice(&e.to_canonical_bytes());
        }
    }
    Ok(())
}

/// 序列化 IpaCommitment（compressed G1 point, length-prefixed）。
fn serialize_commitment(
    cmt: &crate::pcs::ipa::IpaCommitment,
    out: &mut Vec<u8>,
) -> Result<(), ZkvmError> {
    let mut bytes = Vec::new();
    cmt.0
        .serialize_compressed(&mut bytes)
        .map_err(|e| ZkvmError::Other(format!("serialize commitment: {e}")))?;
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&bytes);
    Ok(())
}

/// 序列化 Fr 切片（length-prefixed）。
fn serialize_fr_slice(elems: &[ZkvmFr], out: &mut Vec<u8>) {
    out.extend_from_slice(&(elems.len() as u32).to_le_bytes());
    for e in elems {
        out.extend_from_slice(&e.to_canonical_bytes());
    }
}

/// 序列化 IpaProof（l_vec + r_vec + a_final）。
fn serialize_ipa_proof(
    opening: &crate::pcs::ipa::IpaProof,
    out: &mut Vec<u8>,
) -> Result<(), ZkvmError> {
    out.extend_from_slice(&(opening.l_vec.len() as u32).to_le_bytes());
    for p in &opening.l_vec {
        let mut b = Vec::new();
        p.serialize_compressed(&mut b)
            .map_err(|e| ZkvmError::Other(format!("serialize L point: {e}")))?;
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(&b);
    }
    out.extend_from_slice(&(opening.r_vec.len() as u32).to_le_bytes());
    for p in &opening.r_vec {
        let mut b = Vec::new();
        p.serialize_compressed(&mut b)
            .map_err(|e| ZkvmError::Other(format!("serialize R point: {e}")))?;
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(&b);
    }
    out.extend_from_slice(&opening.a_final.to_canonical_bytes());
    Ok(())
}

/// 序列化 HypernovaProof 为二进制格式（v3 — 完整 verifier 版本）。
///
/// 格式（v3）：
/// - magic(4B) + version(1B) + abi_version(1B)
/// - ccs_commitment(32B) + public_io_commitment(32B)
/// - batch_public_inputs: count(4B LE) + 每组 [count(4B LE) + Fr×count]
/// - initial_lcccs(ccs_ref + u_l + x_l + trace_l + r_x_l + v_l)
/// - initial_witness_commitment(compressed G1, len-prefixed)
/// - fold_steps: count(4B LE) + 每步:
///   ccccs_witness_commitment + ccccs_u_c + ccccs_x_c + ccccs_trace_c
///   + sumcheck_proof + r_y + z_at_r_y + actual_u_prime
///   + folded_lcccs + folded_witness_commitment
/// - final_sumcheck(outer_round_polys + v_pp + inner_round_polys)
/// - pcs_opening(l_vec + r_vec + a_final)
/// - r_y(length-prefixed Fr 序列) + z_at_point(32B Fr)
pub fn serialize_proof(proof: &HypernovaProof) -> Result<Vec<u8>, ZkvmError> {
    let mut out = Vec::new();
    out.extend_from_slice(PROOF_MAGIC);
    out.push(PROOF_VERSION);
    out.push(proof.abi_version);

    // ccs_commitment + public_io_commitment
    out.extend_from_slice(&proof.ccs_commitment);
    out.extend_from_slice(&proof.public_io_commitment);

    // batch_public_inputs: count + 每组 [count + Fr×count]
    out.extend_from_slice(&(proof.batch_public_inputs.len() as u32).to_le_bytes());
    for group in &proof.batch_public_inputs {
        serialize_fr_slice(group, &mut out);
    }

    // initial_lcccs
    serialize_lcccs(&proof.initial_lcccs, &mut out)?;

    // initial_witness_commitment
    serialize_commitment(&proof.initial_witness_commitment, &mut out)?;

    // fold_steps
    out.extend_from_slice(&(proof.fold_steps.len() as u32).to_le_bytes());
    for step in &proof.fold_steps {
        // ccccs_witness_commitment
        serialize_commitment(&step.ccccs_witness_commitment, &mut out)?;
        // ccccs_u_c + ccccs_x_c + ccccs_trace_c
        out.extend_from_slice(&step.ccccs_u_c.to_canonical_bytes());
        serialize_fr_slice(&step.ccccs_x_c, &mut out);
        serialize_fr_slice(&step.ccccs_trace_c, &mut out);
        // sumcheck_proof
        serialize_sumcheck(&step.sumcheck_proof, &mut out)?;
        // r_y + z_at_r_y + actual_u_prime
        serialize_fr_slice(&step.r_y, &mut out);
        out.extend_from_slice(&step.z_at_r_y.to_canonical_bytes());
        out.extend_from_slice(&step.actual_u_prime.to_canonical_bytes());
        // folded_lcccs + folded_witness_commitment
        serialize_lcccs(&step.folded_lcccs, &mut out)?;
        serialize_commitment(&step.folded_witness_commitment, &mut out)?;
    }

    // final_sumcheck
    serialize_sumcheck(&proof.final_sumcheck, &mut out)?;

    // pcs_opening
    serialize_ipa_proof(&proof.pcs_opening, &mut out)?;

    // r_y + z_at_point
    serialize_fr_slice(&proof.r_y, &mut out);
    out.extend_from_slice(&proof.z_at_point.to_canonical_bytes());

    Ok(out)
}

/// 反序列化 Lcccs（ccs_ref + u_l + x_l + trace_l + r_x_l + v_l），含维度校验。
fn deserialize_lcccs(bytes: &[u8], pos: &mut usize) -> Result<crate::fold::lcccs::Lcccs, ZkvmError> {
    let ccs_bytes = read_length_prefixed(bytes, pos)?;
    let ccs_ref = crate::ccs::Ccs::from_bytes(&ccs_bytes)?;

    let u_l = read_field(bytes, pos)?;

    let x_l_len = read_u32_le(bytes, pos)? as usize;
    let mut x_l = Vec::with_capacity(x_l_len);
    for _ in 0..x_l_len {
        x_l.push(read_field(bytes, pos)?);
    }
    let trace_l_len = read_u32_le(bytes, pos)? as usize;
    let mut trace_l = Vec::with_capacity(trace_l_len);
    for _ in 0..trace_l_len {
        trace_l.push(read_field(bytes, pos)?);
    }
    let r_x_l_len = read_u32_le(bytes, pos)? as usize;
    let mut r_x_l = Vec::with_capacity(r_x_l_len);
    for _ in 0..r_x_l_len {
        r_x_l.push(read_field(bytes, pos)?);
    }
    let v_l_len = read_u32_le(bytes, pos)? as usize;
    let mut v_l = Vec::with_capacity(v_l_len);
    for _ in 0..v_l_len {
        v_l.push(read_field(bytes, pos)?);
    }

    crate::fold::lcccs::Lcccs::new(ccs_ref, u_l, x_l, trace_l, r_x_l, v_l)
}

/// 反序列化 SumcheckProof（outer_round_polys + v_pp + inner_round_polys）。
fn deserialize_sumcheck(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<crate::fold::sumcheck::SumcheckProof, ZkvmError> {
    let outer_len = read_u32_le(bytes, pos)? as usize;
    let mut outer_round_polys = Vec::with_capacity(outer_len);
    for _ in 0..outer_len {
        let round_len = read_u32_le(bytes, pos)? as usize;
        let mut round = Vec::with_capacity(round_len);
        for _ in 0..round_len {
            round.push(read_field(bytes, pos)?);
        }
        outer_round_polys.push(round);
    }
    let v_pp_len = read_u32_le(bytes, pos)? as usize;
    let mut v_pp = Vec::with_capacity(v_pp_len);
    for _ in 0..v_pp_len {
        v_pp.push(read_field(bytes, pos)?);
    }
    let inner_len = read_u32_le(bytes, pos)? as usize;
    let mut inner_round_polys = Vec::with_capacity(inner_len);
    for _ in 0..inner_len {
        let round_len = read_u32_le(bytes, pos)? as usize;
        let mut round = Vec::with_capacity(round_len);
        for _ in 0..round_len {
            round.push(read_field(bytes, pos)?);
        }
        inner_round_polys.push(round);
    }
    Ok(crate::fold::sumcheck::SumcheckProof {
        outer_round_polys,
        v_pp,
        inner_round_polys,
    })
}

/// 反序列化 IpaCommitment（compressed G1 point, length-prefixed）。
fn deserialize_commitment(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<crate::pcs::ipa::IpaCommitment, ZkvmError> {
    use ark_serialize::CanonicalDeserialize;
    let b = read_length_prefixed(bytes, pos)?;
    let point = ark_bn254::G1Affine::deserialize_compressed(&b[..])
        .map_err(|e| ZkvmError::Other(format!("deserialize commitment: {e}")))?;
    Ok(crate::pcs::ipa::IpaCommitment(point))
}

/// 反序列化 Fr 切片（length-prefixed）。
fn deserialize_fr_slice(bytes: &[u8], pos: &mut usize) -> Result<Vec<ZkvmFr>, ZkvmError> {
    let len = read_u32_le(bytes, pos)? as usize;
    let mut elems = Vec::with_capacity(len);
    for _ in 0..len {
        elems.push(read_field(bytes, pos)?);
    }
    Ok(elems)
}

/// 反序列化 IpaProof（l_vec + r_vec + a_final）。
fn deserialize_ipa_proof(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<crate::pcs::ipa::IpaProof, ZkvmError> {
    use ark_serialize::CanonicalDeserialize;
    let l_vec_len = read_u32_le(bytes, pos)? as usize;
    let mut l_vec = Vec::with_capacity(l_vec_len);
    for _ in 0..l_vec_len {
        let b = read_length_prefixed(bytes, pos)?;
        l_vec.push(
            ark_bn254::G1Affine::deserialize_compressed(&b[..])
                .map_err(|e| ZkvmError::Other(format!("deserialize L point: {e}")))?,
        );
    }
    let r_vec_len = read_u32_le(bytes, pos)? as usize;
    let mut r_vec = Vec::with_capacity(r_vec_len);
    for _ in 0..r_vec_len {
        let b = read_length_prefixed(bytes, pos)?;
        r_vec.push(
            ark_bn254::G1Affine::deserialize_compressed(&b[..])
                .map_err(|e| ZkvmError::Other(format!("deserialize R point: {e}")))?,
        );
    }
    let a_final = read_field(bytes, pos)?;
    Ok(crate::pcs::ipa::IpaProof {
        l_vec,
        r_vec,
        a_final,
    })
}

/// 反序列化 HypernovaProof（v3 格式）。
///
/// 校验 magic / version / abi_version；总长度优先校验（v1.3 M2-002）；
/// 反序列化后各 Lcccs 由 `Lcccs::new` 校验维度一致性。
pub fn deserialize_proof(bytes: &[u8]) -> Result<HypernovaProof, ZkvmError> {
    // 总长度优先校验
    if bytes.len() > MAX_PROOF_TOTAL_SIZE {
        return Err(ZkvmError::InvalidZkProofFormat(format!(
            "proof 总长度 {} > MAX_PROOF_TOTAL_SIZE {}",
            bytes.len(),
            MAX_PROOF_TOTAL_SIZE
        )));
    }
    if bytes.len() < 6 {
        return Err(ZkvmError::InvalidZkProofFormat(format!(
            "proof 头部过短：{} < 6",
            bytes.len()
        )));
    }
    // magic
    if &bytes[0..4] != PROOF_MAGIC {
        return Err(ZkvmError::InvalidZkProofFormat(
            "proof magic 不匹配".to_string(),
        ));
    }
    // version
    let version = bytes[4];
    if version != PROOF_VERSION {
        return Err(ZkvmError::InvalidZkProofFormat(format!(
            "proof version {version} != {} (v3 完整 verifier 版本)",
            PROOF_VERSION
        )));
    }
    let abi_version = bytes[5];
    let mut pos: usize = 6;

    // ccs_commitment + public_io_commitment（各 32B）
    let mut ccs_commitment = [0u8; 32];
    let mut public_io_commitment = [0u8; 32];
    let end_ccs = pos.checked_add(32).ok_or_else(|| {
        ZkvmError::InvalidZkProofFormat("ccs_commitment overflow".to_string())
    })?;
    if end_ccs > bytes.len() {
        return Err(ZkvmError::InvalidZkProofFormat(
            "ccs_commitment data too short".to_string(),
        ));
    }
    ccs_commitment.copy_from_slice(&bytes[pos..end_ccs]);
    pos = end_ccs;
    let end_pio = pos.checked_add(32).ok_or_else(|| {
        ZkvmError::InvalidZkProofFormat("public_io_commitment overflow".to_string())
    })?;
    if end_pio > bytes.len() {
        return Err(ZkvmError::InvalidZkProofFormat(
            "public_io_commitment data too short".to_string(),
        ));
    }
    public_io_commitment.copy_from_slice(&bytes[pos..end_pio]);
    pos = end_pio;

    // batch_public_inputs: count + 每组 [count + Fr×count]
    let batch_count = read_u32_le(bytes, &mut pos)? as usize;
    let mut batch_public_inputs = Vec::with_capacity(batch_count);
    for _ in 0..batch_count {
        batch_public_inputs.push(deserialize_fr_slice(bytes, &mut pos)?);
    }

    // initial_lcccs
    let initial_lcccs = deserialize_lcccs(bytes, &mut pos)?;

    // initial_witness_commitment
    let initial_witness_commitment = deserialize_commitment(bytes, &mut pos)?;

    // fold_steps
    let fold_steps_count = read_u32_le(bytes, &mut pos)? as usize;
    let mut fold_steps = Vec::with_capacity(fold_steps_count);
    for _ in 0..fold_steps_count {
        let ccccs_witness_commitment = deserialize_commitment(bytes, &mut pos)?;
        let ccccs_u_c = read_field(bytes, &mut pos)?;
        let ccccs_x_c = deserialize_fr_slice(bytes, &mut pos)?;
        let ccccs_trace_c = deserialize_fr_slice(bytes, &mut pos)?;
        let sumcheck_proof = deserialize_sumcheck(bytes, &mut pos)?;
        let r_y = deserialize_fr_slice(bytes, &mut pos)?;
        let z_at_r_y = read_field(bytes, &mut pos)?;
        let actual_u_prime = read_field(bytes, &mut pos)?;
        let folded_lcccs = deserialize_lcccs(bytes, &mut pos)?;
        let folded_witness_commitment = deserialize_commitment(bytes, &mut pos)?;
        fold_steps.push(crate::fold::fold_loop::FoldStepData {
            ccccs_witness_commitment,
            ccccs_u_c,
            ccccs_x_c,
            ccccs_trace_c,
            sumcheck_proof,
            r_y,
            z_at_r_y,
            actual_u_prime,
            folded_lcccs,
            folded_witness_commitment,
        });
    }

    // final_sumcheck
    let final_sumcheck = deserialize_sumcheck(bytes, &mut pos)?;

    // pcs_opening
    let pcs_opening = deserialize_ipa_proof(bytes, &mut pos)?;

    // r_y + z_at_point
    let r_y = deserialize_fr_slice(bytes, &mut pos)?;
    let z_at_point = read_field(bytes, &mut pos)?;

    Ok(HypernovaProof {
        abi_version,
        ccs_commitment,
        public_io_commitment,
        batch_public_inputs,
        initial_lcccs,
        initial_witness_commitment,
        fold_steps,
        final_sumcheck,
        pcs_opening,
        r_y,
        z_at_point,
    })
}

/// 端到端证明生成（spec L689-696）。
///
/// # 流程
/// 1. `validate_elf` → ElfMetadata
/// 2. `execute_elf_with_config` → ExecuteResult（trace + output + events）
/// 3. trace padding（dummy NOP Step）使 `trace.len() % batch_size == 0`
/// 4. `compile_trace_to_ccs` → Vec<CcsInstance>
/// 5. CCS 一致性校验（所有实例共享同一 CCS 结构）
/// 6. 创建 IpaPcs + Transcript
/// 7. 第一个 CcsInstance → LCCCS，其余 → CCCCS
/// 8. `fold_loop` → HypernovaProof
/// 9. `serialize_proof` → proof_bytes
/// 10. proof 大小检查
///
/// # 参数
/// - `elf_bytes` — ELF 字节
/// - `input` — 程序输入
/// - `config` — prover 配置
///
/// # 返回
/// `(proof_bytes, ZkPublicIo)`
///
/// # 错误
/// - `InvalidZkProofFormat` — ELF 校验失败
/// - `TraceTooLong` — trace 步数超限
/// - `FoldStepCountExceeded` — batch 数超限
/// - `FoldError` — CCS 结构不一致
/// - `Other` — proof 过大 / num_vars 非 2 的幂 / 实例数不足
pub fn prove(
    elf_bytes: &[u8],
    input: &[u8],
    config: &ProverConfig,
) -> Result<(Vec<u8>, ZkPublicIo), ZkvmError> {
    config.validate()?;

    // 1. ELF 校验
    let _metadata = validate_elf(elf_bytes)?;

    // 2. 执行
    let exec_config = ZkvmExecutionConfig {
        input: input.to_vec(),
        randomness_seed: config.randomness_seed.into_fr(),
        initial_commitment: config.initial_commitment.into_fr(),
        final_commitment: config.final_commitment.into_fr(),
        host_state: Box::new(StubHostState),
    };
    let exec_result = execute_elf_with_config(elf_bytes, exec_config)?;

    // 2.5 提前构造 ZkPublicIo（需在 transcript 初始化前计算 public_io_commitment）
    // 所有字段在执行后均已可用：input/output/randomness_seed/initial_commitment/final_commitment/event_hashes
    let public_io = ZkPublicIo {
        input: input.to_vec(),
        output: exec_result.output.clone(),
        randomness_seed: config.randomness_seed,
        initial_commitment: config.initial_commitment,
        final_commitment: config.final_commitment,
        event_hashes: exec_result
            .events
            .iter()
            .map(|f| ZkvmFr::from_fr(*f))
            .collect(),
    };
    let public_io_commitment = hash_public_io(&public_io);

    // 3. trace padding
    let mut trace = exec_result.trace;
    pad_trace(&mut trace, config.batch_size)?;

    // 4. 编译 CCS 实例
    let ccs_instances = compile_trace_to_ccs(&trace, config.batch_size)?;

    if ccs_instances.is_empty() {
        return Err(ZkvmError::Other(
            "prove: CCS 实例为空（trace 为空或 batch_size 过大）".to_string(),
        ));
    }

    // 5. CCS 一致性校验 + num_vars 须为 2 的幂（由 compile_batch_to_ccs padding 保证）
    let ccs = ccs_instances[0].ccs.clone();
    let num_vars = ccs.num_vars;
    if !num_vars.is_power_of_two() {
        return Err(ZkvmError::Other(format!(
            "prove: num_vars = {num_vars} 不是 2 的幂（IPA PCS 要求）。\
             compile_batch_to_ccs 应已 padding，此错误表示 padding 逻辑缺陷"
        )));
    }
    let pcs_n_vars = num_vars.trailing_zeros() as usize;
    if pcs_n_vars > config.max_n_vars {
        return Err(ZkvmError::Other(format!(
            "prove: pcs_n_vars = {pcs_n_vars} > config.max_n_vars = {}",
            config.max_n_vars
        )));
    }

    let expected_commitment = ccs.ccs_commitment();
    for inst in &ccs_instances {
        let commit = inst.ccs.ccs_commitment();
        if commit != expected_commitment {
            return Err(ZkvmError::FoldError(format!(
                "CCS 结构不一致: 首实例 commitment {:?} != 当前 {:?}",
                &expected_commitment[..8],
                &commit[..8]
            )));
        }
    }

    // 6. 创建 PCS + Transcript
    let pcs = IpaPcs::new(pcs_n_vars)?;
    let mut transcript = Transcript::with_domain(b"poker_zkvm_prover_v1");

    // absorb public_io_commitment 在 ccs_commitment 之前（verifier 需重放相同顺序）
    transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &public_io_commitment);
    transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &expected_commitment);

    // 收集 batch_public_inputs（每组 [batch_id, first_idx, last_idx]），并 absorb 到 transcript
    let batch_public_inputs: Vec<Vec<ZkvmFr>> = ccs_instances
        .iter()
        .map(|inst| inst.public_inputs.clone())
        .collect();
    for inst in &ccs_instances {
        for pi in &inst.public_inputs {
            transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, pi);
        }
    }

    // 7. 派生 r_x_l（长度 = log2(num_rows)）
    let num_rows = ccs.num_rows();
    let r_x_l_len = if num_rows > 0 && num_rows.is_power_of_two() {
        num_rows.trailing_zeros() as usize
    } else {
        return Err(ZkvmError::Other(format!(
            "prove: num_rows = {num_rows} 不是 2 的幂（sumcheck 要求）"
        )));
    };
    let r_x_l: Vec<ZkvmFr> = (0..r_x_l_len)
        .map(|_| transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG))
        .collect();

    // 8. 转换 CcsInstance → LCCCS / CCCCS
    // x_l / x_c 均为 r_x_l（长度 = log2(num_rows)），不是 CcsInstance.public_inputs。
    // CcsInstance.public_inputs（[batch_id, first_idx, last_idx]）用于 verifier 侧 batch 连续性校验，
    // 已在 step 6 absorb 到 transcript 中，不参与 fold 协议。
    let first = &ccs_instances[0];
    let initial_lcccs = ccs.to_lcccs(&first.witness, &r_x_l, r_x_l.clone())?;

    let initial_poly = MultilinearPoly::from_evals(first.witness.clone())?;
    let initial_commitment = pcs.commit(&initial_poly)?;

    let mut ccccs_instances = Vec::with_capacity(ccs_instances.len().saturating_sub(1));
    for inst in &ccs_instances[1..] {
        let poly = MultilinearPoly::from_evals(inst.witness.clone())?;
        let commitment = pcs.commit(&poly)?;
        let ccccs = ccs.to_cccs(&inst.witness, r_x_l.clone(), commitment)?;
        ccccs_instances.push(ccccs);
    }

    // 9. fold_loop（传递 ccs_commitment + public_io_commitment + batch_public_inputs）
    let proof = fold_loop(
        &ccs,
        initial_lcccs,
        initial_commitment,
        &ccccs_instances,
        &pcs,
        &mut transcript,
        expected_commitment,
        public_io_commitment,
        batch_public_inputs,
    )?;

    // 10. 序列化
    let proof_bytes = serialize_proof(&proof)?;

    // 11. proof 大小检查
    if proof_bytes.len() > config.proof_size_limit {
        return Err(ZkvmError::Other(format!(
            "proof 过大 ({} bytes > {} limit)，须 CycleFold 压缩（Phase 12）",
            proof_bytes.len(),
            config.proof_size_limit
        )));
    }

    Ok((proof_bytes, public_io))
}

/// 对 trace 追加 dummy NOP Step 使其长度整除 batch_size。
///
/// padding Step 的 step_index 从原 trace 末步 +1 开始递增，
/// pc 从原 trace 末步 pc + 4 开始递增（保证 PC 连续性约束 Group B 成立），
/// instruction = `Addi { rd: 0, rs1: 0, imm: 0 }`（RISC-V NOP），
/// registers = [0; 32]，mem_access = vec![]。
///
/// padding 不影响执行结果（output/events 已在 ExecuteResult 中固定），
/// 仅保证所有 batch 生成相同结构的 CCS（num_vars / num_rows 一致）。
fn pad_trace(trace: &mut Trace, batch_size: usize) -> Result<(), ZkvmError> {
    if batch_size == 0 {
        return Err(ZkvmError::Other(
            "pad_trace: batch_size 须 > 0".to_string(),
        ));
    }
    let len = trace.len();
    let remainder = len % batch_size;
    if remainder == 0 {
        return Ok(());
    }
    let pad_count = batch_size - remainder;
    let mut next_index = if len == 0 {
        0
    } else {
        trace.step(len - 1)?.step_index + 1
    };
    let mut next_pc = if len == 0 {
        0
    } else {
        trace.step(len - 1)?.pc.wrapping_add(4)
    };
    for _ in 0..pad_count {
        trace.push_step(Step {
            step_index: next_index,
            pc: next_pc,
            instruction: Instruction::Addi {
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            registers: [0u32; 32],
            mem_access: vec![],
        });
        next_index += 1;
        next_pc = next_pc.wrapping_add(4);
    }
    Ok(())
}

/// 测试辅助：生成合法 proof bytes + public_io（供其他模块测试使用）。
///
/// 构造 5 步程序（3 NOP + commit_output + ECALL），batch_size=3。
///
/// **注意**：此函数为测试辅助函数，仅在 `test` 或 `test-helpers` feature 启用时可用。
/// 跨 crate 测试（如 poker_l1 集成测试）需在 `Cargo.toml` 中启用 `poker_zkvm` 的 `test-helpers` feature。
#[cfg(any(test, feature = "test-helpers"))]
pub fn generate_test_proof() -> (Vec<u8>, ZkPublicIo) {
    // 编码 I-type 指令
    fn encode_i(opcode: u32, funct3: u8, rd: u8, rs1: u8, imm12: u32) -> u32 {
        ((imm12 & 0xFFF) << 20)
            | ((rs1 as u32) << 15)
            | ((funct3 as u32) << 12)
            | ((rd as u32) << 7)
            | opcode
    }

    // 构造最小 ELF32
    fn build_test_elf(entry: u32, text_vaddr: u32, text_bytes: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(84 + text_bytes.len());
        bytes.extend_from_slice(&[
            0x7f, b'E', b'L', b'F',
            1, 1, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&0xF3u16.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&entry.to_le_bytes());
        bytes.extend_from_slice(&52u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&52u16.to_le_bytes());
        bytes.extend_from_slice(&32u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&40u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let p_offset = 84u32;
        let p_filesz = text_bytes.len() as u32;
        let p_memsz = text_bytes.len() as u32;
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&p_offset.to_le_bytes());
        bytes.extend_from_slice(&text_vaddr.to_le_bytes());
        bytes.extend_from_slice(&text_vaddr.to_le_bytes());
        bytes.extend_from_slice(&p_filesz.to_le_bytes());
        bytes.extend_from_slice(&p_memsz.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&0x1000u32.to_le_bytes());
        bytes.extend_from_slice(text_bytes);
        bytes
    }

    // 将 u32 指令序列编码为 LE 字节
    fn encode_text(words: &[u32]) -> Vec<u8> {
        words.iter().copied().flat_map(u32::to_le_bytes).collect()
    }

    let text = encode_text(&[
        // LUI a0, 1 — a0 = 0x1000 (text segment start, 32 bytes 可读)
        (1 << 12) | (10 << 7) | 0x37,
        encode_i(0x13, 0, 11, 0, 32),  // ADDI a1, x0, 32 (output len = 32 bytes)
        encode_i(0x13, 0, 17, 0, 2),   // ADDI a7, x0, 2 (commit_output)
        0x00000073,                     // ECALL
        encode_i(0x13, 0, 0, 0, 0),    // NOP (padding 使 text ≥ 32 bytes)
        encode_i(0x13, 0, 0, 0, 0),    // NOP
        encode_i(0x13, 0, 0, 0, 0),    // NOP
        encode_i(0x13, 0, 0, 0, 0),    // NOP
    ]);
    let elf = build_test_elf(0x1000, 0x1000, &text);

    let config = ProverConfig {
        batch_size: 3,
        proof_size_limit: MAX_PROOF_TOTAL_SIZE,
        ..Default::default()
    };

    // 使用 32 字节 input，使 poker_l1 public_io 双向转换可逆
    let input = vec![0u8; 32];
    prove(&elf, &input, &config).expect("prove 应成功")
}

/// 测试辅助：生成单实例 proof bytes + public_io。
///
/// 构造 2 步程序（ADDI + ECALL），batch_size=3 → padding 到 3 步 → 1 batch → 单实例 proof。
/// 用于验证单实例 proof 路径的端到端 verify。
#[cfg(any(test, feature = "test-helpers"))]
pub fn generate_single_instance_test_proof() -> (Vec<u8>, ZkPublicIo) {
    fn encode_i(opcode: u32, funct3: u8, rd: u8, rs1: u8, imm12: u32) -> u32 {
        ((imm12 & 0xFFF) << 20)
            | ((rs1 as u32) << 15)
            | ((funct3 as u32) << 12)
            | ((rd as u32) << 7)
            | opcode
    }

    fn build_test_elf(entry: u32, text_vaddr: u32, text_bytes: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(84 + text_bytes.len());
        bytes.extend_from_slice(&[
            0x7f, b'E', b'L', b'F',
            1, 1, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&0xF3u16.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&entry.to_le_bytes());
        bytes.extend_from_slice(&52u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&52u16.to_le_bytes());
        bytes.extend_from_slice(&32u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&40u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let p_offset = 84u32;
        let p_filesz = text_bytes.len() as u32;
        let p_memsz = text_bytes.len() as u32;
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&p_offset.to_le_bytes());
        bytes.extend_from_slice(&text_vaddr.to_le_bytes());
        bytes.extend_from_slice(&text_vaddr.to_le_bytes());
        bytes.extend_from_slice(&p_filesz.to_le_bytes());
        bytes.extend_from_slice(&p_memsz.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&0x1000u32.to_le_bytes());
        bytes.extend_from_slice(text_bytes);
        bytes
    }

    fn encode_text(words: &[u32]) -> Vec<u8> {
        words.iter().copied().flat_map(u32::to_le_bytes).collect()
    }

    let text = encode_text(&[
        encode_i(0x13, 0, 17, 0, 2),  // ADDI a7, x0, 2 (commit_output)
        0x00000073,                     // ECALL
    ]);
    let elf = build_test_elf(0x1000, 0x1000, &text);

    let config = ProverConfig {
        batch_size: 3,
        proof_size_limit: MAX_PROOF_TOTAL_SIZE,
        ..Default::default()
    };

    let input = vec![0u8; 32];
    prove(&elf, &input, &config).expect("单实例 prove 应成功")
}

/// 构造默认 CCS 白名单（从 `generate_test_proof` 提取 ccs_commitment）。
///
/// **MVP 权宜之计**：仅供测试、基准测试和 MVP 生产调用方使用。
/// 生产环境应由链上治理配置白名单。
#[cfg(any(test, feature = "test-helpers"))]
pub fn default_ccs_whitelist() -> Vec<[u8; 32]> {
    let (proof_bytes, _) = generate_test_proof();
    let proof = deserialize_proof(&proof_bytes)
        .expect("deserialize generate_test_proof 应成功");
    vec![proof.ccs_commitment]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== ProverConfig 测试 =====

    #[test]
    fn test_prover_config_default_valid() {
        let config = ProverConfig::default();
        config.validate().expect("默认配置应通过校验");
        // 默认 batch_size = 256（Stage 1.1 padding 后不再需要 2 的幂约束）
        assert_eq!(config.batch_size, 256);
        assert_eq!(config.max_n_vars, 20);
        assert_eq!(config.proof_size_limit, MAX_ZKVM_PROOF_SIZE);
        assert_eq!(config.max_recursion_depth, MAX_RECURSION_DEPTH);
    }

    #[test]
    fn test_prover_config_zero_batch_size_rejected() {
        let config = ProverConfig {
            batch_size: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref m) if m.contains("batch_size")));
    }

    #[test]
    fn test_prover_config_max_n_vars_exceeded() {
        let config = ProverConfig {
            max_n_vars: MAX_N_VARS + 1,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref m) if m.contains("max_n_vars")));
    }

    #[test]
    fn test_prover_config_max_n_vars_at_limit_ok() {
        let config = ProverConfig {
            max_n_vars: MAX_N_VARS,
            ..Default::default()
        };
        config.validate().expect("max_n_vars = MAX_N_VARS 应通过");
    }

    #[test]
    fn test_prover_config_zero_proof_size_limit_rejected() {
        let config = ProverConfig {
            proof_size_limit: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref m) if m.contains("proof_size_limit")));
    }

    // ===== ZkPublicIo 序列化测试 =====

    #[test]
    fn test_zk_public_io_roundtrip_empty() {
        let io = ZkPublicIo {
            input: vec![],
            output: vec![],
            randomness_seed: ZkvmFr::zero(),
            initial_commitment: ZkvmFr::zero(),
            final_commitment: ZkvmFr::zero(),
            event_hashes: vec![],
        };
        let bytes = io.to_bytes();
        let restored = ZkPublicIo::from_bytes(&bytes).expect("反序列化应成功");
        assert_eq!(io, restored);
    }

    #[test]
    fn test_zk_public_io_roundtrip_with_data() {
        let io = ZkPublicIo {
            input: vec![0x01, 0x02, 0x03],
            output: vec![0xAA, 0xBB],
            randomness_seed: ZkvmFr::from_u64(42),
            initial_commitment: ZkvmFr::from_u64(100),
            final_commitment: ZkvmFr::from_u64(200),
            event_hashes: vec![ZkvmFr::from_u64(1), ZkvmFr::from_u64(2)],
        };
        let bytes = io.to_bytes();
        let restored = ZkPublicIo::from_bytes(&bytes).expect("反序列化应成功");
        assert_eq!(io, restored);
    }

    #[test]
    fn test_zk_public_io_roundtrip_large_input() {
        let io = ZkPublicIo {
            input: vec![0u8; 1024],
            output: vec![0xFF; 512],
            randomness_seed: ZkvmFr::one(),
            initial_commitment: ZkvmFr::from_u64(999),
            final_commitment: ZkvmFr::zero(),
            event_hashes: vec![ZkvmFr::from_u64(7); 10],
        };
        let bytes = io.to_bytes();
        let restored = ZkPublicIo::from_bytes(&bytes).expect("反序列化应成功");
        assert_eq!(io, restored);
    }

    #[test]
    fn test_zk_public_io_from_bytes_too_short() {
        let bytes = [0u8; 3];
        let err = ZkPublicIo::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ZkvmError::InvalidZkProofFormat(_)));
    }

    #[test]
    fn test_zk_public_io_from_bytes_length_overflow() {
        let mut bytes = vec![0xFF, 0xFF, 0xFF, 0xFF];
        bytes.extend_from_slice(&[0u8; 10]);
        let err = ZkPublicIo::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ZkvmError::InvalidZkProofFormat(_)));
    }

    // ===== pad_trace 测试 =====

    #[test]
    fn test_pad_trace_no_padding_needed() {
        let mut trace = Trace::new();
        for i in 0..10 {
            trace.push_step(Step {
                step_index: i,
                pc: 0,
                instruction: Instruction::Ecall,
                registers: [0u32; 32],
                mem_access: vec![],
            });
        }
        pad_trace(&mut trace, 5).expect("应成功");
        assert_eq!(trace.len(), 10);
    }

    #[test]
    fn test_pad_trace_adds_padding() {
        let mut trace = Trace::new();
        for i in 0..7 {
            trace.push_step(Step {
                step_index: i,
                pc: 0,
                instruction: Instruction::Ecall,
                registers: [0u32; 32],
                mem_access: vec![],
            });
        }
        pad_trace(&mut trace, 5).expect("应成功");
        assert_eq!(trace.len(), 10);

        let last_step = trace.step(9).unwrap();
        assert_eq!(last_step.step_index, 9);
    }

    #[test]
    fn test_pad_trace_zero_batch_size_errors() {
        let mut trace = Trace::new();
        let err = pad_trace(&mut trace, 0).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref m) if m.contains("batch_size")));
    }

    #[test]
    fn test_pad_trace_empty_trace() {
        let mut trace = Trace::new();
        pad_trace(&mut trace, 5).expect("空 trace 0 % 5 == 0，无需 padding");
        assert_eq!(trace.len(), 0);
    }

    #[test]
    fn test_pad_trace_single_step() {
        let mut trace = Trace::new();
        trace.push_step(Step {
            step_index: 0,
            pc: 0,
            instruction: Instruction::Ecall,
            registers: [0u32; 32],
            mem_access: vec![],
        });
        pad_trace(&mut trace, 4).expect("应成功");
        assert_eq!(trace.len(), 4);
    }

    // ===== prove() 端到端集成测试 =====

    /// 编码 I-type 指令（复制自 executor::tests，因该函数为私有）。
    fn encode_i(opcode: u32, funct3: u8, rd: u8, rs1: u8, imm12: u32) -> u32 {
        ((imm12 & 0xFFF) << 20)
            | ((rs1 as u32) << 15)
            | ((funct3 as u32) << 12)
            | ((rd as u32) << 7)
            | opcode
    }

    /// 构造最小 ELF32（复制自 executor::tests，因该函数为私有）。
    fn build_test_elf(entry: u32, text_vaddr: u32, text_bytes: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(84 + text_bytes.len());
        bytes.extend_from_slice(&[
            0x7f, b'E', b'L', b'F',
            1, 1, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&0xF3u16.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&entry.to_le_bytes());
        bytes.extend_from_slice(&52u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&52u16.to_le_bytes());
        bytes.extend_from_slice(&32u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&40u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let p_offset = 84u32;
        let p_filesz = text_bytes.len() as u32;
        let p_memsz = text_bytes.len() as u32;
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&p_offset.to_le_bytes());
        bytes.extend_from_slice(&text_vaddr.to_le_bytes());
        bytes.extend_from_slice(&text_vaddr.to_le_bytes());
        bytes.extend_from_slice(&p_filesz.to_le_bytes());
        bytes.extend_from_slice(&p_memsz.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&0x1000u32.to_le_bytes());
        bytes.extend_from_slice(text_bytes);
        bytes
    }

    /// 将 u32 指令序列编码为 LE 字节。
    fn encode_text(words: &[u32]) -> Vec<u8> {
        words.iter().copied().flat_map(u32::to_le_bytes).collect()
    }

    #[test]
    fn test_prove_invalid_elf_errors() {
        let config = ProverConfig {
            batch_size: 3,
            ..Default::default()
        };
        let err = prove(&[0u8; 10], &[], &config).unwrap_err();
        // validate_elf 对 parse 错误返回 Other("ELF parse error: ...")
        assert!(
            matches!(err, ZkvmError::Other(ref m) if m.contains("ELF parse error")),
            "expected Other with ELF parse error, got {err:?}"
        );
    }

    #[test]
    fn test_prove_empty_input_success() {
        // 构造 5 步程序：3 NOP + commit_output + ECALL
        // batch_size = 3 → padding 到 6 步 → 2 batches
        // 每批 3 步 → num_vars = 4 = 2^2, num_rows = 2 = 2^1
        let text = encode_text(&[
            encode_i(0x13, 0, 1, 0, 0),   // ADDI x1, x0, 0 (NOP)
            encode_i(0x13, 0, 1, 0, 0),   // ADDI x1, x0, 0 (NOP)
            encode_i(0x13, 0, 1, 0, 0),   // ADDI x1, x0, 0 (NOP)
            encode_i(0x13, 0, 17, 0, 2),  // ADDI a7, x0, 2 (commit_output)
            0x00000073,                    // ECALL
        ]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let config = ProverConfig {
            batch_size: 3,
            proof_size_limit: MAX_PROOF_TOTAL_SIZE,
            ..Default::default()
        };

        let result = prove(&elf, &[], &config);
        match &result {
            Ok((proof_bytes, public_io)) => {
                assert!(!proof_bytes.is_empty(), "proof 不应为空");
                assert!(public_io.input.is_empty());
                assert!(public_io.output.is_empty());
            }
            Err(e) => {
                panic!("prove 应成功但返回错误: {e:?}");
            }
        }
    }

    #[test]
    fn test_prove_returns_public_io_with_input() {
        // 构造 read_input + commit_output 程序
        let text = encode_text(&[
            encode_i(0x13, 0, 17, 0, 1),  // ADDI a7, x0, 1 (read_input)
            encode_i(0x13, 0, 11, 0, 3),  // ADDI a1, x0, 3 (len=3)
            0x00000073,                    // ECALL (read_input)
            encode_i(0x13, 0, 17, 0, 2),  // ADDI a7, x0, 2 (commit_output)
            0x00000073,                    // ECALL (commit_output)
        ]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let config = ProverConfig {
            batch_size: 3,
            proof_size_limit: MAX_PROOF_TOTAL_SIZE,
            ..Default::default()
        };

        let input = vec![0xAAu8, 0xBB, 0xCC];
        let result = prove(&elf, &input, &config);
        match &result {
            Ok((proof_bytes, public_io)) => {
                assert!(!proof_bytes.is_empty());
                assert_eq!(public_io.input, input);
                assert_eq!(public_io.output, input, "echo 程序应回显 input");
            }
            Err(e) => {
                panic!("prove 应成功但返回错误: {e:?}");
            }
        }
    }

    #[test]
    fn test_prove_padding_enables_non_power_of_two_batch_size() {
        // batch_size = 4 → raw num_vars = 5 (非 2 的幂)，padding 到 8
        // 6 步 → padding 到 8 → 2 batches (8/4=2)
        // Stage 1.1 padding 使 num_vars 始终为 2 的幂，prove 应成功
        let text = encode_text(&[
            encode_i(0x13, 0, 1, 0, 0),   // NOP
            encode_i(0x13, 0, 1, 0, 0),   // NOP
            encode_i(0x13, 0, 1, 0, 0),   // NOP
            encode_i(0x13, 0, 1, 0, 0),   // NOP
            encode_i(0x13, 0, 17, 0, 2),  // ADDI a7, x0, 2 (commit_output)
            0x00000073,                    // ECALL
        ]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let config = ProverConfig {
            batch_size: 4,
            proof_size_limit: MAX_PROOF_TOTAL_SIZE,
            ..Default::default()
        };

        let (proof_bytes, _public_io) = prove(&elf, &[], &config)
            .expect("padding 应使 batch_size=4 可用");
        assert!(!proof_bytes.is_empty());
    }

    #[test]
    fn test_prove_single_instance_succeeds() {
        // 仅 2 步（ADDI + ECALL），batch_size = 3
        // padding 到 3 步 → 1 batch → 1 实例 → 单实例 proof 路径
        // Stage 1.2 单实例路径应成功
        let text = encode_text(&[
            encode_i(0x13, 0, 17, 0, 2),  // ADDI a7, x0, 2
            0x00000073,                    // ECALL
        ]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let config = ProverConfig {
            batch_size: 3,
            proof_size_limit: MAX_PROOF_TOTAL_SIZE,
            ..Default::default()
        };

        let (proof_bytes, _public_io) = prove(&elf, &[], &config)
            .expect("单实例 proof 应成功");
        assert!(!proof_bytes.is_empty());
    }

    #[test]
    fn test_prove_proof_size_limit_exceeded() {
        // 设置极小 proof_size_limit → proof 过大
        let text = encode_text(&[
            encode_i(0x13, 0, 1, 0, 0),
            encode_i(0x13, 0, 1, 0, 0),
            encode_i(0x13, 0, 1, 0, 0),
            encode_i(0x13, 0, 17, 0, 2),
            0x00000073,
        ]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let config = ProverConfig {
            batch_size: 3,
            proof_size_limit: 10, // 极小限制
            ..Default::default()
        };

        let err = prove(&elf, &[], &config).unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref m) if m.contains("proof 过大")),
            "expected proof too large error, got {err:?}"
        );
    }

    // ===== Phase 8 Step 3: deserialize_proof 测试 =====

    /// 辅助：生成合法 proof bytes（3 NOP + commit_output + ECALL）。
    fn make_valid_proof_bytes() -> Vec<u8> {
        let text = encode_text(&[
            encode_i(0x13, 0, 1, 0, 0),
            encode_i(0x13, 0, 1, 0, 0),
            encode_i(0x13, 0, 1, 0, 0),
            encode_i(0x13, 0, 17, 0, 2),
            0x00000073,
        ]);
        let elf = build_test_elf(0x1000, 0x1000, &text);
        let config = ProverConfig {
            batch_size: 3,
            proof_size_limit: MAX_PROOF_TOTAL_SIZE,
            ..Default::default()
        };
        let (proof_bytes, _public_io) = prove(&elf, &[], &config).expect("prove 应成功");
        proof_bytes
    }

    #[test]
    fn test_deserialize_proof_roundtrip() {
        let proof_bytes = make_valid_proof_bytes();
        let proof = deserialize_proof(&proof_bytes).expect("deserialize_proof 应成功");
        // 重新序列化后应与原 proof_bytes 长度相同（内容一致）
        let re = serialize_proof(&proof).expect("serialize_proof 应成功");
        assert_eq!(proof_bytes, re, "往返序列化应一致");
    }

    #[test]
    fn test_deserialize_proof_magic_error() {
        let mut bytes = make_valid_proof_bytes();
        bytes[0] = b'X'; // 篡改 magic
        let result = deserialize_proof(&bytes);
        assert!(
            matches!(result, Err(ZkvmError::InvalidZkProofFormat(ref m)) if m.contains("magic")),
            "expected InvalidZkProofFormat with magic error, got {result:?}"
        );
    }

    #[test]
    fn test_deserialize_proof_oversized_fails() {
        // 构造超过 MAX_PROOF_TOTAL_SIZE 的大 buffer
        let oversized = vec![0u8; MAX_PROOF_TOTAL_SIZE + 1];
        let result = deserialize_proof(&oversized);
        assert!(
            matches!(result, Err(ZkvmError::InvalidZkProofFormat(ref m)) if m.contains("MAX_PROOF_TOTAL_SIZE")),
            "expected InvalidZkProofFormat with size error, got {result:?}"
        );
    }
}
