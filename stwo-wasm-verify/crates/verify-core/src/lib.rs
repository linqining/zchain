//! Path A crate A — canonical 真证明的完整 STARK 验证（native / wasm32 同源）。
//!
//! 验证对象：`poker_texas_air::texas_canonical_air::ArchivedCanonicalTaggedProof`
//! 的 borsh 归档字节（与网关 proof 通道、settlement 侧用的是同一种字节串）。
//! 验证逻辑即 poker_texas_air 的 `verify_canonical_tagged_proof`（只读复用）：
//! 归档形状校验 → state image / rake binding 校验 → scope 公开承诺重建
//! （SimdBackend + Poseidon252，需要 stwo `prover` feature）→ 完整 STARK
//! verify（FRI + Merkle + 约束）。
//!
//! 为什么能进 wasm32：poker_texas_air 依赖的 `stwo = "2.3"` 经本 workspace 的
//! `[patch.crates-io]` 重定向到 `third_party/stwo-wasm-patch/stwo-2.3.0`
//! （poseidon252 家族从 `cfg(not(target_arch="wasm32"))` 改为 default 开启的
//! `wasm-poseidon` feature 门，详见该目录 README）。验证逻辑本身零改动。
//!
//! 计时口径（诚实边界）：wasm32-unknown-unknown 上 `std::time::Instant` 会
//! panic（探针实测，stwo-wasm-probe 报告 §1.4），因此 wasm 侧
//! [`VerifyStats::internal_elapsed_ms`] 返回 `None`，墙钟由宿主（node/浏览器
//! 胶水）测量；native 侧返回内部实测值。两者在报告里分开标注，不混用。

use borsh::BorshDeserialize;
use poker_texas_air::texas_canonical_air::{ArchivedCanonicalTaggedProof, verify_canonical_tagged_proof};

/// 验证器身份串（portal / harness 展示用；如实标注 stwo 来源）。
pub const VERIFIER_ID: &str =
    "stwo-wasm-verify/0.1.0 (stwo 2.3.0 vendored+wasm-poseidon; poker_texas_air canonical AIR)";

/// 一次验证的结构化结果。
#[derive(Debug, Clone)]
pub struct VerifyStats {
    /// true = 完整 STARK 验证通过（含公开 scope 重建比对）。
    pub verified: bool,
    /// 验证失败原因（verified=false 时非空；Err 分支的解码失败不进这里）。
    pub error: Option<String>,
    /// 输入归档字节数。
    pub archive_len: usize,
    pub table_id: u64,
    pub log_size: u32,
    pub num_columns: u32,
    pub transition_count: u16,
    /// 批次摘要（hex，64 字符）。
    pub batch_digest_hex: String,
    /// native：验证器内部耗时（ms）。wasm32：None（无时钟 syscall，宿主测墙钟）。
    pub internal_elapsed_ms: Option<f64>,
}

/// 验证一份 canonical 归档（borsh 字节）。
///
/// - `Err(String)`：归档信封本身无法 borsh 解码（连形状校验都进不去）。
/// - `Ok(stats)`：解码成功；`stats.verified` 区分验证通过/失败，
///   `stats.error` 带具体失败原因（形状违规 / 承诺不匹配 / FRI 失败等）。
pub fn verify_canonical_proof_wasm(archive_bytes: &[u8]) -> Result<VerifyStats, String> {
    let archive: ArchivedCanonicalTaggedProof = BorshDeserialize::try_from_slice(archive_bytes)
        .map_err(|e| format!("archive borsh decode: {e}"))?;

    let mut stats = VerifyStats {
        verified: false,
        error: None,
        archive_len: archive_bytes.len(),
        table_id: archive.table_id,
        log_size: archive.log_size,
        num_columns: archive.num_columns,
        transition_count: archive.transition_count,
        batch_digest_hex: hex_encode(&archive.batch_digest),
        internal_elapsed_ms: None,
    };
    // native：内部计时（验证主体，不含 borsh 解码）；wasm32：保持 None。
    let _t = ScopedTimer::start();
    let result = verify_canonical_tagged_proof(&archive);
    stats.internal_elapsed_ms = _t.finish_ms();
    match result {
        Ok(()) => {
            stats.verified = true;
            Ok(stats)
        }
        Err(e) => {
            stats.verified = false;
            stats.error = Some(e.to_string());
            Ok(stats)
        }
    }
}

// ===== 平台差异（唯一一处）：wasm32 无时钟 =====

/// native：内部秒表。wasm32：空壳（`std::time::Instant` 在
/// wasm32-unknown-unknown 上 panic——探针实测——由宿主测墙钟）。
struct ScopedTimer {
    #[cfg(not(target_arch = "wasm32"))]
    started: std::time::Instant,
}

impl ScopedTimer {
    fn start() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            started: std::time::Instant::now(),
        }
    }

    fn finish_ms(&self) -> Option<f64> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Some(self.started.elapsed().as_secs_f64() * 1e3)
        }
        #[cfg(target_arch = "wasm32")]
        {
            None
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

impl VerifyStats {
    /// 紧凑 JSON（wasm C ABI `sv_stats` 与 harness 直接用；手写避免引入 serde_json）。
    pub fn to_json(&self) -> String {
        let error_json = match &self.error {
            Some(e) => format!("\"{}\"", json_escape(e)),
            None => "null".to_string(),
        };
        let elapsed_json = match self.internal_elapsed_ms {
            Some(ms) => format!("{ms:.3}"),
            None => "null".to_string(),
        };
        format!(
            "{{\"verified\":{},\"error\":{},\"archive_len\":{},\"table_id\":{},\
             \"log_size\":{},\"num_columns\":{},\"transition_count\":{},\
             \"batch_digest\":\"{}\",\"internal_elapsed_ms\":{},\"verifier\":\"{}\"}}",
            self.verified,
            error_json,
            self.archive_len,
            self.table_id,
            self.log_size,
            self.num_columns,
            self.transition_count,
            self.batch_digest_hex,
            elapsed_json,
            json_escape(VERIFIER_ID),
        )
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_json_shape() {
        let stats = VerifyStats {
            verified: true,
            error: None,
            archive_len: 12,
            table_id: 7,
            log_size: 10,
            num_columns: 5392,
            transition_count: 5,
            batch_digest_hex: "ab".repeat(32),
            internal_elapsed_ms: Some(1.5),
        };
        let json = stats.to_json();
        assert!(json.contains("\"verified\":true"));
        assert!(json.contains("\"table_id\":7"));
        assert!(json.contains("\"internal_elapsed_ms\":1.500"));
    }

    #[test]
    fn garbage_input_is_decode_error() {
        assert!(verify_canonical_proof_wasm(&[0u8; 8]).is_err());
        assert!(verify_canonical_proof_wasm(&[]).is_err());
    }
}
