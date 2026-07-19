//! Phase 3.3 — zkvm 服务化类型定义。
//!
//! 定义 HTTP API 的请求/响应类型，使用 `serde` 进行 JSON 序列化。
//! 所有二进制字段（ELF / input / proof / public_io）以 hex 字符串传输，
//! 避免基 64 编码的 padding 开销与 JSON 转义问题。

use serde::{Deserialize, Serialize};

// ===========================================================================
// prove 端点
// ===========================================================================

/// `/prove` 请求体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveRequest {
    /// ELF 字节的 hex 编码。
    pub elf_hex: String,
    /// input 字节的 hex 编码。
    pub input_hex: String,
}

/// `/prove` 响应体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveResponse {
    /// proof 字节的 hex 编码。
    pub proof_hex: String,
    /// `ZkPublicIo` 的二进制序列化（`ZkPublicIo::to_bytes()`）的 hex 编码。
    pub public_io_hex: String,
    /// prove 耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 是否命中 proof_cache。
    pub cache_hit: bool,
    /// proof 字节数。
    pub proof_size: usize,
}

// ===========================================================================
// verify 端点
// ===========================================================================

/// `/verify` 请求体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// proof 字节的 hex 编码。
    pub proof_hex: String,
    /// `ZkPublicIo` 二进制序列化的 hex 编码。
    pub public_io_hex: String,
}

/// `/verify` 响应体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// proof 是否合法。
    pub valid: bool,
    /// verify 耗时（毫秒）。
    pub elapsed_ms: u64,
}

// ===========================================================================
// health / stats 端点
// ===========================================================================

/// `/health` 响应体（轻量探活）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// 服务状态（"ok" / "shutting_down"）。
    pub status: String,
    /// 服务运行时长（秒）。
    pub uptime_s: u64,
    /// 累计请求数。
    pub request_count: u64,
    /// 累计生成 proof 数。
    pub proofs_generated: u64,
}

/// `/stats` 响应体（详细统计）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    /// CCS registry 大小（启动时固定）。
    pub ccs_registry_size: usize,
    /// IPA PCS 缓存大小（按 n_vars 缓存）。
    pub ipa_pcs_cache_size: usize,
    /// proof 缓存大小。
    pub proof_cache_size: usize,
    /// 累计生成 proof 数。
    pub total_proofs: u64,
    /// 累计 verify 次数。
    pub total_verifies: u64,
    /// proof 平均延迟（毫秒）。
    pub avg_prove_latency_ms: f64,
    /// verify 平均延迟（毫秒）。
    pub avg_verify_latency_ms: f64,
}

/// `/shutdown` 响应体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownResponse {
    /// 关闭状态。
    pub status: String,
}

// ===========================================================================
// 错误响应
// ===========================================================================

/// 统一错误响应体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// 错误消息。
    pub error: String,
}

impl ErrorResponse {
    /// 构造错误响应。
    #[must_use]
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            error: msg.into(),
        }
    }
}

// ===========================================================================
// 辅助函数
// ===========================================================================

/// 将字节切片编码为 hex 字符串。
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 将 hex 字符串解码为字节向量。
///
/// # Errors
/// - 长度非偶数
/// - 含非 hex 字符
pub fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("hex 长度 {} 非偶数", hex.len()));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("非法 hex 字符: {b}")),
    }
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let original = [0x00, 0x01, 0xff, 0xab, 0xcd, 0xef];
        let hex = to_hex(&original);
        assert_eq!(hex, "0001ffabcdef");
        let decoded = from_hex(&hex).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_from_hex_odd_length() {
        assert!(from_hex("abc").is_err());
    }

    #[test]
    fn test_from_hex_invalid_char() {
        assert!(from_hex("xy").is_err());
    }

    #[test]
    fn test_error_response_new() {
        let resp = ErrorResponse::new("bad request");
        assert_eq!(resp.error, "bad request");
    }

    #[test]
    fn test_prove_request_serde() {
        let req = ProveRequest {
            elf_hex: "7f454c46".to_string(),
            input_hex: "deadbeef".to_string(),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let decoded: ProveRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.elf_hex, "7f454c46");
        assert_eq!(decoded.input_hex, "deadbeef");
    }
}
