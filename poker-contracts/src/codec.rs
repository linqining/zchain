//! calldata 编码层（对标 aztec 的 ABI 编码：felt / ByteArray / uint256 /
//! selector）。
//!
//! 全部编码与 poker_texas_air 的 snops（其同 ABI 已上链验证）以及 Cairo
//! corelib 2.19.4 serde 语义逐字节一致。

use starknet::core::utils::starknet_keccak;

/// 统一 felt 类型：`starknet_crypto::Felt` 即 `starknet-types-core::Felt`
/// （与 `starknet` crate 的 `Felt` 同源，可直接混用）。
pub type Felt = starknet_crypto::Felt;

use crate::error::{ContractsError, ContractsResult};

/// 解析 felt：`0x` 前缀按 hex，其余按十进制（与 snops / Starknet 生态工具
/// 惯例一致，避免十进制金额被当 hex 误读）。
///
/// # Errors
/// 空串或非法 hex/十进制 → [`ContractsError::Codec`]。
pub fn parse_felt(s: &str) -> ContractsResult<Felt> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Felt::from_hex(hex).map_err(|e| ContractsError::Codec(format!("hex felt `{t}`: {e}")))
    } else {
        Felt::from_dec_str(t).map_err(|e| ContractsError::Codec(format!("dec felt `{t}`: {e}")))
    }
}

/// ASCII 短串 → felt252（≤31 字节；超长或含非 ASCII 拒绝）。
///
/// # Errors
/// 超长 / 非 ASCII → [`ContractsError::Codec`]。
pub fn short_string(s: &str) -> ContractsResult<Felt> {
    if s.len() > 31 {
        return Err(ContractsError::Codec(format!(
            "short string too long ({}, max 31): {s:?}",
            s.len()
        )));
    }
    if !s.is_ascii() {
        return Err(ContractsError::Codec(format!("non-ascii short string: {s:?}")));
    }
    Ok(Felt::from_bytes_be(&padded_left_be(s.as_bytes())))
}

/// 入参解析（与 snops `parse_args_mixed` 同形）：逗号分隔，`@str:` 前缀走
/// Cairo [`encode_byte_array`]，`-` 开头的十进制按有符号 i128 编码（结算
/// deltas），其余按 [`parse_felt`]。
///
/// # Errors
/// 任一段解析失败 → [`ContractsError::Codec`]。
pub fn parse_calldata(s: &str) -> ContractsResult<Vec<Felt>> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for part in t.split(',') {
        if let Some(rest) = part.strip_prefix("@str:") {
            out.extend(encode_byte_array(rest));
        } else if let Some(rest) = part.strip_prefix('-') {
            // 有符号：结算 deltas 用（负数域上取负）
            let v: i128 = rest
                .trim()
                .parse()
                .map_err(|e| ContractsError::Codec(format!("i128 `{part}`: {e}")))?;
            out.push(i128_to_felt(-v));
        } else {
            out.push(parse_felt(part)?);
        }
    }
    Ok(out)
}

/// Cairo `ByteArray` → calldata（corelib serde 语义，与 snops 逐字节一致）：
/// `[data_len, 31B 全词…, pending_word, pending_word_len]`。
///
/// pending word 顶对齐：corelib `byte_array.cairo`——"The first byte is the
/// most significant byte among the `pending_word_len` bytes in the word"，
/// bytes31 → felt 的映射落在 felt 低 31 字节，故余量字节从 felt 字节下标
/// 1 开始写（snops 同式）。
pub fn encode_byte_array(s: &str) -> Vec<Felt> {
    let bytes = s.as_bytes();
    let n_full = bytes.len() / 31;
    let rem = &bytes[n_full * 31..];
    let mut out = Vec::with_capacity(n_full + 3);
    // Array<felt252> serde：先写长度
    out.push(Felt::from(n_full as u64));
    for i in 0..n_full {
        // bytes31 → felt：31 字节落在 felt 低 31 字节（最高位补零）
        let mut word = [0u8; 32];
        word[1..32].copy_from_slice(&bytes[i * 31..(i + 1) * 31]);
        out.push(Felt::from_bytes_be(&word));
    }
    if !rem.is_empty() {
        let mut buf = [0u8; 32];
        buf[1..1 + rem.len()].copy_from_slice(rem);
        out.push(Felt::from_bytes_be(&buf));
        out.push(Felt::from(rem.len() as u64));
    } else {
        out.push(Felt::ZERO);
        out.push(Felt::ZERO);
    }
    out
}

/// Cairo `u256` → calldata：`[low, high]` 两个 felt（各 128 位）。
pub fn u256_to_felts(v: Uint256) -> [Felt; 2] {
    [
        Felt::from(v.low),
        Felt::from(v.high),
    ]
}

/// calldata（≥2 felts）→ [`Uint256`]（`[low, high]`）。
///
/// # Errors
/// 返回段不足 2 felts → [`ContractsError::Codec`]。
pub fn u256_from_felts(felts: &[Felt]) -> ContractsResult<Uint256> {
    let low = felts.first().copied().ok_or_else(|| ContractsError::Codec("u256 missing low".into()))?;
    let high = felts.get(1).copied().ok_or_else(|| ContractsError::Codec("u256 missing high".into()))?;
    Ok(Uint256 { low: felt_to_u128(low)?, high: felt_to_u128(high)? })
}

/// felt → u128（超出 2^128−1 拒绝）。
///
/// # Errors
/// 数值超界 → [`ContractsError::Codec`]。
pub fn felt_to_u128(f: Felt) -> ContractsResult<u128> {
    let be = f.to_bytes_be();
    if be[..16].iter().any(|&b| b != 0) {
        return Err(ContractsError::Codec(format!("felt exceeds u128: {f:#x}")));
    }
    Ok(u128::from_be_bytes(be[16..32].try_into().unwrap()))
}

/// 入口选择器：`starknet_keccak(fn_name)`。
pub fn selector(name: &str) -> Felt {
    starknet_keccak(name.as_bytes())
}

/// i128 → felt（负数域上取负，与 texas `submit.rs::i128_to_felt` 及合约侧
/// `from_felt_signed_i128` 语义一致——结算 deltas 的 calldata 编码）。
#[must_use]
pub fn i128_to_felt(value: i128) -> Felt {
    if value >= 0 {
        Felt::from(value.unsigned_abs())
    } else {
        -Felt::from(value.unsigned_abs())
    }
}

/// Starknet `Uint256`（low/high 各 128 位）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Uint256 {
    /// 低 128 位。
    pub low: u128,
    /// 高 128 位。
    pub high: u128,
}

impl Uint256 {
    /// `u128` 提升（高 32 字节全零；筹码/金额常规路径）。
    #[must_use]
    pub fn from_u128(v: u128) -> Self {
        Self { low: v, high: 0 }
    }

    /// 饱和取 u128（高 128 位非零时取 `u128::MAX`；与 texas 服务端
    /// `u256_from_felts` 同语义——读数展示用，不做静默截断判断）。
    #[must_use]
    pub fn saturating_u128(self) -> u128 {
        if self.high != 0 {
            u128::MAX
        } else {
            self.low
        }
    }
}

impl std::ops::Add for Uint256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let (low, carry) = self.low.overflowing_add(rhs.low);
        Self { low, high: self.high + rhs.high + u128::from(carry) }
    }
}

impl std::ops::Sub for Uint256 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let (low, borrow) = self.low.overflowing_sub(rhs.low);
        Self { low, high: self.high - rhs.high - u128::from(borrow) }
    }
}

/// 左对齐填充到 32 字节 BE（前导零）。
fn padded_left_be(bytes: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_felt_hex_and_decimal() {
        // 0x 前缀走 hex（与 snops 一致）
        assert_eq!(parse_felt("0x10").unwrap(), Felt::from(0x10_u32));
        // 无前缀走十进制：1e18 级金额不被误读
        assert_eq!(
            parse_felt("1000000000000000000").unwrap(),
            Felt::from(1_000_000_000_000_000_000_u128)
        );
        assert!(parse_felt("").is_err());
        assert!(parse_felt("0xzz").is_err());
        assert!(parse_felt("12x3").is_err());
    }

    #[test]
    fn byte_array_matches_snops_encoding() {
        // 空串：[len=0, pending_word=0, pending_word_len=0]
        assert_eq!(encode_byte_array(""), vec![Felt::ZERO, Felt::ZERO, Felt::ZERO]);
        // ≤31 字节：无全词，pending 顶对齐（"abc" → 0x616263000…0）
        let enc = encode_byte_array("abc");
        assert_eq!(enc.len(), 3);
        assert_eq!(enc[0], Felt::ZERO);
        let mut expect = [0u8; 32];
        expect[1] = b'a';
        expect[2] = b'b';
        expect[3] = b'c';
        assert_eq!(enc[1], Felt::from_bytes_be(&expect));
        assert_eq!(enc[2], Felt::from(3_u64));
        // 31 字节边界：正好一个全词 + 空 pending
        let s31 = "a".repeat(31);
        let enc = encode_byte_array(&s31);
        assert_eq!(enc.len(), 4);
        assert_eq!(enc[0], Felt::from(1_u64));
        assert_eq!(enc[1], Felt::from_bytes_be(&{
            let mut b = [0u8; 32];
            b[1..].copy_from_slice(s31.as_bytes());
            b
        }));
        assert_eq!((enc[2], enc[3]), (Felt::ZERO, Felt::ZERO));
        // 32 字节：1 全词 + 1 字节 pending
        let enc = encode_byte_array(&format!("{s31}b"));
        assert_eq!(enc.len(), 4);
        assert_eq!(enc[0], Felt::from(1_u64));
        assert_eq!(enc[2], Felt::from_bytes_be(&{
            let mut b = [0u8; 32];
            b[1] = b'b';
            b
        }));
        assert_eq!(enc[3], Felt::from(1_u64));
    }

    #[test]
    fn byte_array_long_string_layout() {
        // 62 字节：两个全词 + 空 pending；词内容为原始字节分块
        let s = "x".repeat(62);
        let enc = encode_byte_array(&s);
        assert_eq!(enc.len(), 5);
        assert_eq!(enc[0], Felt::from(2_u64));
        assert_eq!(enc[1], enc[2]);
    }

    #[test]
    fn u256_roundtrip_and_bounds() {
        let v = Uint256 { low: u128::MAX, high: 5 };
        let felts = u256_to_felts(v);
        assert_eq!(u256_from_felts(&felts).unwrap(), v);
        assert!(u256_from_felts(&felts[..1]).is_err());
        // felt → u128 越界拒绝
        let big = Felt::TWO.pow(128_u128);
        assert!(felt_to_u128(big).is_err());
        assert_eq!(felt_to_u128(Felt::from(u128::MAX)).unwrap(), u128::MAX);
        // 饱和读（与 texas 服务端同语义）
        assert_eq!(v.saturating_u128(), u128::MAX);
        // 进位/借位（余额增量断言用）
        let one = Uint256::from_u128(1);
        assert_eq!(v + one, Uint256 { low: 0, high: 6 });
        assert_eq!(v + one - one, v);
    }

    #[test]
    fn short_string_and_selector() {
        assert_eq!(short_string("pSTRK").unwrap(), parse_felt("0x705354524b").unwrap());
        assert!(short_string(&"a".repeat(32)).is_err());
        // ERC20 transfer selector 稳定向量（starknet_keccak("transfer")，
        // 部署/调用对拍锚点）
        assert_eq!(
            selector("transfer").to_string(),
            "232670485425082704932579856502088130646006032362877466777181098476241604910"
        );
    }

    #[test]
    fn parse_calldata_mixed() {
        let cd = parse_calldata("0x10,300,@str:hi").unwrap();
        assert_eq!(cd.len(), 2 + 3); // 0x10, 300 + ByteArray("hi")
        assert_eq!(cd[0], Felt::from(0x10_u32));
        assert_eq!(cd[1], Felt::from(300_u64));
    }

    #[test]
    fn negative_deltas_use_field_negation() {
        // 与 texas submit.rs::i128_to_felt 同语义：负数域上取负
        assert_eq!(i128_to_felt(300), Felt::from(300_u64));
        assert_eq!(i128_to_felt(-300), -Felt::from(300_u64));
        let cd = parse_calldata("300,-300").unwrap();
        assert_eq!(cd, vec![Felt::from(300_u64), -Felt::from(300_u64)]);
        assert!(parse_calldata("-zz").is_err());
    }
}
