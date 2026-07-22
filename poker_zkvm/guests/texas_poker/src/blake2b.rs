//! 纯 Rust Blake2b-256 实现（无外部依赖，`const fn`）。
//!
//! 用于 `dispatch::compute_method_selector`，使方法选择器计算在 riscv32 ELF
//! 与 host std-test 两种模式下均可用（不经 syscall）。
//!
//! # `const fn` 设计
//!
//! 所有函数均为 `const fn`，使 selector 可在编译时计算为 `const` 常量，
//! 避免 RV32I 运行时 sret 调用 `blake2b_256`（返回 `[u8; 32]` = 32 字节 >
//! 2×XLEN = 8 字节，通过 sret 返回，触发 RV32I sret codegen bug）。
//!
//! 算法参考：RFC 7693。仅实现 32 字节输出（Blake2b-256），无 key。
//! 与 `blake2::Blake2bVar::new(32)` + `update` + `finalize_variable` 逐字节一致，
//! host syscall `Blake2b256Syscall` (0x33) 使用相同的 `blake2` crate 验证过兼容性。

// ========== 常量 ==========

/// Blake2b 初始向量（IV）。
const IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

/// 轮函数的 message schedule（12 轮）。
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 10, 4, 8, 6, 2],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Blake2b 块大小（字节）。
const BLOCK_SIZE: usize = 128;

// ========== 压缩函数 ==========

/// Blake2b G 函数（混合函数）。
const fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// Blake2b 压缩函数：用 128 字节消息块更新哈希状态。
///
/// - `h`：哈希状态（8 × u64），in-place 更新
/// - `block`：128 字节消息块
/// - `t`：已处理的字节总数（counter）
/// - `last`：是否为最后一块（置 finalize flag）
const fn compress(h: &mut [u64; 8], block: &[u8; BLOCK_SIZE], t: u64, last: bool) {
    let mut v = [0u64; 16];
    // v[..8].copy_from_slice(h) — 手动展开（const fn 兼容）
    let mut i = 0;
    while i < 8 {
        v[i] = h[i];
        i += 1;
    }
    // v[8..].copy_from_slice(&IV) — 手动展开
    i = 0;
    while i < 8 {
        v[8 + i] = IV[i];
        i += 1;
    }
    // counter（低 64 位；高 64 位在 32 位 target 上始终为 0，与 blake2 crate 一致）
    v[12] ^= t;
    // last block flag
    if last {
        v[14] ^= u64::MAX;
    }

    // 解析 16 个 64-bit 小端 message words
    let mut m = [0u64; 16];
    i = 0;
    while i < 16 {
        m[i] = u64::from_le_bytes([
            block[i * 8],
            block[i * 8 + 1],
            block[i * 8 + 2],
            block[i * 8 + 3],
            block[i * 8 + 4],
            block[i * 8 + 5],
            block[i * 8 + 6],
            block[i * 8 + 7],
        ]);
        i += 1;
    }

    // 12 轮
    i = 0;
    while i < 12 {
        let s = &SIGMA[i];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        i += 1;
    }

    i = 0;
    while i < 8 {
        h[i] ^= v[i] ^ v[i + 8];
        i += 1;
    }
}

// ========== 公开 API ==========

/// Blake2b-256 哈希（32 字节输出，无 key）。
///
/// 与 `blake2::Blake2bVar::new(32)` + `update(data)` + `finalize_variable(out)` 逐字节一致。
/// 参数块：`digest_length=32, key_length=0, fanout=1, depth=1`。
///
/// `const fn` 使 selector 可在编译时计算，避免 RV32I 运行时 sret 调用。
#[must_use]
pub const fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut h = IV;
    // 参数块：digest_length(1B) | key_length(1B) | fanout(1B) | depth(1B)
    // = 0x20 | 0x00<<8 | 0x01<<16 | 0x01<<24 = 0x01010020
    h[0] ^= 0x0101_0020;

    let n = data.len();
    let mut t: u64 = 0;

    if n == 0 {
        // 空输入：单块全零，t=0，last=true
        let block = [0u8; BLOCK_SIZE];
        compress(&mut h, &block, 0, true);
    } else {
        let mut i = 0;
        // 处理除最后一块外的所有完整块
        while i + BLOCK_SIZE < n {
            t += BLOCK_SIZE as u64;
            let mut block = [0u8; BLOCK_SIZE];
            // block.copy_from_slice(&data[i..i + BLOCK_SIZE]) — 手动展开
            let mut j = 0;
            while j < BLOCK_SIZE {
                block[j] = data[i + j];
                j += 1;
            }
            compress(&mut h, &block, t, false);
            i += BLOCK_SIZE;
        }
        // 最后一块（1..=128 字节，零填充至 128）
        t += (n - i) as u64;
        let mut block = [0u8; BLOCK_SIZE];
        // block[..n - i].copy_from_slice(&data[i..n]) — 手动展开
        let mut j = 0;
        let rem = n - i;
        while j < rem {
            block[j] = data[i + j];
            j += 1;
        }
        compress(&mut h, &block, t, true);
    }

    // 输出前 32 字节（4 × u64 小端）
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 4 {
        let bytes = h[i].to_le_bytes();
        out[i * 8] = bytes[0];
        out[i * 8 + 1] = bytes[1];
        out[i * 8 + 2] = bytes[2];
        out[i * 8 + 3] = bytes[3];
        out[i * 8 + 4] = bytes[4];
        out[i * 8 + 5] = bytes[5];
        out[i * 8 + 6] = bytes[6];
        out[i * 8 + 7] = bytes[7];
        i += 1;
    }
    out
}

// ========== 测试 ==========

#[cfg(test)]
mod tests {
    use super::*;

    /// Blake2b-256 空输入 → 已知向量。
    #[test]
    fn blake2b_256_empty() {
        let out = blake2b_256(b"");
        // Blake2b-256("") = 0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
        let expected: [u8; 32] = [
            0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99,
            0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd,
            0xf1, 0x2f, 0xe3, 0xa8,
        ];
        assert_eq!(out, expected);
    }

    /// Blake2b-256("abc") → 已知向量（Python hashlib.blake2b 验证）。
    #[test]
    fn blake2b_256_abc() {
        let out = blake2b_256(b"abc");
        // Blake2b-256("abc") = bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319
        let expected: [u8; 32] = [
            0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98,
            0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0,
            0x68, 0xd5, 0x23, 0x19,
        ];
        assert_eq!(out, expected);
    }

    /// 边界：恰好 128 字节（单块，last=true）。
    #[test]
    fn blake2b_256_one_block() {
        let data = [0x42u8; 128];
        let out = blake2b_256(&data);
        // 非全零即可（验证不 panic 且输出确定性）
        assert_ne!(out, [0u8; 32]);
        // 确定性
        assert_eq!(out, blake2b_256(&data));
    }

    /// 边界：129 字节（一块完整 + 1 字节尾块）。
    #[test]
    fn blake2b_256_block_plus_one() {
        let data = vec![0x42u8; 129];
        let out = blake2b_256(&data);
        assert_ne!(out, blake2b_256(&[0x42u8; 128]));
        assert_eq!(out, blake2b_256(&data));
    }

    /// 边界：256 字节（两块完整，第二块为 last）。
    #[test]
    fn blake2b_256_two_blocks() {
        let data = vec![0x42u8; 256];
        let out = blake2b_256(&data);
        assert_ne!(out, blake2b_256(&[0x42u8; 128]));
        assert_eq!(out, blake2b_256(&data));
    }
}
