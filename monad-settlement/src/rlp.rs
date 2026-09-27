//! 最小 RLP 编码（仅覆盖遗留交易所需面：字符串/字节串 + 整数 + 列表）。
//!
//! 不引入 ethereum 类型 crate：整数以最小大端字节传入（`encode_uint_be`
//! 剥前导零，零 → 空串），调用方保证语义正确。

/// 编码字节串（RLP string 分支）。
#[must_use]
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return vec![data[0]];
    }
    let mut out = encode_length(data.len(), 0x80);
    out.extend_from_slice(data);
    out
}

/// 编码整数（最小大端字节；`0` → 空串）。`bytes` 内的前导零会被剥离。
#[must_use]
pub fn encode_uint_be(bytes: &[u8]) -> Vec<u8> {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    encode_bytes(&bytes[first_nonzero..])
}

/// 编码 u64 整数。
#[must_use]
pub fn encode_u64(value: u64) -> Vec<u8> {
    encode_uint_be(&value.to_be_bytes())
}

/// 编码 u128 整数。
#[must_use]
pub fn encode_u128(value: u128) -> Vec<u8> {
    encode_uint_be(&value.to_be_bytes())
}

/// 编码列表（RLP list 分支；payload = 各子项编码的拼接）。
#[must_use]
pub fn encode_list(payload: &[u8]) -> Vec<u8> {
    let mut out = encode_length(payload.len(), 0xc0);
    out.extend_from_slice(payload);
    out
}

fn encode_length(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        // 长形式：0xf7/0xbf + 长度本身的最小大端表示。
        let len_bytes = minimal_be(len);
        let mut out = vec![offset + 55 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out
    }
}

fn minimal_be(value: usize) -> Vec<u8> {
    let be = value.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    be[first..].to_vec()
}

/// 解码外层列表 → 各子项载荷（仅测试用；覆盖本模块编码出的全部形状）。
#[cfg(test)]
pub(crate) fn decode_list_items(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let (&prefix, rest) = bytes.split_first()?;
    let (payload_len, rest) = match prefix {
        0xc0..=0xf7 => ((prefix - 0xc0) as usize, rest),
        0xf8..=0xff => {
            let (&len_byte, r2) = rest.split_first()?;
            (len_byte as usize, r2)
        }
        _ => return None, // 非列表
    };
    if rest.len() < payload_len {
        return None;
    }
    let payload = &rest[..payload_len];
    let mut items = Vec::new();
    let mut cur = payload;
    while !cur.is_empty() {
        let (&p, c) = cur.split_first()?;
        let (item, advance) = match p {
            // 单字节内联。
            0x00..=0x7f => (vec![p], 1),
            // 短字符串。
            0x80..=0xb7 => {
                let len = (p - 0x80) as usize;
                if c.len() < len {
                    return None;
                }
                (c[..len].to_vec(), 1 + len)
            }
            // 长字符串。
            0xb8..=0xbf => {
                let len_of = (p - 0xb7) as usize;
                if c.len() < len_of {
                    return None;
                }
                let mut len = 0usize;
                for &b in &c[1..=len_of] {
                    len = (len << 8) | b as usize;
                }
                if c.len() < 1 + len_of + len {
                    return None;
                }
                (
                    c[1 + len_of..1 + len_of + len].to_vec(),
                    1 + len_of + len,
                )
            }
            // 嵌套列表（不展开——本 crate 编码的列表只有一层）。
            0xc0..=0xff => return None,
        };
        items.push(item);
        cur = &cur[advance..];
    }
    Some(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn canonical_cases() {
        // 空串 / 单字节 < 0x80 / 单字节 >= 0x80 / 短串 / 长串。
        assert_eq!(hex::encode(encode_bytes(b"")), "80");
        assert_eq!(hex::encode(encode_bytes(b"\x00")), "00");
        assert_eq!(hex::encode(encode_bytes(b"\x05")), "05");
        assert_eq!(hex::encode(encode_bytes(b"\x82")), "8182");
        assert_eq!(hex::encode(encode_bytes(b"dog")), "83646f67");
        assert_eq!(hex::encode(encode_u64(0)), "80");
        assert_eq!(hex::encode(encode_u64(9)), "09");
        assert_eq!(hex::encode(encode_u64(127)), "7f");
        assert_eq!(hex::encode(encode_u64(128)), "8180");
        assert_eq!(hex::encode(encode_u64(1024)), "820400");
        // 列表 ["cat","dog"] = c88363617483646f67
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_bytes(b"cat"));
        payload.extend_from_slice(&encode_bytes(b"dog"));
        assert_eq!(hex::encode(encode_list(&payload)), "c88363617483646f67");
    }

    #[test]
    fn long_form_length() {
        // 56+ 字节串 → 长形式（b8 38 = 0x80+56=0xb8, 长度 56 = 0x38）。
        let data = vec![0xa5u8; 56];
        let enc = encode_bytes(&data);
        assert_eq!(enc[0], 0xb8);
        assert_eq!(enc[1], 56);
        assert_eq!(enc.len(), 58);
    }
}
