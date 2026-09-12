//! B4 fuzz target `note_abi`（M8-ACC-7）：
//!
//! 任意字节 → Note/NoteSpec 的 borsh 解码 + 承诺/nullifier 计算，
//! 结构化输入优先，同时保留原始字节路径。全部拒绝路径一律返回
//! `Err`——**任何 panic 即 fuzz 失败**。
//!
//! 覆盖的拒绝/边界路径：
//! - 原始字节截断 / 坏判别（AssetClass 非法 u8）/ 越界数组 → borsh `Err`；
//! - `Note::new` 面额 0 → `InvalidAmount`；
//! - 非法压缩公钥（33B 任意字节）→ 承诺计算仍安全（上层签名验证拒绝，
//!   `public_xy_bytes_from_compressed` 对坏输入返回零字节）；
//! - 解码往返（borsh → encode → decode）承诺必须逐位一致。

#![no_main]

use arbitrary::Arbitrary;
use borsh::BorshDeserialize;
use libfuzzer_sys::fuzz_target;
use poker_appchain::note::{AssetClass, Note, NoteSpec};

/// 结构化输入形状（arbitrary 派生）。
#[derive(Debug, Arbitrary)]
struct NoteShape {
    class_byte: u8,
    amount: u64,
    owner: [u8; 33],
    nonce: [u8; 32],
    table_id: Option<u64>,
    spec_pot_index: u8,
    spec_runout_index: u8,
}

fuzz_target!(|data: &[u8]| {
    // ===== 原始字节路径：borsh 解码（截断/坏判别 → Err，不 panic）=====
    if let Ok(note) = <Note as BorshDeserialize>::try_from_slice(data) {
        // 解码成功 → 承诺/nullifier 计算对任意（含非法公钥）note 必须安全
        let c = note.commitment();
        let _ = note.commitment_bytes();
        let mut secret = [0u8; 32];
        let n = data.len().min(32);
        secret[..n].copy_from_slice(&data[..n]);
        let _ = note.nullifier(&secret);
        // 往返：编码 → 再解码 → 承诺逐位一致（ABI 稳定不变量）
        if let Ok(bytes) = borsh::to_vec(&note) {
            if let Ok(round) = Note::try_from_slice(&bytes) {
                assert_eq!(round.commitment(), c, "note commitment must round-trip");
            }
        }
    }
    if let Ok(spec) = <NoteSpec as BorshDeserialize>::try_from_slice(data) {
        // NoteSpec.mint（amount==0 → Err 拒绝路径）
        let _ = spec.mint([7u8; 32]);
    }

    // ===== 结构化路径：任意形状 → 构造 + 承诺计算 =====
    let mut u = arbitrary::Unstructured::new(data);
    if let Ok(shape) = NoteShape::arbitrary(&mut u) {
        // 非法类字节（≠1/≠2）→ 拒绝路径（from_u8 fail-closed）
        if let Ok(class) = AssetClass::from_u8(shape.class_byte) {
            // 面额 0 → InvalidAmount（其余任意字段都必须可构造）
            if let Ok(note) =
                Note::new(class, shape.amount, shape.owner, shape.nonce, shape.table_id)
            {
                let c = note.commitment();
                let spec = NoteSpec {
                    asset_class: class,
                    amount: shape.amount,
                    owner: shape.owner,
                    table_id: shape.table_id,
                    pot_index: shape.spec_pot_index,
                    runout_index: shape.spec_runout_index,
                };
                if let Ok(minted) = spec.mint(shape.nonce) {
                    assert_eq!(minted.commitment(), c, "spec.mint must preserve commitment");
                }
            }
        }
    }
});
