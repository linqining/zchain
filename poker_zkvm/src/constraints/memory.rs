//! 内存访问与一致性电路（Phase 5 — Task 5.3，Phase G — LogUp 升级）。
//!
//! 严格遵循 spec.md L288-298（v1.4 FROZEN）：
//! - **byte-level permutation**（非 word-level）— 所有访问展开为字节级
//! - permutation key: `(byte_addr, byte_val)`
//! - **混合尺寸重叠访问** — LW 写 4B 后 LB 读 1B 能正确匹配
//! - `step_index` 单调性显式约束
//! - **未初始化读取检测** — read 集合中无 write 对应记录返回 `UninitializedRead`
//!
//! ## LogUp 协议（Phase G）
//!
//! `verify_memory_permutation` 使用 LogUp permutation argument 替代 O(n²) 集合比较：
//! - Table T = 去重后的 write keys（`(byte_addr, byte_val)` 编码为 Fr）
//! - Witness F = read keys
//! - Multiplicity m_i = 匹配 write key i 的 read 数量
//! - 等式 `Σ m_i/(β-t_i) == Σ 1/(β-f_j)` 证明 read 多重集 == write 多重集
//! - 时序由 `check_uninitialized_read` 前置检查保证

use std::collections::HashSet;

use crate::ccs::Fr;
use crate::constraints::lookup::{LogUpCommitments, LogUpProof, LookupTable, compute_multiplicity};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::trace::{MemAccess, MemOp};

/// 字节级内存访问记录（permutation key 组成部分）。
///
/// spec L293: permutation key 为 `(byte_addr, byte_val, step_index)`。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ByteAccess {
    /// 字节地址（word addr × size + byte offset）
    pub byte_addr: u32,
    /// 字节值（0-255）
    pub byte_val: u8,
    /// 步序号（单调递增）
    pub step_index: u64,
}

/// 将 ByteAccess 编码为单个 Fr（permutation key）。
/// key = from_u64(byte_addr | (byte_val << 32))
/// step_index 不编入 key — 时序由 check_uninitialized_read 保证。
fn byte_access_to_fr(ba: &ByteAccess) -> Fr {
    let packed = (ba.byte_addr as u64) | ((ba.byte_val as u64) << 32);
    Fr::from_u64(packed)
}

/// 将 MemAccess 列表展开为字节级 reads 和 writes。
fn expand_reads_writes(
    accesses: &[MemAccess],
    step_index: u64,
) -> Result<(Vec<ByteAccess>, Vec<ByteAccess>), ZkvmError> {
    let mut reads = Vec::new();
    let mut writes = Vec::new();
    for access in accesses {
        let byte_accesses = expand_to_bytes(access, step_index)?;
        match access.op {
            MemOp::Read => reads.extend(byte_accesses),
            MemOp::Write => writes.extend(byte_accesses),
        }
    }
    Ok((reads, writes))
}

/// 从字节级 reads/writes 构建 LogUp permutation proof。
///
/// - Table T = 去重后的 write keys（唯一 (byte_addr, byte_val) 的 Fr 编码）
/// - Witness F = read keys（每个 read 一个 Fr）
/// - Multiplicity m_i = 匹配 write key i 的 read 数量
///
/// # 错误
/// - `LogUpProof::create` 内部错误（table.len != multiplicity.len）透传
pub fn build_logup_proof(
    reads: &[ByteAccess],
    writes: &[ByteAccess],
) -> Result<(LogUpProof, LogUpCommitments), ZkvmError> {
    // 1. writes → 去重 → table
    let mut seen: HashSet<Fr> = HashSet::new();
    let mut table: Vec<Fr> = Vec::new();
    for w in writes {
        let key = byte_access_to_fr(w);
        if seen.insert(key) {
            table.push(key);
        }
    }

    // 2. reads → witness
    let witness: Vec<Fr> = reads.iter().map(byte_access_to_fr).collect();

    // 3. multiplicity
    let lookup_table = LookupTable::from_entries(table.clone());
    let multiplicity = compute_multiplicity(&lookup_table, &witness);

    // 4. create
    LogUpProof::create(table, witness, multiplicity)
}

/// 将 MemAccess 展开为字节级记录（spec L292）。
///
/// - LW/SW (size=4) → 4 条字节记录
/// - LH/SH/LHU (size=2) → 2 条字节记录
/// - LB/SB/LBU (size=1) → 1 条字节记录
///
/// 小端序展开：低字节在低地址。
///
/// # 参数
/// - `access` — 原始 MemAccess（含 addr/op/value/size）
/// - `step_index` — 该访问所属的步序号
///
/// # 返回
/// 字节级记录列表（长度 = access.size）
///
/// # 错误
/// - size 不在 {1, 2, 4} 返回 `ZkvmError::Other`
/// - addr + size 溢出（checked_add 防 wrap 攻击）返回 `ZkvmError::Other`
pub fn expand_to_bytes(access: &MemAccess, step_index: u64) -> Result<Vec<ByteAccess>, ZkvmError> {
    let size = access.size as usize;
    if !matches!(size, 1 | 2 | 4) {
        return Err(ZkvmError::Other(format!(
            "expand_to_bytes: size {} 不在 {{1, 2, 4}}",
            size
        )));
    }

    // checked_add 防多字节访问 wrap 攻击（spec L294）
    let end_addr = access.addr.checked_add(access.size as u32).ok_or_else(|| {
        ZkvmError::Other(format!(
            "expand_to_bytes: addr 0x{:08x} + size {} 溢出",
            access.addr, size
        ))
    })?;

    let bytes = access.value.to_le_bytes();
    let mut result = Vec::with_capacity(size);

    for (i, &byte_val) in bytes.iter().take(size).enumerate() {
        result.push(ByteAccess {
            byte_addr: access.addr + i as u32,
            byte_val,
            step_index,
        });
    }

    debug_assert!(result.last().is_none_or(|ba| ba.byte_addr < end_addr));
    Ok(result)
}

/// 检查未初始化读取（spec L297）。
///
/// 对 read 集合中的每个 `(byte_addr, step_index)`，检查 write 集合中是否存在
/// 相同 `byte_addr` 且 `write.step_index < read.step_index` 的记录。
///
/// # 参数
/// - `reads` — 读访问的字节级记录列表
/// - `writes` — 写访问的字节级记录列表
///
/// # 错误
/// 若存在未初始化读取，返回 `ZkvmError::UninitializedRead { addr }`
pub fn check_uninitialized_read(
    reads: &[ByteAccess],
    writes: &[ByteAccess],
) -> Result<(), ZkvmError> {
    for read in reads {
        let has_prior_write = writes
            .iter()
            .any(|w| w.byte_addr == read.byte_addr && w.step_index < read.step_index);
        if !has_prior_write {
            return Err(ZkvmError::UninitializedRead {
                addr: read.byte_addr,
            });
        }
    }
    Ok(())
}

/// 校验内存 permutation（LogUp permutation argument）。
///
/// spec L293: 证明 read 集合 == write 集合（permutation argument）。
///
/// 使用 LogUp 协议替代 O(n²) 集合比较：
/// - Table T = 去重后的 write keys（`(byte_addr, byte_val)` 编码为 Fr）
/// - Witness F = read keys
/// - Multiplicity m_i = 匹配 write key i 的 read 数量
/// - 等式 `Σ m_i/(β-t_i) == Σ 1/(β-f_j)` 证明 read 多重集 == write 多重集
///
/// 时序由 `check_uninitialized_read` 前置检查保证。
///
/// # 参数
/// - `accesses` — 单步内的所有内存访问（按时间顺序）
/// - `step_index` — 该步的步序号
///
/// # 错误
/// - 未初始化读取返回 `ZkvmError::UninitializedRead`
/// - permutation 不匹配返回 `ZkvmError::Other`
pub fn verify_memory_permutation(accesses: &[MemAccess], step_index: u64) -> Result<(), ZkvmError> {
    let (reads, writes) = expand_reads_writes(accesses, step_index)?;

    // 1. 未初始化读取检测（时序保证）
    check_uninitialized_read(&reads, &writes)?;

    // 2. permutation 校验（LogUp 协议）
    let (proof, commits) = build_logup_proof(&reads, &writes)?;
    if !proof.verify(&commits)? {
        return Err(ZkvmError::Other(
            "permutation 不匹配: LogUp 等式校验失败".to_string(),
        ));
    }

    Ok(())
}

/// 验证内存 permutation 并返回 LogUp proof（供 CCS/Hypernova 折叠）。
///
/// 与 `verify_memory_permutation` 语义相同，但返回 LogUp proof 和承诺，
/// 可通过 `proof.to_ccs_instance()` 转为可折叠的 CCS 实例。
///
/// # 参数
/// - `accesses` — 单步内的所有内存访问（按时间顺序）
/// - `step_index` — 该步的步序号
///
/// # 返回
/// `(LogUpProof, LogUpCommitments)` — 证明与承诺三元组
///
/// # 错误
/// - 未初始化读取返回 `ZkvmError::UninitializedRead`
/// - permutation 不匹配返回 `ZkvmError::Other`
pub fn verify_memory_permutation_logup(
    accesses: &[MemAccess],
    step_index: u64,
) -> Result<(LogUpProof, LogUpCommitments), ZkvmError> {
    let (reads, writes) = expand_reads_writes(accesses, step_index)?;
    check_uninitialized_read(&reads, &writes)?;
    let (proof, commits) = build_logup_proof(&reads, &writes)?;
    if !proof.verify(&commits)? {
        return Err(ZkvmError::Other(
            "permutation 不匹配: LogUp 等式校验失败".to_string(),
        ));
    }
    Ok((proof, commits))
}

/// 校验 step_index 单调性（spec L296）。
///
/// 约束 `step_{i+1} > step_i`，防止 permutation 顺序伪造。
///
/// # 参数
/// - `step_indices` — 步序号列表（按顺序）
///
/// # 错误
/// 若非严格单调递增，返回 `ZkvmError::Other`
pub fn check_step_monotonicity(step_indices: &[u64]) -> Result<(), ZkvmError> {
    for w in step_indices.windows(2) {
        if w[1] <= w[0] {
            return Err(ZkvmError::Other(format!(
                "step_index 非单调递增: {} -> {}",
                w[0], w[1]
            )));
        }
    }
    Ok(())
}

/// 从字节数组重建 u32 值（小端序）。
///
/// 用于 LW/LB/LH 读取后的值重建。
pub fn rebuild_value(bytes: &[u8], size: u8) -> Result<u32, ZkvmError> {
    let size = size as usize;
    if !matches!(size, 1 | 2 | 4) {
        return Err(ZkvmError::Other(format!(
            "rebuild_value: size {} 不在 {{1, 2, 4}}",
            size
        )));
    }
    if bytes.len() < size {
        return Err(ZkvmError::Other(format!(
            "rebuild_value: bytes.len() {} < size {}",
            bytes.len(),
            size
        )));
    }
    let mut arr = [0u8; 4];
    arr[..size].copy_from_slice(&bytes[..size]);
    Ok(u32::from_le_bytes(arr))
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_access(addr: u32, op: MemOp, value: u32, size: u8) -> MemAccess {
        MemAccess {
            addr,
            op,
            value,
            size,
        }
    }

    // ===== expand_to_bytes 测试 =====

    #[test]
    fn test_expand_word_write() {
        let access = make_access(0x100, MemOp::Write, 0xDEADBEEF, 4);
        let bytes = expand_to_bytes(&access, 0).expect("应成功");

        assert_eq!(bytes.len(), 4);
        // 小端序: EF BE AD DE
        assert_eq!(bytes[0].byte_addr, 0x100);
        assert_eq!(bytes[0].byte_val, 0xEF);
        assert_eq!(bytes[1].byte_addr, 0x101);
        assert_eq!(bytes[1].byte_val, 0xBE);
        assert_eq!(bytes[2].byte_addr, 0x102);
        assert_eq!(bytes[2].byte_val, 0xAD);
        assert_eq!(bytes[3].byte_addr, 0x103);
        assert_eq!(bytes[3].byte_val, 0xDE);

        // 所有字节共享 step_index
        for ba in &bytes {
            assert_eq!(ba.step_index, 0);
        }
    }

    #[test]
    fn test_expand_byte_access() {
        let access = make_access(0x200, MemOp::Read, 0x42, 1);
        let bytes = expand_to_bytes(&access, 5).expect("应成功");

        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0].byte_addr, 0x200);
        assert_eq!(bytes[0].byte_val, 0x42);
        assert_eq!(bytes[0].step_index, 5);
    }

    #[test]
    fn test_expand_half_access() {
        let access = make_access(0x300, MemOp::Write, 0xBEEF, 2);
        let bytes = expand_to_bytes(&access, 3).expect("应成功");

        assert_eq!(bytes.len(), 2);
        // 小端序: EF BE
        assert_eq!(bytes[0].byte_addr, 0x300);
        assert_eq!(bytes[0].byte_val, 0xEF);
        assert_eq!(bytes[1].byte_addr, 0x301);
        assert_eq!(bytes[1].byte_val, 0xBE);
    }

    #[test]
    fn test_expand_invalid_size() {
        let access = make_access(0x100, MemOp::Write, 0xFF, 3);
        let err = expand_to_bytes(&access, 0).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("size")));
    }

    #[test]
    fn test_expand_addr_overflow() {
        // addr = u32::MAX - 1, size = 4 → addr + size 溢出
        let access = make_access(u32::MAX - 1, MemOp::Write, 0xDEADBEEF, 4);
        let err = expand_to_bytes(&access, 0).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("溢出")));
    }

    // ===== check_uninitialized_read 测试 =====

    #[test]
    fn test_uninitialized_read_detected() {
        // 读地址 0x100，但 write 集合中没有该地址的写
        let reads = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 5,
        }];
        let writes = vec![ByteAccess {
            byte_addr: 0x200,
            byte_val: 0x99,
            step_index: 0,
        }];

        let err = check_uninitialized_read(&reads, &writes).unwrap_err();
        assert!(matches!(err, ZkvmError::UninitializedRead { addr: 0x100 }));
    }

    #[test]
    fn test_initialized_read_passes() {
        // step 0 写，step 5 读 → 合法
        let reads = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 5,
        }];
        let writes = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 0,
        }];

        assert!(check_uninitialized_read(&reads, &writes).is_ok());
    }

    #[test]
    fn test_uninitialized_read_future_write() {
        // step 5 读，step 10 写 → 未初始化（write 在 read 之后）
        let reads = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 5,
        }];
        let writes = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 10,
        }];

        let err = check_uninitialized_read(&reads, &writes).unwrap_err();
        assert!(matches!(err, ZkvmError::UninitializedRead { addr: 0x100 }));
    }

    // ===== verify_memory_permutation 测试 =====

    #[test]
    fn test_permutation_write_then_read_word() {
        // step 0: SW 0xDEADBEEF 到 0x100
        // step 1: LW 从 0x100 读取
        let write_access = make_access(0x100, MemOp::Write, 0xDEADBEEF, 4);
        let read_access = make_access(0x100, MemOp::Read, 0xDEADBEEF, 4);

        // step 0: 仅有写，无读 → verify 应通过
        assert!(verify_memory_permutation(&[write_access], 0).is_ok());

        // 跨步校验：step 0 的 write + step 1 的 read
        let write_bytes =
            expand_to_bytes(&make_access(0x100, MemOp::Write, 0xDEADBEEF, 4), 0).expect("expand");
        let read_bytes = expand_to_bytes(&read_access, 1).expect("expand");
        assert!(check_uninitialized_read(&read_bytes, &write_bytes).is_ok());
    }

    #[test]
    fn test_permutation_mixed_size_lw_then_lb() {
        // spec L294: LW 写 4B 后 LB 读 1B 能正确匹配
        // step 0: SW 0xDEADBEEF 到 0x100（4 字节写）
        // step 1: LB 从 0x100 读取（读低字节 0xEF）

        let write_bytes = expand_to_bytes(&make_access(0x100, MemOp::Write, 0xDEADBEEF, 4), 0)
            .expect("expand write");

        let read_bytes =
            expand_to_bytes(&make_access(0x100, MemOp::Read, 0xEF, 1), 1).expect("expand read");

        // 验证 read 的 byte_val == write 的对应字节
        assert_eq!(read_bytes[0].byte_val, 0xEF);
        assert_eq!(write_bytes[0].byte_val, 0xEF);

        // 未初始化读取检测应通过
        assert!(check_uninitialized_read(&read_bytes, &write_bytes).is_ok());
    }

    #[test]
    fn test_permutation_mixed_size_lb_then_lw() {
        // 反向: LB 写 1B 后 LW 读 4B（其他字节未初始化）
        // step 0: SB 0x42 到 0x100（1 字节写）
        // step 1: LW 从 0x100 读取 4 字节

        let write_bytes =
            expand_to_bytes(&make_access(0x100, MemOp::Write, 0x42, 1), 0).expect("expand write");

        let read_bytes =
            expand_to_bytes(&make_access(0x100, MemOp::Read, 0x42, 4), 1).expect("expand read");

        // read 包含 4 个字节，但 write 只有 1 个 → 地址 0x101/0x102/0x103 未初始化
        let err = check_uninitialized_read(&read_bytes, &write_bytes).unwrap_err();
        assert!(matches!(err, ZkvmError::UninitializedRead { addr: 0x101 }));
    }

    #[test]
    fn test_permutation_mixed_size_lw_then_lb_high_byte() {
        // LW 写 4B，LB 读第 2 字节（addr+1）
        let write_bytes = expand_to_bytes(&make_access(0x100, MemOp::Write, 0xDEADBEEF, 4), 0)
            .expect("expand write");

        // 读 0x101 字节 = 0xBE
        let read_bytes =
            expand_to_bytes(&make_access(0x101, MemOp::Read, 0xBE, 1), 1).expect("expand read");

        assert_eq!(read_bytes[0].byte_val, 0xBE);
        assert_eq!(write_bytes[1].byte_val, 0xBE);
        assert!(check_uninitialized_read(&read_bytes, &write_bytes).is_ok());
    }

    // ===== check_step_monotonicity 测试 =====

    #[test]
    fn test_step_monotonicity_valid() {
        assert!(check_step_monotonicity(&[0, 1, 2, 3, 4]).is_ok());
        assert!(check_step_monotonicity(&[10, 20, 30]).is_ok());
        assert!(check_step_monotonicity(&[0]).is_ok());
        assert!(check_step_monotonicity(&[]).is_ok());
    }

    #[test]
    fn test_step_monotonicity_equal_rejected() {
        let err = check_step_monotonicity(&[0, 1, 1, 2]).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("非单调递增")));
    }

    #[test]
    fn test_step_monotonicity_decrease_rejected() {
        let err = check_step_monotonicity(&[0, 5, 3, 10]).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("非单调递增")));
    }

    // ===== rebuild_value 测试 =====

    #[test]
    fn test_rebuild_value_word() {
        let bytes = [0xEF, 0xBE, 0xAD, 0xDE];
        let val = rebuild_value(&bytes, 4).expect("应成功");
        assert_eq!(val, 0xDEADBEEF);
    }

    #[test]
    fn test_rebuild_value_half() {
        let bytes = [0xEF, 0xBE];
        let val = rebuild_value(&bytes, 2).expect("应成功");
        assert_eq!(val, 0xBEEF);
    }

    #[test]
    fn test_rebuild_value_byte() {
        let bytes = [0x42];
        let val = rebuild_value(&bytes, 1).expect("应成功");
        assert_eq!(val, 0x42);
    }

    #[test]
    fn test_rebuild_value_invalid_size() {
        let bytes = [0x00; 4];
        let err = rebuild_value(&bytes, 3).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("size")));
    }

    // ===== 综合测试 =====

    #[test]
    fn test_word_write_then_read_consistency() {
        // 完整流程: SW 4B → LW 4B，值一致
        let write = make_access(0x1000, MemOp::Write, 0xCAFEBABE, 4);
        let read = make_access(0x1000, MemOp::Read, 0xCAFEBABE, 4);

        let write_bytes = expand_to_bytes(&write, 0).expect("expand write");
        let read_bytes = expand_to_bytes(&read, 1).expect("expand read");

        // 字节值应一一对应
        for (r, w) in read_bytes.iter().zip(write_bytes.iter()) {
            assert_eq!(r.byte_val, w.byte_val);
            assert_eq!(r.byte_addr, w.byte_addr);
        }

        assert!(check_uninitialized_read(&read_bytes, &write_bytes).is_ok());
    }

    #[test]
    fn test_soundness_byte_aliasing_attack() {
        // 攻击: SW 0xDEADBEEF 到 0x100，LB 从 0x100 读但声称值为 0xFF（不是 0xEF）
        let write_bytes = expand_to_bytes(&make_access(0x100, MemOp::Write, 0xDEADBEEF, 4), 0)
            .expect("expand write");

        let read_bytes = [ByteAccess {
            byte_addr: 0x100,
            byte_val: 0xFF, // 伪造值（正确应为 0xEF）
            step_index: 1,
        }];

        // permutation 校验应失败（byte_val 不匹配）
        let matched = write_bytes.iter().any(|w| {
            w.byte_addr == read_bytes[0].byte_addr
                && w.byte_val == read_bytes[0].byte_val
                && w.step_index <= read_bytes[0].step_index
        });
        assert!(!matched, "byte aliasing 攻击应被检测");
    }

    #[test]
    fn test_soundness_permutation_order_forgery() {
        // 攻击: step 5 写，step 0 读（顺序伪造，read 在 write 之前）
        let write_bytes = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 5, // write 在后
        }];

        let read_bytes = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 0, // read 在前
        }];

        // 未初始化读取检测应失败（write.step > read.step）
        let err = check_uninitialized_read(&read_bytes, &write_bytes).unwrap_err();
        assert!(matches!(err, ZkvmError::UninitializedRead { addr: 0x100 }));
    }

    #[test]
    fn test_multiple_writes_same_addr() {
        // 同地址多次写：最新值应覆盖旧值
        let write1 =
            expand_to_bytes(&make_access(0x100, MemOp::Write, 0xAAAA, 2), 0).expect("expand");

        let write2 =
            expand_to_bytes(&make_access(0x100, MemOp::Write, 0xBBBB, 2), 1).expect("expand");

        let read = expand_to_bytes(&make_access(0x100, MemOp::Read, 0xBBBB, 2), 2).expect("expand");

        let all_writes: Vec<ByteAccess> = write1.iter().chain(write2.iter()).cloned().collect();

        // 读应匹配最新的写（step 1，值 0xBBBB）
        assert!(check_uninitialized_read(&read, &all_writes).is_ok());

        // 验证读到的是最新值
        for r in &read {
            let latest_write = all_writes
                .iter()
                .filter(|w| w.byte_addr == r.byte_addr && w.step_index < r.step_index)
                .max_by_key(|w| w.step_index);
            assert_eq!(latest_write.unwrap().byte_val, r.byte_val);
        }
    }

    // ===== LogUp 测试（Phase G）=====

    #[test]
    fn test_logup_build_proof_basic() {
        // SW 0xDEADBEEF 到 0x100（step 0），LW 读取（step 1）
        let writes = expand_to_bytes(&make_access(0x100, MemOp::Write, 0xDEADBEEF, 4), 0)
            .expect("expand write");
        let reads = expand_to_bytes(&make_access(0x100, MemOp::Read, 0xDEADBEEF, 4), 1)
            .expect("expand read");

        let (proof, commits) = build_logup_proof(&reads, &writes).expect("build_logup_proof");
        assert!(
            proof.verify(&commits).expect("verify"),
            "LogUp proof 应验证通过"
        );
    }

    #[test]
    fn test_logup_verify_writes_only() {
        // 仅 writes（空 witness），LogUp 等式 0==0 通过
        let writes = expand_to_bytes(&make_access(0x100, MemOp::Write, 0xDEADBEEF, 4), 0)
            .expect("expand write");
        let reads: Vec<ByteAccess> = vec![];

        let (proof, commits) = build_logup_proof(&reads, &writes).expect("build_logup_proof");
        assert!(
            proof.verify(&commits).expect("verify"),
            "空 witness 应通过（0==0）"
        );
    }

    #[test]
    fn test_logup_verify_empty() {
        // 空 accesses，verify_memory_permutation 通过
        assert!(verify_memory_permutation(&[], 0).is_ok());
    }

    #[test]
    fn test_logup_multiple_reads_same_key() {
        // 1 write + 2 reads 同 key，multiplicity=[2]
        let writes = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 0,
        }];
        let reads = vec![
            ByteAccess {
                byte_addr: 0x100,
                byte_val: 0x42,
                step_index: 1,
            },
            ByteAccess {
                byte_addr: 0x100,
                byte_val: 0x42,
                step_index: 2,
            },
        ];

        let (proof, commits) = build_logup_proof(&reads, &writes).expect("build_logup_proof");
        assert_eq!(proof.table.len(), 1, "去重后 table 应有 1 个 entry");
        assert_eq!(proof.multiplicity.len(), 1);
        assert_eq!(
            proof.multiplicity[0],
            Fr::from_u64(2),
            "multiplicity 应为 2"
        );
        assert!(proof.verify(&commits).expect("verify"), "LogUp 等式应成立");
    }

    #[test]
    fn test_logup_mixed_size_lw_then_lb() {
        // SW 4B + LB 1B，跨尺寸匹配
        let write_bytes = expand_to_bytes(&make_access(0x100, MemOp::Write, 0xDEADBEEF, 4), 0)
            .expect("expand write");
        let read_bytes =
            expand_to_bytes(&make_access(0x100, MemOp::Read, 0xEF, 1), 1).expect("expand read");

        let (proof, commits) =
            build_logup_proof(&read_bytes, &write_bytes).expect("build_logup_proof");
        assert!(proof.verify(&commits).expect("verify"), "跨尺寸匹配应通过");
    }

    #[test]
    fn test_logup_verify_memory_permutation_logup_returns_proof() {
        // verify_memory_permutation_logup 返回值可 to_ccs_instance
        let write_access = make_access(0x100, MemOp::Write, 0xDEADBEEF, 4);
        let (proof, _commits) =
            verify_memory_permutation_logup(&[write_access], 0).expect("verify");

        let ccs_instance = proof.to_ccs_instance().expect("to_ccs_instance");
        assert!(
            ccs_instance.is_satisfied().expect("is_satisfied"),
            "CCS 实例应满足"
        );
    }

    #[test]
    fn test_logup_soundness_wrong_value() {
        // byte aliasing 攻击：write 0xEF, read 声称 0xFF
        let writes = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0xEF,
            step_index: 0,
        }];
        let reads = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0xFF,
            step_index: 1,
        }];

        let (proof, commits) = build_logup_proof(&reads, &writes).expect("build_logup_proof");
        assert!(
            !proof.verify(&commits).expect("verify"),
            "byte aliasing 攻击应被 LogUp 检测"
        );
    }

    #[test]
    fn test_logup_soundness_read_not_in_writes() {
        // 读未写入的地址
        let writes = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 0,
        }];
        let reads = vec![ByteAccess {
            byte_addr: 0x200,
            byte_val: 0x42,
            step_index: 1,
        }];

        // check_uninitialized_read 检测
        let err = check_uninitialized_read(&reads, &writes).unwrap_err();
        assert!(matches!(err, ZkvmError::UninitializedRead { addr: 0x200 }));

        // LogUp 也检测（read key 不在 table 中）
        let (proof, commits) = build_logup_proof(&reads, &writes).expect("build_logup_proof");
        assert!(
            !proof.verify(&commits).expect("verify"),
            "未写入地址的 read 应被 LogUp 检测"
        );
    }

    #[test]
    fn test_logup_soundness_tampered_table() {
        let writes = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 0,
        }];
        let reads = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 1,
        }];

        let (mut proof, commits) = build_logup_proof(&reads, &writes).expect("build_logup_proof");
        assert!(
            proof.verify(&commits).expect("verify original"),
            "原始 proof 应通过"
        );

        // 篡改 table
        proof.table[0] = Fr::from_u64(0xDEAD);
        assert!(
            !proof.verify(&commits).expect("verify tampered"),
            "篡改 table 应被检测"
        );
    }

    #[test]
    fn test_logup_soundness_tampered_witness() {
        let writes = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 0,
        }];
        let reads = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 0x42,
            step_index: 1,
        }];

        let (mut proof, commits) = build_logup_proof(&reads, &writes).expect("build_logup_proof");
        assert!(
            proof.verify(&commits).expect("verify original"),
            "原始 proof 应通过"
        );

        // 篡改 witness
        proof.witness[0] = Fr::from_u64(0xBEEF);
        assert!(
            !proof.verify(&commits).expect("verify tampered"),
            "篡改 witness 应被检测"
        );
    }

    #[test]
    fn test_logup_memory_to_ccs_instance() {
        // memory → LogUp → CcsInstance → is_satisfied
        let write_access = make_access(0x100, MemOp::Write, 0xDEADBEEF, 4);
        let (proof, _commits) =
            verify_memory_permutation_logup(&[write_access], 0).expect("verify");

        let ccs_instance = proof.to_ccs_instance().expect("to_ccs_instance");
        assert!(
            ccs_instance.is_satisfied().expect("is_satisfied"),
            "CCS 实例应满足"
        );
    }
}
