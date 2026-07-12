# Phase G: LogUp 内存一致性 — 执行计划（续）

## Summary

将 `verify_memory_permutation` 从 O(n²) 集合比较升级为 LogUp permutation argument，复用 `lookup.rs` 中已有的 `LogUpProof` 基础设施。Verifier 端复杂度从 O(n²) 降至 O(n)，且 LogUp proof 可转 CCS 实例供 Hypernova 折叠。

## Current State Analysis

**已完成**（上一会话）：
- ✅ `memory.rs` L1-L25：模块文档更新（LogUp 协议说明）+ import 添加
  - `HashSet`, `Fr`, `compute_multiplicity`, `LogUpCommitments`, `LogUpProof`, `LookupTable`, `ZkvmField`
- ✅ 计划文件 `phase_g_logup_memory_plan.md` 已获批

**未完成**（本计划执行）：
- ❌ `byte_access_to_fr` 私有辅助函数
- ❌ `expand_reads_writes` 私有辅助函数
- ❌ `build_logup_proof` 公开函数
- ❌ `verify_memory_permutation` 改造（L135-L169 仍为 O(n²)）
- ❌ `verify_memory_permutation_logup` 公开函数
- ❌ 11 个新测试

## 技术验证（已确认）

| 项目 | 验证结果 |
|------|----------|
| `Fr` trait bounds | `Bn254ScalarField` derives `Clone, Copy, PartialEq, Eq, Hash` → `HashSet<Fr>` 可用 |
| `compute_multiplicity` 签名 | `fn(table: &LookupTable, witness: &[Fr]) -> Vec<Fr>` — 需包装为 `LookupTable` |
| `ZkvmField::from_u64` | `fn(v: u64) -> Self` — 存在于 `field.rs:L34` |
| `LogUpProof::create` | `fn(table: Vec<Fr>, witness: Vec<Fr>, multiplicity: Vec<Fr>) -> Result<(Self, LogUpCommitments)>` |
| `LogUpProof::verify` | `fn(&self, commits: &LogUpCommitments) -> Result<bool>` |
| `LogUpProof::to_ccs_instance` | `fn(&self) -> Result<CcsInstance>` |

## Proposed Changes

**仅修改一个文件**：`/Users/mac/projects/zchain/poker_zkvm/src/constraints/memory.rs`

### Step 1: G-1 — 添加 `byte_access_to_fr` 辅助函数

**位置**：`ByteAccess` struct 之后（L38 之后），`expand_to_bytes` 之前（L40 之前）

```rust
/// 将 ByteAccess 编码为单个 Fr（permutation key）。
/// key = from_u64(byte_addr | (byte_val << 32))
/// step_index 不编入 key — 时序由 check_uninitialized_read 保证。
fn byte_access_to_fr(ba: &ByteAccess) -> Fr {
    let packed = (ba.byte_addr as u64) | ((ba.byte_val as u64) << 32);
    Fr::from_u64(packed)
}
```

**Why**：LogUp 协议的 table/witness 都是 `Vec<Fr>`，需要将 `(byte_addr, byte_val)` 编码为单个域元素。`byte_addr` 占低 32 位，`byte_val` 占 bits 32-39，无重叠。step_index 不编入（时序由 `check_uninitialized_read` 前置保证）。

### Step 2: G-1 — 添加 `expand_reads_writes` 辅助函数

**位置**：`byte_access_to_fr` 之后

```rust
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
```

**Why**：提取自 `verify_memory_permutation` L139-L148 的重复逻辑，供 `verify_memory_permutation` 和 `verify_memory_permutation_logup` 共用。

### Step 3: G-1 — 添加 `build_logup_proof` 公开函数

**位置**：`expand_reads_writes` 之后

```rust
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
```

**Why**：去重保证 table 中每个 key 唯一，multiplicity 计数对应每个 table entry 被 read 引用的次数。LogUp 等式 `Σ m_i/(β-t_i) == Σ 1/(β-f_j)` 成立 ⟺ read 多重集 == write 多重集（值维度）。

### Step 4: G-3 — 改造 `verify_memory_permutation`

**位置**：L135-L169

**修改点**：
1. L139-L148 替换为 `expand_reads_writes` 调用
2. L153-L166 的 O(n²) 循环替换为 LogUp verify

```rust
pub fn verify_memory_permutation(
    accesses: &[MemAccess],
    step_index: u64,
) -> Result<(), ZkvmError> {
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
```

**Why**：保留 `check_uninitialized_read` 前置检查（时序），LogUp 验证值维度多重集相等。两者组合与旧 O(n²) 实现语义等价。

### Step 5: G-4 — 添加 `verify_memory_permutation_logup` 公开函数

**位置**：`verify_memory_permutation` 之后

```rust
/// 验证内存 permutation 并返回 LogUp proof（供 CCS/Hypernova 折叠）。
///
/// 与 `verify_memory_permutation` 语义相同，但返回 LogUp proof 和承诺，
/// 可通过 `proof.to_ccs_instance()` 转为可折叠的 CCS 实例。
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
```

**Why**：供下游需要 CCS 实例的调用方使用（如 `fold_loop` 集成）。

### Step 6: G-5 — 测试

**位置**：`mod tests` 内（L220 之后）

**正例**（6 个）：
1. `test_logup_build_proof_basic` — SW+LW 相同值，`build_logup_proof` 成功 + `proof.verify` 通过
2. `test_logup_verify_writes_only` — 仅 writes（空 witness），LogUp 等式 0==0 通过
3. `test_logup_verify_empty` — 空 accesses，`verify_memory_permutation` 通过
4. `test_logup_multiple_reads_same_key` — 1 write + 2 reads 同 key，multiplicity=[2]
5. `test_logup_mixed_size_lw_then_lb` — SW 4B + LB 1B，跨尺寸匹配
6. `test_logup_verify_memory_permutation_logup_returns_proof` — 返回值可 `to_ccs_instance`

**负例**（4 个）：
7. `test_logup_soundness_wrong_value` — byte aliasing 攻击（write 0xEF, read 声称 0xFF）
8. `test_logup_soundness_read_not_in_writes` — 读未写入的地址
9. `test_logup_soundness_tampered_table` — 篡改 `proof.table`
10. `test_logup_soundness_tampered_witness` — 篡改 `proof.witness`

**CCS 集成**（1 个）：
11. `test_logup_memory_to_ccs_instance` — memory → LogUp → CcsInstance → `is_satisfied`

## Assumptions & Decisions

1. **permutation key 不含 step_index**：时序由 `check_uninitialized_read` 前置保证，key 只含 `(byte_addr, byte_val)`。这与旧 O(n²) 实现的值匹配逻辑等价（旧实现在 `check_uninitialized_read` 通过后只比较 `byte_addr + byte_val`）。
2. **Domain tag**：复用 `LOOKUP_DOMAIN_TAG (0x12)` 而非新增 `MEM_CHECK_DOMAIN_TAG`。不是安全漏洞（β 从承诺派生），未来可改进。
3. **Prover 端 `compute_multiplicity` 仍为 O(table × witness)**：但 verifier 端从 O(n²) 降至 O(n)。Prover 端优化（如 HashMap 索引）留待未来。
4. **空 witness 特殊情况**：reads 为空时 `Σ 1/(β-f_j) = 0`，writes 为空时 `Σ m_i/(β-t_i) = 0`，等式 0==0 成立。`compute_multiplicity` 对空 witness 返回全零 multiplicity，`LogUpProof::create` 接受空 witness。

## Verification Steps

```bash
# 1. memory 模块测试（现有 14 个 + 新增 11 个 = 25 个）
cargo test -p poker_zkvm --lib constraints::memory

# 2. lookup 模块测试（确保无回归）
cargo test -p poker_zkvm --lib constraints::lookup

# 3. 全 constraints 模块测试
cargo test -p poker_zkvm --lib constraints

# 4. clippy（memory.rs 新增代码应无警告）
cargo clippy -p poker_zkvm --lib

# 5. 全量回归
cargo test -p poker_zkvm --lib
```

## 语义等价性分析

| 场景 | 旧 O(n²) | 新 LogUp |
|------|----------|----------|
| 同步 read-after-write (step 相同) | `check_uninitialized_read` 失败 (`<`) | 同左 |
| 异步 read-after-write，值匹配 | `check_uninitialized_read` 通过 + O(n²) 匹配 | `check_uninitialized_read` 通过 + LogUp 等式成立 |
| 异步 read-after-write，值不匹配 | `check_uninitialized_read` 通过 + O(n²) 不匹配 | `check_uninitialized_read` 通过 + LogUp 等式失败 |
| read 未写入地址 | `check_uninitialized_read` 失败 | 同左 |

LogUp 验证 `(addr, val)` 多重集相等，`check_uninitialized_read` 验证时序。两者组合与旧实现语义等价。
