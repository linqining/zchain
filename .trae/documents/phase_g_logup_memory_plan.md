# Phase G: LogUp 内存一致性 — 执行计划

## Context

当前 `verify_memory_permutation`（`memory.rs:L126-160`）使用 O(n²) 嵌套循环：对每个 read 遍历所有 writes 查找匹配。Phase G 将此替换为 LogUp permutation argument，复用 `lookup.rs` 中已有的 `LogUpProof` 基础设施。

**动机**：O(n²) 验证无法转为电路内约束，且大规模内存访问性能差。LogUp 将验证复杂度降至 O(n)，且 `LogUpProof::to_ccs_instance()` 已存在，可直接生成可折叠的 CCS 实例。

**交付物**：`verify_memory_permutation` 使用 LogUp；新增 `build_logup_proof` + `verify_memory_permutation_logup`；LogUp proof 可转 CCS 实例供 Hypernova 折叠。

---

## 修改范围

**仅修改一个文件**：`poker_zkvm/src/constraints/memory.rs`

**复用（不修改）**：
- `constraints/lookup.rs` — `LogUpProof::create/verify/verify_equation/to_ccs_instance`、`compute_multiplicity`、`LookupTable`
- `ccs/mod.rs` — `Fr` 类型、`CcsInstance`
- `field.rs` — `ZkvmField::from_u64`
- `transcript.rs` — `LOOKUP_DOMAIN_TAG`（已有，`MEM_CHECK_DOMAIN_TAG` 留待未来改进）

---

## 实现步骤

### G-1: `build_logup_proof` + 编码辅助

**新增 import**（memory.rs 顶部）：
```rust
use std::collections::HashSet;
use crate::ccs::Fr;
use crate::constraints::lookup::{compute_multiplicity, LogUpCommitments, LogUpProof, LookupTable};
use crate::field::ZkvmField;
```

**新增私有辅助 `byte_access_to_fr`**：
```rust
/// 将 ByteAccess 编码为单个 Fr（permutation key）。
/// key = from_u64(byte_addr | (byte_val << 32))
/// step_index 不编入 key — 时序由 check_uninitialized_read 保证。
fn byte_access_to_fr(ba: &ByteAccess) -> Fr {
    let packed = (ba.byte_addr as u64) | ((ba.byte_val as u64) << 32);
    Fr::from_u64(packed)
}
```

**新增私有辅助 `expand_reads_writes`**：
```rust
/// 将 MemAccess 列表展开为字节级 reads 和 writes。
fn expand_reads_writes(
    accesses: &[MemAccess],
    step_index: u64,
) -> Result<(Vec<ByteAccess>, Vec<ByteAccess>), ZkvmError>
```
提取自 `verify_memory_permutation` 的 L130-139，供两个公开函数复用。

**新增公开函数 `build_logup_proof`**：
```rust
/// 从字节级 reads/writes 构建 LogUp permutation proof。
///
/// - Table T = 去重后的 write keys（唯一 (byte_addr, byte_val) 的 Fr 编码）
/// - Witness F = read keys（每个 read 一个 Fr）
/// - Multiplicity m_i = 匹配 write key i 的 read 数量
pub fn build_logup_proof(
    reads: &[ByteAccess],
    writes: &[ByteAccess],
) -> Result<(LogUpProof, LogUpCommitments), ZkvmError>
```

逻辑：
1. `writes` → `byte_access_to_fr` → `HashSet<Fr>` 去重 → `table: Vec<Fr>`
2. `reads` → `byte_access_to_fr` → `witness: Vec<Fr>`
3. `LookupTable::from_entries(table)` + `compute_multiplicity(&table, &witness)` → `multiplicity: Vec<Fr>`
4. `LogUpProof::create(table, witness, multiplicity)` → `(proof, commits)`

### G-2: 保留 `check_uninitialized_read` 作为前置检查

不修改。在 `verify_memory_permutation` 和 `verify_memory_permutation_logup` 中均作为第一步调用。

### G-3: 修改 `verify_memory_permutation`

**签名不变**：`pub fn verify_memory_permutation(accesses: &[MemAccess], step_index: u64) -> Result<(), ZkvmError>`

**替换 L144-157 的 O(n²) 循环**：
```rust
// 2. permutation 校验（LogUp 协议）
let (proof, commits) = build_logup_proof(&reads, &writes)?;
if !proof.verify(&commits)? {
    return Err(ZkvmError::Other(
        "permutation 不匹配: LogUp 等式校验失败".to_string(),
    ));
}
```

### G-4: CCS 集成（已存在）

`LogUpProof::to_ccs_instance()` 已在 `lookup.rs:L382` 实现，可直接调用：
```rust
let ccs_instance = proof.to_ccs_instance()?;  // 可被 fold_loop 消费
```

新增 `verify_memory_permutation_logup` 公开函数返回 LogUp proof，供下游 CCS 集成：
```rust
/// 验证内存 permutation 并返回 LogUp proof（供 CCS/Hypernova 折叠）。
pub fn verify_memory_permutation_logup(
    accesses: &[MemAccess],
    step_index: u64,
) -> Result<(LogUpProof, LogUpCommitments), ZkvmError>
```

### G-5: 测试

**正例**（6 个）：
1. `test_logup_build_proof_basic` — SW+LW 相同值，proof.verify 通过
2. `test_logup_verify_writes_only` — 仅 writes（空 witness），0==0 通过
3. `test_logup_verify_empty` — 空 accesses，通过
4. `test_logup_multiple_reads_same_key` — 1 write + 2 reads，multiplicity=[2]
5. `test_logup_mixed_size_lw_then_lb` — SW 4B + LB 1B，跨尺寸匹配
6. `test_logup_verify_memory_permutation_logup_returns_proof` — 返回值可 to_ccs_instance

**负例**（4 个）：
7. `test_logup_soundness_wrong_value` — byte aliasing 攻击（write 0xEF, read 声称 0xFF）
8. `test_logup_soundness_read_not_in_writes` — 读未写入的地址
9. `test_logup_soundness_tampered_table` — 篡改 proof.table
10. `test_logup_soundness_tampered_witness` — 篡改 proof.witness

**CCS 集成**（1 个）：
11. `test_logup_memory_to_ccs_instance` — memory → LogUp → CcsInstance → is_satisfied

**回归**：
- 现有 `test_permutation_write_then_read_word` 等 14 个测试必须不变通过

---

## 语义等价性分析

| 场景 | 旧 O(n²) | 新 LogUp |
|------|----------|----------|
| 同步 read-after-write (step 相同) | `check_uninitialized_read` 失败 (`<`) | 同左 |
| 异步 read-after-write，值匹配 | `check_uninitialized_read` 通过 + O(n²) 匹配 | `check_uninitialized_read` 通过 + LogUp 等式成立 |
| 异步 read-after-write，值不匹配 | `check_uninitialized_read` 通过 + O(n²) 不匹配 | `check_uninitialized_read` 通过 + LogUp 等式失败 |
| read 未写入地址 | `check_uninitialized_read` 失败 | 同左 |

LogUp 验证 `(addr, val)` 多重集相等，`check_uninitialized_read` 验证时序。两者组合与旧实现语义等价。

---

## 已知限制

1. **Domain tag**：LogUp 使用 `LOOKUP_DOMAIN_TAG (0x12)` 而非 `MEM_CHECK_DOMAIN_TAG (0x13)`。不是安全漏洞（β 从承诺派生，不同 proof 的 β 不同），但未来可添加 `create_with_domain_tag` 方法。
2. **Prover 端复杂度**：`compute_multiplicity` 仍为 O(table × witness)，但 verifier 端从 O(n²) 降至 O(n)。
3. **最新值保证**：与旧实现相同，不保证 read 获得最新 write 值（multiset 语义）。未来可通过 step_index 编入 key 改进。

---

## 验证策略

```bash
# 1. memory 模块测试（现有 + 新增）
cargo test -p poker_zkvm --lib constraints::memory

# 2. lookup 模块测试（确保无回归）
cargo test -p poker_zkvm --lib constraints::lookup

# 3. 全 constraints 模块测试
cargo test -p poker_zkvm --lib constraints

# 4. clippy
cargo clippy -p poker_zkvm --lib

# 5. 全量回归
cargo test -p poker_zkvm --lib
```
