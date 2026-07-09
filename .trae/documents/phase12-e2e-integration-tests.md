# Phase 12：端到端集成测试 — 实现计划

## Context

Phase 11a (Task 11.2) 已完成，CheckinTx proof_kind 序列化与 execute_checkin/execute_partial_checkin 接线已就位。现在推进 Phase 12：端到端集成测试，验证完整 ZKVM 流水线（compile → run → prove → verify）的正确性、性能与 soundness。

**关键约束**：`riscv32i-unknown-none-elf` target 未安装（`rustup target list --installed` 确认），`compile_crate()` 无法使用。所有示例电路的 ELF 通过内存字节构造生成，复用 `generate_test_proof()`（[src/prover/mod.rs:L746](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs#L746)）建立的模式。

## 文件结构

```
poker_zkvm/
├── Cargo.toml                              # 修改：bench 添加 required-features
├── src/
│   ├── lib.rs                              # 修改：添加 test_helpers 模块
│   └── test_helpers.rs                     # 新建：RV32I 编码器 + ELF32 构建器
├── tests/
│   ├── common/mod.rs                       # 新建：三个电路 ELF 生成器
│   ├── e2e_fibonacci.rs                    # 新建：Task 12.2.1
│   ├── e2e_sha256_chain.rs                 # 新建：Task 12.2.2
│   ├── e2e_poker_hand_eval.rs              # 新建：Task 12.2.3
│   └── soundness_tests.rs                  # 新建：Task 12.4.1-12.4.6
├── benches/phase12_benchmarks.rs           # 修改：替换 stub 为 criterion 基准
└── examples/{fibonacci,sha256_chain,poker_hand_eval}.rs  # 新建：算法文档
```

## 实施步骤

### Step 1：创建 `src/test_helpers.rs` — 共享测试基础设施

门控：`#[cfg(any(test, feature = "test-helpers"))]`

**RV32I 指令编码器**（从 [src/isa/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/isa/mod.rs) 测试模块提取，6 种类型）：
- `encode_r(opcode, funct3, funct7, rd, rs1, rs2) -> u32`
- `encode_i(opcode, funct3, rd, rs1, imm12) -> u32`
- `encode_s(opcode, funct3, rs1, rs2, imm12) -> u32`
- `encode_b(opcode, funct3, rs1, rs2, imm13) -> u32` — 13 位有符号偏移
- `encode_u(opcode, rd, imm20) -> u32`
- `encode_j(opcode, rd, imm21) -> u32`

**便捷指令函数**：`nop()`, `addi(rd, rs1, imm)`, `add(rd, rs1, rs2)`, `sw(rs2, rs1, imm)`, `lw(rd, rs1, imm)`, `bne(rs1, rs2, imm)`, `beq(rs1, rs2, imm)`, `lui(rd, imm20)`, `ecall()`

**ELF32 构建器**（从 [src/prover/mod.rs:L757](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs#L757) 提取）：
- `build_elf32(entry, text_vaddr, text_bytes) -> Vec<u8>` — 最小 ELF32 + 单 PT_LOAD 段
- `encode_text(words: &[u32]) -> Vec<u8>`

**NOP ELF 生成器**（基准测试用）：
- `build_nop_elf(steps: usize) -> Vec<u8>` — 生成 (steps-2) NOP + ADDI a7,2 + ECALL，trace 恰好 `steps` 步

### Step 2：修改 `src/lib.rs` + `Cargo.toml`

`lib.rs` 添加：
```rust
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;
```

`Cargo.toml` 的 `[[bench]]` 添加：
```toml
required-features = ["test-helpers"]
```

### Step 3：创建 `tests/common/mod.rs` — 三个电路 ELF 生成器

**`build_fibonacci_elf(n: u32) -> Vec<u8>`**：
- 寄存器：x1=a, x2=b, x3=temp, x4=counter
- 循环体 5 条指令：ADD, ADD, ADD, ADDI(-1), BNE(-16)
- 输出：SW x2 到地址 0, ADDI a0=0, a1=4, a7=2, ECALL
- N=100 → 508 步，batch_size=3 → 170 batches

**`build_sha256_chain_elf(iterations: u32) -> Vec<u8>`**：
- LUI x20, 0x2 → x20=0x2000（数据缓冲区地址）
- read_input(a0=0x2000, a1=32) → 读取 32B seed
- 循环：sha256(a0=0x2000, a1=32, a2=0x2000) × iterations 次（in-place 安全）
- commit_output(a0=0x2000, a1=32) → 输出 32B 哈希
- 10 次迭代 → ~40 步，batch_size=3 → 14 batches

**`build_poker_hand_eval_elf() -> Vec<u8>`**：
- read_input 读取 5 字节到 0x2000
- LB 逐个加载 5 张牌到 x1-x5
- ADD 累加求和 → x6
- SW x6 到地址 0, commit_output 4 字节
- 输入 `[2, 7, 11, 1, 13]` → 输出 sum=34

### Step 4-6：创建三个 E2E 测试文件

每个测试文件的流程：
1. 构建 ELF + input
2. `prove(elf, input, &config)` → `(proof_bytes, public_io)`
3. `verify_production(&proof_bytes, &public_io)` → `Ok(true)`
4. 验证 `public_io.output` 正确性
5. 验证 `proof_bytes.len() <= MAX_ZKVM_PROOF_SIZE`

sha256_chain 测试额外验证：用 host 端 `sha2::Sha256` 计算 10 次哈希，比对 output 一致。

### Step 7：创建 `tests/soundness_tests.rs` — 6 项 soundness 测试

| SubTask | 测试内容 | 方法 |
|---------|---------|------|
| 12.4.1 | 恶意 ELF（未支持指令） | 注入 FLW(0x07)/atomic(0x2F)/compressed 指令 → `validate_elf` 拒绝 |
| 12.4.2 | 恶意 ELF（段溢出） | 设置 vaddr=0xFFFFFFF0, memsz=0x20 → wrap 攻击 → `validate_elf` 拒绝 |
| 12.4.3 | 篡改 witness | `deserialize_proof` → 替换 `witness_commitment` → `verify_production` 失败 |
| 12.4.4 | 伪造 multiplicity | `LogUpProof::create` → 篡改 multiplicity → `verify` 返回 `Ok(false)` |
| 12.4.5 | 篡改 trace | `compile_trace_to_ccs` → 修改 witness → `Ccs::satisfied_by` 返回 `false` |
| 12.4.6 | 非白名单 slot | 构建调用 read_state(slot=0x06) 的 ELF → `execute_elf` 返回 `InvalidSlot(6)` |

关键 API（均已确认 public）：
- `validate_elf`：[src/compiler/elf_validator.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/compiler/elf_validator.rs)
- `LogUpProof::create/verify`：[src/constraints/lookup.rs:L247](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/lookup.rs#L247)
- `compile_trace_to_ccs`：[src/constraints/mod.rs:L72](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L72)
- `Ccs::satisfied_by`：[src/ccs/mod.rs:L298](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs#L298)
- `execute_elf`：[src/isa/executor.rs:L105](file:///Users/mac/projects/zchain/poker_zkvm/src/isa/executor.rs#L105)

### Step 8：替换 `benches/phase12_benchmarks.rs`

三个 benchmark group：
- `prover_time_vs_steps`：100/1000/10000 步（batch_size=3/3/15）
- `proof_size_vs_steps`：同上步数，测量 `proof_bytes.len()`
- `verifier_time_vs_steps`：同上步数，`verify_production` 时间

10000 步必须用 batch_size=15（667 batches ≤ MAX_FOLD_STEP_COUNT=1000）。batch_size=3 会产生 3334 batches 超限。

sample_size 设为 10（默认 100 太慢）。

### Step 9：创建 `examples/` 算法文档

三个 host 可编译的 `.rs` 文件，展示算法逻辑 + 注释说明对应的 RV32I 指令序列。不依赖 RISC-V target。

## 验证

```bash
# 编译
cargo build -p poker_zkvm --features test-helpers
cargo build -p poker_zkvm --examples

# 集成测试
cargo test -p poker_zkvm --features test-helpers

# 基准测试
cargo bench -p poker_zkvm --features test-helpers

# Clippy
cargo clippy -p poker_zkvm --features test-helpers --all-targets -- -D warnings
```

## 文档更新

完成后更新：
- `.trae/specs/build-hypernova-zkvm/tasks.md` L352-372 — 标记 Task 12.1-12.4 完成
- `.trae/specs/build-hypernova-zkvm/checklist.md` L336-353 — 标记对应项完成
