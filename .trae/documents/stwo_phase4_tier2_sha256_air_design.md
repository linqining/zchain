# Stwo Phase 4 Tier 2 — Sha256 AIR 详细设计（v2.1）

> **创建日期**：2026-07-20
> **状态**：Step 5.1 完成（基础结构 + 列布局 + logup yield）；Step 5.2 部分完成（binality + 重建约束）；Step 5.2 后续 + 5.3 待实施
> **前置条件**：Phase 4 Tier 2 Step 4.2.6（3 组件集成测试）✅ 已完成
> **遵循规范**：v2.1 Hard Constraint — 所有 AIR 约束 degree ≤ 2（强制 SubDomain 评估模式）

## 实施进度

| Step | 状态 | 说明 |
|------|------|------|
| 5.1 基础结构 + 列布局 + logup yield | ✅ 完成 | `sha256_air.rs`（338 列常量 + Sha256Air struct + FrameworkEval 骨架 + 5 单元测试）；`Sha256Lookup` relation + 2 测试 |
| 5.2 位分解 binality（128 条）| ✅ 完成 | BitA/BitE/BitW15/BitW2 各 32 条 `bit*(bit-1)==0` |
| 5.2 位分解重建（16 条）| ✅ 完成 | `L = sum(bit_i * 2^i)` degree 1 |
| 5.2 ROTR/SHR 列重排 | ⬜ 待做 | 4 函数 × 32 bit = 128 条 degree-1 约束 |
| 5.2 XOR via AND | ⬜ 待做 | 需中间列分解 3-way XOR 为 2 步 2-way XOR |
| 5.2 Working variable update | ⬜ 待做 | T1/T2 计算 + carry + a_next/e_next |
| 5.2 Message schedule update | ⬜ 待做 | W[t+1] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16] |
| 5.2 Round counter + boundary | ⬜ 待做 | RoundCounter 递增 + First/Last round 约束 |
| 5.3 多块 hash + 4 组件 logup | ⬜ 待做 | CPU + Memory + Poseidon + Sha256 4 组件集成 |


***

## 1. 背景与挑战

### 1.1 SHA-256 算法概要

SHA-256 compression function 处理 512-bit block：
- **8 个 working variables**（a, b, c, d, e, f, g, h），每个 32-bit
- **64 轮**，每轮：
  - Message schedule: W[t] = M[t] (t<16) 或 W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16] (t≥16)
  - Working variable update:
    - T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
    - T2 = Σ0(a) + Maj(a,b,c)
    - h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2
- **辅助函数**：
  - Σ0(a) = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22)
  - Σ1(e) = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25)
  - σ0(x) = ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3)
  - σ1(x) = ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10)
  - Ch(x,y,z) = (x & y) ^ (~x & z)
  - Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
- **模 2^32 加法**：所有 `+` 运算

### 1.2 M31 limb 表示的核心挑战

SHA-256 使用 32-bit 字上的布尔运算（ROTR/SHR/XOR/AND/NOT），这些在 4×8-bit limb 表示下非平凡：

| 运算 | limb 难度 | 说明 |
|------|----------|------|
| ADD mod 2^32 | **简单** | 标准 limb 加法 + carry（复用 CPU AIR 的 ADD 约束模式） |
| AND | **简单** | limb-wise：a[i] & b[i]，8-bit AND 不跨 limb（需中间列约束） |
| NOT | **简单** | limb-wise：255 - a[i] |
| XOR | **中等** | a^b = a + b - 2*(a&b)，需先计算 AND（中间列） |
| SHR(x, n) | **困难** | 跨 limb 边界的位移 |
| ROTR(x, n) | **困难** | 跨 limb 边界的旋转 |

### 1.3 v2.1 Hard Constraint

所有约束 degree ≤ 2，强制 Stwo 使用 `EvaluationMode::SubDomain`（与 Poseidon AIR v2.1 一致）。
高次运算必须通过中间列分解（参考 Poseidon S-box `x^5 = x*(x^2)^2` 的 3 列分解）。

***

## 2. 解决方案：Bit Decomposition + Helper Columns

### 2.1 核心思想

对于需要 ROTR/SHR 的 32-bit 字，**完全位分解为 32 个 boolean 列**。
在 bit 层面，ROTR/SHR 只是列重排（degree 0），XOR/AND 是 limb-wise（degree 2）。

### 2.2 位分解策略

**每轮需要位分解的字**（4 个）：
- `a` — 用于 Σ0(a) = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22)
- `e` — 用于 Σ1(e) = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25)
- `W[t-15]` — 用于 σ0(W[t-15]) = ROTR(W,7) ^ ROTR(W,18) ^ SHR(W,3)
- `W[t-2]` — 用于 σ1(W[t-2]) = ROTR(W,17) ^ ROTR(W,19) ^ SHR(W,10)

每个 32-bit 字 → 32 boolean 列，共 4 × 32 = **128 boolean 列**。

### 2.3 位分解约束（degree 2）

对每个 boolean 列 `b_i`：
```
b_i * (b_i - 1) == 0    (degree 2, binality)
```

对每个 8-bit limb `[b_0, b_1, ..., b_7]` 重建为 limb 值 `L`：
```
L = b_0 * 1 + b_1 * 2 + b_2 * 4 + b_3 * 8 + b_4 * 16 + b_5 * 32 + b_6 * 64 + b_7 * 128
```

**关键**：这个重建公式是 degree 1（线性组合），无需中间列。但 binality 约束是 degree 2。

### 2.4 ROTR/SHR 约束（degree 1，列重排）

设输入位为 `x[0..31]`（little-endian: x[0] 是 LSB），输出位为 `y[0..31]`：
- `ROTR(x, n)`: `y[i] = x[(i+n) mod 32]`
- `SHR(x, n)`: `y[i] = x[i+n]` for i+n < 32, else `y[i] = 0`

**约束**：`y[i] - x[(i+n) mod 32] == 0`（degree 1，无 gating）

**Padding 行处理**：所有 boolean 列填 0，约束自动满足。

### 2.5 XOR 约束（degree 2，通过 AND 中间列）

`x ^ y = x + y - 2*(x & y)`

对 8-bit limb：
- 中间列 `AND_L = x_L & y_L`（需约束）
- `XOR_L = x_L + y_L - 2 * AND_L`（degree 2 约束）

**AND 约束**（8-bit，degree 2 with bit decomposition）：
- 将 x_L 和 y_L 各自位分解为 8 bits
- `AND_bit_i = x_bit_i * y_bit_i`（degree 2）
- `AND_L = sum(AND_bit_i * 2^i)`（degree 1 重建）

**优化**：如果 x 和 y 都已经位分解（如 Σ0 中的 ROTR 结果），AND 可直接在 bit 层面计算，
无需额外位分解。

### 2.6 多块 hash 支持

- **IsFirstBlock=1**：初始 working variables = H0[0..7]（SHA-256 initial hash）
- **IsLastBlock=1**：输出 = 当前 block 的最终 working variables
- 多块时，prev block 的输出 = next block 的输入（通过 logup 或显式传递）

***

## 3. 列布局（v2.1 详细版）

### 3.1 总列数：~250 列

| 范围 | 列名 | 列数 | 说明 |
|------|------|------|------|
| 0-3 | W_cur | 4 | 当前轮 W[t]（4×8-bit limb） |
| 4-7 | W_next | 4 | 下一轮 W[t+1]（避免 prev-row 读取） |
| 8-11 | W_t15 | 4 | W[t-15]（4×8-bit limb，用于 σ0） |
| 12-15 | W_t2 | 4 | W[t-2]（4×8-bit limb，用于 σ1） |
| 16-19 | W_t7 | 4 | W[t-7]（用于 message schedule update） |
| 20-23 | W_t16 | 4 | W[t-16]（用于 message schedule update） |
| 24-55 | A-H cur | 32 | 8 working variables × 4 limbs |
| 56-87 | A-H next | 32 | 8 working variables next × 4 limbs |
| 88 | IsPadding | 1 | padding 标记 |
| 89 | IsFirstBlock | 1 | 多块 hash 第 0 块 |
| 90 | IsLastBlock | 1 | 多块 hash 最后一块 |
| 91 | IsFirstRound | 1 | 该 block 的第 0 轮 |
| 92 | IsLastRound | 1 | 该 block 的最后一轮（第 63 轮） |
| 93 | RoundCounter | 1 | 0-63 |
| 94-125 | H0[0..7] | 32 | 初始 hash（8 words × 4 limbs） |
| 126-157 | H_out[0..7] | 32 | 输出 hash（8 words × 4 limbs） |
| 158-189 | BitA[0..31] | 32 | `a` 的 32-bit 分解 |
| 190-221 | BitE[0..31] | 32 | `e` 的 32-bit 分解 |
| 222-253 | BitW15[0..31] | 32 | `W[t-15]` 的 32-bit 分解 |
| 254-285 | BitW2[0..31] | 32 | `W[t-2]` 的 32-bit 分解 |
| 286-289 | Sigma0 | 4 | Σ0(a) 结果（4×8-bit limb） |
| 290-293 | Sigma1 | 4 | Σ1(e) 结果 |
| 294-297 | Sigma0_W | 4 | σ0(W[t-15]) 结果 |
| 298-301 | Sigma1_W | 4 | σ1(W[t-2]) 结果 |
| 302-305 | ChResult | 4 | Ch(e,f,g) 结果 |
| 306-309 | MajResult | 4 | Maj(a,b,c) 结果 |
| 310-313 | T1 | 4 | T1 = h + Σ1(e) + Ch + K[t] + W[t] |
| 314-317 | T2 | 4 | T2 = Σ0(a) + Maj(a,b,c) |
| 318-321 | Carry_T1 | 4 | T1 加法的 carry 列 |
| 322-325 | Carry_T2 | 4 | T2 加法的 carry 列 |
| 326-329 | Carry_W | 4 | W[t+1] 加法的 carry 列 |
| 330-333 | Carry_E | 4 | e_next = d + T1 加法的 carry 列 |
| 334-337 | Carry_A | 4 | a_next = T1 + T2 加法的 carry 列 |

**总列数：338 列**

### 3.2 与原设计的差异

原设计（§4.2.2）76 列，v2.1 详细版 338 列。差异原因：
- 原设计未包含位分解列（128 列）
- 原设计未包含中间结果列（Σ0/Σ1/σ0/σ1/Ch/Maj/T1/T2 = 48 列）
- 原设计未包含 carry 列（20 列）
- 原设计未包含 W[t-7]/W[t-16] 显式存储（8 列）
- 原设计未包含 H0/H_out 显式存储（64 列）

### 3.3 列数优化空间

338 列较大，但可优化：
1. **W[t-7]/W[t-16] 可省略**：通过 prev-row 读取（需 `next_interaction_mask` offset 调整）
2. **H0/H_out 可移到 preprocessed columns**：作为常量列，不计入 original trace
3. **BitW15/BitW2 可复用**：如果 W[t-15] 和 W[t-2] 在其他轮已分解
4. **Carry 列可合并**：复用 CPU AIR 的 carry 约束模式

优化后估计：~200-250 列。

***

## 4. 约束清单（degree ≤ 2）

### 4.1 Binality 约束（degree 2，无 gating）

| # | 约束 | 列 |
|---|------|----|
| S1-S5 | IsPadding/IsFirstBlock/IsLastBlock/IsFirstRound/IsLastRound binality | 5 个 flag |
| S6-S37 | BitA[0..31] binality | 32 bits |
| S38-S69 | BitE[0..31] binality | 32 bits |
| S70-S101 | BitW15[0..31] binality | 32 bits |
| S102-S133 | BitW2[0..31] binality | 32 bits |

共 133 条 binality 约束。

### 4.2 位分解重建约束（degree 1，无 gating）

对每个 8-bit limb L 和其 8 个 bit [b0..b7]：
```
L = b0*1 + b1*2 + b2*4 + b3*8 + b4*16 + b5*32 + b6*64 + b7*128
```

| # | 约束 | 数量 |
|---|------|------|
| S134-S137 | BitA → A[0..3] 重建 | 4 |
| S138-S141 | BitE → E[0..3] 重建 | 4 |
| S142-S145 | BitW15 → W_t15[0..3] 重建 | 4 |
| S146-S149 | BitW2 → W_t2[0..3] 重建 | 4 |

共 16 条重建约束。

### 4.3 ROTR/SHR 约束（degree 1，列重排）

对 Σ0(a) = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22)：
- 需要计算 3 个 ROTR 结果（中间列或 inline）
- 每个 ROTR 是 32 个 degree-1 约束（位重排）

但 Σ0 是 3 个 ROTR 的 XOR，需要 XOR 中间列。

**优化方案**：直接约束 Σ0 的每个 bit = XOR of 3 input bits：
```
Sigma0_bit[i] = BitA[(i+2)%32] ^ BitA[(i+13)%32] ^ BitA[(i+22)%32]
```

XOR of 3 bits: `x ^ y ^ z = x + y + z - 2*(x&y + x&z + y&z) + 4*(x&y&z)`
这是 degree 3，需要中间列分解。

**替代**：分两步 XOR（degree 2）：
```
tmp_bit[i] = BitA[(i+2)%32] ^ BitA[(i+13)%32]  // degree 2, 需 AND 中间列
Sigma0_bit[i] = tmp_bit[i] ^ BitA[(i+22)%32]    // degree 2, 需 AND 中间列
```

每个 XOR 需要 1 个 AND 中间列。32 bits × 2 XOR × 4 函数（Σ0/Σ1/σ0/σ1）= 256 AND 中间列。

**这太多了。** 需要更优方案。

### 4.4 优化：Lookup table for 8-bit XOR

**方案**：创建一个 8-bit XOR lookup table AIR 组件。
- Table: (x, y, x^y) for all x,y in [0,255]
- 主 AIR 通过 logup claim 查询 (x_limb, y_limb, xor_limb)

这样 XOR 在主 AIR 中只是 logup claim（degree 1），无需位分解。

但这是另一个 AIR 组件，增加复杂性。

### 4.5 最终方案：Bit-level direct XOR with intermediate columns

对每个 32-bit XOR 结果（如 Σ0(a)），分解为 32 bits：
- 每个 output bit = XOR of 3 input bits
- 用 2 步 XOR（degree 2），每步需 1 个 AND bit 中间列

每个 32-bit XOR 函数需要：
- 32 个 output bit 列
- 32 个 tmp bit 列（第一步 XOR 结果）
- 32 个 AND bit 列（第一步 AND 结果）
- 32 个 AND bit 列（第二步 AND 结果）

= 128 列 per XOR 函数 × 4 函数 = 512 列。**太多了。**

### 4.6 更优方案：8-bit chunk XOR with 8-bit lookup

**关键洞察**：4×8-bit limb 中，每个 8-bit limb 的 XOR 可以独立处理。

对 8-bit XOR `z = x ^ y`：
- 位分解 x, y, z 各 8 bits（24 bits）
- z_bit_i = x_bit_i * (1 - y_bit_i) + y_bit_i * (1 - x_bit_i) = x_bit_i + y_bit_i - 2*x_bit_i*y_bit_i
- 这是 degree 2（x_bit_i * y_bit_i 是 degree 2）

每个 8-bit XOR 需要 24 bit 列 + 8 AND 列 = 32 列。
但多个 XOR 可复用已分解的 bits。

**最终估算**：整个 SHA-256 AIR 约 400-500 列。这比 Poseidon AIR（30 列）大一个数量级。

***

## 5. 实施策略

### 5.1 分阶段实施（降低单次实施复杂度）

**Step 5.1: 基础结构 + 单轮测试**
- 实现 Sha256Air 结构 + 列布局常量
- 实现单轮 compression（64 行）的 trace 生成
- 实现基础约束（binality + 重建 + round counter）
- 测试：单轮 trace 生成 + prove/verify

**Step 5.2: 完整 compression function**
- 实现 Σ0/Σ1/σ0/σ1 约束（含位分解和 XOR）
- 实现 Ch/Maj 约束
- 实现 working variable update 约束
- 实现 message schedule update 约束
- 测试：单 block hash vs `sha2::Sha256` 一致性

**Step 5.3: 多块 hash + logup 集成**
- 实现多块 hash 支持（IsFirstBlock/IsLastBlock）
- 实现 Sha256Lookup logup yield
- 集成到 4 组件 prover（CPU + Memory + Poseidon + Sha256）
- 测试：多块 hash + 4 组件 prove/verify

### 5.2 工期估算

| Step | 工期 | 依赖 |
|------|------|------|
| 5.1 基础结构 + 单轮测试 | 3-5 天 | 无 |
| 5.2 完整 compression | 5-7 天 | Step 5.1 |
| 5.3 多块 + logup 集成 | 3-5 天 | Step 5.2 |
| **总计** | **11-17 天** | |

原设计文档估算 2-3 周（14-21 天），本估算 11-17 天，一致。

### 5.3 风险

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| 列数过多导致 prove 性能差 | 高 | 工期 +1 周 | 优化列布局（§3.3）；参考 Nexus zkVM 优化 |
| 位分解约束数量大（500+）| 高 | prove 时间增加 | 接受；SHA-256 本身复杂 |
| 多块 hash 传递复杂 | 中 | 工期 +2-3 天 | 先实现单块，再扩展多块 |
| Stwo logup 多 batch 限制 | 低 | 设计调整 | 已验证 3 组件 logup 可行（Step 4.2.6） |

***

## 6. 替代方案（如果 338 列方案性能不可接受）

### 6.1 Option B-1: Trusted Host + Logup（降级）

- SHA-256 由 host 计算（`sha2::Sha256`）
- AIR 仅约束 (Input, Output) 的 logup yield，不验证 compression 计算
- Soundness：信任 host 不作弊
- 列数：~20 列（仅 Input/Output/flags）
- 工期：1-2 天

**适用场景**：开发/测试阶段，或资金路径不依赖 SHA-256 的非核心场景。

### 6.2 Option B-2: Separate Bitwise AIR Component

- 创建独立的 BitwiseAir 组件处理 AND/XOR/ROTR/SHR
- 主 Sha256 AIR 通过 logup 查询 BitwiseAir
- 列数：Sha256 AIR ~80 列 + BitwiseAir ~50 列
- 工期：+1 周（额外 AIR 组件）

**优点**：模块化，BitwiseAir 可复用于其他 AIR（Keccak256/ECDSA）。

### 6.3 Option B-3: 8-bit Lookup Table AIR

- 创建 8-bit operation lookup table AIR（AND/XOR/ROTR 全部预计算）
- 主 Sha256 AIR 通过 logup 查询
- 列数：Sha256 AIR ~80 列 + LookupTable AIR ~30 列
- 工期：+1 周

**优点**：主 AIR 简单；**缺点**：lookup table 巨大（256×256 entries）。

***

## 7. 决策与下一步

### 7.1 推荐方案

**主方案**：§3 的 338 列详细设计（bit decomposition + helper columns）
- 完全 self-contained（无额外 AIR 依赖）
- 所有约束 degree ≤ 2（满足 v2.1 Hard Constraint）
- Soundness 完整（不依赖 trusted host）

**降级方案**：如果工期紧张或性能不可接受，先用 Option B-1（Trusted Host）快速交付，
后续替换为主方案。

### 7.2 下一步

1. ⬜ 创建 `poker_zkvm/src/stwo_backend/sha256_air.rs`（列布局常量 + Sha256Air 结构）
2. ⬜ 添加 `Sha256Lookup` relation 到 `lookups.rs`（9 元组：SyscallId + Input[0..3] + Output[0..3] + IsLastBlock + IsPadding）
3. ⬜ 实现 Step 5.1：基础结构 + 单轮 trace 生成 + 基础约束
4. ⬜ 实现 Step 5.2：完整 compression function 约束
5. ⬜ 实现 Step 5.3：多块 hash + 4 组件 logup 集成
6. ⬜ 测试：单块/多块 hash + soundness + 4 组件 prover 集成

### 7.3 与现有设计的关联

- 本文档取代 `stwo_phase4_precompile_air_design.md` §4.2 的简略设计
- §4.2 的 76 列设计是 v1.0 简化版，未考虑位分解；本文档是 v2.1 详细版
- 实施时以本文档为准

***

## 8. 附录：SHA-256 常量

### 8.1 Initial Hash Values H0[0..7]

```
H0[0] = 0x6a09e667
H0[1] = 0xbb67ae85
H0[2] = 0x3c6ef372
H0[3] = 0xa54ff53a
H0[4] = 0x510e527f
H0[5] = 0x9b05688c
H0[6] = 0x1f83d9ab
H0[7] = 0x5be0cd19
```

### 8.2 Round Constants K[0..63]

（省略，见 `sha2` crate 或 FIPS 180-4）

### 8.3 ROTR 常量

| 函数 | ROTR 参数 |
|------|-----------|
| Σ0(a) | 2, 13, 22 |
| Σ1(e) | 6, 11, 25 |
| σ0(x) | 7, 18, SHR 3 |
| σ1