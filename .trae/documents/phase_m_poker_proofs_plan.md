# Phase M: Poker Protocol Proofs (RemaskProof / LeaveProof / ReconstructProof)

## Context

poker\_zkvm 的 `precompiles/` 模块已实现 ZkShuffle CCS 电路（J 系列）和 batch DLEq proof（`dleq.rs`）。
poker\_protocol 项目（`/Users/mac/projects/zgame/poker_protocol/`）中有更多 proof 类型（RemaskProof、LeaveProof、ReconstructProof 及其子证明），需要移植到 poker\_zkvm precompiles 中，提供 prove/verify + byte-level API。

**范围**: 仅 poker\_zkvm/src/precompiles/ 中实现，不修改 poker\_l1。

## 源码参考

| 源文件                                                              | 内容                                              |
| ---------------------------------------------------------------- | ----------------------------------------------- |
| `poker_protocol/src/zk_shuffle/dleq_proof.rs`                    | DLEqProof 结构 + RemaskKind/LeaveKind + verify 逻辑 |
| `poker_protocol/src/zk_shuffle/reconstruction/chaum_pedersen.rs` | ChaumPedersenDLEQProof                          |
| `poker_protocol/src/zk_shuffle/generalized_schnorr_proof.rs`     | GeneralizedSchnorrProof                         |
| `poker_protocol/src/zk_shuffle/reconstruction/swap_out.rs`       | SwapOutCardProof + ReconstructionDLEQProof      |
| `poker_protocol/src/zk_shuffle/reconstruction/mod.rs`            | ReconstructProof 组合证明                           |
| `poker_zkvm/src/precompiles/dleq.rs`                             | 参考：ark+byte 双 API、Blake2b FS、序列化模式              |
| `poker_zkvm/src/precompiles/elgamal.rs`                          | 复用：ElGamalCiphertext、g1\_to\_u256、u256\_to\_g1  |

## 关键设计决策

1. **Transcript**: 新建共享 `PokerTranscript`（Blake2b256 有状态 transcript），因为 ReconstructProof 有 10+ 顺序 challenge 操作，现有 dleq.rs 的无状态 `fs_challenge` 无法满足。不引入 sha3 依赖。
2. **方向区分**: `DleqDirection` enum（Remask/Leave）替代 trait 泛型，因 BN254 硬编码无需泛型。
3. **序列化**: G1 点 = 33B（32B x LE + 1B flags），Fr = 32B LE，变长用 u16 LE 前缀。
4. **ElGamal 映射**: `ct.c` = c1, `ct.d` = c2（poker\_zkvm 已有定义）。

## 实现步骤

### M-1: poker\_transcript.rs — 共享 Fiat-Shamir Transcript

新建 `poker_zkvm/src/precompiles/poker_transcript.rs`。

**结构体**: `PokerTranscript { state: Vec<u8> }`（有状态，每次 append 更新 state = Blake2b256(state || len\_label\_le4 || label || len\_msg\_le4 || msg)）

**API**:

* `new(domain: &[u8]) -> Self`

* `append_message(&mut self, label: &[u8], msg: &[u8])`

* `append_point(&mut self, label: &[u8], pt: &G1Affine)` — 64B (x||y LE)

* `append_scalar(&mut self, label: &[u8], s: &Fr)` — 32B LE

* `challenge(&mut self, label: &[u8]) -> Fr` — append\_message(label, b"challenge"); hash state → Fr

* `challenge_vec(&mut self, label: &[u8], n: usize) -> Vec<Fr>` — 子标签 = label + i.to\_string()

**辅助函数（从 dleq.rs 提取为 pub）**: `g1_to_64bytes`, `parse_g1_from_64bytes`, `compress_g1`, `decompress_g1`, `fr_to_32bytes`, `fr_from_32bytes`

### M-2: elgamal.rs 添加 is\_valid()

在现有 `elgamal.rs` 中添加:

```rust
impl ElGamalCiphertext {
    pub fn is_valid(&self) -> bool {
        !self.c.is_zero() && !self.d.is_zero()
    }
}
```

### M-3: chaum\_pedersen.rs — ChaumPedersenDLEQProof

新建 `poker_zkvm/src/precompiles/chaum_pedersen.rs`。

**结构体**: `ChaumPedersenDLEQProof { commitment_a: G1Affine, commitment_b: G1Affine, response: Fr }`

**Ark API**:

* `prove(g1, g2, s, p1, p2, &mut PokerTranscript) -> Option<Self>` — 拒绝 identity 基点/P1/P2；标签: cp\_G1/cp\_G2/cp\_P1/cp\_P2/cp\_commitment\_a/cp\_commitment\_b/cp\_challenge

* `verify(&self, g1, g2, p1, p2, &mut PokerTranscript) -> bool` — 验证 G1*response == A + P1*c AND G2*response == B + P2*c（MSM 优化）

**Byte API**: `to_bytes() -> [u8; 98]`（33+33+32）, `from_bytes`, `verify_bytes(g1, g2, p1, p2, proof) -> bool`

### M-4: generalized\_schnorr.rs — GeneralizedSchnorrProof

新建 `poker_zkvm/src/precompiles/generalized_schnorr.rs`。

**结构体**: `GeneralizedSchnorrProof { commitment: G1Affine, responses: Vec<Fr> }`

**Ark API**:

* `prove(base_points, secrets, r_point, &mut PokerTranscript) -> Option<Self>` — 标签: gen\_schnorr\_n/gen\_schnorr\_base/gen\_schnorr\_R/gen\_schnorr\_commitment/gen\_schnorr\_challenge

* `verify(&self, base_points, r_point, &mut PokerTranscript) -> bool` — 验证 MSM(responses, base\_points) == commitment + r\_point \* c

**Byte API**: `to_bytes() -> Vec<u8>`（33B commitment + 2B count + n\*32B）, `from_bytes`, `verify_bytes`

### M-5: remask\_leave.rs — PerCardDleqProof (RemaskProof + LeaveProof)

新建 `poker_zkvm/src/precompiles/remask_leave.rs`。

**Enum**: `DleqDirection { Remask, Leave }` — Remask: d2 = output.c2 - input.c2, 校验输入+输出; Leave: d2 = input.c2 - output.c2, 仅校验输入

**结构体**: `PerCardDleqProof { per_card_commitments: Vec<G1Affine>, commitment_pk: G1Affine, response: Fr, nonce: Fr, direction: DleqDirection }`

**共享 transcript 函数** `append_dleq_context()` — 保证 prove/verify 追加完全相同的字节序列（关键 soundness 保证）

**Ark API**:

* `prove(input_cts, output_cts, sk, pk, direction, &mut PokerTranscript) -> Option<Self>`

* `verify(&self, input_cts, output_cts, pk, &mut PokerTranscript) -> bool` — c1 不变性 + 密文有效性 + G*response == commitment\_pk + pk*c + 逐卡 c1\_i*response == per\_card\_commitment\_i + d2\_i*c

**Byte API**: `to_bytes() -> Vec<u8>`（2B count + n\*33B commitments + 33B commitment\_pk + 32B response + 32B nonce）, `from_bytes`, `verify_bytes`

**类型别名**: `RemaskProof = PerCardDleqProof`, `LeaveProof = PerCardDleqProof`

### M-6: reconstruction.rs — ReconstructProof + 子证明

新建 `poker_zkvm/src/precompiles/reconstruction.rs`，含 3 个结构体:

#### ReconstructionDLEQProof

* 字段: `commitment: G1Affine, response: Fr, nonce: Fr`

* prove/verify: blind DLEq，标签 reconstruct\_blind\_nonce/reconstruct\_blind\_in\_{i}/reconstruct\_blind\_out\_{i}/reconstruct\_base\_coeff/reconstruct\_blind\_commitment/reconstruct\_blind\_challenge

* 序列化: 98 字节

#### SwapOutCardProof

* 字段: `user_readable_card: ElGamalCiphertext, swap_out_card: ElGamalCiphertext, chaum_pedersen_proof: ChaumPedersenDLEQProof`

* prove/verify: 委托 ChaumPedersenDLEQProof，delta\_c1 = swap.c - user.c, delta\_c2 = swap.d - user.d

* 序列化: 66 + 66 + 98 = 230 字节

#### ReconstructProof

* 字段: `swap_out_cards_proofs: Vec<SwapOutCardProof>, sum_c1_r_commit, sum_c2_r_commit, swap_sum_c1_commit, swap_sum_c2_commit: G1Affine, nonce: Fr, blind_dleq_proof: ReconstructionDLEQProof, total_dleq_proof: ChaumPedersenDLEQProof, swap_combined_schnorr_proof, sum_swap_out_c1_schnorr_proof, sum_swap_out_c2_schnorr_proof: GeneralizedSchnorrProof`

* prove/verify: 完整移植 poker\_protocol reconstruction/mod.rs 逻辑（10+ 顺序 transcript 步骤）

* Byte API: `to_bytes() -> Vec<u8>`, `from_bytes`, `verify_bytes`

### M-7: mod.rs 注册

在 `poker_zkvm/src/precompiles/mod.rs` 添加:

```rust
pub mod poker_transcript;
pub mod chaum_pedersen;
pub mod generalized_schnorr;
pub mod remask_leave;
pub mod reconstruction;
```

### M-8: 单元测试

每个模块内 `#[cfg(test)] mod tests`，测试列表:

* **poker\_transcript**: 确定性、不同顺序不同结果、challenge\_vec 一致性

* **chaum\_pedersen**: roundtrip、错误 P2、篡改 response、identity 拒绝、序列化、byte verify

* **generalized\_schnorr**: n=1/3/10 roundtrip、错误 R、篡改 commitment/response、identity 拒绝、序列化、byte verify

* **remask\_leave**: 52 卡 remask/leave roundtrip、错误 pk、篡改输出、identity c1 拒绝、单卡、remask+leave 恢复、序列化（n=1/5/52）、byte verify

* **reconstruction**: 52 卡完整证明、单卡、nonce 防重放、c1/c2 信息转移攻击阻止、序列化、byte verify

### M-9: 集成测试 + clippy + fmt

新建 `poker_zkvm/tests/poker_proofs_integration.rs`:

* `test_remask_then_leave_roundtrip` — remask 后 leave 恢复原始密文

* `test_reconstruct_full_deck` — 完整重建证明

* `test_all_proofs_byte_level` — 所有 proof 字节级验证

最终: `cargo test -p poker_zkvm --lib && cargo test -p poker_zkvm --test poker_proofs_integration && cargo clippy -p poker_zkvm --tests --features test-helpers -- -D warnings && cargo fmt -p poker_zkvm -- --check`

## 实现顺序

```
M-1 poker_transcript.rs (无依赖)
M-2 elgamal.rs is_valid() (无新依赖)
M-3 chaum_pedersen.rs (依赖 M-1)
M-4 generalized_schnorr.rs (依赖 M-1)
M-5 remask_leave.rs (依赖 M-1, M-2)
M-6 reconstruction.rs (依赖 M-1~M-5)
M-7 mod.rs 注册
M-8 单元测试
M-9 集成测试 + clippy + fmt
```

## 验证

```bash
# 编译
cargo test -p poker_zkvm --lib --no-run
cargo test -p poker_zkvm --test poker_proofs_integration --no-run

# 单元测试
cargo test -p poker_zkvm --lib precompiles::poker_transcript
cargo test -p poker_zkvm --lib precompiles::chaum_pedersen
cargo test -p poker_zkvm --lib precompiles::generalized_schnorr
cargo test -p poker_zkvm --lib precompiles::remask_leave
cargo test -p poker_zkvm --lib precompiles::reconstruction

# 集成测试
cargo test -p poker_zkvm --test poker_proofs_integration

# 全量回归
cargo test -p poker_zkvm --lib
cargo clippy -p poker_zkvm --tests --features test-helpers -- -D warnings
cargo fmt -p poker_zkvm -- --check
```

