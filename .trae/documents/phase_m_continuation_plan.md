# Phase M 续作计划：修复 M-5 + 完成 M-6~M-9

## 当前状态

| 步骤 | 状态 | 说明 |
|------|------|------|
| M-1 poker_transcript.rs | ✅ 完成 | 12 测试通过 |
| M-2 elgamal.rs is_valid() | ✅ 完成 | 8 测试通过 |
| M-3 chaum_pedersen.rs | ✅ 完成 | 7 测试通过 |
| M-4 generalized_schnorr.rs | ✅ 完成 | 10 测试通过 |
| M-5 remask_leave.rs | ⚠️ 待修复 | `remask_cts` helper 已改为 2 参数，但 10 个测试调用点仍用旧 3 参数签名 |
| M-6 reconstruction.rs | ❌ 未开始 | ReconstructionDLEQProof + SwapOutCardProof + ReconstructProof |
| M-7 mod.rs 注册 | ⚠️ 部分 | 已注册 4 模块，缺 `reconstruction` |
| M-8 单元测试 | ❌ 未开始 | reconstruction 模块测试 |
| M-9 集成测试 + clippy + fmt | ❌ 未开始 | |

## 剩余工作

### M-5-fix: 修复 remask_leave.rs 测试编译错误

**文件**: [poker_zkvm/src/precompiles/remask_leave.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/remask_leave.rs)

**问题**: `remask_cts` helper 已从 3 参数改为 2 参数（移除 `rng`），但所有测试调用点仍使用旧签名 `remask_cts(&input_cts, &sk, &mut rng)`。

**修复**:
1. 将所有 10 处 `remask_cts(&xxx, &sk, &mut rng)` 改为 `remask_cts(&xxx, &sk)`
2. 修复 `test_remask_tampered_output` 测试逻辑：当前 prove 和 verify 用同一 tampered output（断言 true），应改为 prove 用原始 output、verify 用 tampered output（断言 false）
3. 运行 `cargo test -p poker_zkvm --lib precompiles::remask_leave` 验证全部 10 测试通过

**修复的测试调用点**（共 10 处，行号约 445/461/478/495/517/535/558/579/600/621）:
```rust
// OLD: remask_cts(&input_cts, &sk, &mut rng)
// NEW: remask_cts(&input_cts, &sk)
```

**`test_remask_tampered_output` 重写**:
```rust
#[test]
fn test_remask_tampered_output() {
    let mut rng = test_rng();
    let (sk, pk, input_cts) = make_ciphertexts(3, &mut rng);
    let (_pk2, output_cts) = remask_cts(&input_cts, &sk);

    // Prove with original output
    let mut ts = PokerTranscript::new(b"test_remask");
    let proof = PerCardDleqProof::prove(
        &input_cts, &output_cts, &sk, &pk, DleqDirection::Remask, &mut ts, &mut rng,
    )
    .expect("prove should succeed");

    // Tamper: change output card 0's d component
    let mut tampered_output = output_cts.clone();
    tampered_output[0].d = (G1Projective::generator() * Fr::from(999u64)).into_affine();

    // Verify with tampered output should fail
    let mut ts2 = PokerTranscript::new(b"test_remask");
    assert!(!proof.verify(&input_cts, &tampered_output, &pk, &mut ts2), "应验证失败");
}
```

### M-6: reconstruction.rs — ReconstructProof + 子证明

**新建文件**: `poker_zkvm/src/precompiles/reconstruction.rs`

#### 6.1 ReconstructionDLEQProof

**结构体**:
```rust
pub struct ReconstructionDLEQProof {
    pub commitment: G1Affine,
    pub response: Fr,
    pub nonce: Fr,
}
```

**Ark API**:
- `prove(points_in: &[G1Affine], points_out: &[G1Affine], blind: Fr, transcript: &mut PokerTranscript, rng: &mut impl Rng) -> Option<Self>`
  - 拒绝 blind == 0
  - nonce = Fr::rand(rng)
  - transcript.append_scalar("reconstruct_blind_nonce", &nonce)
  - for i, point in points_in: transcript.append_point("reconstruct_blind_in_{i}", point)
  - for i, point in points_out: transcript.append_point("reconstruct_blind_out_{i}", point)
  - base_coeff = transcript.challenge("reconstruct_base_coeff")
  - sum_point_total = Σ points_in[i] * base_coeff^i (从 base^0=1 开始)
  - 拒绝 sum_point_total is identity
  - w = Fr::rand(rng)
  - commitment = sum_point_total * w
  - transcript.append_point("reconstruct_blind_commitment", &commitment)
  - c = transcript.challenge("reconstruct_blind_challenge")
  - response = w + blind * c

- `verify(&self, points_in: &[G1Affine], points_out: &[G1Affine], transcript: &mut PokerTranscript) -> bool`
  - 拒绝 commitment is identity
  - 相同 transcript 流程
  - sum_point_in_total = Σ points_in[i] * base_coeff^i
  - sum_point_out_total = Σ points_out[i] * base_coeff^i
  - 验证 sum_point_in_total * response == commitment + sum_point_out_total * c

**序列化**: 33B (commitment) + 32B (response) + 32B (nonce) = 97B
- `to_bytes() -> [u8; 97]`
- `from_bytes(&[u8]) -> Option<Self>`

#### 6.2 SwapOutCardProof

**结构体**:
```rust
pub struct SwapOutCardProof {
    pub user_readable_card: ElGamalCiphertext,
    pub swap_out_card: ElGamalCiphertext,
    pub chaum_pedersen_proof: ChaumPedersenDLEQProof,
}
```

**Ark API**:
- `prove(user_readable_card: ElGamalCiphertext, swap_out_card: ElGamalCiphertext, user_sk: &Fr, user_pk: &G1Affine, transcript: &mut PokerTranscript, rng: &mut impl Rng) -> Option<Self>`
  - delta_c1 = swap.c - user.c (projective 减法)
  - delta_c2 = swap.d - user.d
  - chaum_pedersen_proof = ChaumPedersenDLEQProof::prove(delta_c1, G, user_sk, delta_c2, user_pk, transcript, rng)

- `verify(&self, user_readable_card: &ElGamalCiphertext, swap_out_card: &ElGamalCiphertext, user_pk: &G1Affine, transcript: &mut PokerTranscript) -> bool`
  - 检查 self.user_readable_card == *user_readable_card
  - 检查 self.swap_out_card == *swap_out_card
  - delta_c1 = swap.c - user.c, delta_c2 = swap.d - user.d
  - chaum_pedersen_proof.verify(delta_c1, G, delta_c2, user_pk, transcript)

**序列化**: 66B (user_readable_card: 2×33B compressed) + 66B (swap_out_card) + 98B (chaum_pedersen_proof) = 230B
- `to_bytes() -> [u8; 230]`
- `from_bytes(&[u8]) -> Option<Self>`

#### 6.3 ReconstructProof

**结构体** (11 字段):
```rust
pub struct ReconstructProof {
    pub swap_out_cards_proofs: Vec<SwapOutCardProof>,
    pub sum_c1_r_commit: G1Affine,
    pub sum_c2_r_commit: G1Affine,
    pub swap_sum_c1_commit: G1Affine,
    pub swap_sum_c2_commit: G1Affine,
    pub nonce: Fr,
    pub blind_dleq_proof: ReconstructionDLEQProof,
    pub total_dleq_proof: ChaumPedersenDLEQProof,
    pub swap_combined_schnorr_proof: GeneralizedSchnorrProof,
    pub sum_swap_out_c1_schnorr_proof: GeneralizedSchnorrProof,
    pub sum_swap_out_c2_schnorr_proof: GeneralizedSchnorrProof,
}
```

**Ark API — prove**:
```rust
pub fn prove(
    cards: &[G1Affine],
    user_readable_cards: &[ElGamalCiphertext],
    output_cards: &[ElGamalCiphertext],
    swap_out_cards: &[(usize, ElGamalCiphertext)],
    user_sk: &Fr,
    user_pk: &G1Affine,
    s_vec: &[Fr],
    transcript: &mut PokerTranscript,
    rng: &mut impl Rng,
) -> Option<Self>
```

流程（完全移植 poker_protocol reconstruction/mod.rs prove()）:
1. nonce = Fr::rand(rng) — **不追加到 transcript**（Move 兼容）
2. 对每个 user_readable_card 创建 SwapOutCardProof::prove(...)
3. transcript.append_point("reconstruct_card", card) for each card
4. transcript.append_point("reconstruct_output_c1", &output_card.c) for each output_card
5. transcript.append_point("reconstruct_output_c2", &output_card.d) for each output_card
6. scalars = transcript.challenge_vec("reconstruct_rho", output_cards.len())
7. points_c1 = output_cards.c, points_c2 = output_cards.d - cards
8. sum_output_c1 = MSM(scalars, points_c1), sum_output_c2 = MSM(scalars, points_c2)
9. blind = Fr::rand(rng)
10. sum_c1_r_commit = sum_output_c1 * blind, sum_c2_r_commit = sum_output_c2 * blind
11. blind_dleq_proof = ReconstructionDLEQProof::prove([sum_output_c1, sum_output_c2], [sum_c1_r_commit, sum_c2_r_commit], blind, transcript, rng)
12. secret_vec[i] = scalars[swap_out_cards[i].0] * blind
13. swap_sum_c1_commit = MSM(secret_vec, swap_out_cards.c), swap_sum_c2_commit = MSM(secret_vec, swap_out_cards.d)
14. combined_base_points = [swap.c1, swap.c2, ...], combined_secret_vec = [sv[0], sv[0], sv[1], sv[1], ...]
15. swap_combined_commit = swap_sum_c1_commit + swap_sum_c2_commit
16. swap_combined_schnorr_proof = GeneralizedSchnorrProof::prove(combined_base_points, combined_secret_vec, swap_combined_commit, transcript, rng)
17. sum_swap_out_c1_schnorr_proof = GeneralizedSchnorrProof::prove(swap_out_cards.c, secret_vec, swap_sum_c1_commit, transcript, rng)
18. sum_swap_out_c2_schnorr_proof = GeneralizedSchnorrProof::prove(swap_out_cards.d, secret_vec, swap_sum_c2_commit, transcript, rng)
19. c1_total = sum_c1_r_commit + swap_sum_c1_commit, c2_total = sum_c2_r_commit + swap_sum_c2_commit
20. s = (Σ s_vec[i] * scalars[i] for i in 0..cards.len()) + (Σ s_vec[cards.len()+i] * scalars[swap_out_cards[i].0] for i in 0..swap_out_cards.len())
21. s = s * blind
22. total_dleq_proof = ChaumPedersenDLEQProof::prove(G, user_pk, s, c1_total, c2_total, transcript, rng)

**Ark API — verify**:
```rust
pub fn verify(
    &self,
    cards: &[G1Affine],
    output_cards: &[ElGamalCiphertext],
    swap_out_cards: &[ElGamalCiphertext],
    user_readable_cards: &[ElGamalCiphertext],
    user_pk: &G1Affine,
    transcript: &mut PokerTranscript,
) -> bool
```

流程（完全移植 poker_protocol reconstruction/mod.rs verify()）:
1. 检查 swap_out_cards_proofs.len() == user_readable_cards.len()
2. 检查 swap_out_cards.len() == swap_out_cards_proofs.len()
3. 对每个 proof: 检查 swap_out_card/user_readable_card 一致性 + 计算 delta + verify chaum_pedersen_proof
4. transcript.append_point("reconstruct_card", card) for each card
5. transcript.append_point("reconstruct_output_c1", &output_card.c) for each
6. transcript.append_point("reconstruct_output_c2", &output_card.d) for each
7. scalars = transcript.challenge_vec("reconstruct_rho", output_cards.len())
8. 计算 sum_output_c1, sum_output_c2
9. blind_dleq_proof.verify([sum_output_c1, sum_output_c2], [sum_c1_r_commit, sum_c2_r_commit], transcript)
10. 检查 swap_sum_c1_commit, swap_sum_c2_commit 非 identity
11. 验证 swap_combined_schnorr_proof（combined_base_points, combined_commit）
12. 验证 sum_swap_out_c1_schnorr_proof（base_points_c1, swap_sum_c1_commit）
13. 验证 sum_swap_out_c2_schnorr_proof（base_points_c2, swap_sum_c2_commit）
14. c1_total = sum_c1_r_commit + swap_sum_c1_commit, c2_total = sum_c2_r_commit + swap_sum_c2_commit
15. total_dleq_proof.verify(G, user_pk, c1_total, c2_total, transcript)

**Byte API**: `to_bytes() -> Vec<u8>`, `from_bytes`, `reconstruct_verify_bytes`

**变长序列化格式**:
| 字段 | 长度 | 说明 |
|------|------|------|
| swap_count | 2 | u16 LE，SwapOutCardProof 数量 |
| swap_out_cards_proofs | swap_count × 230 | 每个 SwapOutCardProof 230B |
| sum_c1_r_commit | 33 | G1 压缩 |
| sum_c2_r_commit | 33 | G1 压缩 |
| swap_sum_c1_commit | 33 | G1 压缩 |
| swap_sum_c2_commit | 33 | G1 压缩 |
| nonce | 32 | Fr LE |
| blind_dleq_proof | 97 | ReconstructionDLEQProof |
| total_dleq_proof | 98 | ChaumPedersenDLEQProof |
| swap_combined_schnorr_proof | 变长 | 33B commitment + 2B count + n×32B |
| sum_swap_out_c1_schnorr_proof | 变长 | 同上 |
| sum_swap_out_c2_schnorr_proof | 变长 | 同上 |

#### 6.4 辅助函数（用于测试和 prove）

移植 poker_protocol 的 `reconstruct_deck` 和 `derive_from_output_cards` 为 pub 函数:
- `exp_iter(x: Fr) -> impl Iterator<Item = Fr>` — x 的幂迭代
- `derive_from_output_cards(output_cards: &[ElGamalCiphertext], user_sk: &Fr) -> Fr`
- `reconstruct_deck(cards, user_readable_cards, user_sk, user_pk, coefficient) -> Option<(Vec<Fr>, Vec<ElGamalCiphertext>, Vec<(usize, ElGamalCiphertext)>)>`

### M-7: mod.rs 注册 reconstruction

**文件**: [poker_zkvm/src/precompiles/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs)

在现有模块声明中添加:
```rust
pub mod reconstruction;
```

### M-8: reconstruction.rs 单元测试

在 reconstruction.rs 内 `#[cfg(test)] mod tests` 中添加测试:

1. `test_reconstruction_dleq_roundtrip` — ReconstructionDLEQProof 基础 roundtrip
2. `test_reconstruction_dleq_wrong_blind` — 错误 blind 验证失败
3. `test_swap_out_card_proof_roundtrip` — SwapOutCardProof roundtrip
4. `test_swap_out_card_proof_wrong_card` — 篡改 swap_out_card 验证失败
5. `test_reconstruct_proof_single_card` — 单卡完整重建证明
6. `test_reconstruct_proof_multi_cards` — 多卡（3 张）完整重建证明
7. `test_reconstruct_proof_serialization` — 序列化/反序列化 roundtrip
8. `test_reconstruct_proof_byte_verify` — 字节级验证

### M-9: 集成测试 + clippy + fmt

**新建文件**: `poker_zkvm/tests/poker_proofs_integration.rs`

测试:
1. `test_remask_then_leave_roundtrip` — remask 后 leave 恢复原始密文
2. `test_reconstruct_full_deck` — 完整重建证明（5 张卡 + 2 张 user_readable）
3. `test_all_proofs_byte_level` — 所有 proof 字节级验证

**最终验证命令**:
```bash
cargo test -p poker_zkvm --lib precompiles::remask_leave
cargo test -p poker_zkvm --lib precompiles::reconstruction
cargo test -p poker_zkvm --lib
cargo test -p poker_zkvm --test poker_proofs_integration
cargo clippy -p poker_zkvm --tests --features test-helpers -- -D warnings
cargo fmt -p poker_zkvm -- --check
```

## 实现顺序

```
M-5-fix 修复 remask_leave.rs 测试调用点 → 编译 + 测试
M-6     reconstruction.rs（ReconstructionDLEQProof → SwapOutCardProof → ReconstructProof）
M-7     mod.rs 注册 reconstruction
M-8     reconstruction 单元测试
M-9     集成测试 + clippy + fmt
```

## 关键设计决策

1. **ElGamal 字段映射**: `ct.c` = c1, `ct.d` = c2（poker_zkvm 已有定义）
2. **nonce 不参与 transcript**: 兼容 Move 合约，nonce 仅作为结构体字段（防重放）
3. **G1 压缩格式**: 序列化使用 33B 压缩格式（32B x LE + 1B flags），非 64B x||y
4. **RNG 参数**: 所有 prove 函数使用 `rng: &mut impl Rng` 参数（不使用 OsRng/thread_rng，因 feature 限制）
5. **MSM 优化**: 使用 `VariableBaseMSM::msm` 进行多标量乘法
6. **transcript 标签**: 完全匹配 poker_protocol（reconstruct_card/reconstruct_output_c1/reconstruct_output_c2/reconstruct_rho/reconstruct_blind_*/reconstruct_base_coeff）
7. **challenge_vec 子标签**: 使用 `label + i.to_string()` 格式
