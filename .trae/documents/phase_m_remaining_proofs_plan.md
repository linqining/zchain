# Phase M 补充计划：RevealTokenProof + ZKShuffleProof

## 总结

用户要求补充实现遗漏的 poker protocol proof 类型，并将 verify 方法放入 precompile。

经过对比 poker_protocol 参考实现和 poker_zkvm precompiles 已有模块，发现两个遗漏的 proof 类型：

1. **RevealTokenProof** — 卡片 reveal token 的 Chaum-Pedersen DLEq 证明（双基对）
2. **ZKShuffleProof** — shuffle 排列一致性的 Sigma 协议证明

## 当前状态分析

### poker_protocol 中所有 proof 类型 vs poker_zkvm 实现

| poker_protocol 文件 | proof 类型 | poker_zkvm 实现 | 状态 |
|---------------------|-----------|----------------|------|
| `remask_proof.rs` | RemaskProof | `remask_leave.rs::PerCardDleqProof` | ✅ |
| `leave_proof.rs` | LeaveProof | `remask_leave.rs::PerCardDleqProof` | ✅ |
| `dleq_proof.rs` | DLEqProof (generic) | `dleq.rs::DleqProof` + `remask_leave.rs` | ✅ |
| `generalized_schnorr_proof.rs` | GeneralizedSchnorrProof | `generalized_schnorr.rs` | ✅ |
| `reconstruction/mod.rs` | ReconstructProof 等 | `reconstruction.rs` | ✅ |
| `transcript_ext.rs` | CryptoTranscript | `poker_transcript.rs::PokerTranscript` | ✅ |
| **`reveal_token_proof.rs`** | **RevealTokenProof** | **无** | **❌ 缺失** |
| **`shuffle_proof.rs`** | **ZKShuffleProof** | **无** | **❌ 缺失** |

注：poker_zkvm 的 `zk_shuffle.rs` 模块是 CCS 电路（`ZkShuffleCcsCircuit`），不是 Sigma 协议 proof 类型，与 `ZKShuffleProof` 是完全不同的东西。

## 提议变更

### M-10：创建 `precompiles/reveal_token.rs`

**参考文件**：`/Users/mac/projects/zgame/poker_protocol/src/zk_shuffle/reveal_token_proof.rs`

**协议说明**：
- Chaum-Pedersen DLEq 双基对证明
- Statement: `(G, c1) → (pk, token)` 两组离散对数相等
- Witness: `sk`（满足 `log_G(pk) == log_c1(token) == sk`）
- Commit: `T1 = G·ω, T2 = c1·ω`
- Challenge: `c = H(nonce, pk, c1, c2, reveal_token, T1, T2)`
- Response: `s = ω + c·sk`
- Verify: `G·s == T1 + pk·c` AND `c1·s == T2 + token·c`

**结构体**：

```rust
/// RevealTokenProof — 证明 log_G(pk) == log_c1(reveal_token) == sk
pub struct RevealTokenProof {
    /// 用户公钥 pk = sk · G
    pub user_public_key: G1Affine,
    /// 承诺 T1 = G · ω
    pub commitment_t1: G1Affine,
    /// 承诺 T2 = c1 · ω
    pub commitment_t2: G1Affine,
    /// 响应 s = ω + c · sk
    pub response_s: Fr,
    /// 防重放 nonce
    pub nonce: Fr,
}

/// RevealTokenAndProof — reveal token + proof 的组合
pub struct RevealTokenAndProof {
    /// reveal token = c1 · sk
    pub reveal_token: G1Affine,
    /// 对应的 proof
    pub proof: RevealTokenProof,
}
```

**序列化**：
- `RevealTokenProof`: 33 + 33 + 33 + 32 + 32 = 163 字节
- `RevealTokenAndProof`: 33 + 163 = 196 字节

**Transcript 标签**（完全匹配 poker_protocol）：
- `reveal_token_nonce`（scalar）
- `pk`（point）
- `c1`（point）
- `c2`（point）
- `reveal_token`（point）
- `t1`（point）
- `t2`（point）
- `challenge`（scalar）

**API**：
- `RevealTokenProof::prove(sk, user_pk, encrypted_card, reveal_token, transcript, rng) -> Option<Self>`
- `RevealTokenProof::verify(&self, encrypted_card, reveal_token, expected_pk, transcript) -> bool`
- `RevealTokenProof::to_bytes(&self) -> [u8; 163]`
- `RevealTokenProof::from_bytes(&[u8]) -> Option<Self>`
- `reveal_token_verify_bytes(encrypted_card_bytes, reveal_token_bytes, expected_pk_bytes, proof_bytes, transcript) -> bool`

**安全检查**（匹配 poker_protocol）：
- 拒绝 identity 密文（c1/c2 为 identity）
- 拒绝 identity reveal_token
- 校验 `self.user_public_key == expected_pk`
- 拒绝 identity 承诺点 T1/T2

**单元测试**（~8 个）：
1. `test_reveal_token_valid` — 正常 prove/verify roundtrip
2. `test_reveal_token_wrong_sk` — 错误 sk 应验证失败
3. `test_reveal_token_wrong_pk` — 错误 expected_pk 应验证失败
4. `test_reveal_token_tampered_response` — 篡改 response 应失败
5. `test_reveal_token_tampered_commitment` — 篡改 commitment 应失败
6. `test_reveal_token_identity_reveal_token` — identity token 应拒绝
7. `test_reveal_token_serialization_roundtrip` — 序列化/反序列化 roundtrip
8. `test_reveal_token_byte_verify` — 字节级 verify API

### M-11：创建 `precompiles/shuffle_proof.rs`

**参考文件**：`/Users/mac/projects/zgame/poker_protocol/src/zk_shuffle/shuffle_proof.rs`

**协议说明**：
- 证明 output_cts 是 input_cts 的合法 shuffle（排列 + 重加密）
- 使用 3 个 GeneralizedSchnorrProof（combined + c1 独立 + c2 独立）
- 防止 c1/c2 信息转移攻击

**结构体**：

```rust
/// ZKShuffleProof — 证明 shuffle 排列一致性
pub struct ZKShuffleProof {
    /// Σ ρ_i · input[i].c1
    pub sum_c1_commit: G1Affine,
    /// Σ ρ_i · input[i].c2
    pub sum_c2_commit: G1Affine,
    /// 合并 Schnorr 证明（c1+c2 使用相同排列）
    pub combined_schnorr_proof: GeneralizedSchnorrProof,
    /// c1 独立 Schnorr 证明
    pub sum_c1_schnorr_proof: GeneralizedSchnorrProof,
    /// c2 独立 Schnorr 证明
    pub sum_c2_schnorr_proof: GeneralizedSchnorrProof,
    /// 防重放 nonce
    pub nonce: Fr,
}
```

**序列化**（变长）：
- `sum_c1_commit`: 33 字节
- `sum_c2_commit`: 33 字节
- `nonce`: 32 字节
- `combined_schnorr_proof`: 变长（33 + 2 + n*32）
- `sum_c1_schnorr_proof`: 变长
- `sum_c2_schnorr_proof`: 变长
- 总长度取决于卡数 n

**Transcript 标签**（完全匹配 poker_protocol）：
- `shuffle_pk`（point）
- `shuffle_nonce`（scalar）
- `input c1`（point, per card）
- `input c2`（point, per card）
- `output c1`（point, per card）
- `output c2`（point, per card）
- `rho_challenge`（challenge_vec with n challenges）

**API**：
- `ZKShuffleProof::prove(input_cts, output_cts, permute, r_values, pk, transcript, rng) -> Option<Self>`
- `ZKShuffleProof::verify(&self, input_cts, output_cts, pk, transcript) -> bool`
- `ZKShuffleProof::to_bytes(&self) -> Vec<u8>`
- `ZKShuffleProof::from_bytes(&[u8]) -> Option<Self>`
- `shuffle_verify_bytes(input_cts_bytes, output_cts_bytes, pk_bytes, proof_bytes, transcript) -> bool`

**安全检查**（匹配 poker_protocol）：
- 拒绝 identity 基点（output c1/c2 非 identity）
- 拒绝 identity input c1/c2
- pk 加入 transcript（绑定证明到玩家公钥）
- 3 个 Schnorr 证明防止 c1/c2 信息转移攻击

**单元测试**（~10 个）：
1. `test_shuffle_honest_prover` — 正常 prove/verify roundtrip
2. `test_shuffle_identity_permutation` — 恒等排列通过
3. `test_shuffle_tampered_output` — 篡改 output 应失败
4. `test_shuffle_tampered_input` — 篡改 input 应失败
5. `test_shuffle_c2_swap_attack` — c2 swap 攻击应失败
6. `test_shuffle_tampered_nonce` — 篡改 nonce 应失败
7. `test_shuffle_wrong_pk` — 错误 pk 应失败
8. `test_shuffle_serialization_roundtrip` — 序列化 roundtrip
9. `test_shuffle_byte_verify` — 字节级 verify API
10. `test_shuffle_tampered_commitment` — 篡改 commitment 应失败

### M-12：注册新模块

**文件**：`poker_zkvm/src/precompiles/mod.rs`

添加：
```rust
pub mod reveal_token;
pub mod shuffle_proof;
```

### M-13：集成测试

**文件**：`poker_zkvm/tests/poker_proofs_integration.rs`

在现有 3 个集成测试基础上，添加 2 个新测试：
1. `test_reveal_token_proof_roundtrip` — 完整 reveal token prove/verify + 字节级 API
2. `test_shuffle_proof_roundtrip` — 完整 shuffle prove/verify + 字节级 API

### M-14：最终回归验证

```bash
cargo test -p poker_zkvm --lib
cargo test -p poker_zkvm --test poker_proofs_integration
cargo clippy -p poker_zkvm --tests --features test-helpers -- -D warnings
cargo fmt -p poker_zkvm -- --check
```

## 假设与决策

1. **Transcript 兼容性**：使用 `PokerTranscript`（Blake2b256），标签完全匹配 poker_protocol。proof 字节不与 poker_protocol 的 MerlinTranscript 交叉兼容，但 poker_zkvm 内部 prove/verify 一致。

2. **曲线类型**：使用 BN254 G1（`G1Affine`/`G1Projective`），与既有 precompiles 一致。poker_protocol 使用 Ristretto，但 poker_zkvm 统一使用 BN254。

3. **MSM 优化**：验证使用 `VariableBaseMSM::msm`，与既有 proof 类型一致。

4. **不实现 ExpelHandState**：poker_protocol 的 `ExpelHandState` 是数据容器而非 proof 类型，不实现。

5. **ZKShuffleProof vs ZkShuffleCcsCircuit**：两者完全不同。`ZKShuffleProof` 是 Sigma 协议 proof（轻量、无 ZK circuit），`ZkShuffleCcsCircuit` 是 CCS 电路（重量级、用于 ZK VM）。两者共存，不冲突。

6. **RNG 模式**：使用 `rng: &mut impl Rng` 参数（与既有 proof 类型一致），不使用 `OsRng`/`thread_rng`。

## 验证步骤

完成后，向用户报告：
1. RevealTokenProof 实现完成，8 个单元测试通过
2. ZKShuffleProof 实现完成，10 个单元测试通过
3. 集成测试 5 个全部通过
4. 全量 lib 测试无回归
5. Clippy 0 warnings
6. Fmt 0 diffs
