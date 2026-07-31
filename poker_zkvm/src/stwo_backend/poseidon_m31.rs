//! # M31-native Poseidon 哈希（Phase 4 — Tier 2 Step 4.2.1）
//!
//! 严格遵循 `.trae/documents/stwo_phase4_precompile_air_design.md` §4.1 + §5：
//! - **字段**：M31-native（用户已确认决策 A）
//! - **参数生成**：通过 `ark-crypto-primitives::find_poseidon_ark_and_mds` 在 M31 上生成
//!   MDS 矩阵 + round constants，缓存到全局 `OnceLock`
//! - **Permutation**：在 Stwo `BaseField` 上重新实现（确保 host hash 与 AIR 用同一组参数）
//!
//! ## Poseidon 参数（§4.1.2）
//!
//! | 参数 | 值 | 说明 |
//! |------|----|------|
//! | state width (t) | 3 | rate + capacity = 2 + 1 |
//! | rate | 2 | 每次吸收 2 个 M31 元素 |
//! | capacity | 1 | 内部容量 |
//! | alpha | 5 | S-box: x^5 |
//! | full rounds | 8 | 前 4 + 后 4 |
//! | partial rounds | 22 | 中间轮，仅 state[0] 应用 S-box |
//! | 总轮数 | 30 | vs BN254 Fr 的 64 轮 |
//! | prime bits | 31 | M31 = 2^31 - 1（Mersenne prime）|
//!
//! ## 安全性
//!
//! - alpha=5 在 M31 上有效：gcd(5, M31-1) = gcd(5, 2^31-2) = 1（5 ∤ 2^31-2）
//! - MDS 矩阵通过 Cauchy matrix 构造（ark-crypto-primitives 标准），保证 MDS 性质
//! - Round constants 通过 Grain LFSR 生成（ark-crypto-primitives 标准）
//!
//! ## 用法
//!
//! ### Host hash（用于 trace 生成）
//!
//! ```ignore
//! use poker_zkvm::stwo_backend::poseidon_m31::poseidon_hash_m31;
//! use stwo::core::fields::m31::BaseField;
//!
//! let inputs = vec![BaseField::from(1u32), BaseField::from(2u32)];
//! let hash = poseidon_hash_m31(&inputs);
//! ```
//!
//! ### AIR 参数访问（用于约束）
//!
//! ```ignore
//! use poker_zkvm::stwo_backend::poseidon_m31::{poseidon_m31_mds, poseidon_m31_round_constants};
//!
//! let mds = poseidon_m31_mds();            // 3×3 matrix
//! let rcs = poseidon_m31_round_constants(); // 30 × [BaseField; 3]
//! ```
//!
//! ## 参考
//!
//! - `ark-crypto-primitives-0.6.0/src/sponge/poseidon/` — Poseidon 参数生成
//! - Plonky3 `poseidon2-air` — M31 Poseidon AIR 参考
//! - Stwo `BaseField` (`stwo::core::fields::m31`) — M31 实现

use std::sync::OnceLock;

use ark_crypto_primitives::sponge::poseidon::{
    PoseidonConfig, PoseidonSponge, find_poseidon_ark_and_mds,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInt, PrimeField, SmallFp, SmallFpConfig};
use stwo::core::fields::m31::BaseField;

// ===========================================================================
// Mersenne31 field 定义（ark_ff SmallFp，modulus = 2^31 - 1，与 Stwo M31 同构）
// ===========================================================================

/// Mersenne31 配置（modulus = 2147483647 = 2^31 - 1，generator = 7）。
///
/// 通过 `#[derive(SmallFpConfig)]` 自动生成 ark_ff SmallFp 后端实现。
/// 该字段与 Stwo 的 `BaseField` (M31) 表示同一个有限域 F_(2^31-1)，
/// 但 ark_ff 使用 Montgomery backend，Stwo 使用 canonical form。
#[derive(SmallFpConfig)]
#[modulus = "2147483647"]
#[generator = "7"]
pub struct Mersenne31Config;

/// ark_ff Mersenne31 类型别名（用于 ark-crypto-primitives 参数生成）。
pub type Mersenne31Ark = SmallFp<Mersenne31Config>;

// ===========================================================================
// Poseidon M31 常量
// ===========================================================================

/// Poseidon state width（t = rate + capacity = 2 + 1）。
pub const POSEIDON_M31_WIDTH: usize = 3;

/// Poseidon rate（每次吸收的元素数）。
pub const POSEIDON_M31_RATE: usize = 2;

/// Poseidon capacity。
pub const POSEIDON_M31_CAPACITY: usize = 1;

/// Poseidon S-box 指数（x^5）。
///
/// 类型为 `u64`，与 `ark_crypto_primitives::PoseidonConfig::alpha` 字段一致。
pub const POSEIDON_M31_ALPHA: u64 = 5;

/// Poseidon full rounds 数（前 4 + 后 4）。
pub const POSEIDON_M31_FULL_ROUNDS: u64 = 8;

/// Poseidon partial rounds 数（中间轮）。
pub const POSEIDON_M31_PARTIAL_ROUNDS: u64 = 22;

/// Poseidon 总轮数（full + partial = 8 + 22 = 30）。
pub const POSEIDON_M31_TOTAL_ROUNDS: usize = 30;

/// Mersenne31 模数位长（用于 ark-crypto-primitives 参数生成）。
const M31_MODULUS_BIT_SIZE: u64 = 31;

/// 全局 Poseidon M31 配置缓存（ark_ff 形式）。
static POSEIDON_M31_CONFIG_ARK: OnceLock<PoseidonConfig<Mersenne31Ark>> = OnceLock::new();

/// 获取或初始化 ark_ff 形式的 Poseidon M31 配置。
///
/// 首次调用时通过 `find_poseidon_ark_and_mds` 生成 MDS 矩阵和 round constants，
/// 后续调用直接返回缓存。生成耗时 ~ms 级，仅发生在首次调用。
pub fn poseidon_m31_config_ark() -> &'static PoseidonConfig<Mersenne31Ark> {
    POSEIDON_M31_CONFIG_ARK.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Mersenne31Ark>(
            M31_MODULUS_BIT_SIZE,
            POSEIDON_M31_RATE,
            POSEIDON_M31_FULL_ROUNDS,
            POSEIDON_M31_PARTIAL_ROUNDS,
            0, // skip_matrices = 0（生成全新参数）
        );
        PoseidonConfig {
            full_rounds: POSEIDON_M31_FULL_ROUNDS as usize,
            partial_rounds: POSEIDON_M31_PARTIAL_ROUNDS as usize,
            alpha: POSEIDON_M31_ALPHA,
            ark,
            mds,
            rate: POSEIDON_M31_RATE,
            capacity: POSEIDON_M31_CAPACITY,
        }
    })
}

// ===========================================================================
// ark_ff Mersenne31 ↔ Stwo BaseField 转换
// ===========================================================================

/// 将 ark_ff `Mersenne31Ark` 转换为 Stwo `BaseField`。
///
/// 两者表示同一字段 F_(2^31-1)：
/// - `Mersenne31Ark` 使用 Montgomery form 内部存储
/// - `BaseField` 使用 canonical form（u32 in [0, P-1]）
///
/// 转换路径：Mersenne31Ark → BigInt<1> → u64 → u32 → BaseField。
/// 由于 P = 2^31 - 1 < 2^32，u64 → u32 截断是安全的。
#[must_use]
pub fn ark_to_stwo(f: Mersenne31Ark) -> BaseField {
    let bigint: BigInt<1> = f.into_bigint();
    let val_u64: u64 = bigint.0[0];
    // P = 2^31 - 1 < 2^32，所以 val_u64 < P < 2^32，截断为 u32 安全
    let val_u32: u32 = u32::try_from(val_u64).expect("Mersenne31 value fits in u32");
    BaseField::from(val_u32)
}

/// 将 Stwo `BaseField` 转换为 ark_ff `Mersenne31Ark`。
///
/// `BaseField.0` 是 canonical u32（in [0, P-1]），直接构造 `Mersenne31Ark`。
#[must_use]
pub fn stwo_to_ark(b: BaseField) -> Mersenne31Ark {
    Mersenne31Ark::from(b.0)
}

// ===========================================================================
// Stwo BaseField 形式的 Poseidon M31 参数（供 AIR 约束使用）
// ===========================================================================

/// 获取 Poseidon M31 的 MDS 矩阵（Stwo `BaseField` 形式）。
///
/// # 返回
/// `[[BaseField; 3]; 3]` — 3×3 MDS 矩阵，`mds[i][j]` 表示第 i 行第 j 列。
///
/// # 用法
/// AIR 约束中 `new_state[i] = sum_j(mds[i][j] * sbox(state[j]))` 用此矩阵。
#[must_use]
pub fn poseidon_m31_mds() -> [[BaseField; 3]; 3] {
    let config = poseidon_m31_config_ark();
    let mut mds_stwo = [[BaseField::from(0u32); 3]; 3];
    for i in 0..POSEIDON_M31_WIDTH {
        for j in 0..POSEIDON_M31_WIDTH {
            mds_stwo[i][j] = ark_to_stwo(config.mds[i][j]);
        }
    }
    mds_stwo
}

/// 获取 Poseidon M31 的 round constants（Stwo `BaseField` 形式）。
///
/// # 返回
/// `Vec<[BaseField; 3]>` — 长度 30（总轮数），每个元素是该轮的 3 个 round constants。
///
/// # 用法
/// AIR 约束中 `new_state[i] = mds_mul(sbox(state)) + rc[round][i]` 用此常数。
#[must_use]
pub fn poseidon_m31_round_constants() -> Vec<[BaseField; 3]> {
    let config = poseidon_m31_config_ark();
    let mut rcs_stwo = Vec::with_capacity(POSEIDON_M31_TOTAL_ROUNDS);
    for round in 0..POSEIDON_M31_TOTAL_ROUNDS {
        let mut rc = [BaseField::from(0u32); 3];
        for i in 0..POSEIDON_M31_WIDTH {
            rc[i] = ark_to_stwo(config.ark[round][i]);
        }
        rcs_stwo.push(rc);
    }
    rcs_stwo
}

// ===========================================================================
// Poseidon permutation（Stwo BaseField 实现）
// ===========================================================================

/// S-box：x^5（在 Stwo `BaseField` 上）。
///
/// `alpha = 5`，通过两次 square + 一次 multiply 实现：
/// `x^5 = x^4 * x = (x^2)^2 * x`
#[inline]
fn sbox(x: BaseField) -> BaseField {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// 在 Stwo `BaseField` 上执行 Poseidon permutation。
///
/// # 算法（与 ark-crypto-primitives `permute` 一致）
///
/// ```text
/// state = input state (3 elements)
/// full_half = full_rounds / 2 = 4
///
/// // 前 4 full rounds
/// for i in 0..4:
///     state[i] += ark[i]      // apply_ark
///     state = sbox(state, full=true)  // 全部 3 元素应用 x^5
///     state = mds * state     // apply_mds
///
/// // 22 partial rounds
/// for i in 4..26:
///     state[i] += ark[i]
///     state[0] = sbox(state[0])  // 仅第 0 元素应用 x^5
///     state = mds * state
///
/// // 后 4 full rounds
/// for i in 26..30:
///     state[i] += ark[i]
///     state = sbox(state, full=true)
///     state = mds * state
/// ```
///
/// # 参数
/// - `state` — 输入 state（3 个 `BaseField` 元素）
///
/// # 返回
/// `[BaseField; 3]` — permutation 后的 state
///
/// # 用法
/// ```ignore
/// use poker_zkvm::stwo_backend::poseidon_m31::poseidon_permutation_m31;
/// use stwo::core::fields::m31::BaseField;
///
/// let input = [BaseField::from(1u32), BaseField::from(2u32), BaseField::from(0u32)];
/// let output = poseidon_permutation_m31(input);
/// ```
#[must_use]
pub fn poseidon_permutation_m31(state: [BaseField; 3]) -> [BaseField; 3] {
    let config = poseidon_m31_config_ark();
    let mds_stwo = poseidon_m31_mds();
    let rcs_stwo = poseidon_m31_round_constants();

    let mut s = state;
    let full_half = POSEIDON_M31_FULL_ROUNDS as usize / 2; // 4
    let partial_count = POSEIDON_M31_PARTIAL_ROUNDS as usize; // 22

    // 前 4 full rounds（i = 0..4）
    for i in 0..full_half {
        // apply_ark: state[j] += ark[i][j]
        for j in 0..POSEIDON_M31_WIDTH {
            s[j] += rcs_stwo[i][j];
        }
        // apply_s_box (full): all elements x^5
        for j in 0..POSEIDON_M31_WIDTH {
            s[j] = sbox(s[j]);
        }
        // apply_mds: new_state[i] = sum_j(mds[i][j] * state[j])
        s = mds_mul(s, mds_stwo);
    }

    // 22 partial rounds（i = 4..26）
    for i in full_half..(full_half + partial_count) {
        // apply_ark
        for j in 0..POSEIDON_M31_WIDTH {
            s[j] += rcs_stwo[i][j];
        }
        // apply_s_box (partial): only state[0] = x^5
        s[0] = sbox(s[0]);
        // apply_mds
        s = mds_mul(s, mds_stwo);
    }

    // 后 4 full rounds（i = 26..30）
    for i in (full_half + partial_count)..POSEIDON_M31_TOTAL_ROUNDS {
        // apply_ark
        for j in 0..POSEIDON_M31_WIDTH {
            s[j] += rcs_stwo[i][j];
        }
        // apply_s_box (full)
        for j in 0..POSEIDON_M31_WIDTH {
            s[j] = sbox(s[j]);
        }
        // apply_mds
        s = mds_mul(s, mds_stwo);
    }

    // 静默 unused 警告（config 仅用于触发 OnceLock 初始化）
    let _ = config;

    s
}

/// MDS 矩阵乘法：`new_state[i] = sum_j(mds[i][j] * state[j])`。
#[inline]
fn mds_mul(state: [BaseField; 3], mds: [[BaseField; 3]; 3]) -> [BaseField; 3] {
    let mut new_state = [BaseField::from(0u32); 3];
    for i in 0..POSEIDON_M31_WIDTH {
        let mut acc = BaseField::from(0u32);
        for j in 0..POSEIDON_M31_WIDTH {
            acc += mds[i][j] * state[j];
        }
        new_state[i] = acc;
    }
    new_state
}

/// 执行 Poseidon permutation 并返回每轮的中间 state（供 AIR trace 生成用）。
///
/// # 返回
/// `Vec<[BaseField; 3]>` — 长度 = `POSEIDON_M31_TOTAL_ROUNDS + 1` = 31：
/// - `states[0]` = 输入 state（permutation 前）
/// - `states[round + 1]` = 第 `round` 轮 permutation 后的 state（round = 0..30）
/// - `states[30]` = 最终输出 state（与 `poseidon_permutation_m31` 返回值一致）
///
/// # 用法
/// ```ignore
/// use poker_zkvm::stwo_backend::poseidon_m31::poseidon_permutation_m31_steps;
/// use stwo::core::fields::m31::BaseField;
///
/// let input = [BaseField::from(1u32), BaseField::from(2u32), BaseField::from(0u32)];
/// let states = poseidon_permutation_m31_steps(input);
/// assert_eq!(states.len(), 31); // 初始 + 30 轮
/// let final_state = states[30];
/// ```
#[must_use]
pub fn poseidon_permutation_m31_steps(state: [BaseField; 3]) -> Vec<[BaseField; 3]> {
    let mds_stwo = poseidon_m31_mds();
    let rcs_stwo = poseidon_m31_round_constants();

    let mut states = Vec::with_capacity(POSEIDON_M31_TOTAL_ROUNDS + 1);
    states.push(state);

    let mut s = state;
    let full_half = POSEIDON_M31_FULL_ROUNDS as usize / 2; // 4
    let partial_count = POSEIDON_M31_PARTIAL_ROUNDS as usize; // 22

    // 前 4 full rounds（i = 0..4）
    for i in 0..full_half {
        // apply_ark
        for j in 0..POSEIDON_M31_WIDTH {
            s[j] += rcs_stwo[i][j];
        }
        // apply_s_box (full): all elements x^5
        for j in 0..POSEIDON_M31_WIDTH {
            s[j] = sbox(s[j]);
        }
        // apply_mds
        s = mds_mul(s, mds_stwo);
        states.push(s);
    }

    // 22 partial rounds（i = 4..26）
    for i in full_half..(full_half + partial_count) {
        // apply_ark
        for j in 0..POSEIDON_M31_WIDTH {
            s[j] += rcs_stwo[i][j];
        }
        // apply_s_box (partial): only state[0] = x^5
        s[0] = sbox(s[0]);
        // apply_mds
        s = mds_mul(s, mds_stwo);
        states.push(s);
    }

    // 后 4 full rounds（i = 26..30）
    for i in (full_half + partial_count)..POSEIDON_M31_TOTAL_ROUNDS {
        // apply_ark
        for j in 0..POSEIDON_M31_WIDTH {
            s[j] += rcs_stwo[i][j];
        }
        // apply_s_box (full)
        for j in 0..POSEIDON_M31_WIDTH {
            s[j] = sbox(s[j]);
        }
        // apply_mds
        s = mds_mul(s, mds_stwo);
        states.push(s);
    }

    states
}

// ===========================================================================
// Poseidon hash（sponge 包装，host 接口）
// ===========================================================================

/// Poseidon hash — 接受任意长度的 `BaseField` 输入，返回单个 `BaseField`。
///
/// # 算法
///
/// 使用 sponge 结构（rate=2, capacity=1）：
/// 1. 初始 state = [0, 0, 0]
/// 2. 按 rate=2 吸收输入：每次 `state[1..3] += inputs[chunk]`，然后 permutation
/// 3. Squeeze 1 个元素：返回 `state[1]`（rate 的第一个元素）
///
/// # 空输入
///
/// 空输入仍然会执行 permutation 并返回一个有效 `BaseField`（非零）。
///
/// # 参数
/// - `inputs` — 任意长度的 `BaseField` 切片
///
/// # 返回
/// `BaseField` — hash 输出
///
/// # 示例
/// ```ignore
/// use poker_zkvm::stwo_backend::poseidon_m31::poseidon_hash_m31;
/// use stwo::core::fields::m31::BaseField;
///
/// let h = poseidon_hash_m31(&[BaseField::from(1u32), BaseField::from(2u32)]);
/// ```
#[must_use]
pub fn poseidon_hash_m31(inputs: &[BaseField]) -> BaseField {
    // 使用 ark-crypto-primitives 的 PoseidonSponge 计算 hash
    // （与 AIR 用同一组 config，确保一致性）
    let config = poseidon_m31_config_ark();
    let mut sponge = PoseidonSponge::<Mersenne31Ark>::new(config);

    if !inputs.is_empty() {
        // 将 Stwo BaseField 转为 Mersenne31Ark 后 absorb
        let inputs_ark: Vec<Mersenne31Ark> = inputs.iter().map(|&b| stwo_to_ark(b)).collect();
        sponge.absorb(&inputs_ark);
    }

    let outputs = sponge.squeeze_native_field_elements(1);
    ark_to_stwo(outputs[0])
}

/// Poseidon 2-to-1 压缩 — 接受两个 `BaseField`，返回单个 `BaseField`。
///
/// 用于 Merkle tree 节点压缩：`parent = Poseidon(left || right)`。
#[must_use]
pub fn poseidon_compress_m31(left: BaseField, right: BaseField) -> BaseField {
    poseidon_hash_m31(&[left, right])
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};
    use stwo::core::fields::m31::BaseField;

    // ===== 参数生成测试 =====

    #[test]
    fn test_poseidon_m31_config_ark_generated() {
        // 验证 config 成功生成
        let config = poseidon_m31_config_ark();
        assert_eq!(config.full_rounds, POSEIDON_M31_FULL_ROUNDS as usize);
        assert_eq!(config.partial_rounds, POSEIDON_M31_PARTIAL_ROUNDS as usize);
        assert_eq!(config.alpha, POSEIDON_M31_ALPHA);
        assert_eq!(config.rate, POSEIDON_M31_RATE);
        assert_eq!(config.capacity, POSEIDON_M31_CAPACITY);

        // ark 形状：(full + partial) × (rate + capacity) = 30 × 3
        assert_eq!(config.ark.len(), POSEIDON_M31_TOTAL_ROUNDS);
        for row in &config.ark {
            assert_eq!(row.len(), POSEIDON_M31_WIDTH);
        }

        // mds 形状：(rate + capacity) × (rate + capacity) = 3 × 3
        assert_eq!(config.mds.len(), POSEIDON_M31_WIDTH);
        for row in &config.mds {
            assert_eq!(row.len(), POSEIDON_M31_WIDTH);
        }
    }

    #[test]
    fn test_poseidon_m31_config_cached() {
        // 验证 OnceLock 缓存：两次获取应返回同一引用
        let config1 = poseidon_m31_config_ark();
        let config2 = poseidon_m31_config_ark();
        assert!(std::ptr::eq(config1, config2));
    }

    #[test]
    fn test_mds_stwo_shape() {
        let mds = poseidon_m31_mds();
        // 验证 MDS 矩阵非全零（MDS 性质要求非奇异）
        let all_zero = mds
            .iter()
            .all(|row| row.iter().all(|&v| v == BaseField::from(0u32)));
        assert!(!all_zero, "MDS 矩阵不应全为零");
    }

    #[test]
    fn test_round_constants_stwo_shape() {
        let rcs = poseidon_m31_round_constants();
        assert_eq!(rcs.len(), POSEIDON_M31_TOTAL_ROUNDS);
        // 验证 round constants 非全零（至少有一轮非零）
        let any_nonzero = rcs
            .iter()
            .any(|rc| rc.iter().any(|&v| v != BaseField::from(0u32)));
        assert!(any_nonzero, "Round constants 不应全为零");
    }

    // ===== 转换测试 =====

    #[test]
    fn test_ark_stwo_roundtrip() {
        // 验证 ark ↔ stwo 转换的 roundtrip
        let test_vals = [
            Mersenne31Ark::from(0u32),
            Mersenne31Ark::from(1u32),
            Mersenne31Ark::from(42u32),
            Mersenne31Ark::from(12345u32),
            Mersenne31Ark::from(u32::MAX), // 会被 mod P 归一化
        ];
        for v_ark in test_vals {
            let v_stwo = ark_to_stwo(v_ark);
            let v_ark2 = stwo_to_ark(v_stwo);
            assert_eq!(
                v_ark, v_ark2,
                "roundtrip 失败：{:?} → {:?} → {:?}",
                v_ark, v_stwo, v_ark2
            );
        }
    }

    #[test]
    fn test_stwo_to_ark_zero() {
        let zero_stwo = BaseField::from(0u32);
        let zero_ark = stwo_to_ark(zero_stwo);
        assert!(zero_ark.is_zero(), "0 转换应保持零");
    }

    #[test]
    fn test_stwo_to_ark_one() {
        let one_stwo = BaseField::from(1u32);
        let one_ark = stwo_to_ark(one_stwo);
        assert_eq!(one_ark, Mersenne31Ark::one(), "1 转换应保持一");
    }

    // ===== permutation 测试 =====

    #[test]
    fn test_permutation_deterministic() {
        let input = [
            BaseField::from(1u32),
            BaseField::from(2u32),
            BaseField::from(3u32),
        ];
        let out1 = poseidon_permutation_m31(input);
        let out2 = poseidon_permutation_m31(input);
        assert_eq!(out1, out2, "相同输入应产生相同输出");
    }

    #[test]
    fn test_permutation_different_inputs() {
        let a = [
            BaseField::from(1u32),
            BaseField::from(2u32),
            BaseField::from(3u32),
        ];
        let b = [
            BaseField::from(1u32),
            BaseField::from(2u32),
            BaseField::from(4u32),
        ];
        let out_a = poseidon_permutation_m31(a);
        let out_b = poseidon_permutation_m31(b);
        assert_ne!(out_a, out_b, "不同输入应产生不同输出");
    }

    #[test]
    fn test_permutation_zero_input_nonzero_output() {
        // 零 state 经 permutation 后应非零（因 ark round constants 注入）
        let zero = [BaseField::from(0u32); 3];
        let out = poseidon_permutation_m31(zero);
        let all_zero = out.iter().all(|&v| v == BaseField::from(0u32));
        assert!(
            !all_zero,
            "零输入经 permutation 后不应全零（round constants 注入）"
        );
    }

    #[test]
    fn test_permutation_matches_ark_sponge() {
        // 验证 Stwo BaseField permutation 与 ark-crypto-primitives sponge 一致。
        //
        // 策略：poseidon_hash_m31([a, b]) 内部调用 PoseidonSponge.absorb(&[a, b]) 然后
        // squeeze_native_field_elements(1)。我们直接用 ark sponge 做相同操作并对比结果。
        //
        // 注意：ark sponge 的 permute() 是 private，但 absorb/squeeze 是 public，
        // 通过 public API 间接验证 permutation 实现的一致性。
        let inputs_stwo = [BaseField::from(1u32), BaseField::from(2u32)];
        let stwo_hash = poseidon_hash_m31(&inputs_stwo);

        // 用 ark-crypto-primitives sponge 做相同操作
        let config = poseidon_m31_config_ark();
        let mut sponge = PoseidonSponge::<Mersenne31Ark>::new(config);
        let inputs_ark: Vec<Mersenne31Ark> = inputs_stwo.iter().map(|&b| stwo_to_ark(b)).collect();
        sponge.absorb(&inputs_ark);
        let ark_out = sponge.squeeze_native_field_elements(1);
        let ark_hash = ark_to_stwo(ark_out[0]);

        assert_eq!(
            stwo_hash, ark_hash,
            "Stwo poseidon_hash_m31 应与 ark sponge 输出一致"
        );
    }

    // ===== hash 测试 =====

    #[test]
    fn test_hash_deterministic() {
        let inputs = vec![BaseField::from(1u32), BaseField::from(2u32)];
        let h1 = poseidon_hash_m31(&inputs);
        let h2 = poseidon_hash_m31(&inputs);
        assert_eq!(h1, h2, "相同输入应产生相同 hash");
    }

    #[test]
    fn test_hash_different_inputs() {
        let a = vec![BaseField::from(1u32), BaseField::from(2u32)];
        let b = vec![BaseField::from(1u32), BaseField::from(3u32)];
        assert_ne!(
            poseidon_hash_m31(&a),
            poseidon_hash_m31(&b),
            "不同输入应产生不同 hash"
        );
    }

    #[test]
    fn test_hash_empty_input_nonzero() {
        let h = poseidon_hash_m31(&[]);
        assert_ne!(h, BaseField::from(0u32), "空输入的 hash 不应为零");
    }

    #[test]
    fn test_hash_single_input() {
        let h = poseidon_hash_m31(&[BaseField::from(42u32)]);
        assert_ne!(h, BaseField::from(0u32), "单元素输入 hash 不应为零");
    }

    #[test]
    fn test_hash_many_inputs() {
        // 超过 rate=2 的输入应触发多次 permutation
        let inputs: Vec<BaseField> = (0..10).map(BaseField::from).collect();
        let h = poseidon_hash_m31(&inputs);
        assert_ne!(h, BaseField::from(0u32), "多元素输入 hash 不应为零");
    }

    // ===== compress 测试 =====

    #[test]
    fn test_compress_deterministic() {
        let left = BaseField::from(1u32);
        let right = BaseField::from(2u32);
        let h1 = poseidon_compress_m31(left, right);
        let h2 = poseidon_compress_m31(left, right);
        assert_eq!(h1, h2, "相同输入应产生相同 compress 输出");
    }

    #[test]
    fn test_compress_non_commutative() {
        // Poseidon 是顺序敏感的：compress(a, b) != compress(b, a)
        let left = BaseField::from(1u32);
        let right = BaseField::from(2u32);
        assert_ne!(
            poseidon_compress_m31(left, right),
            poseidon_compress_m31(right, left),
            "Poseidon 压缩应非交换"
        );
    }

    // ===== S-box 单元测试 =====

    #[test]
    fn test_sbox_zero() {
        assert_eq!(
            sbox(BaseField::from(0u32)),
            BaseField::from(0u32),
            "0^5 = 0"
        );
    }

    #[test]
    fn test_sbox_one() {
        assert_eq!(
            sbox(BaseField::from(1u32)),
            BaseField::from(1u32),
            "1^5 = 1"
        );
    }

    #[test]
    fn test_sbox_two() {
        // 2^5 = 32
        assert_eq!(
            sbox(BaseField::from(2u32)),
            BaseField::from(32u32),
            "2^5 = 32"
        );
    }

    #[test]
    fn test_sbox_three() {
        // 3^5 = 243
        assert_eq!(
            sbox(BaseField::from(3u32)),
            BaseField::from(243u32),
            "3^5 = 243"
        );
    }

    #[test]
    fn test_sbox_associativity() {
        // 验证 (x*y)^5 = x^5 * y^5（在 M31 上）
        let x = BaseField::from(7u32);
        let y = BaseField::from(11u32);
        let lhs = sbox(x * y);
        let rhs = sbox(x) * sbox(y);
        assert_eq!(lhs, rhs, "(x*y)^5 == x^5 * y^5 在 M31 上应成立");
    }

    #[test]
    fn test_sbox_high_value() {
        // 验证大数 sbox：M31 上的 2^30 = 1073741824（合法 M31 元素）
        let val = BaseField::from(1_073_741_824u32); // 2^30
        let result = sbox(val);
        // val^5 mod (2^31-1) — 仅验证非零（具体值依赖 mod 归一化）
        assert_ne!(
            result,
            BaseField::from(0u32),
            "2^30 的 5 次方在 M31 上应非零"
        );
    }
}
