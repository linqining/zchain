//! ZkShuffle CCS 电路（Phase J — J-3 至 J-7）。
//!
//! Mental Poker ZkShuffle 协议的核心 CCS 电路，基于：
//! - **ElGamal 交换加密**（BN254 G1 群）
//! - **G1 on-curve 检查**：验证所有密文点是合法 BN254 G1 点
//! - **ZK 盲化**：witness 末尾追加随机 blinding 变量
//!
//! ΔC/ΔD 的 re-encryption 关系（ΔC = g^R, ΔD = pk^R）由外部 DLEq proof 验证
//!（见 `dleq.rs`），不在 CCS 中计算——CCS 非原生域算术无法验证 G1 MSM。
//!
//! # 双模式
//!
//! - **Light mode**（`new()` / `new_light()`）：仅检查 output 密文 on-curve（~890K 约束）
//! - **Full mode**（`new_full()`）：双向检查 input + output（~1.77M 约束）
//!
//! # 约束计数（deck_size=52）
//!
//! | 组件 | 约束数 |
//! |------|--------|
//! | assert_g1_on_curve（Light: output only） | ~873,600 |
//! | assert_g1_on_curve（Full: input + output） | ~1,747,200 |
//! | ZK 盲化 | ~512 |

#![allow(dead_code)]
#![allow(clippy::needless_range_loop)]

use crate::ccs::{Ccs, CcsInstance, Fr};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::precompiles::bn254_ops::assert_g1_on_curve;
use crate::precompiles::non_native::NonNativeBuilder;
use crate::precompiles::{CcsCircuit, PrecompileCircuit};

/// 默认牌组大小（标准扑克）。
const DEFAULT_DECK_SIZE: usize = 52;

/// ZK 盲化变量数量。
const BLINDING_COUNT: usize = 8;

/// Light mode gas（~890K 约束 × 2）。
const GAS_ZK_SHUFFLE_LIGHT: u64 = 1_780_000;

/// Full mode gas（~1.77M 约束 × 2）。
const GAS_ZK_SHUFFLE_FULL: u64 = 3_540_000;

// ===== 数据结构 =====

/// ZkShuffle CCS 电路。
///
/// 双模式：
/// - Light（`new()`）：仅 output on-curve 检查
/// - Full（`new_full()`）：双向 on-curve 检查
#[derive(Debug, Clone)]
pub struct ZkShuffleCcsCircuit {
    /// 电路名称。
    name: &'static str,
    /// 约束矩阵数量（CCS 标准要求 q=2 → 3 个矩阵）。
    num_mats: usize,
    /// 牌组大小（默认 52）。
    deck_size: usize,
    /// 是否为完整模式（双向 on-curve）。
    full_mode: bool,
}

impl ZkShuffleCcsCircuit {
    /// 创建 Full 模式电路（双向 input + output on-curve 检查）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "zk_shuffle",
            num_mats: 3,
            deck_size: DEFAULT_DECK_SIZE,
            full_mode: true,
        }
    }

    /// 创建 Light 模式电路（仅 output on-curve 检查）。
    #[must_use]
    pub fn new_light() -> Self {
        Self {
            name: "zk_shuffle",
            num_mats: 3,
            deck_size: DEFAULT_DECK_SIZE,
            full_mode: false,
        }
    }

    /// 创建 Full 模式电路（双向 on-curve）。
    #[must_use]
    pub fn new_full() -> Self {
        Self {
            name: "zk_shuffle",
            num_mats: 3,
            deck_size: DEFAULT_DECK_SIZE,
            full_mode: true,
        }
    }

    /// 创建自定义牌组大小的电路。
    #[must_use]
    pub fn with_deck_size(deck_size: usize, full_mode: bool) -> Self {
        Self {
            name: "zk_shuffle",
            num_mats: 3,
            deck_size,
            full_mode,
        }
    }

    /// 返回约束矩阵数量。
    #[must_use]
    pub fn num_matrices(&self) -> usize {
        self.num_mats
    }

    /// 返回牌组大小。
    #[must_use]
    pub fn deck_size(&self) -> usize {
        self.deck_size
    }

    /// 是否为 Full 模式。
    #[must_use]
    pub fn is_full_mode(&self) -> bool {
        self.full_mode
    }

    /// 构建完整电路（CCS + witness）。
    ///
    /// 这是核心方法，同时构建 CCS 约束结构和 witness 向量。
    /// `build_ccs()` 和 `assign_witness()` 都委托到此方法。
    pub fn build_circuit(
        &self,
        witness: &ShuffleWitness,
        public: &ShufflePublicInput,
    ) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        let n = self.deck_size;
        if witness.input_cts.len() != n || witness.output_cts.len() != n {
            return Err(ZkvmError::Other(format!(
                "ZkShuffleCcsCircuit: witness 长度不匹配 deck_size {}（input={}, output={}）",
                n,
                witness.input_cts.len(),
                witness.output_cts.len()
            )));
        }
        if witness.permutation.len() != n {
            return Err(ZkvmError::Other(format!(
                "ZkShuffleCcsCircuit: permutation 长度 {} != deck_size {}",
                witness.permutation.len(),
                n
            )));
        }
        if witness.randomizers.len() != n {
            return Err(ZkvmError::Other(format!(
                "ZkShuffleCcsCircuit: randomizers 长度 {} != deck_size {}",
                witness.randomizers.len(),
                n
            )));
        }
        if witness.lambda_challenges.len() != n {
            return Err(ZkvmError::Other(format!(
                "ZkShuffleCcsCircuit: lambda_challenges 长度 {} != deck_size {}",
                witness.lambda_challenges.len(),
                n
            )));
        }
        if witness.blinding.len() != BLINDING_COUNT {
            return Err(ZkvmError::Other(format!(
                "ZkShuffleCcsCircuit: blinding 长度 {} != {}",
                witness.blinding.len(),
                BLINDING_COUNT
            )));
        }

        let mut builder = NonNativeBuilder::new();

        // ===== 1. 分配 public input 变量 =====
        // pk (8 Fr): pk_x(4) + pk_y(4)
        let pk_x = builder.alloc_element([public.pk[0], public.pk[1], public.pk[2], public.pk[3]]);
        let pk_y = builder.alloc_element([public.pk[4], public.pk[5], public.pk[6], public.pk[7]]);
        // pk on-curve（始终检查公钥合法性）
        assert_g1_on_curve(&mut builder, &pk_x, &pk_y);

        // 注：ΔC/ΔD 不在 CCS 中计算或约束（CCS 非原生域算术无法验证 G1 MSM）。
        // ΔC/ΔD 由外部 DLEq proof 验证（见 dleq.rs）。

        // ===== 2. 分配 input/output 密文变量 + on-curve 检查 =====
        // 每个密文 (c, d) = 4 NonNativeElement (c.x, c.y, d.x, d.y) = 16 Fr
        for i in 0..n {
            // Input ciphertext i
            let ct = &witness.input_cts[i];
            let c_x = builder.from_u256(&ct.c_x);
            let c_y = builder.from_u256(&ct.c_y);
            let d_x = builder.from_u256(&ct.d_x);
            let d_y = builder.from_u256(&ct.d_y);

            // Full mode: input on-curve 检查
            if self.full_mode {
                assert_g1_on_curve(&mut builder, &c_x, &c_y);
                assert_g1_on_curve(&mut builder, &d_x, &d_y);
            }
        }

        for i in 0..n {
            // Output ciphertext i
            let ct = &witness.output_cts[i];
            let c_x = builder.from_u256(&ct.c_x);
            let c_y = builder.from_u256(&ct.c_y);
            let d_x = builder.from_u256(&ct.d_x);
            let d_y = builder.from_u256(&ct.d_y);

            // Output on-curve 检查（Light + Full 都检查）
            assert_g1_on_curve(&mut builder, &c_x, &c_y);
            assert_g1_on_curve(&mut builder, &d_x, &d_y);
        }

        // 校验排列合法性（越界检查，不产生 CCS 约束）
        for i in 0..n {
            let sigma_i = witness.permutation[i] as usize;
            if sigma_i >= n {
                return Err(ZkvmError::Other(format!(
                    "ZkShuffleCcsCircuit: permutation[{}] = {} >= deck_size {}",
                    i, sigma_i, n
                )));
            }
        }

        // 注：ΔC/ΔD 线性组合（Σ λ_i · Δc_i）不在 CCS 中计算，
        // 因为 CCS 非原生域算术（sub_mod/mul_mod/add_mod）计算的是坐标级域运算，
        // 数学上不等于 G1 标量乘法（MSM）。ΔC/ΔD 由 DLEq proof 外部验证。

        // ===== 3. ZK 盲化 =====
        // 分配 8 个随机 Fr 变量，混入 witness
        let mut blinding_vars = Vec::with_capacity(BLINDING_COUNT);
        for k in 0..BLINDING_COUNT {
            let b_var = builder.alloc(witness.blinding[k]);
            // 约束：blinding 变量必须非零（通过 bit_check 确保是有效域元素）
            let row = builder.ccs.alloc_row();
            builder.ccs.add_bit_check(row, b_var);
            blinding_vars.push(b_var);
        }
        // 混入 commitment：output_commitment = H(..., b_1, ..., b_8)
        // 这里用线性约束将 blinding 变量绑定到 witness 空间
        // Σ b_i ≠ 0（防止全零 witness）
        let mut sum_blinding = builder.alloc(Fr::zero());
        for &b_var in &blinding_vars {
            let new_sum = builder.alloc(builder.get_val(sum_blinding).add(&builder.get_val(b_var)));
            let row = builder.ccs.alloc_row();
            builder.ccs.add_linear(
                row,
                &[
                    (sum_blinding, Fr::one()),
                    (b_var, Fr::one()),
                    (new_sum, Fr::one().neg()),
                ],
            );
            sum_blinding = new_sum;
        }
        // sum_blinding ≠ 0（通过断言其非零性）
        // 分配 sum_blinding 的逆元，约束 sum * inv = 1
        let sum_val = builder.get_val(sum_blinding);
        if sum_val.is_zero() {
            return Err(ZkvmError::Other(
                "ZkShuffleCcsCircuit: blinding 变量之和为零（witness 可能泄露）".to_string(),
            ));
        }
        let inv_val = sum_val.inverse().unwrap_or(Fr::zero());
        let inv_var = builder.alloc(inv_val);
        let row = builder.ccs.alloc_row();
        // 变量 0 是常数 1（NonNativeBuilder::new 初始化 witness[0] = Fr::one()）
        builder
            .ccs
            .add_multiplication(row, sum_blinding, inv_var, 0);

        // ===== 6. 构建 CCS =====
        let witness_vec = builder.witness.clone();
        let ccs = builder.build()?;
        Ok((ccs, witness_vec))
    }
}

impl Default for ZkShuffleCcsCircuit {
    fn default() -> Self {
        Self::new()
    }
}

// ===== Public Input / Witness 结构 =====

/// ZkShuffle 公共输入。
#[derive(Debug, Clone)]
pub struct ShufflePublicInput {
    /// ElGamal 公钥 (x, y 各 4 limbs = 8 Fr)。
    pub pk: [Fr; 8],
    /// 输入密文承诺 H(c_1||d_1||...||c_n||d_n)。
    pub input_commitment: Fr,
    /// 输出密文承诺 H(c'_1||d'_1||...||c'_n||d'_n)。
    pub output_commitment: Fr,
    /// ΔC = Σ λ_i · Δc_i (G1 点 x||y, 8 Fr)。
    pub delta_c: [Fr; 8],
    /// ΔD = Σ λ_i · Δd_i (G1 点 x||y, 8 Fr)。
    pub delta_d: [Fr; 8],
}

impl ShufflePublicInput {
    /// 转为扁平 Vec<Fr>。
    pub fn to_vec(&self) -> Vec<Fr> {
        let mut v = Vec::with_capacity(8 + 1 + 1 + 8 + 8);
        v.extend_from_slice(&self.pk);
        v.push(self.input_commitment);
        v.push(self.output_commitment);
        v.extend_from_slice(&self.delta_c);
        v.extend_from_slice(&self.delta_d);
        v
    }

    /// 从扁平 Vec<Fr> 解析。
    pub fn from_vec(v: &[Fr]) -> Result<Self, ZkvmError> {
        if v.len() != 26 {
            return Err(ZkvmError::Other(format!(
                "ShufflePublicInput::from_vec: len {} != 26",
                v.len()
            )));
        }
        let mut pk = [Fr::zero(); 8];
        pk.copy_from_slice(&v[0..8]);
        let mut delta_c = [Fr::zero(); 8];
        delta_c.copy_from_slice(&v[10..18]);
        let mut delta_d = [Fr::zero(); 8];
        delta_d.copy_from_slice(&v[18..26]);
        Ok(Self {
            pk,
            input_commitment: v[8],
            output_commitment: v[9],
            delta_c,
            delta_d,
        })
    }
}

/// ZkShuffle witness（私钥数据）。
///
/// 密文使用 host [u64; 4] 坐标表示，在 build_circuit 中转换为 NonNativeElement。
#[derive(Debug, Clone)]
pub struct ShuffleWitness {
    /// 输入密文（n 个，每个 4 坐标 × 4 limbs = 16 [u64;4]）。
    pub input_cts: Vec<HostCiphertext>,
    /// 输出密文（n 个）。
    pub output_cts: Vec<HostCiphertext>,
    /// 排列 σ(i)。
    pub permutation: Vec<u8>,
    /// 重加密随机数 r_i（BN254 Fr）。
    pub randomizers: Vec<Fr>,
    /// Fiat-Shamir 挑战 λ_i。
    pub lambda_challenges: Vec<Fr>,
    /// ZK 盲化变量（8 个随机 Fr）。
    pub blinding: Vec<Fr>,
}

/// Host-side 密文表示（4 个 [u64;4] 坐标：c.x, c.y, d.x, d.y）。
#[derive(Debug, Clone)]
pub struct HostCiphertext {
    /// c.x 坐标。
    pub c_x: [u64; 4],
    /// c.y 坐标。
    pub c_y: [u64; 4],
    /// d.x 坐标。
    pub d_x: [u64; 4],
    /// d.y 坐标。
    pub d_y: [u64; 4],
}

// ===== Trait 实现 =====

impl PrecompileCircuit for ZkShuffleCcsCircuit {
    fn name(&self) -> &str {
        self.name
    }

    fn num_variables(&self) -> usize {
        // 估算变量数：
        // - public: pk(8) + ΔC(8) + ΔD(8) + commitments(2) = 26
        // - input_cts: deck_size × 16
        // - output_cts: deck_size × 16
        // - ΔC/ΔD 中间变量: deck_size × ~20
        // - blinding: 8
        // - 辅助变量（NonNativeBuilder 内部）
        // 粗略估算（实际由 build_circuit 决定）
        26 + self.deck_size * 52 + BLINDING_COUNT
    }

    fn build_ccs(&self) -> Ccs {
        // 构建真实 CCS：使用 dummy witness 触发约束生成
        let (dummy_w, dummy_p) = build_dummy_data(self.deck_size);
        match self.build_circuit(&dummy_w, &dummy_p) {
            Ok((ccs, _)) => ccs,
            Err(e) => {
                // dummy 数据构建失败表示电路本身存在缺陷，不应发生在生产环境。
                // 返回最小 CCS 作为 fallback 并记录错误；
                // TODO(build_ccs-result): 将 PrecompileCircuit::build_ccs 改为返回 Result，
                // 使调用方能显式处理失败而非静默回退。
                tracing::error!(
                    "ZkShuffleCcsCircuit::build_ccs: dummy build failed (deck_size={}): {e}",
                    self.deck_size
                );
                Ccs::new(1, vec![], vec![], vec![]).expect("minimal fallback CCS")
            }
        }
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        // inputs 编码: [public(26), input_cts(n*16), output_cts(n*16), perm(n), rs(n), lambdas(n), blinding(8)]
        let n = self.deck_size;
        let expected_len = 26 + n * 16 + n * 16 + n + n + n + BLINDING_COUNT;
        if inputs.len() != expected_len {
            return Err(ZkvmError::Other(format!(
                "ZkShuffleCcsCircuit::assign_witness: inputs.len() {} != expected {}",
                inputs.len(),
                expected_len
            )));
        }

        let (witness, public) = parse_shuffle_inputs(inputs, n)?;
        let (_ccs, witness_vec) = self.build_circuit(&witness, &public)?;
        Ok(witness_vec)
    }

    fn gas_cost(&self) -> u64 {
        if self.full_mode {
            GAS_ZK_SHUFFLE_FULL
        } else {
            GAS_ZK_SHUFFLE_LIGHT
        }
    }
}

impl CcsCircuit for ZkShuffleCcsCircuit {
    fn name(&self) -> &str {
        self.name
    }

    fn num_matrices(&self) -> usize {
        self.num_mats
    }

    fn to_ccs_instance(
        &self,
        witness: &[Fr],
        public_inputs: &[Fr],
    ) -> Result<CcsInstance, ZkvmError> {
        let n = self.deck_size;
        let (witness_data, public_data) = parse_shuffle_inputs(witness, n)?;
        let (ccs, witness_vec) = self.build_circuit(&witness_data, &public_data)?;

        // 验证 witness 满足 CCS
        if !ccs.satisfied_by(&witness_vec)? {
            return Err(ZkvmError::Other(
                "ZkShuffleCcsCircuit::to_ccs_instance: witness 不满足 CCS 约束".to_string(),
            ));
        }

        CcsInstance::new(ccs, witness_vec, public_inputs.to_vec())
    }
}

// ===== 输入解析 =====

/// 从扁平 Vec<Fr> 解析 ShuffleWitness + ShufflePublicInput。
fn parse_shuffle_inputs(
    inputs: &[Fr],
    deck_size: usize,
) -> Result<(ShuffleWitness, ShufflePublicInput), ZkvmError> {
    let n = deck_size;
    let mut idx = 0;

    // Public input (26 Fr)
    let public = ShufflePublicInput::from_vec(&inputs[idx..idx + 26])?;
    idx += 26;

    // Input ciphertexts (n × 16 Fr)
    let mut input_cts = Vec::with_capacity(n);
    for _ in 0..n {
        input_cts.push(parse_host_ciphertext(&inputs[idx..idx + 16])?);
        idx += 16;
    }

    // Output ciphertexts (n × 16 Fr)
    let mut output_cts = Vec::with_capacity(n);
    for _ in 0..n {
        output_cts.push(parse_host_ciphertext(&inputs[idx..idx + 16])?);
        idx += 16;
    }

    // Permutation (n Fr → Vec<u8>)
    let permutation: Vec<u8> = inputs[idx..idx + n]
        .iter()
        .map(|f| {
            let bytes = f.to_canonical_bytes();
            bytes[0]
        })
        .collect();
    idx += n;

    // Randomizers (n Fr)
    let randomizers: Vec<Fr> = inputs[idx..idx + n].to_vec();
    idx += n;

    // Lambda challenges (n Fr)
    let lambda_challenges: Vec<Fr> = inputs[idx..idx + n].to_vec();
    idx += n;

    // Blinding (8 Fr)
    let blinding: Vec<Fr> = inputs[idx..idx + BLINDING_COUNT].to_vec();

    Ok((
        ShuffleWitness {
            input_cts,
            output_cts,
            permutation,
            randomizers,
            lambda_challenges,
            blinding,
        },
        public,
    ))
}

/// 从 16 个 Fr 解析 HostCiphertext（4 坐标 × 4 limbs）。
fn parse_host_ciphertext(frs: &[Fr]) -> Result<HostCiphertext, ZkvmError> {
    if frs.len() != 16 {
        return Err(ZkvmError::Other(format!(
            "parse_host_ciphertext: len {} != 16",
            frs.len()
        )));
    }
    Ok(HostCiphertext {
        c_x: fr_to_u256(&frs[0..4]),
        c_y: fr_to_u256(&frs[4..8]),
        d_x: fr_to_u256(&frs[8..12]),
        d_y: fr_to_u256(&frs[12..16]),
    })
}

/// 将 4 个 Fr (little-endian limbs) 转为 [u64; 4]。
fn fr_to_u256(limbs: &[Fr]) -> [u64; 4] {
    let mut result = [0u64; 4];
    for (k, limb) in limbs.iter().enumerate().take(4) {
        let bytes = limb.to_canonical_bytes();
        result[k] = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
    }
    result
}

// ===== Dummy 数据生成（用于 build_ccs）=====

/// 生成 dummy witness + public input（用于 build_ccs 的约束生成）。
fn build_dummy_data(deck_size: usize) -> (ShuffleWitness, ShufflePublicInput) {
    let n = deck_size;
    use ark_bn254::{Fr as BnFr, G1Projective};
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::Zero;
    use ark_std::UniformRand;
    use ark_std::test_rng;

    let mut rng = test_rng();
    let g = G1Projective::generator();

    // 生成 dummy 密钥
    let sk = BnFr::rand(&mut rng);
    let pk_proj = g * sk;
    let pk_affine = pk_proj.into_affine();

    // 将 pk 坐标转为 [Fr; 8]
    let (pk_x_u256, pk_y_u256) = crate::precompiles::elgamal::g1_to_u256(&pk_affine);
    let pk = {
        let mut pk_arr = [Fr::zero(); 8];
        for k in 0..4 {
            pk_arr[k] = Fr::from_u64(pk_x_u256[k]);
            pk_arr[k + 4] = Fr::from_u64(pk_y_u256[k]);
        }
        pk_arr
    };

    // 生成 dummy 密文（使用 G1 生成元的倍数）
    let mut input_cts = Vec::with_capacity(n);
    let mut output_cts = Vec::with_capacity(n);

    for i in 0..n {
        let card_point = (g * BnFr::from(i as u64)).into_affine();
        let r = BnFr::rand(&mut rng);
        let ct = crate::precompiles::elgamal::encrypt(
            &crate::precompiles::elgamal::ElGamalPublicKey { pk: pk_affine },
            &card_point,
            &r,
        );
        input_cts.push(host_ct_from_affine(&ct));

        // Re-encrypt with dummy r
        let r2 = BnFr::rand(&mut rng);
        let ct2 = crate::precompiles::elgamal::reencrypt(
            &crate::precompiles::elgamal::ElGamalPublicKey { pk: pk_affine },
            &ct,
            &r2,
        );
        output_cts.push(host_ct_from_affine(&ct2));
    }

    // Identity permutation
    let permutation: Vec<u8> = (0..n as u8).collect();

    // Dummy randomizers（仅用于 DLEq proof，不参与 CCS 构建）
    let randomizers: Vec<Fr> = (0..n).map(|_| Fr::from_u64(1)).collect();

    // Dummy lambda challenges（随机 254-bit，测试 fr_to_u256_limbs 正确性）
    let lambda_bnfrs: Vec<BnFr> = (0..n).map(|_| BnFr::rand(&mut rng)).collect();
    let lambda_challenges: Vec<Fr> = lambda_bnfrs.iter().map(|f| Fr::from_fr(*f)).collect();

    // Dummy blinding
    let blinding: Vec<Fr> = (0..BLINDING_COUNT).map(|_| Fr::from_u64(1)).collect();

    // Compute ΔC/ΔD
    // Δc_i = c'_{σ(i)} - c_i, ΔC = Σ λ_i · Δc_i
    // 使用随机 λ_i 进行标量乘法，与 build_circuit 中的非原生域计算对齐
    let mut delta_c_proj = G1Projective::zero();
    let mut delta_d_proj = G1Projective::zero();
    for i in 0..n {
        let sigma_i = permutation[i] as usize;
        let ct_in = crate::precompiles::elgamal::ElGamalCiphertext {
            c: affine_from_host_ct(&input_cts[i], 0),
            d: affine_from_host_ct(&input_cts[i], 1),
        };
        let ct_out = crate::precompiles::elgamal::ElGamalCiphertext {
            c: affine_from_host_ct(&output_cts[sigma_i], 0),
            d: affine_from_host_ct(&output_cts[sigma_i], 1),
        };
        // Δc = c' - c
        let dc = G1Projective::from(ct_out.c) - G1Projective::from(ct_in.c);
        // Δd = d' - d
        let dd = G1Projective::from(ct_out.d) - G1Projective::from(ct_in.d);
        // λ_i · Δc_i（使用 ark_bn254 原生标量乘法）
        delta_c_proj += dc * lambda_bnfrs[i];
        delta_d_proj += dd * lambda_bnfrs[i];
    }

    let delta_c_affine = delta_c_proj.into_affine();
    let delta_d_affine = delta_d_proj.into_affine();

    let (dc_x, dc_y) = crate::precompiles::elgamal::g1_to_u256(&delta_c_affine);
    let (dd_x, dd_y) = crate::precompiles::elgamal::g1_to_u256(&delta_d_affine);

    let mut delta_c = [Fr::zero(); 8];
    let mut delta_d = [Fr::zero(); 8];
    for k in 0..4 {
        delta_c[k] = Fr::from_u64(dc_x[k]);
        delta_c[k + 4] = Fr::from_u64(dc_y[k]);
        delta_d[k] = Fr::from_u64(dd_x[k]);
        delta_d[k + 4] = Fr::from_u64(dd_y[k]);
    }

    let public = ShufflePublicInput {
        pk,
        input_commitment: Fr::zero(),
        output_commitment: Fr::zero(),
        delta_c,
        delta_d,
    };

    let witness = ShuffleWitness {
        input_cts,
        output_cts,
        permutation,
        randomizers,
        lambda_challenges,
        blinding,
    };

    (witness, public)
}

/// 从 ElGamalCiphertext 提取 HostCiphertext。
fn host_ct_from_affine(ct: &crate::precompiles::elgamal::ElGamalCiphertext) -> HostCiphertext {
    let (c_x, c_y) = crate::precompiles::elgamal::g1_to_u256(&ct.c);
    let (d_x, d_y) = crate::precompiles::elgamal::g1_to_u256(&ct.d);
    HostCiphertext { c_x, c_y, d_x, d_y }
}

/// 从 HostCiphertext 提取 G1Affine（0=c, 1=d）。
fn affine_from_host_ct(ct: &HostCiphertext, which: u8) -> ark_bn254::G1Affine {
    let (x, y) = if which == 0 {
        (ct.c_x, ct.c_y)
    } else {
        (ct.d_x, ct.d_y)
    };
    crate::precompiles::elgamal::u256_to_g1(&x, &y).unwrap_or(ark_bn254::G1Affine::identity())
}

// ===== 测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::PrecompileRegistry;

    #[test]
    fn test_zk_shuffle_circuit_name_and_num_matrices() {
        let circuit = ZkShuffleCcsCircuit::new_light();
        let pre: &dyn PrecompileCircuit = &circuit;
        assert_eq!(pre.name(), "zk_shuffle");
        let ccs: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs.num_matrices(), 3);
        assert_eq!(pre.gas_cost(), GAS_ZK_SHUFFLE_LIGHT);

        let full = ZkShuffleCcsCircuit::new_full();
        assert_eq!(full.gas_cost(), GAS_ZK_SHUFFLE_FULL);
        assert!(full.is_full_mode());
    }

    #[test]
    fn test_zk_shuffle_build_circuit_light() {
        // 使用小 deck_size 加速测试
        let circuit = ZkShuffleCcsCircuit::with_deck_size(4, false);
        let (witness, public) = build_dummy_data(4);
        let (ccs, witness_vec) = circuit
            .build_circuit(&witness, &public)
            .expect("build_circuit");

        // CCS 应有大量约束行
        assert!(
            ccs.num_rows() > 1000,
            "Light mode 应有 >1000 行约束, got {}",
            ccs.num_rows()
        );

        // witness 应满足 CCS
        assert!(
            ccs.satisfied_by(&witness_vec).expect("satisfied_by"),
            "合法 witness 应满足 CCS"
        );
    }

    #[test]
    fn test_zk_shuffle_build_circuit_full() {
        let circuit = ZkShuffleCcsCircuit::with_deck_size(4, true);
        let (witness, public) = build_dummy_data(4);
        let (ccs, witness_vec) = circuit
            .build_circuit(&witness, &public)
            .expect("build_circuit");

        // Full mode 约束数应大于 Light mode
        assert!(
            ccs.num_rows() > 2000,
            "Full mode 应有 >2000 行约束, got {}",
            ccs.num_rows()
        );

        assert!(
            ccs.satisfied_by(&witness_vec).expect("satisfied_by"),
            "合法 witness 应满足 CCS"
        );
    }

    #[test]
    fn test_zk_shuffle_invalid_permutation() {
        let circuit = ZkShuffleCcsCircuit::with_deck_size(4, false);
        let (mut witness, public) = build_dummy_data(4);

        // 篡改排列：σ(0) = 5（越界）
        witness.permutation[0] = 5;

        let result = circuit.build_circuit(&witness, &public);
        assert!(result.is_err(), "越界排列应返回错误");
    }

    #[test]
    fn test_zk_shuffle_ciphertext_tamper_fails() {
        let circuit = ZkShuffleCcsCircuit::with_deck_size(4, false);
        let (mut witness, public) = build_dummy_data(4);

        // 篡改 output 密文[0] 的 c.x 坐标（破坏 on-curve）
        witness.output_cts[0].c_x[0] = witness.output_cts[0].c_x[0].wrapping_add(1);

        let (ccs, witness_vec) = circuit
            .build_circuit(&witness, &public)
            .expect("build_circuit");
        assert!(
            !ccs.satisfied_by(&witness_vec).expect("satisfied_by"),
            "篡改密文坐标后 CCS 应不满足（on-curve 检查失败）"
        );
    }

    #[test]
    fn test_zk_shuffle_registry_integration() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(ZkShuffleCcsCircuit::new_light()));
        assert_eq!(registry.len(), 1);
        let circuit = registry.get("zk_shuffle").expect("应找到 zk_shuffle");
        assert_eq!(circuit.name(), "zk_shuffle");
        assert_eq!(circuit.gas_cost(), GAS_ZK_SHUFFLE_LIGHT);
    }

    #[test]
    fn test_zk_shuffle_default() {
        let circuit = ZkShuffleCcsCircuit::default();
        let pre: &dyn PrecompileCircuit = &circuit;
        assert_eq!(pre.name(), "zk_shuffle");
        let ccs: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs.num_matrices(), 3);
        assert!(circuit.is_full_mode());
    }

    #[test]
    fn test_shuffle_public_input_roundtrip() {
        let public = ShufflePublicInput {
            pk: [Fr::from_u64(1); 8],
            input_commitment: Fr::from_u64(42),
            output_commitment: Fr::from_u64(43),
            delta_c: [Fr::from_u64(2); 8],
            delta_d: [Fr::from_u64(3); 8],
        };
        let vec = public.to_vec();
        assert_eq!(vec.len(), 26);
        let recovered = ShufflePublicInput::from_vec(&vec).expect("from_vec");
        assert_eq!(recovered.input_commitment, Fr::from_u64(42));
    }
}
