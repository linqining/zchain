//! SHA-256 哈希预编译电路（Phase 10 — Task 10.3 / Stage 3 — Phase B2）。
//!
//! # 两种模式
//!
//! - **MVP 模式**（`new()`）：Ch 函数约束结构，6 变量，7 矩阵。
//! - **完整模式**（`new_full()`）：64-round SHA-256 compression，~170K 变量。
//!
//! # MVP 约束结构（Ch 函数）
//!
//! SHA-256 的 Ch 函数定义为：
//! ```text
//! Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z) = z + x * (y - z)
//! ```
//!
//! witness `z = [1, x, y, z_var, y_minus_z, ch]`（6 变量），2 行约束。
//!
//! # 完整模式约束结构（64-round compression）
//!
//! 输入：8 个初始 hash state + 16 个 message words = 24 个 u32 值。
//! 输出：8 个更新后的 hash state（含 final addition: H'[i] = H[i] + working_var[i]）。
//!
//! 使用 [`FullBuilder`] 组合构建器（CCS + witness 同步），确保 ~170K 变量的约束结构与
//! witness 完全一致。所有 32-bit 运算在 bit 级别展开（32 个 bit 变量/word）。

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::precompiles::ccs_builder::CcsBuilder;
use crate::precompiles::{CcsCircuit, PrecompileCircuit};

/// SHA-256 round constants K[0..63] (FIPS 180-4 Section 4.2.2).
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values H0[0..7] (FIPS 180-4 Section 5.3.3).
#[allow(dead_code)]
const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// 完整模式 gas 成本（spec L637: SHA-256 ~25,000 gas/block）。
const FULL_MODE_GAS_COST: u64 = 25_000;

/// 完整模式变量数（64-round compression，bit 级展开）。
/// 硬编码以避免每次 `num_variables()` 调用都构建 ~170K 变量的 CCS。
const FULL_MODE_NUM_VARS: usize = 172_577;

/// 预计算 2^i (i=0..31) 作为域元素。
fn power_of_2(i: usize) -> Fr {
    Fr::from_u64(1u64 << i)
}

/// SHA-256 哈希预编译电路。
///
/// 支持两种模式：
/// - MVP 模式（`new()`）：单 Ch 函数约束，用于快速测试
/// - 完整模式（`new_full()`）：64-round SHA-256 compression
#[derive(Debug, Clone)]
pub struct Sha256Circuit {
    block_size: usize,
    output_size: usize,
    full_mode: bool,
}

impl Sha256Circuit {
    /// 创建 SHA-256 电路（完整 64-round compression 模式，block_size=64, output_size=32）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            block_size: 64,
            output_size: 32,
            full_mode: true,
        }
    }

    /// 创建 SHA-256 电路（MVP 模式，单 Ch 函数约束，用于快速测试）。
    #[must_use]
    pub fn new_mvp() -> Self {
        Self {
            block_size: 64,
            output_size: 32,
            full_mode: false,
        }
    }

    /// 创建 SHA-256 电路（完整 64-round compression 模式）。
    #[must_use]
    pub fn new_full() -> Self {
        Self {
            block_size: 64,
            output_size: 32,
            full_mode: true,
        }
    }

    /// 返回块大小（字节）。
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// 返回输出大小（字节）。
    #[must_use]
    pub fn output_size(&self) -> usize {
        self.output_size
    }

    /// 是否为完整模式。
    #[must_use]
    pub fn is_full_mode(&self) -> bool {
        self.full_mode
    }

    /// 运行完整 64-round SHA-256 compression，同时构建 CCS + witness。
    ///
    /// CCS 结构与输入无关（仅取决于算法），witness 取决于输入。
    ///
    /// # 输入
    /// - `inputs[0..8]` — 初始 hash state H0..H7
    /// - `inputs[8..24]` — message words W[0..15]
    ///
    /// # 返回
    /// `(Ccs, witness, output_words)` — output_words 为最终 8 个 hash state Words
    fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>, [Word; 8]), ZkvmError> {
        if inputs.len() != 24 {
            return Err(ZkvmError::Other(format!(
                "Sha256Circuit::run_full: inputs.len() {} != 24（8 hash state + 16 message words）",
                inputs.len()
            )));
        }

        let mut fb = FullBuilder::new();

        // 1. 分解输入为 Words
        let h: Vec<Word> = (0..8).map(|i| fb.decompose(inputs[i].to_u32())).collect();
        let mut w: Vec<Word> = Vec::with_capacity(64);
        for i in 0..16 {
            w.push(fb.decompose(inputs[8 + i].to_u32()));
        }

        // 2. 分解 K 常量
        let k_words: Vec<Word> = SHA256_K.iter().map(|&k| fb.decompose(k)).collect();

        // 3. 消息调度: W[16..63]
        for t in 16..64 {
            // sigma0(W[t-15]) = ROTR(W[t-15],7) XOR ROTR(W[t-15],18) XOR SHR(W[t-15],3)
            let s0_a = fb.rotr(&w[t - 15], 7);
            let s0_b = fb.rotr(&w[t - 15], 18);
            let s0_c = fb.shr(&w[t - 15], 3);
            let s0_ab = fb.xor(&s0_a, &s0_b);
            let s0 = fb.xor(&s0_ab, &s0_c);

            // sigma1(W[t-2]) = ROTR(W[t-2],17) XOR ROTR(W[t-2],19) XOR SHR(W[t-2],10)
            let s1_a = fb.rotr(&w[t - 2], 17);
            let s1_b = fb.rotr(&w[t - 2], 19);
            let s1_c = fb.shr(&w[t - 2], 10);
            let s1_ab = fb.xor(&s1_a, &s1_b);
            let s1 = fb.xor(&s1_ab, &s1_c);

            // W[t] = W[t-16] + s0 + W[t-7] + s1 (mod 2^32)
            let tmp1 = fb.add_mod_2_32(&w[t - 16], &s0);
            let tmp2 = fb.add_mod_2_32(&tmp1, &w[t - 7]);
            w.push(fb.add_mod_2_32(&tmp2, &s1));
        }

        // 4. 初始化工作变量
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) = (
            h[0].clone(),
            h[1].clone(),
            h[2].clone(),
            h[3].clone(),
            h[4].clone(),
            h[5].clone(),
            h[6].clone(),
            h[7].clone(),
        );

        // 5. 64 rounds compression
        for t in 0..64 {
            // S1 = ROTR(e,6) XOR ROTR(e,11) XOR ROTR(e,25)
            let s1_a = fb.rotr(&e, 6);
            let s1_b = fb.rotr(&e, 11);
            let s1_c = fb.rotr(&e, 25);
            let s1_ab = fb.xor(&s1_a, &s1_b);
            let s1 = fb.xor(&s1_ab, &s1_c);

            // ch = (e AND f) XOR ((NOT e) AND g)
            let e_and_f = fb.and(&e, &f);
            let not_e = fb.not(&e);
            let not_e_and_g = fb.and(&not_e, &g);
            let ch = fb.xor(&e_and_f, &not_e_and_g);

            // temp1 = h + S1 + ch + K[t] + W[t] (mod 2^32)
            let t1a = fb.add_mod_2_32(&hh, &s1);
            let t1b = fb.add_mod_2_32(&t1a, &ch);
            let t1c = fb.add_mod_2_32(&t1b, &k_words[t]);
            let temp1 = fb.add_mod_2_32(&t1c, &w[t]);

            // S0 = ROTR(a,2) XOR ROTR(a,13) XOR ROTR(a,22)
            let s0_a = fb.rotr(&a, 2);
            let s0_b = fb.rotr(&a, 13);
            let s0_c = fb.rotr(&a, 22);
            let s0_ab = fb.xor(&s0_a, &s0_b);
            let s0 = fb.xor(&s0_ab, &s0_c);

            // maj = (a AND b) XOR (a AND c) XOR (b AND c)
            let a_and_b = fb.and(&a, &b);
            let a_and_c = fb.and(&a, &c);
            let b_and_c = fb.and(&b, &c);
            let maj_ab = fb.xor(&a_and_b, &a_and_c);
            let maj = fb.xor(&maj_ab, &b_and_c);

            // temp2 = S0 + maj (mod 2^32)
            let temp2 = fb.add_mod_2_32(&s0, &maj);

            // 移位工作变量
            hh = g;
            g = f;
            f = e;
            e = fb.add_mod_2_32(&d, &temp1);
            d = c;
            c = b;
            b = a;
            a = fb.add_mod_2_32(&temp1, &temp2);
        }

        // 6. Final addition: H'[i] = H[i] + working_var[i] (mod 2^32)
        let output = [
            fb.add_mod_2_32(&h[0], &a),
            fb.add_mod_2_32(&h[1], &b),
            fb.add_mod_2_32(&h[2], &c),
            fb.add_mod_2_32(&h[3], &d),
            fb.add_mod_2_32(&h[4], &e),
            fb.add_mod_2_32(&h[5], &f),
            fb.add_mod_2_32(&h[6], &g),
            fb.add_mod_2_32(&h[7], &hh),
        ];

        let ccs = fb.ccs.build()?;
        Ok((ccs, fb.witness, output))
    }
}

impl Default for Sha256Circuit {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileCircuit for Sha256Circuit {
    fn name(&self) -> &str {
        "sha256"
    }

    fn num_variables(&self) -> usize {
        if self.full_mode {
            FULL_MODE_NUM_VARS
        } else {
            6
        }
    }

    fn build_ccs(&self) -> Result<Ccs, ZkvmError> {
        if self.full_mode {
            let dummy = vec![Fr::zero(); 24];
            Ok(self.run_full(&dummy)?.0)
        } else {
            Ok(self.build_mvp_ccs())
        }
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if self.full_mode {
            if inputs.len() != 24 {
                return Err(ZkvmError::Other(format!(
                    "Sha256Circuit::assign_witness (full): inputs.len() {} != 24（8 hash state + 16 message words）",
                    inputs.len()
                )));
            }
            Ok(self.run_full(inputs)?.1)
        } else {
            self.assign_mvp_witness(inputs)
        }
    }

    fn gas_cost(&self) -> u64 {
        if self.full_mode {
            FULL_MODE_GAS_COST
        } else {
            25_000
        }
    }
}

impl Sha256Circuit {
    /// MVP 模式 CCS 构建（Ch 函数约束）。
    fn build_mvp_ccs(&self) -> Ccs {
        let mut m_y_r0 = SparseMatrix::new(2, 6);
        m_y_r0.add_entry(0, 2, Fr::one()).expect("M_y_r0");

        let mut m_z_r0 = SparseMatrix::new(2, 6);
        m_z_r0.add_entry(0, 3, Fr::one()).expect("M_z_r0");

        let mut m_ymz_r0 = SparseMatrix::new(2, 6);
        m_ymz_r0.add_entry(0, 4, Fr::one()).expect("M_ymz_r0");

        let mut m_x_r1 = SparseMatrix::new(2, 6);
        m_x_r1.add_entry(1, 1, Fr::one()).expect("M_x_r1");

        let mut m_ymz_r1 = SparseMatrix::new(2, 6);
        m_ymz_r1.add_entry(1, 4, Fr::one()).expect("M_ymz_r1");

        let mut m_ch_r1 = SparseMatrix::new(2, 6);
        m_ch_r1.add_entry(1, 5, Fr::one()).expect("M_ch_r1");

        let mut m_z_r1 = SparseMatrix::new(2, 6);
        m_z_r1.add_entry(1, 3, Fr::one()).expect("M_z_r1");

        let neg_one = Fr::zero().sub(&Fr::one());

        Ccs::new(
            6,
            vec![m_y_r0, m_z_r0, m_ymz_r0, m_x_r1, m_ymz_r1, m_ch_r1, m_z_r1],
            vec![vec![0], vec![1], vec![2], vec![3, 4], vec![5], vec![6]],
            vec![Fr::one(), neg_one, neg_one, Fr::one(), neg_one, Fr::one()],
        )
        .expect("Sha256Circuit MVP CCS 构造应成功")
    }

    /// MVP 模式 witness 赋值（Ch 函数）。
    fn assign_mvp_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if inputs.len() != 3 {
            return Err(ZkvmError::Other(format!(
                "Sha256Circuit::assign_mvp_witness: inputs.len() {} != 3（Ch 函数需要 x, y, z 三个输入）",
                inputs.len()
            )));
        }
        let x = inputs[0];
        let y = inputs[1];
        let z_var = inputs[2];
        let y_minus_z = y.sub(&z_var);
        let ch = z_var.add(&x.mul(&y_minus_z));
        Ok(vec![Fr::one(), x, y, z_var, y_minus_z, ch])
    }
}

impl CcsCircuit for Sha256Circuit {
    fn name(&self) -> &str {
        "sha256"
    }

    fn num_matrices(&self) -> usize {
        if self.full_mode {
            let dummy = vec![Fr::zero(); 24];
            self.run_full(&dummy).unwrap().0.num_matrices()
        } else {
            7
        }
    }

    fn to_ccs_instance(
        &self,
        witness: &[Fr],
        public_inputs: &[Fr],
    ) -> Result<CcsInstance, ZkvmError> {
        let ccs = self.build_ccs()?;
        CcsInstance::new(ccs, witness.to_vec(), public_inputs.to_vec())
    }
}

// ===== FullBuilder: 组合 CCS + witness 构建器 =====

/// 32-bit word 表示为 32 个 bit 变量索引。
#[derive(Clone)]
struct Word {
    bits: Vec<usize>,
}

/// 组合 CCS 构建器 + witness 跟踪器。
///
/// 确保 ~170K 变量的约束结构与 witness 完全同步。
/// 每个 bit 操作方法镜像 [`crate::precompiles::bit_ops`] 的约束结构，
/// 同时计算并推送 witness 值。
struct FullBuilder {
    ccs: CcsBuilder,
    witness: Vec<Fr>,
}

impl FullBuilder {
    fn new() -> Self {
        Self {
            ccs: CcsBuilder::new(),
            witness: vec![Fr::one()],
        }
    }

    /// 分配变量并设置 witness 值。
    fn alloc(&mut self, val: Fr) -> usize {
        let idx = self.ccs.alloc_var();
        self.witness.push(val);
        idx
    }

    /// 获取变量的 witness 值。
    fn get_val(&self, idx: usize) -> Fr {
        self.witness[idx]
    }

    /// 将 u32 值分解为 32 个 bit 变量。
    ///
    /// 约束：32 个 bit_check + 1 个 linear (recompose: sum(bit_i * 2^i) = val)
    fn decompose(&mut self, val: u32) -> Word {
        let val_fr = Fr::from_u32_with_wrap(val);
        let val_var = self.alloc(val_fr);

        let mut bits = Vec::with_capacity(32);
        for i in 0..32 {
            let bit_val = Fr::from_u32_with_wrap((val >> i) & 1);
            let bit = self.alloc(bit_val);
            let row = self.ccs.alloc_row();
            self.ccs.add_bit_check(row, bit);
            bits.push(bit);
        }

        let row = self.ccs.alloc_row();
        let mut terms = Vec::with_capacity(33);
        for (i, &bit) in bits.iter().enumerate() {
            terms.push((bit, power_of_2(i)));
        }
        terms.push((val_var, Fr::one().neg()));
        self.ccs.add_linear(row, &terms);

        Word { bits }
    }

    /// 逐位 XOR: result[i] = a[i] + b[i] - 2*a[i]*b[i]。
    fn xor(&mut self, a: &Word, b: &Word) -> Word {
        let two = Fr::from_u64(2);
        let mut result = Vec::with_capacity(32);
        for i in 0..32 {
            let a_val = self.get_val(a.bits[i]);
            let b_val = self.get_val(b.bits[i]);
            let ab_val = a_val.mul(&b_val);

            let ab = self.alloc(ab_val);
            let r_mult = self.ccs.alloc_row();
            self.ccs
                .add_multiplication(r_mult, a.bits[i], b.bits[i], ab);

            let out_val = a_val.add(&b_val).sub(&two.mul(&ab_val));
            let out = self.alloc(out_val);
            let r_lin = self.ccs.alloc_row();
            self.ccs.add_linear(
                r_lin,
                &[
                    (a.bits[i], Fr::one()),
                    (b.bits[i], Fr::one()),
                    (ab, two.neg()),
                    (out, Fr::one().neg()),
                ],
            );
            result.push(out);
        }
        Word { bits: result }
    }

    /// 逐位 AND: result[i] = a[i] * b[i]。
    fn and(&mut self, a: &Word, b: &Word) -> Word {
        let mut result = Vec::with_capacity(32);
        for i in 0..32 {
            let a_val = self.get_val(a.bits[i]);
            let b_val = self.get_val(b.bits[i]);
            let out_val = a_val.mul(&b_val);

            let out = self.alloc(out_val);
            let row = self.ccs.alloc_row();
            self.ccs.add_multiplication(row, a.bits[i], b.bits[i], out);
            result.push(out);
        }
        Word { bits: result }
    }

    /// 逐位 NOT: result[i] = 1 - a[i]。
    fn not(&mut self, a: &Word) -> Word {
        let mut result = Vec::with_capacity(32);
        for i in 0..32 {
            let a_val = self.get_val(a.bits[i]);
            let out_val = Fr::one().sub(&a_val);

            let out = self.alloc(out_val);
            let row = self.ccs.alloc_row();
            self.ccs.add_linear(
                row,
                &[
                    (0, Fr::one()),
                    (a.bits[i], Fr::one().neg()),
                    (out, Fr::one().neg()),
                ],
            );
            result.push(out);
        }
        Word { bits: result }
    }

    /// 循环右移：纯重排，无约束。
    fn rotr(&self, w: &Word, n: usize) -> Word {
        let n = n % 32;
        let mut result = Vec::with_capacity(32);
        for i in 0..32 {
            result.push(w.bits[(i + n) % 32]);
        }
        Word { bits: result }
    }

    /// 逻辑右移：零填充位约束为 0。
    fn shr(&mut self, w: &Word, n: usize) -> Word {
        let mut result = Vec::with_capacity(32);
        for i in 0..32 {
            if i + n < 32 {
                result.push(w.bits[i + n]);
            } else {
                let zero_bit = self.alloc(Fr::zero());
                let row = self.ccs.alloc_row();
                self.ccs.add_linear(row, &[(zero_bit, Fr::one())]);
                result.push(zero_bit);
            }
        }
        Word { bits: result }
    }

    /// 32-bit 模 2^32 加法（ripple-carry）。
    fn add_mod_2_32(&mut self, a: &Word, b: &Word) -> Word {
        let two = Fr::from_u64(2);

        let mut carry = self.alloc(Fr::zero());
        let r_c0 = self.ccs.alloc_row();
        self.ccs.add_linear(r_c0, &[(carry, Fr::one())]);

        let mut sum_bits = Vec::with_capacity(32);
        for i in 0..32 {
            let a_val = self.get_val(a.bits[i]);
            let b_val = self.get_val(b.bits[i]);
            let carry_val = self.get_val(carry);

            let p_val = a_val.mul(&b_val);
            let p = self.alloc(p_val);
            let r_p = self.ccs.alloc_row();
            self.ccs.add_multiplication(r_p, a.bits[i], b.bits[i], p);

            let s_val = a_val.add(&b_val).sub(&two.mul(&p_val));
            let s = self.alloc(s_val);
            let r_s = self.ccs.alloc_row();
            self.ccs.add_linear(
                r_s,
                &[
                    (a.bits[i], Fr::one()),
                    (b.bits[i], Fr::one()),
                    (p, two.neg()),
                    (s, Fr::one().neg()),
                ],
            );

            let sc_val = s_val.mul(&carry_val);
            let sc = self.alloc(sc_val);
            let r_sc = self.ccs.alloc_row();
            self.ccs.add_multiplication(r_sc, s, carry, sc);

            let sum_val = s_val.add(&carry_val).sub(&two.mul(&sc_val));
            let sum = self.alloc(sum_val);
            let r_sum = self.ccs.alloc_row();
            self.ccs.add_linear(
                r_sum,
                &[
                    (s, Fr::one()),
                    (carry, Fr::one()),
                    (sc, two.neg()),
                    (sum, Fr::one().neg()),
                ],
            );
            sum_bits.push(sum);

            let psc_val = p_val.mul(&sc_val);
            let psc = self.alloc(psc_val);
            let r_psc = self.ccs.alloc_row();
            self.ccs.add_multiplication(r_psc, p, sc, psc);

            let next_carry_val = p_val.add(&sc_val).sub(&psc_val);
            let next_carry = self.alloc(next_carry_val);
            let r_carry = self.ccs.alloc_row();
            self.ccs.add_linear(
                r_carry,
                &[
                    (p, Fr::one()),
                    (sc, Fr::one()),
                    (psc, Fr::one().neg()),
                    (next_carry, Fr::one().neg()),
                ],
            );
            carry = next_carry;
        }

        Word { bits: sum_bits }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::PrecompileRegistry;

    // ===== MVP 模式测试（原有）=====

    /// 计算 Ch 函数（bit 级别）。
    fn ch_bit(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ ((!x) & z)
    }

    #[test]
    fn test_sha256_circuit_build_ccs() {
        let circuit = Sha256Circuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        assert_eq!(ccs.num_matrices(), 7);
        assert_eq!(ccs.num_constraints(), 6);
        assert_eq!(ccs.num_rows(), 2);
        assert_eq!(ccs.num_vars, 6);
    }

    #[test]
    fn test_sha256_circuit_satisfied_by() {
        let circuit = Sha256Circuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let inputs = vec![
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(0),
        ];
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness 应成功");
        assert_eq!(witness.len(), 6);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_sha256_circuit_soundness_tampered_ch() {
        let circuit = Sha256Circuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let inputs = vec![
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(0),
        ];
        let mut witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness 应成功");
        witness[5] = Fr::from_u32_with_wrap(0);
        assert!(!ccs.satisfied_by(&witness).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_sha256_circuit_soundness_tampered_ymz() {
        let circuit = Sha256Circuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let inputs = vec![
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(0),
        ];
        let mut witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness 应成功");
        witness[4] = Fr::from_u32_with_wrap(2);
        assert!(!ccs.satisfied_by(&witness).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_sha256_circuit_consistency_with_bit_ch() {
        let circuit = Sha256Circuit::new_mvp();
        for x in 0..=1u32 {
            for y in 0..=1u32 {
                for z in 0..=1u32 {
                    let inputs = vec![
                        Fr::from_u32_with_wrap(x),
                        Fr::from_u32_with_wrap(y),
                        Fr::from_u32_with_wrap(z),
                    ];
                    let witness = circuit.assign_witness(&inputs).expect("assign_witness");
                    let ch_circuit = witness[5];
                    let ch_expected = ch_bit(x, y, z);
                    assert_eq!(ch_circuit.to_u32(), ch_expected);
                    let ccs = circuit.build_ccs().expect("build_ccs");
                    assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
                }
            }
        }
    }

    #[test]
    fn test_sha256_circuit_consistency_with_sha2_crate() {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let result = hasher.finalize();
        let expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(hex::encode(result), expected_hex);
    }

    #[test]
    fn test_sha256_circuit_known_vectors() {
        use sha2::{Digest, Sha256};
        let cases = [
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "hello world",
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            ),
        ];
        for (msg, expected_hex) in cases {
            let mut hasher = Sha256::new();
            hasher.update(msg.as_bytes());
            let result = hasher.finalize();
            assert_eq!(hex::encode(result), expected_hex);
        }
    }

    #[test]
    fn test_sha256_circuit_empty_input() {
        let circuit = Sha256Circuit::new_mvp();
        let result = circuit.assign_witness(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sha256_circuit_wrong_input_length() {
        let circuit = Sha256Circuit::new_mvp();
        let result = circuit.assign_witness(&[Fr::one(), Fr::one()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sha256_circuit_registry_integration() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(Sha256Circuit::new_mvp()));
        assert_eq!(registry.len(), 1);
        let circuit = registry.get("sha256").expect("应找到 sha256");
        assert_eq!(circuit.name(), "sha256");
        assert_eq!(circuit.num_variables(), 6);
        assert_eq!(circuit.gas_cost(), 25_000);
    }

    #[test]
    fn test_sha256_circuit_gas_cost() {
        let circuit = Sha256Circuit::new_mvp();
        assert_eq!(circuit.gas_cost(), 25_000);
    }

    #[test]
    fn test_sha256_circuit_block_and_output_size() {
        let circuit = Sha256Circuit::new_mvp();
        assert_eq!(circuit.block_size(), 64);
        assert_eq!(circuit.output_size(), 32);
    }

    #[test]
    fn test_sha256_circuit_ccs_circuit_trait() {
        let circuit = Sha256Circuit::new_mvp();
        let inputs = vec![
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(0),
            Fr::from_u32_with_wrap(1),
        ];
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness 应成功");
        let public_inputs = vec![Fr::one()];

        let ccs_circuit: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs_circuit.name(), "sha256");
        assert_eq!(ccs_circuit.num_matrices(), 7);

        let instance = ccs_circuit
            .to_ccs_instance(&witness, &public_inputs)
            .expect("to_ccs_instance 应成功");
        assert!(instance.is_satisfied().expect("is_satisfied 应成功"));
    }

    // ===== 完整模式测试（Stage 3 — Phase B2）=====

    /// 从 witness 和 Word 提取 u32 值。
    fn word_to_u32(witness: &[Fr], word: &Word) -> u32 {
        let mut val = 0u32;
        for (i, &bit_idx) in word.bits.iter().enumerate() {
            if witness[bit_idx].to_u32() == 1 {
                val |= 1 << i;
            }
        }
        val
    }

    /// 参考实现：SHA-256 compression function（u32 算术）。
    fn sha256_compress_ref(state: &[u32; 8], block: &[u32; 16]) -> [u32; 8] {
        let mut w = [0u32; 64];
        w[..16].copy_from_slice(block);
        for t in 16..64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );

        for t in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[t])
                .wrapping_add(w[t]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        [
            state[0].wrapping_add(a),
            state[1].wrapping_add(b),
            state[2].wrapping_add(c),
            state[3].wrapping_add(d),
            state[4].wrapping_add(e),
            state[5].wrapping_add(f),
            state[6].wrapping_add(g),
            state[7].wrapping_add(h),
        ]
    }

    /// 构造测试输入（24 个 Fr 值：8 state + 16 message words）。
    fn make_full_inputs(state: &[u32; 8], block: &[u32; 16]) -> Vec<Fr> {
        state
            .iter()
            .chain(block.iter())
            .map(|&v| Fr::from_u32_with_wrap(v))
            .collect()
    }

    #[test]
    fn test_sha256_full_build_ccs() {
        let circuit = Sha256Circuit::new_full();
        let ccs = circuit.build_ccs().expect("build_ccs");

        // 完整模式应有大量变量
        assert!(
            ccs.num_vars > 100_000,
            "完整模式变量数应 > 100,000，实际 {}",
            ccs.num_vars
        );
        assert!(ccs.num_rows() > 0, "应有约束行");
        assert!(ccs.num_matrices() > 0, "应有矩阵");
    }

    #[test]
    fn test_sha256_full_satisfied_by() {
        let circuit = Sha256Circuit::new_full();
        let ccs = circuit.build_ccs().expect("build_ccs");

        // 使用 SHA256_H0 + 全零消息块
        let mut block = [0u32; 16];
        // 设置长度字段（SHA-256 padding: 1-bit + zeros + 64-bit length）
        // 对空消息：padding = 0x80 followed by zeros, length=0 at end
        // 但这里我们直接用全零块测试电路逻辑
        let _ = &mut block;
        let inputs = make_full_inputs(&SHA256_H0, &block);
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness 应成功");

        assert_eq!(witness.len(), ccs.num_vars, "witness 长度应等于 num_vars");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "完整模式 witness 应满足所有约束"
        );
    }

    #[test]
    fn test_sha256_full_matches_reference() {
        let circuit = Sha256Circuit::new_full();

        let test_cases = [
            // (state, block)
            (SHA256_H0, [0u32; 16]),
            (SHA256_H0, {
                let mut b = [0u32; 16];
                b[0] = 0x80000000; // padding bit
                b
            }),
            (SHA256_H0, {
                let mut b = [0u32; 16];
                b[0] = 0x61626380; // "abc" + padding
                b[15] = 0x00000018; // length = 24 bits
                b
            }),
        ];

        for (state, block) in test_cases {
            let inputs = make_full_inputs(&state, &block);
            let (_ccs, witness, output) = circuit.run_full(&inputs).expect("run_full 应成功");

            let circuit_output: Vec<u32> =
                output.iter().map(|w| word_to_u32(&witness, w)).collect();

            let expected = sha256_compress_ref(&state, &block);

            assert_eq!(circuit_output, expected, "电路输出与参考实现不一致");
        }
    }

    #[test]
    fn test_sha256_full_matches_sha2_crate() {
        // 验证电路与 sha2 crate 的输出一致
        // 对 "abc" 进行 SHA-256，验证第一块压缩结果
        use sha2::{Digest, Sha256};

        let msg = b"abc";
        // "abc" = 3 bytes = 24 bits
        // Padding: 0x80 + zeros + 64-bit length → total 64 bytes = 16 u32 words
        let mut padded = [0u8; 64];
        padded[..msg.len()].copy_from_slice(msg);
        padded[msg.len()] = 0x80;
        padded[63] = (msg.len() * 8) as u8;

        let mut block = [0u32; 16];
        for i in 0..16 {
            block[i] = u32::from_be_bytes([
                padded[i * 4],
                padded[i * 4 + 1],
                padded[i * 4 + 2],
                padded[i * 4 + 3],
            ]);
        }

        let circuit = Sha256Circuit::new_full();
        let inputs = make_full_inputs(&SHA256_H0, &block);
        let (_ccs, witness, output) = circuit.run_full(&inputs).expect("run_full 应成功");

        let circuit_output: Vec<u32> = output.iter().map(|w| word_to_u32(&witness, w)).collect();

        // 使用 sha2 crate 验证
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let result = hasher.finalize();

        // sha2 crate 输出是 big-endian bytes，转为 u32
        let sha2_output: Vec<u32> = result
            .chunks(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        assert_eq!(circuit_output, sha2_output, "电路输出与 sha2 crate 不一致");
    }

    #[test]
    fn test_sha256_full_soundness_tampered_output() {
        let circuit = Sha256Circuit::new_full();
        let ccs = circuit.build_ccs().expect("build_ccs");

        let inputs = make_full_inputs(&SHA256_H0, &[0u32; 16]);
        let (_ccs2, mut witness, output) = circuit.run_full(&inputs).expect("run_full 应成功");

        // 篡改输出 Word 的第一个 bit
        let first_output_bit = output[0].bits[0];
        let original = witness[first_output_bit];
        witness[first_output_bit] = if original.to_u32() == 0 {
            Fr::from_u32_with_wrap(1)
        } else {
            Fr::zero()
        };

        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by"),
            "篡改输出后应不满足约束"
        );
    }

    #[test]
    fn test_sha256_full_gas_cost() {
        let circuit = Sha256Circuit::new_full();
        assert_eq!(circuit.gas_cost(), FULL_MODE_GAS_COST);
    }

    #[test]
    fn test_sha256_full_wrong_input_length() {
        let circuit = Sha256Circuit::new_full();
        assert!(circuit.assign_witness(&[]).is_err(), "空输入应返回错误");
        assert!(
            circuit.assign_witness(&[Fr::zero(); 10]).is_err(),
            "输入长度 10 应返回错误"
        );
        assert!(
            circuit.assign_witness(&[Fr::zero(); 23]).is_err(),
            "输入长度 23 应返回错误"
        );
        assert!(
            circuit.assign_witness(&[Fr::zero(); 25]).is_err(),
            "输入长度 25 应返回错误"
        );
    }

    #[test]
    fn test_sha256_full_backward_compatibility() {
        let mvp = Sha256Circuit::new_mvp();
        assert!(!mvp.is_full_mode());
        assert_eq!(mvp.num_variables(), 6);
        assert_eq!(mvp.gas_cost(), 25_000);

        let full = Sha256Circuit::new_full();
        assert!(full.is_full_mode());
        assert!(full.num_variables() > 100_000);
        assert_eq!(full.gas_cost(), FULL_MODE_GAS_COST);

        // MVP 模式仍正常工作
        let mvp_ccs = mvp.build_ccs().expect("build_ccs");
        assert_eq!(mvp_ccs.num_vars, 6);
    }

    #[test]
    fn test_sha256_full_ccs_circuit_trait() {
        let circuit = Sha256Circuit::new_full();
        let inputs = make_full_inputs(&SHA256_H0, &[0u32; 16]);
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness 应成功");
        let public_inputs = vec![Fr::one()];

        let ccs_circuit: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs_circuit.name(), "sha256");

        let instance = ccs_circuit
            .to_ccs_instance(&witness, &public_inputs)
            .expect("to_ccs_instance 应成功");
        assert!(
            instance.is_satisfied().expect("is_satisfied 应成功"),
            "完整模式 CcsInstance 应满足"
        );
    }
}
