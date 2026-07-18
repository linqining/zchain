//! Keccak-256 预编译电路（Phase I — Batch 1）。
//!
//! # 两种模式
//!
//! - **MVP 模式**（`new()`）：单轮 Keccak-f[1600] 置换，验证 round(state) = output。
//! - **完整模式**（`new_full()`）：24 轮置换 + squeeze，验证 keccak256(input) = output。
//!
//! # Keccak-f[1600] 算法
//!
//! 状态：5×5 矩阵，每 lane 64-bit（共 1600 bit）。
//! 24 轮，每轮 5 步：theta + rho + pi + chi + iota。
//!
//! 所有 bit 级操作（XOR/AND/NOT/ROTR）通过 `bit_decompose` 将 64-bit lane
//! 分解为 64 个 bit 变量，在 bit 域操作后 `bit_recompose` 回 lane 变量。
//!
//! # 约束数
//!
//! - MVP（单轮）：~8,000 行
//! - Full（24 轮）：~192,000 行（与 SHA-256 Full 同量级）

// Theta/Pi/Chi 步骤需同时索引多个 2D 数组，clippy needless_range_loop 建议不适用。
#![allow(clippy::needless_range_loop)]

use crate::ccs::{Ccs, CcsInstance, Fr};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::precompiles::ccs_builder::CcsBuilder;
use crate::precompiles::{CcsCircuit, PrecompileCircuit};

/// Keccak-256 gas 常量（与 syscalls/gas.rs 对齐）。
const GAS_PER_ROUND: u64 = 10_000;

/// 完整模式变量数（24 轮 Keccak-f[1600] 置换，bit 级展开）。
/// 硬编码以避免每次 `num_variables()` 调用都构建 ~350K 变量的 CCS。
const FULL_MODE_NUM_VARS: usize = 350_838;

/// Rho 旋转偏移量表（FIPS 202 Section 3.2.2）。
///
/// `RHO_OFFSETS[x][y]` = lane (x,y) 的旋转位数。
const RHO_OFFSETS: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// Iota 轮常量表（FIPS 202 Section 3.2.3），24 轮各一个 64-bit 常量。
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Keccak-256 rate（bits）= 1088，即 136 bytes = 17 lanes。
#[cfg(test)]
const RATE_BITS: usize = 1088;
#[cfg(test)]
const RATE_LANES: usize = RATE_BITS / 64; // 17

/// 预计算 2^i (i=0..63) 作为域元素。
fn power_of_2(i: u32) -> Fr {
    Fr::from_u64(1u64 << i)
}

// ===== KeccakBuilder: CCS + witness 同步构建器 =====

/// 组合 CCS 构建器 + witness 跟踪器。
///
/// 每个 bit 操作方法同时添加约束和计算 witness，确保两者同步。
struct KeccakBuilder {
    ccs: CcsBuilder,
    witness: Vec<Fr>,
}

impl KeccakBuilder {
    fn new() -> Self {
        Self {
            ccs: CcsBuilder::new(),
            witness: vec![Fr::one()], // var 0 = constant 1
        }
    }

    /// 分配变量并设置 witness 值。
    fn alloc(&mut self, val: Fr) -> usize {
        let idx = self.ccs.alloc_var();
        self.witness.push(val);
        idx
    }

    /// 获取变量的 witness 值。
    fn get_val(&self, var: usize) -> Fr {
        self.witness[var]
    }

    /// 获取变量的 u64 值（低 64 位）。
    fn get_u64(&self, var: usize) -> u64 {
        let bytes = self.get_val(var).to_canonical_bytes();
        u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"))
    }

    /// 分配一个值为 u64 的变量。
    fn alloc_u64(&mut self, val: u64) -> usize {
        self.alloc(Fr::from_u64(val))
    }

    /// 将 64-bit lane 变量分解为 64 个 bit 变量。
    ///
    /// 约束：64 个 bit_check + 1 个 linear（recompose）。
    fn bit_decompose_64(&mut self, var: usize) -> Vec<usize> {
        let u64_val = self.get_u64(var);

        let mut bits = Vec::with_capacity(64);
        for i in 0..64 {
            let bit_val = Fr::from_u64((u64_val >> i) & 1);
            let bit = self.alloc(bit_val);
            let row = self.ccs.alloc_row();
            self.ccs.add_bit_check(row, bit);
            bits.push(bit);
        }

        // recompose: sum(bit_i * 2^i) - var = 0
        let row = self.ccs.alloc_row();
        let mut terms = Vec::with_capacity(65);
        for (i, &bit) in bits.iter().enumerate() {
            terms.push((bit, power_of_2(i as u32)));
        }
        terms.push((var, Fr::one().neg()));
        self.ccs.add_linear(row, &terms);

        bits
    }

    /// 将 64 个 bit 变量重组为 64-bit lane 变量。
    ///
    /// 约束：1 个 linear（recompose）。
    fn bit_recompose_64(&mut self, bits: &[usize]) -> usize {
        let mut val = Fr::zero();
        for (i, &bit) in bits.iter().enumerate() {
            let bit_val = self.get_val(bit);
            val = val.add(&bit_val.mul(&power_of_2(i as u32)));
        }
        let result = self.alloc(val);

        // recompose: sum(bit_i * 2^i) - result = 0
        let row = self.ccs.alloc_row();
        let mut terms = Vec::with_capacity(65);
        for (i, &bit) in bits.iter().enumerate() {
            terms.push((bit, power_of_2(i as u32)));
        }
        terms.push((result, Fr::one().neg()));
        self.ccs.add_linear(row, &terms);

        result
    }

    /// 逐位 XOR：result[i] = a[i] XOR b[i] = a[i] + b[i] - 2*a[i]*b[i]。
    ///
    /// 约束（per bit）：1 multiplication + 1 linear。
    fn bit_xor(&mut self, a: &[usize], b: &[usize]) -> Vec<usize> {
        debug_assert_eq!(a.len(), b.len());
        let two = Fr::from_u64(2);
        let mut result = Vec::with_capacity(a.len());
        for i in 0..a.len() {
            let ab_val = self.get_val(a[i]).mul(&self.get_val(b[i]));
            let ab = self.alloc(ab_val);
            let row_m = self.ccs.alloc_row();
            self.ccs.add_multiplication(row_m, a[i], b[i], ab);

            let out_val = self
                .get_val(a[i])
                .add(&self.get_val(b[i]))
                .sub(&ab_val.mul(&two));
            let out = self.alloc(out_val);
            let row_l = self.ccs.alloc_row();
            self.ccs.add_linear(
                row_l,
                &[
                    (a[i], Fr::one()),
                    (b[i], Fr::one()),
                    (ab, two.neg()),
                    (out, Fr::one().neg()),
                ],
            );
            result.push(out);
        }
        result
    }

    /// 逐位 AND：result[i] = a[i] AND b[i] = a[i] * b[i]。
    ///
    /// 约束（per bit）：1 multiplication。
    fn bit_and(&mut self, a: &[usize], b: &[usize]) -> Vec<usize> {
        debug_assert_eq!(a.len(), b.len());
        let mut result = Vec::with_capacity(a.len());
        for i in 0..a.len() {
            let ab_val = self.get_val(a[i]).mul(&self.get_val(b[i]));
            let ab = self.alloc(ab_val);
            let row = self.ccs.alloc_row();
            self.ccs.add_multiplication(row, a[i], b[i], ab);
            result.push(ab);
        }
        result
    }

    /// 逐位 NOT：result[i] = 1 - a[i]。
    ///
    /// 约束（per bit）：1 linear — `bit + not_bit - 1 = 0`（var 0 = 常数 1）。
    fn bit_not(&mut self, a: &[usize]) -> Vec<usize> {
        let one = Fr::one();
        let mut result = Vec::with_capacity(a.len());
        for &bit in a {
            let not_val = one.sub(&self.get_val(bit));
            let not_bit = self.alloc(not_val);
            let row = self.ccs.alloc_row();
            self.ccs.add_linear(
                row,
                &[(bit, Fr::one()), (not_bit, Fr::one()), (0, Fr::one().neg())],
            );
            result.push(not_bit);
        }
        result
    }

    /// 旋转右移：result = rotr(a, offset)。
    ///
    /// 纯 witness 重排，0 约束（bit 索引重排）。
    fn bit_rotr(&mut self, a: &[usize], offset: u32) -> Vec<usize> {
        let n = a.len() as u32;
        let offset = offset % n;
        let mut result = Vec::with_capacity(a.len());
        for i in 0..a.len() as u32 {
            // result[i] = a[(i + offset) % n]
            result.push(a[((i + offset) % n) as usize]);
        }
        result
    }

    /// 消费 self，构建 CCS。
    fn build(self) -> Result<Ccs, ZkvmError> {
        self.ccs.build()
    }
}

// ===== Keccak 轮函数 =====

/// 执行一轮 Keccak-f[1600]（theta + rho + pi + chi + iota）。
///
/// `state[x][y]` 是 25 个 64-bit lane 变量索引。
/// 返回新的 25 个 lane 变量索引。
fn keccak_round(
    builder: &mut KeccakBuilder,
    state: &[[usize; 5]; 5],
    round_idx: usize,
) -> [[usize; 5]; 5] {
    // ===== Step 1: Theta =====
    // C[x] = A[x,0] XOR A[x,1] XOR A[x,2] XOR A[x,3] XOR A[x,4]
    // D[x] = C[x-1] XOR rot(C[x+1], 1)
    // A'[x,y] = A[x,y] XOR D[x]

    // 分解所有 lane 为 bit 域
    let mut bits: [[Vec<usize>; 5]; 5] = Default::default();
    for x in 0..5 {
        for y in 0..5 {
            bits[x][y] = builder.bit_decompose_64(state[x][y]);
        }
    }

    // C[x] = XOR of all A[x,y] for y=0..4
    let mut c_bits = Vec::with_capacity(5);
    for x in 0..5 {
        let mut acc = bits[x][0].clone();
        for y in 1..5 {
            acc = builder.bit_xor(&acc, &bits[x][y]);
        }
        c_bits.push(acc);
    }

    // D[x] = C[x-1] XOR rot(C[x+1], 1)
    // 注意：x-1 和 x+1 mod 5
    let mut d_bits = Vec::with_capacity(5);
    for x in 0..5 {
        let c_minus1 = &c_bits[(x + 4) % 5]; // C[x-1]
        let c_plus1 = &c_bits[(x + 1) % 5]; // C[x+1]
        let rot_c_plus1 = builder.bit_rotr(c_plus1, 63); // rot right by 63 = rot left by 1
        let d = builder.bit_xor(c_minus1, &rot_c_plus1);
        d_bits.push(d);
    }

    // A'[x,y] = A[x,y] XOR D[x]
    let mut theta_result: [[Vec<usize>; 5]; 5] = Default::default();
    for x in 0..5 {
        for y in 0..5 {
            theta_result[x][y] = builder.bit_xor(&bits[x][y], &d_bits[x]);
        }
    }

    // ===== Step 2: Rho =====
    // A'[x,y] = rot(A[x,y], RHO[x][y])
    let mut rho_result: [[Vec<usize>; 5]; 5] = Default::default();
    for x in 0..5 {
        for y in 0..5 {
            rho_result[x][y] = builder.bit_rotr(&theta_result[x][y], 64 - RHO_OFFSETS[x][y]);
        }
    }

    // ===== Step 3: Pi =====
    // A'[y, (2*x + 3*y) % 5] = A[x, y]
    // 即：新状态 new[y][(2x+3y)%5] = old[x][y]
    let mut pi_result: [[Vec<usize>; 5]; 5] = Default::default();
    for x in 0..5 {
        for y in 0..5 {
            let new_x = y;
            let new_y = (2 * x + 3 * y) % 5;
            pi_result[new_x][new_y] = rho_result[x][y].clone();
        }
    }

    // ===== Step 4: Chi =====
    // A'[x,y] = A[x,y] XOR ((NOT A[x+1,y]) AND A[x+2,y])
    let mut chi_result: [[Vec<usize>; 5]; 5] = Default::default();
    for x in 0..5 {
        for y in 0..5 {
            let a = &pi_result[x][y];
            let b = &pi_result[(x + 1) % 5][y];
            let c = &pi_result[(x + 2) % 5][y];
            let not_b = builder.bit_not(b);
            let not_b_and_c = builder.bit_and(&not_b, c);
            chi_result[x][y] = builder.bit_xor(a, &not_b_and_c);
        }
    }

    // ===== Step 5: Iota =====
    // A'[0,0] = A[0,0] XOR RC[round]
    let rc = RC[round_idx];
    let mut rc_bits = Vec::with_capacity(64);
    for i in 0..64 {
        rc_bits.push(builder.alloc_u64((rc >> i) & 1));
    }
    let iota_00 = builder.bit_xor(&chi_result[0][0], &rc_bits);

    // 重组所有 lane 回 64-bit 变量
    let mut result = [[0usize; 5]; 5];
    for x in 0..5 {
        for y in 0..5 {
            if x == 0 && y == 0 {
                result[x][y] = builder.bit_recompose_64(&iota_00);
            } else {
                result[x][y] = builder.bit_recompose_64(&chi_result[x][y]);
            }
        }
    }

    result
}

// ===== Keccak256Circuit =====

/// Keccak-256 哈希预编译电路。
#[derive(Debug, Clone)]
pub struct Keccak256Circuit {
    full_mode: bool,
}

impl Keccak256Circuit {
    /// 创建 Full 模式电路（24 轮置换 + squeeze）。
    #[must_use]
    pub fn new() -> Self {
        Self { full_mode: true }
    }

    /// 创建 MVP 模式电路（单轮 Keccak-f[1600] 置换，用于快速测试）。
    #[must_use]
    pub fn new_mvp() -> Self {
        Self { full_mode: false }
    }

    /// 创建 Full 模式电路（24 轮置换 + squeeze）。
    #[must_use]
    pub fn new_full() -> Self {
        Self { full_mode: true }
    }

    /// 是否为 Full 模式。
    #[must_use]
    pub fn is_full_mode(&self) -> bool {
        self.full_mode
    }

    /// 运行 MVP 模式：单轮 Keccak-f[1600] 置换。
    ///
    /// # 输入
    /// `inputs[0..25]` — 25 个 64-bit lane 值（state[x][y] 的 flattened 表示）
    /// `inputs[25..50]` — 25 个 64-bit 输出 lane 值
    ///
    /// # 返回
    /// `(Ccs, witness)`
    fn run_mvp(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        if inputs.len() != 50 {
            return Err(ZkvmError::Other(format!(
                "Keccak256Circuit (MVP): inputs.len() {} != 50 (25 input lanes + 25 output lanes)",
                inputs.len()
            )));
        }

        let mut builder = KeccakBuilder::new();

        // 分配 25 个输入 lane 变量
        let mut state = [[0usize; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                state[x][y] = builder.alloc(inputs[x * 5 + y]);
            }
        }

        // 分配 25 个输出 lane 变量
        let mut output_vars = [[0usize; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                output_vars[x][y] = builder.alloc(inputs[25 + x * 5 + y]);
            }
        }

        // 执行单轮 Keccak-f[1600]
        let computed = keccak_round(&mut builder, &state, 0);

        // 约束：computed[x][y] == output_vars[x][y]
        for x in 0..5 {
            for y in 0..5 {
                let row = builder.ccs.alloc_row();
                builder.ccs.add_linear(
                    row,
                    &[
                        (computed[x][y], Fr::one()),
                        (output_vars[x][y], Fr::one().neg()),
                    ],
                );
            }
        }

        let witness = builder.witness.clone();
        let ccs = builder.build()?;
        Ok((ccs, witness))
    }

    /// 运行 Full 模式：24 轮 Keccak-f[1600] 置换 + squeeze。
    ///
    /// # 输入
    /// `inputs[0..25]` — 25 个初始 state lane（吸收+padding 后）
    /// `inputs[25..29]` — 4 个输出 hash lane（32 bytes）
    ///
    /// # 返回
    /// `(Ccs, witness)`
    fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        if inputs.len() != 29 {
            return Err(ZkvmError::Other(format!(
                "Keccak256Circuit (Full): inputs.len() {} != 29 (25 state lanes + 4 output lanes)",
                inputs.len()
            )));
        }

        let mut builder = KeccakBuilder::new();

        // 分配 25 个初始 state lane 变量
        let mut state = [[0usize; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                state[x][y] = builder.alloc(inputs[x * 5 + y]);
            }
        }

        // 分配 4 个输出 lane 变量
        let mut output_vars = [0usize; 4];
        for i in 0..4 {
            output_vars[i] = builder.alloc(inputs[25 + i]);
        }

        // 执行 24 轮 Keccak-f[1600]
        let mut current = state;
        for round in 0..24 {
            current = keccak_round(&mut builder, &current, round);
        }

        // Squeeze: output = state[0..4]（前 4 个 lane = 32 bytes）
        // 约束：current[i][0] == output_vars[i] for i=0..4
        // 注意：state 索引为 state[x][y]，squeeze 取 state[0][0], state[1][0], state[2][0], state[3][0]
        for i in 0..4 {
            let row = builder.ccs.alloc_row();
            builder.ccs.add_linear(
                row,
                &[
                    (current[i][0], Fr::one()),
                    (output_vars[i], Fr::one().neg()),
                ],
            );
        }

        let witness = builder.witness.clone();
        let ccs = builder.build()?;
        Ok((ccs, witness))
    }
}

impl Default for Keccak256Circuit {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileCircuit for Keccak256Circuit {
    fn name(&self) -> &str {
        "keccak256"
    }

    fn num_variables(&self) -> usize {
        if self.full_mode {
            FULL_MODE_NUM_VARS
        } else {
            let dummy = vec![Fr::zero(); 50];
            let (ccs, _) = self.run_mvp(&dummy).expect("dummy run_mvp should succeed");
            ccs.num_vars
        }
    }

    fn build_ccs(&self) -> Result<Ccs, ZkvmError> {
        let dummy = if self.full_mode {
            vec![Fr::zero(); 29]
        } else {
            vec![Fr::zero(); 50]
        };
        if self.full_mode {
            Ok(self.run_full(&dummy)
                .expect("dummy run_full should succeed")
                .0)
        } else {
            Ok(self.run_mvp(&dummy)
                .expect("dummy run_mvp should succeed")
                .0)
        }
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if self.full_mode {
            Ok(self.run_full(inputs)?.1)
        } else {
            Ok(self.run_mvp(inputs)?.1)
        }
    }

    fn gas_cost(&self) -> u64 {
        if self.full_mode {
            GAS_PER_ROUND * 24
        } else {
            GAS_PER_ROUND
        }
    }
}

impl CcsCircuit for Keccak256Circuit {
    fn name(&self) -> &str {
        "keccak256"
    }

    fn num_matrices(&self) -> usize {
        let dummy = if self.full_mode {
            vec![Fr::zero(); 29]
        } else {
            vec![Fr::zero(); 50]
        };
        let (ccs, _) = if self.full_mode {
            self.run_full(&dummy)
                .expect("dummy run_full should succeed")
        } else {
            self.run_mvp(&dummy).expect("dummy run_mvp should succeed")
        };
        ccs.num_matrices()
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

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Host 端 Keccak 实现 =====

    /// Host 端单轮 Keccak-f[1600]（用于测试向量生成）。
    fn host_keccak_round(state: &mut [[u64; 5]; 5], round_idx: usize) {
        // Theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            for y in 0..5 {
                c[x] ^= state[x][y];
            }
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_right(63);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x][y] ^= d[x];
            }
        }

        // Rho + Pi
        let mut new_state = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                let new_x = y;
                let new_y = (2 * x + 3 * y) % 5;
                new_state[new_x][new_y] = state[x][y].rotate_left(RHO_OFFSETS[x][y]);
            }
        }
        *state = new_state;

        // Chi
        let mut chi_state = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                chi_state[x][y] = state[x][y] ^ ((!state[(x + 1) % 5][y]) & state[(x + 2) % 5][y]);
            }
        }
        *state = chi_state;

        // Iota
        state[0][0] ^= RC[round_idx];
    }

    /// Host 端 24 轮 Keccak-f[1600] 置换。
    fn host_keccak_f1600(state: &mut [[u64; 5]; 5]) {
        for round in 0..24 {
            host_keccak_round(state, round);
        }
    }

    /// Host 端 keccak256 哈希（Keccak padding，rate=1088 bits）。
    fn host_keccak256(input: &[u8]) -> [u8; 32] {
        // 初始化状态
        let mut state = [[0u64; 5]; 5];

        // Padding: input || 0x01 || ... || 0x80
        // rate = 136 bytes
        let rate = RATE_BITS / 8; // 136
        let mut padded = input.to_vec();
        padded.push(0x01);
        while !padded.len().is_multiple_of(rate) {
            padded.push(0x00);
        }
        let last_idx = padded.len() - 1;
        padded[last_idx] |= 0x80;

        // Absorb
        for block_start in (0..padded.len()).step_by(rate) {
            // XOR block into state
            for lane_idx in 0..RATE_LANES {
                let offset = block_start + lane_idx * 8;
                let lane =
                    u64::from_le_bytes(padded[offset..offset + 8].try_into().expect("8 bytes"));
                let x = lane_idx % 5;
                let y = lane_idx / 5;
                state[x][y] ^= lane;
            }
            // Permute
            host_keccak_f1600(&mut state);
        }

        // Squeeze: first 32 bytes = 4 lanes
        let mut result = [0u8; 32];
        for lane_idx in 0..4 {
            let x = lane_idx % 5;
            let y = lane_idx / 5;
            let bytes = state[x][y].to_le_bytes();
            result[lane_idx * 8..(lane_idx + 1) * 8].copy_from_slice(&bytes);
        }
        result
    }

    /// 将 state 转为 Vec<Fr>（25 lanes）。
    fn state_to_fr_vec(state: &[[u64; 5]; 5]) -> Vec<Fr> {
        let mut v = Vec::with_capacity(25);
        for x in 0..5 {
            for y in 0..5 {
                v.push(Fr::from_u64(state[x][y]));
            }
        }
        v
    }

    /// 将 4 个 u64 lane 转为 Vec<Fr>。
    fn lanes_to_fr_vec(lanes: &[u64; 4]) -> Vec<Fr> {
        lanes.iter().map(|&l| Fr::from_u64(l)).collect()
    }

    // ===== 测试 =====

    #[test]
    fn test_keccak_mvp_single_round() {
        // 构造一个非零初始状态
        let mut state = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                state[x][y] = ((x + y * 5 + 1) as u64) * 0x100;
            }
        }

        // Host 计算单轮结果
        let mut host_state = state;
        host_keccak_round(&mut host_state, 0);

        // 构造电路输入: 25 input lanes + 25 output lanes
        let mut inputs = state_to_fr_vec(&state);
        inputs.extend(state_to_fr_vec(&host_state));

        let circuit = Keccak256Circuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness should succeed");

        assert!(
            ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed"),
            "单轮 Keccak-f[1600] 置换应满足约束"
        );
    }

    #[test]
    fn test_keccak_mvp_tampered_output() {
        let mut state = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                state[x][y] = ((x + y * 5 + 1) as u64) * 0x100;
            }
        }

        let mut host_state = state;
        host_keccak_round(&mut host_state, 0);
        // 篡改输出
        host_state[0][0] ^= 1;

        let mut inputs = state_to_fr_vec(&state);
        inputs.extend(state_to_fr_vec(&host_state));

        let circuit = Keccak256Circuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness should succeed");

        assert!(
            !ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed"),
            "篡改输出后应不满足约束"
        );
    }

    #[test]
    fn test_host_keccak256_empty() {
        let hash = host_keccak256(b"");
        let expected: [u8; 32] = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(hash, expected, "keccak256(\"\") 应匹配已知值");
    }

    #[test]
    fn test_host_keccak256_abc() {
        let hash = host_keccak256(b"abc");
        let expected: [u8; 32] = [
            0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8,
            0xd6, 0x67, 0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f,
            0xa1, 0x2d, 0x6c, 0x45,
        ];
        assert_eq!(hash, expected, "keccak256(\"abc\") 应匹配已知值");
    }

    #[test]
    fn test_keccak_gas_cost() {
        let mvp = Keccak256Circuit::new_mvp();
        assert_eq!(mvp.gas_cost(), 10_000);

        let full = Keccak256Circuit::new_full();
        assert_eq!(full.gas_cost(), 10_000 * 24);
    }

    #[test]
    fn test_keccak_wrong_input_length() {
        let mvp = Keccak256Circuit::new_mvp();
        let result = mvp.assign_witness(&[Fr::one()]);
        assert!(result.is_err());

        let full = Keccak256Circuit::new_full();
        let result = full.assign_witness(&[Fr::one()]);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "Full mode 24 轮约 192K 约束，需 release 模式手动运行"]
    fn test_keccak_full_empty_input() {
        // keccak256("") = 0xc5d246...
        // 构造 padded state
        let mut state = [[0u64; 5]; 5];
        // 空 input padding: 0x01 || ... || 0x80 (rate=136 bytes)
        // 第一个 byte = 0x01 | 0x80 = 0x81（因为空输入只有 1 byte padding）
        state[0][0] = 0x81;

        // Host 计算
        let expected = host_keccak256(b"");
        let expected_lanes: [u64; 4] = [
            u64::from_le_bytes(expected[0..8].try_into().unwrap()),
            u64::from_le_bytes(expected[8..16].try_into().unwrap()),
            u64::from_le_bytes(expected[16..24].try_into().unwrap()),
            u64::from_le_bytes(expected[24..32].try_into().unwrap()),
        ];

        // 构造电路输入: 25 state lanes + 4 output lanes
        let mut inputs = state_to_fr_vec(&state);
        inputs.extend(lanes_to_fr_vec(&expected_lanes));

        let circuit = Keccak256Circuit::new_full();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness should succeed");

        assert!(
            ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed"),
            "keccak256(\"\") 应满足约束"
        );
    }

    #[test]
    #[ignore = "Full mode 24 轮约 192K 约束，需 release 模式手动运行"]
    fn test_keccak_full_abc() {
        // keccak256("abc") = 0x4e0365...
        // "abc" = 3 bytes, padding: 0x61 0x62 0x63 0x01 ... 0x80 (rate=136 bytes)
        let mut padded = [0u8; 136];
        padded[0] = 0x61; // 'a'
        padded[1] = 0x62; // 'b'
        padded[2] = 0x63; // 'c'
        padded[3] = 0x01; // padding start
        padded[135] = 0x80; // padding end

        let mut state = [[0u64; 5]; 5];
        for lane_idx in 0..RATE_LANES {
            let offset = lane_idx * 8;
            let lane = u64::from_le_bytes(padded[offset..offset + 8].try_into().expect("8 bytes"));
            let x = lane_idx % 5;
            let y = lane_idx / 5;
            state[x][y] ^= lane;
        }

        let expected = host_keccak256(b"abc");
        let expected_lanes: [u64; 4] = [
            u64::from_le_bytes(expected[0..8].try_into().unwrap()),
            u64::from_le_bytes(expected[8..16].try_into().unwrap()),
            u64::from_le_bytes(expected[16..24].try_into().unwrap()),
            u64::from_le_bytes(expected[24..32].try_into().unwrap()),
        ];

        let mut inputs = state_to_fr_vec(&state);
        inputs.extend(lanes_to_fr_vec(&expected_lanes));

        let circuit = Keccak256Circuit::new_full();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness should succeed");

        assert!(
            ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed"),
            "keccak256(\"abc\") 应满足约束"
        );
    }
}
