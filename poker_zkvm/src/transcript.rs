//! Fiat-Shamir transcript（Phase 1 — Task 1.2）。
//!
//! 严格遵循 spec.md L27-30（v1.4 FROZEN）：
//! - 基于 `Blake2bVar` 的 sponge-like 构造
//! - `absorb(domain_tag, data)` — 格式 `domain_tag || len_le(data) || data`
//! - `challenge(domain_tag) -> Bn254ScalarField` — 派生新 challenge，更新内部状态
//! - length-prefixing（4 bytes LE，防 concatenation ambiguity）
//! - canonical 编码：域元素 32 bytes LE
//! - 域分离常量：FOLD=0x10 / SUMCHECK=0x11 / LOOKUP=0x12 / MEM_CHECK=0x13 / PCS_OPEN=0x14

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::error::ZkvmError;
use crate::field::{Bn254ScalarField, ZkvmField};

/// Hypernova fold 阶段域分离标签（spec L29）。
pub const HYPERNOVA_FOLD_DOMAIN_TAG: u8 = 0x10;

/// Sumcheck 阶段域分离标签（spec L29）。
pub const SUMCHECK_DOMAIN_TAG: u8 = 0x11;

/// Lookup（LogUp）阶段域分离标签（spec L29）。
pub const LOOKUP_DOMAIN_TAG: u8 = 0x12;

/// 内存一致性校验阶段域分离标签（spec L29）。
pub const MEM_CHECK_DOMAIN_TAG: u8 = 0x13;

/// PCS opening 阶段域分离标签（spec L29）。
pub const PCS_OPEN_DOMAIN_TAG: u8 = 0x14;

/// Transcript 内部 Blake2b 输出大小（32 bytes = 256 bits）。
const TRANSCRIPT_OUTPUT_SIZE: usize = 32;

/// Fiat-Shamir transcript（spec L27-30）。
///
/// 基于 `Blake2bVar` 的 sponge-like 构造：
/// - `absorb` 更新内部 hasher 状态
/// - `challenge` 克隆当前状态 + 追加 domain_tag + counter，finalize 得到 32 bytes，
///   然后将输出 absorb 回主状态（使后续 challenge 依赖于前一个 challenge）
///
/// # 防歧义设计
///
/// - **length-prefixing**：每个 absorb 的 data 前加 4 bytes LE 长度，防 `"ab"+"c"` vs `"a"+"bc"` 碰撞
/// - **domain separation**：每个 absorb/challenge 带 domain_tag，防跨阶段重放
/// - **counter**：同 domain_tag 的多次 challenge 用 counter 区分
#[derive(Clone)]
pub struct Transcript {
    /// 内部 Blake2b hasher 状态（streaming absorb）。
    state: Blake2bVar,
    /// challenge 调用计数器（防同 domain_tag 多次 challenge 碰撞）。
    counter: u64,
}

impl std::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transcript")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    /// 创建新 transcript（初始状态为空）。
    pub fn new() -> Self {
        Self {
            state: Blake2bVar::new(TRANSCRIPT_OUTPUT_SIZE)
                .expect("Blake2bVar(32) 初始化不应失败"),
            counter: 0,
        }
    }

    /// 创建带初始 domain separation tag 的 transcript。
    ///
    /// 用于协议级别的 domain separation（如 `b"hypernova_v1.4"`）。
    pub fn with_domain(domain: &[u8]) -> Self {
        let mut t = Self::new();
        t.absorb_raw(domain);
        t
    }

    /// 吸收任意字节（无 domain tag，内部使用）。
    fn absorb_raw(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// 吸收字节数据（spec L28 — length-prefixing）。
    ///
    /// 格式：`domain_tag || len_le(data) || data`
    /// - `domain_tag`：1 byte 域分离标签
    /// - `len_le(data)`：4 bytes LE 长度前缀
    /// - `data`：实际数据
    ///
    /// length-prefixing 防 concatenation ambiguity：
    /// `absorb(t, "ab"); absorb(t, "c")` ≠ `absorb(t, "a"); absorb(t, "bc")`
    pub fn absorb(&mut self, domain_tag: u8, data: &[u8]) {
        // domain_tag (1 byte)
        self.state.update(&[domain_tag]);
        // length prefix (4 bytes LE)
        let len = data.len() as u32;
        self.state.update(&len.to_le_bytes());
        // data
        self.state.update(data);
    }

    /// 吸收域元素（canonical 32 bytes LE 编码）。
    pub fn absorb_field(&mut self, domain_tag: u8, elem: &Bn254ScalarField) {
        let bytes = elem.to_canonical_bytes();
        self.absorb(domain_tag, &bytes);
    }

    /// 吸收域元素切片。
    pub fn absorb_field_slice(&mut self, domain_tag: u8, elems: &[Bn254ScalarField]) {
        // 先吸收长度
        let len = elems.len() as u32;
        self.state.update(&[domain_tag]);
        self.state.update(&len.to_le_bytes());
        // 再吸收每个元素（连续，无额外前缀）
        for elem in elems {
            let bytes = elem.to_canonical_bytes();
            self.state.update(&bytes);
        }
    }

    /// 派生新 challenge（spec L28）。
    ///
    /// 步骤：
    /// 1. 克隆当前 hasher 状态
    /// 2. 追加 `domain_tag || counter_le`
    /// 3. finalize 得到 32 bytes
    /// 4. counter += 1
    /// 5. 将 32 bytes absorb 回主状态（使后续 challenge 依赖此 challenge）
    /// 6. 将 32 bytes 转为域元素返回
    ///
    /// # 返回
    /// 32 bytes Blake2b 输出经 `from_le_bytes_mod_order` 转为 `Bn254ScalarField`。
    pub fn challenge(&mut self, domain_tag: u8) -> Bn254ScalarField {
        // 克隆状态用于 finalize（不消耗主状态）
        let mut clone = self.state.clone();
        clone.update(&[domain_tag]);
        clone.update(&self.counter.to_le_bytes());

        let mut out = [0u8; TRANSCRIPT_OUTPUT_SIZE];
        clone
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");

        // counter 递增
        self.counter += 1;

        // 将 challenge 输出 absorb 回主状态
        self.state.update(&out);

        // 转为域元素（from_le_bytes_mod_order 总是成功，因 mod p 后必在 [0, p)）
        Bn254ScalarField::from_canonical_bytes(&out[..])
            .expect("32 bytes Blake2b 输出应能转为域元素")
    }

    /// 派生多个 challenge（批量，用不同 counter 值）。
    pub fn challenge_vec(&mut self, domain_tag: u8, count: usize) -> Vec<Bn254ScalarField> {
        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            result.push(self.challenge(domain_tag));
        }
        result
    }

    /// 获取当前 counter 值（用于测试 / 调试）。
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

/// 从 32 bytes 派生域元素（内部工具）。
///
/// 公开给其他模块使用（如 PCS 需要从 commitment bytes 派生 challenge）。
pub fn bytes_to_field(bytes: &[u8]) -> Result<Bn254ScalarField, ZkvmError> {
    Bn254ScalarField::from_canonical_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== 基础确定性测试 =====

    #[test]
    fn test_transcript_deterministic() {
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        t1.absorb(SUMCHECK_DOMAIN_TAG, b"hello");
        t2.absorb(SUMCHECK_DOMAIN_TAG, b"hello");

        let c1 = t1.challenge(SUMCHECK_DOMAIN_TAG);
        let c2 = t2.challenge(SUMCHECK_DOMAIN_TAG);
        assert_eq!(c1, c2, "相同 absorb 序列应产生相同 challenge");
    }

    #[test]
    fn test_transcript_different_input() {
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        t1.absorb(SUMCHECK_DOMAIN_TAG, b"hello");
        t2.absorb(SUMCHECK_DOMAIN_TAG, b"world");

        let c1 = t1.challenge(SUMCHECK_DOMAIN_TAG);
        let c2 = t2.challenge(SUMCHECK_DOMAIN_TAG);
        assert_ne!(c1, c2, "不同 absorb 应产生不同 challenge");
    }

    // ===== length-prefix 防歧义测试（spec L28 关键安全特性）=====

    /// `"ab"+"c"` vs `"a"+"bc"` 必须产生不同 challenge（防 concatenation ambiguity）。
    #[test]
    fn test_length_prefix_disambiguation() {
        let mut t1 = Transcript::new();
        t1.absorb(SUMCHECK_DOMAIN_TAG, b"ab");
        t1.absorb(SUMCHECK_DOMAIN_TAG, b"c");
        let c1 = t1.challenge(SUMCHECK_DOMAIN_TAG);

        let mut t2 = Transcript::new();
        t2.absorb(SUMCHECK_DOMAIN_TAG, b"a");
        t2.absorb(SUMCHECK_DOMAIN_TAG, b"bc");
        let c2 = t2.challenge(SUMCHECK_DOMAIN_TAG);

        assert_ne!(
            c1, c2,
            "length-prefix 应使 \"ab\"+\"c\" ≠ \"a\"+\"bc\""
        );
    }

    /// 空字节 + 非空 vs 非空 + 空字节 也应不同。
    #[test]
    fn test_length_prefix_empty_vs_nonempty() {
        let mut t1 = Transcript::new();
        t1.absorb(SUMCHECK_DOMAIN_TAG, b"");
        t1.absorb(SUMCHECK_DOMAIN_TAG, b"x");
        let c1 = t1.challenge(SUMCHECK_DOMAIN_TAG);

        let mut t2 = Transcript::new();
        t2.absorb(SUMCHECK_DOMAIN_TAG, b"x");
        t2.absorb(SUMCHECK_DOMAIN_TAG, b"");
        let c2 = t2.challenge(SUMCHECK_DOMAIN_TAG);

        assert_ne!(c1, c2, "空+非空 ≠ 非空+空");
    }

    // ===== 域分离测试 =====

    #[test]
    fn test_domain_separation() {
        let mut t1 = Transcript::new();
        t1.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, b"data");
        let c1 = t1.challenge(HYPERNOVA_FOLD_DOMAIN_TAG);

        let mut t2 = Transcript::new();
        t2.absorb(SUMCHECK_DOMAIN_TAG, b"data");
        let c2 = t2.challenge(SUMCHECK_DOMAIN_TAG);

        assert_ne!(
            c1, c2,
            "不同 domain tag 应产生不同 challenge（即使数据相同）"
        );
    }

    #[test]
    fn test_challenge_domain_tag_differs() {
        let mut t = Transcript::new();
        t.absorb(SUMCHECK_DOMAIN_TAG, b"seed");

        let c1 = t.challenge(HYPERNOVA_FOLD_DOMAIN_TAG);
        let c2 = t.challenge(SUMCHECK_DOMAIN_TAG);

        assert_ne!(c1, c2, "challenge 的 domain tag 不同应产生不同结果");
    }

    // ===== 连续 challenge 测试 =====

    #[test]
    fn test_consecutive_challenges_differ() {
        let mut t = Transcript::new();
        t.absorb(SUMCHECK_DOMAIN_TAG, b"seed");

        let c1 = t.challenge(SUMCHECK_DOMAIN_TAG);
        let c2 = t.challenge(SUMCHECK_DOMAIN_TAG);
        let c3 = t.challenge(SUMCHECK_DOMAIN_TAG);

        assert_ne!(c1, c2, "连续 challenge 应不同（counter 区分）");
        assert_ne!(c2, c3, "连续 challenge 应不同（counter 区分）");
        assert_ne!(c1, c3, "连续 challenge 应不同（counter 区分）");
    }

    #[test]
    fn test_counter_progression() {
        let mut t = Transcript::new();
        assert_eq!(t.counter(), 0);
        t.challenge(SUMCHECK_DOMAIN_TAG);
        assert_eq!(t.counter(), 1);
        t.challenge(SUMCHECK_DOMAIN_TAG);
        assert_eq!(t.counter(), 2);
    }

    // ===== challenge 回写状态测试 =====

    /// challenge 后状态更新，使后续 absorb 受 challenge 影响。
    #[test]
    fn test_challenge_updates_state() {
        let mut t1 = Transcript::new();
        t1.absorb(SUMCHECK_DOMAIN_TAG, b"seed");
        let _c1 = t1.challenge(SUMCHECK_DOMAIN_TAG);
        t1.absorb(SUMCHECK_DOMAIN_TAG, b"more");
        let final_c1 = t1.challenge(SUMCHECK_DOMAIN_TAG);

        // 如果 challenge 不回写状态，则 challenge + absorb "more" 应等价于直接 absorb "more"
        let mut t2 = Transcript::new();
        t2.absorb(SUMCHECK_DOMAIN_TAG, b"seed");
        t2.absorb(SUMCHECK_DOMAIN_TAG, b"more");
        let final_c2 = t2.challenge(SUMCHECK_DOMAIN_TAG);

        assert_ne!(
            final_c1, final_c2,
            "challenge 应回写状态，使后续 absorb 受影响"
        );
    }

    // ===== absorb_field 测试 =====

    #[test]
    fn test_absorb_field() {
        let f1 = Bn254ScalarField::from_u32_with_wrap(42);
        let f2 = Bn254ScalarField::from_u32_with_wrap(42);

        let mut t1 = Transcript::new();
        t1.absorb_field(SUMCHECK_DOMAIN_TAG, &f1);

        let mut t2 = Transcript::new();
        t2.absorb_field(SUMCHECK_DOMAIN_TAG, &f2);

        assert_eq!(
            t1.challenge(SUMCHECK_DOMAIN_TAG),
            t2.challenge(SUMCHECK_DOMAIN_TAG),
            "相同域元素应产生相同 challenge"
        );
    }

    #[test]
    fn test_absorb_field_different() {
        let f1 = Bn254ScalarField::from_u32_with_wrap(42);
        let f2 = Bn254ScalarField::from_u32_with_wrap(43);

        let mut t1 = Transcript::new();
        t1.absorb_field(SUMCHECK_DOMAIN_TAG, &f1);

        let mut t2 = Transcript::new();
        t2.absorb_field(SUMCHECK_DOMAIN_TAG, &f2);

        assert_ne!(
            t1.challenge(SUMCHECK_DOMAIN_TAG),
            t2.challenge(SUMCHECK_DOMAIN_TAG),
            "不同域元素应产生不同 challenge"
        );
    }

    #[test]
    fn test_absorb_field_slice() {
        let elems1 = vec![
            Bn254ScalarField::from_u32_with_wrap(1),
            Bn254ScalarField::from_u32_with_wrap(2),
            Bn254ScalarField::from_u32_with_wrap(3),
        ];
        let elems2 = elems1.clone();

        let mut t1 = Transcript::new();
        t1.absorb_field_slice(SUMCHECK_DOMAIN_TAG, &elems1);

        let mut t2 = Transcript::new();
        t2.absorb_field_slice(SUMCHECK_DOMAIN_TAG, &elems2);

        assert_eq!(
            t1.challenge(SUMCHECK_DOMAIN_TAG),
            t2.challenge(SUMCHECK_DOMAIN_TAG),
            "相同域元素切片应产生相同 challenge"
        );
    }

    #[test]
    fn test_absorb_field_slice_different_length() {
        let elems1 = vec![
            Bn254ScalarField::from_u32_with_wrap(1),
            Bn254ScalarField::from_u32_with_wrap(2),
        ];
        let elems2 = vec![
            Bn254ScalarField::from_u32_with_wrap(1),
            Bn254ScalarField::from_u32_with_wrap(2),
            Bn254ScalarField::from_u32_with_wrap(3),
        ];

        let mut t1 = Transcript::new();
        t1.absorb_field_slice(SUMCHECK_DOMAIN_TAG, &elems1);

        let mut t2 = Transcript::new();
        t2.absorb_field_slice(SUMCHECK_DOMAIN_TAG, &elems2);

        assert_ne!(
            t1.challenge(SUMCHECK_DOMAIN_TAG),
            t2.challenge(SUMCHECK_DOMAIN_TAG),
            "不同长度的域元素切片应产生不同 challenge"
        );
    }

    // ===== with_domain 测试 =====

    #[test]
    fn test_with_domain() {
        let mut t1 = Transcript::with_domain(b"hypernova_v1.4");
        let mut t2 = Transcript::with_domain(b"hypernova_v1.4");
        t1.absorb(SUMCHECK_DOMAIN_TAG, b"data");
        t2.absorb(SUMCHECK_DOMAIN_TAG, b"data");
        assert_eq!(
            t1.challenge(SUMCHECK_DOMAIN_TAG),
            t2.challenge(SUMCHECK_DOMAIN_TAG)
        );

        let mut t3 = Transcript::with_domain(b"spartan_v1.0");
        t3.absorb(SUMCHECK_DOMAIN_TAG, b"data");
        assert_ne!(
            t1.challenge(SUMCHECK_DOMAIN_TAG),
            t3.challenge(SUMCHECK_DOMAIN_TAG),
            "不同 protocol domain 应产生不同 challenge"
        );
    }

    // ===== challenge_vec 测试 =====

    #[test]
    fn test_challenge_vec() {
        let mut t = Transcript::new();
        t.absorb(SUMCHECK_DOMAIN_TAG, b"seed");
        let challenges = t.challenge_vec(SUMCHECK_DOMAIN_TAG, 5);
        assert_eq!(challenges.len(), 5);

        // 所有的 challenge 应不同
        for i in 0..5 {
            for j in (i + 1)..5 {
                assert_ne!(challenges[i], challenges[j], "challenge[{i}] != challenge[{j}]");
            }
        }
    }

    // ===== Clone 测试 =====

    #[test]
    fn test_clone_preserves_state() {
        let mut t1 = Transcript::new();
        t1.absorb(SUMCHECK_DOMAIN_TAG, b"seed");
        let mut t2 = t1.clone();

        let c1 = t1.challenge(SUMCHECK_DOMAIN_TAG);
        let c2 = t2.challenge(SUMCHECK_DOMAIN_TAG);
        assert_eq!(c1, c2, "clone 应保持状态一致");
    }

    // ===== 域标签常量测试 =====

    #[test]
    fn test_domain_tag_constants() {
        assert_eq!(HYPERNOVA_FOLD_DOMAIN_TAG, 0x10);
        assert_eq!(SUMCHECK_DOMAIN_TAG, 0x11);
        assert_eq!(LOOKUP_DOMAIN_TAG, 0x12);
        assert_eq!(MEM_CHECK_DOMAIN_TAG, 0x13);
        assert_eq!(PCS_OPEN_DOMAIN_TAG, 0x14);

        // 确保所有标签互不相同
        let tags = [
            HYPERNOVA_FOLD_DOMAIN_TAG,
            SUMCHECK_DOMAIN_TAG,
            LOOKUP_DOMAIN_TAG,
            MEM_CHECK_DOMAIN_TAG,
            PCS_OPEN_DOMAIN_TAG,
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "域标签必须互不相同");
            }
        }
    }

    // ===== bytes_to_field 工具函数测试 =====

    #[test]
    fn test_bytes_to_field() {
        let bytes = [0u8; 32];
        let f = bytes_to_field(&bytes).expect("全零 bytes 应转为 zero");
        assert!(f.is_zero());

        let bytes = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let f = bytes_to_field(&bytes).expect("应成功");
        assert_eq!(f, Bn254ScalarField::one());
    }

    #[test]
    fn test_bytes_to_field_wrong_length() {
        let bytes = [0u8; 16];
        assert!(bytes_to_field(&bytes).is_err());
    }

    // ===== proptest =====

    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// 相同输入序列 → 相同 challenge（确定性）
            #[test]
            fn prop_deterministic(data: Vec<u8>) {
                let mut t1 = Transcript::new();
                let mut t2 = Transcript::new();
                t1.absorb(SUMCHECK_DOMAIN_TAG, &data);
                t2.absorb(SUMCHECK_DOMAIN_TAG, &data);
                prop_assert_eq!(
                    t1.challenge(SUMCHECK_DOMAIN_TAG),
                    t2.challenge(SUMCHECK_DOMAIN_TAG)
                );
            }

            /// 不同输入 → 不同 challenge（w.h.p.）
            #[test]
            fn prop_different_input(a: Vec<u8>, b: Vec<u8>) {
                if a != b {
                    let mut t1 = Transcript::new();
                    t1.absorb(SUMCHECK_DOMAIN_TAG, &a);
                    let c1 = t1.challenge(SUMCHECK_DOMAIN_TAG);

                    let mut t2 = Transcript::new();
                    t2.absorb(SUMCHECK_DOMAIN_TAG, &b);
                    let c2 = t2.challenge(SUMCHECK_DOMAIN_TAG);

                    prop_assert_ne!(c1, c2);
                }
            }

            /// length-prefix 防歧义：任意 a,b,c,d 使 ab≠cd 时 challenge 不同
            #[test]
            fn prop_length_prefix(a: Vec<u8>, b: Vec<u8>) {
                // absorb(a); absorb(b) vs absorb(a+b)
                let mut t1 = Transcript::new();
                t1.absorb(SUMCHECK_DOMAIN_TAG, &a);
                t1.absorb(SUMCHECK_DOMAIN_TAG, &b);
                let c1 = t1.challenge(SUMCHECK_DOMAIN_TAG);

                let mut t2 = Transcript::new();
                let mut combined = a.clone();
                combined.extend_from_slice(&b);
                t2.absorb(SUMCHECK_DOMAIN_TAG, &combined);
                let c2 = t2.challenge(SUMCHECK_DOMAIN_TAG);

                // 除非 b 为空且 a 为空（此时 ab == a+b）
                if !a.is_empty() && !b.is_empty() {
                    prop_assert_ne!(c1, c2, "length-prefix 应区分 absorb(a)+absorb(b) 与 absorb(a+b)");
                }
            }

            /// 域元素 absorb 确定性
            #[test]
            fn prop_field_absorb_deterministic(v: u32) {
                let f = Bn254ScalarField::from_u32_with_wrap(v);
                let mut t1 = Transcript::new();
                let mut t2 = Transcript::new();
                t1.absorb_field(SUMCHECK_DOMAIN_TAG, &f);
                t2.absorb_field(SUMCHECK_DOMAIN_TAG, &f);
                prop_assert_eq!(
                    t1.challenge(SUMCHECK_DOMAIN_TAG),
                    t2.challenge(SUMCHECK_DOMAIN_TAG)
                );
            }
        }
    }
}
