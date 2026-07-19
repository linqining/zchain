//! Phase B.3 — 扑克牌型评估 v2 + 比较 E2E 测试。
//!
//! 验证 `build_poker_hand_eval_v2_elf` 与 `build_poker_hand_compare_elf` 在 zkvm 中的
//! 端到端行为，包括 prove/verify 完整流程 + 与 host 参考实现的一致性。

#![allow(dead_code)]

mod common;

use common::{
    build_poker_hand_compare_elf, build_poker_hand_eval_v2_elf, poker_hand_compare_expected,
    poker_hand_eval_v2_expected,
};
use poker_zkvm::ccs::Ccs;
use poker_zkvm::prover::{ProverConfig, ZkPublicIo, default_ccs_registry, prove};
use poker_zkvm::verifier::verify_production;

/// 辅助：对给定 ELF + input 执行 prove + verify，返回 (proof_bytes, public_io)。
fn prove_and_verify(elf: &[u8], input: &[u8]) -> (Vec<u8>, ZkPublicIo) {
    let config = ProverConfig::default();
    let (proof, public_io) = prove(elf, input, &config).expect("prove 失败");
    let registry: Vec<Ccs> = default_ccs_registry();
    let ok = verify_production(&proof, &public_io, &registry).expect("verify_production 失败");
    assert!(ok, "verify_production 应返回 true");
    (proof, public_io)
}

/// 辅助：从 public_io.output 提取小端 u32 评分。
fn extract_score(public_io: &ZkPublicIo) -> u32 {
    assert_eq!(public_io.output.len(), 4, "eval 输出应为 4 字节");
    u32::from_le_bytes([
        public_io.output[0],
        public_io.output[1],
        public_io.output[2],
        public_io.output[3],
    ])
}

// === 4 个 eval 测试 ===

#[test]
fn eval_v2_straight() {
    // [2,3,4,5,6] → 顺子（category=5, max=6）→ 0x0605
    let cards: [u8; 5] = [2, 3, 4, 5, 6];
    let elf = build_poker_hand_eval_v2_elf();
    let (_, public_io) = prove_and_verify(&elf, &cards);
    let score = extract_score(&public_io);
    assert_eq!(score, poker_hand_eval_v2_expected(&cards));
    assert_eq!(score, 0x0605);
}

#[test]
fn eval_v2_trips() {
    // [10,10,10,7,8] → 三条（pair_count=3, category=4, max=10）→ 0x0A04
    let cards: [u8; 5] = [10, 10, 10, 7, 8];
    let elf = build_poker_hand_eval_v2_elf();
    let (_, public_io) = prove_and_verify(&elf, &cards);
    let score = extract_score(&public_io);
    assert_eq!(score, poker_hand_eval_v2_expected(&cards));
    assert_eq!(score, 0x0A04);
}

#[test]
fn eval_v2_pair() {
    // [5,5,9,7,8] → 一对（pair_count=1, category=2, max=9）→ 0x0902
    let cards: [u8; 5] = [5, 5, 9, 7, 8];
    let elf = build_poker_hand_eval_v2_elf();
    let (_, public_io) = prove_and_verify(&elf, &cards);
    let score = extract_score(&public_io);
    assert_eq!(score, poker_hand_eval_v2_expected(&cards));
    assert_eq!(score, 0x0902);
}

#[test]
fn eval_v2_highcard() {
    // [2,5,9,11,7] → 高牌（category=0, max=11）→ 0x0B00
    let cards: [u8; 5] = [2, 5, 9, 11, 7];
    let elf = build_poker_hand_eval_v2_elf();
    let (_, public_io) = prove_and_verify(&elf, &cards);
    let score = extract_score(&public_io);
    assert_eq!(score, poker_hand_eval_v2_expected(&cards));
    assert_eq!(score, 0x0B00);
}

// === 3 个 compare 测试 ===

#[test]
fn compare_p1_wins() {
    // s1=0x0A04 (三条) > s2=0x0605 (顺子) — 按数值比较，P1 胜
    // 注意：本评分简化版只比较 u32 数值，不严格遵循扑克标准规则
    let s1: u32 = 0x0A04;
    let s2: u32 = 0x0605;
    let input: Vec<u8> = s1
        .to_le_bytes()
        .iter()
        .chain(s2.to_le_bytes().iter())
        .copied()
        .collect();
    let elf = build_poker_hand_compare_elf();
    let (_, public_io) = prove_and_verify(&elf, &input);
    assert_eq!(public_io.output.len(), 1);
    assert_eq!(public_io.output[0], poker_hand_compare_expected(s1, s2));
    assert_eq!(public_io.output[0], 1, "P1 应胜（s1=0x0A04 > s2=0x0605）");
}

#[test]
fn compare_p2_wins() {
    let s1: u32 = 0x0605;
    let s2: u32 = 0x0A04;
    let input: Vec<u8> = s1
        .to_le_bytes()
        .iter()
        .chain(s2.to_le_bytes().iter())
        .copied()
        .collect();
    let elf = build_poker_hand_compare_elf();
    let (_, public_io) = prove_and_verify(&elf, &input);
    assert_eq!(public_io.output[0], poker_hand_compare_expected(s1, s2));
    assert_eq!(public_io.output[0], 2, "P2 应胜");
}

#[test]
fn compare_tie() {
    let s1: u32 = 0x0605;
    let s2: u32 = 0x0605;
    let input: Vec<u8> = s1
        .to_le_bytes()
        .iter()
        .chain(s2.to_le_bytes().iter())
        .copied()
        .collect();
    let elf = build_poker_hand_compare_elf();
    let (_, public_io) = prove_and_verify(&elf, &input);
    assert_eq!(public_io.output[0], poker_hand_compare_expected(s1, s2));
    assert_eq!(public_io.output[0], 0, "应平局");
}

// === 2 个 full_pipeline 测试 ===

#[test]
fn full_pipeline_straight_vs_trips() {
    // P1=[2,3,4,5,6] (顺子, 0x0605) vs P2=[10,10,10,7,8] (三条, 0x0A04)
    // 简化评分：0x0A04 > 0x0605，P2 胜
    let p1: [u8; 5] = [2, 3, 4, 5, 6];
    let p2: [u8; 5] = [10, 10, 10, 7, 8];
    let elf_eval = build_poker_hand_eval_v2_elf();
    let (_, io1) = prove_and_verify(&elf_eval, &p1);
    let (_, io2) = prove_and_verify(&elf_eval, &p2);
    let s1 = extract_score(&io1);
    let s2 = extract_score(&io2);
    let cmp_input: Vec<u8> = s1
        .to_le_bytes()
        .iter()
        .chain(s2.to_le_bytes().iter())
        .copied()
        .collect();
    let elf_cmp = build_poker_hand_compare_elf();
    let (_, io_cmp) = prove_and_verify(&elf_cmp, &cmp_input);
    let winner = io_cmp.output[0];
    assert_eq!(winner, poker_hand_compare_expected(s1, s2));
    assert_eq!(winner, 2, "P2 应胜（0x0A04 > 0x0605）");
}

#[test]
fn full_pipeline_quads_simplified_vs_straight() {
    // P1=[5,5,5,5,7] (四条简化为 trips, pair_count=6, category=4, max=7 → 0x0704)
    //   注意：5 出现 4 次 → C(4,2)=6 对，pair_count=6 >= 3 → category=4
    // P2=[2,3,4,5,6] (顺子, 0x0605)
    // 比较：0x0704 > 0x0605，P1 胜
    let p1: [u8; 5] = [5, 5, 5, 5, 7];
    let p2: [u8; 5] = [2, 3, 4, 5, 6];
    let elf_eval = build_poker_hand_eval_v2_elf();
    let (_, io1) = prove_and_verify(&elf_eval, &p1);
    let (_, io2) = prove_and_verify(&elf_eval, &p2);
    let s1 = extract_score(&io1);
    let s2 = extract_score(&io2);
    assert_eq!(s1, 0x0704, "P1 评分应为 0x0704");
    assert_eq!(s2, 0x0605, "P2 评分应为 0x0605");
    let cmp_input: Vec<u8> = s1
        .to_le_bytes()
        .iter()
        .chain(s2.to_le_bytes().iter())
        .copied()
        .collect();
    let elf_cmp = build_poker_hand_compare_elf();
    let (_, io_cmp) = prove_and_verify(&elf_cmp, &cmp_input);
    let winner = io_cmp.output[0];
    assert_eq!(winner, 1, "P1 应胜（0x0704 > 0x0605）");
}