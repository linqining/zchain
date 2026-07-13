//! Phase 12 端到端集成测试 — 扑克牌型评估电路（简化版）。
//!
//! 测试流程：构建 ELF → prove() → verify_production() → 验证输出 → proof 大小检查
//!
//! # 电路说明
//!
//! 读取 5 张牌（5 字节输入，每字节为面值 1-13），计算面值之和，输出 4 字节 u32。
//! 注意：使用 LB（符号扩展）加载，面值须 ≤ 127 以避免负数。

mod common;

use common::build_poker_hand_eval_elf;
use poker_zkvm::prover::{MAX_PROOF_TOTAL_SIZE, ProverConfig, default_ccs_whitelist, prove};
use poker_zkvm::verifier::verify_production;

/// 构造扑克牌型评估 prove 配置。
fn poker_config() -> ProverConfig {
    ProverConfig {
        batch_size: 3,
        proof_size_limit: MAX_PROOF_TOTAL_SIZE,
        ..Default::default()
    }
}

/// 验证扑克牌型评估的完整 prove→verify 流程。
fn run_poker_hand_eval_e2e(cards: &[u8; 5]) {
    assert!(
        cards.iter().all(|&c| c <= 127),
        "面值须 ≤ 127（LB 符号扩展限制）"
    );
    let elf = build_poker_hand_eval_elf();
    let config = poker_config();

    // 1. prove
    let (proof_bytes, public_io) =
        prove(&elf, cards, &config).unwrap_or_else(|e| panic!("prove 失败: {e:?}"));

    // 2. verify
    let ccs_whitelist = default_ccs_whitelist();
    let ok = verify_production(&proof_bytes, &public_io, &ccs_whitelist)
        .unwrap_or_else(|e| panic!("verify_production 错误: {e:?}"));
    assert!(ok, "verify_production 应返回 true");

    // 3. 输出正确性
    assert_eq!(public_io.output.len(), 4, "输出应为 4 字节（u32）");
    let got = u32::from_le_bytes(public_io.output[..4].try_into().expect("输出至少 4 字节"));
    // 由于 LB 符号扩展，面值 1-13（< 128）保持不变
    let expected: u32 = cards.iter().map(|&c| c as u32).sum();
    assert_eq!(
        got, expected,
        "扑克牌面值之和不符: got={got}, expected={expected}, cards={cards:?}"
    );

    // 4. proof 大小检查（MVP 阶段 CycleFold 未实现，放宽到 MAX_PROOF_TOTAL_SIZE）
    assert!(
        proof_bytes.len() <= MAX_PROOF_TOTAL_SIZE,
        "proof 超 M2-002 总长度上限: {} > {MAX_PROOF_TOTAL_SIZE}",
        proof_bytes.len()
    );
}

#[test]
fn test_poker_hand_eval_aces() {
    // 4 张 A (1) + 1 张 A → 和 = 5
    run_poker_hand_eval_e2e(&[1, 1, 1, 1, 1]);
}

#[test]
fn test_poker_hand_eval_mixed() {
    // A, 2, 3, 4, 5 → 和 = 15
    run_poker_hand_eval_e2e(&[1, 2, 3, 4, 5]);
}

#[test]
fn test_poker_hand_eval_high_cards() {
    // 10, J(11), Q(12), K(13), A(1) → 和 = 47
    run_poker_hand_eval_e2e(&[10, 11, 12, 13, 1]);
}

#[test]
fn test_poker_hand_eval_all_kings() {
    // 5 张 K (13) → 和 = 65
    run_poker_hand_eval_e2e(&[13, 13, 13, 13, 13]);
}

#[test]
fn test_poker_hand_eval_max_safe_value() {
    // 5 张 127（LB 符号扩展边界值）→ 和 = 635
    run_poker_hand_eval_e2e(&[127, 127, 127, 127, 127]);
}
