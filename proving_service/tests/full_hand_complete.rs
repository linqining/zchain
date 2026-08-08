//! FullHandRunner 性能报告测试。
//!
//! 验证 `--full-hand` 模式：完整牌局序列驱动 + 每步计时。
//!
//! 回归完整 heads-up 对局：每个真实 dispatch 都必须经过 Texas AIR prove + host verify。

use proving_service::full_hand::FullHandRunner;

/// 完整牌局（create/join×2/start/shuffle×2/reveal/四轮下注/showdown）必须
/// prove+verify 成功，并在每个 seat 一次批量提交的最后一个 showdown reveal 中完成结算与 reset。
#[test]
fn full_hand_proves_complete_game() {
    let (plugin, report) = FullHandRunner::new().run();

    assert!(
        report.stopped_at.is_none(),
        "完整牌局不应提前停止: {report:?}"
    );
    let ok_count = report.steps.iter().filter(|s| s.ok).count();
    assert_eq!(ok_count, 25, "24 个 dispatch 和最终 tagged batch 都应成功");
    assert_eq!(
        report.steps.len(),
        25,
        "完整牌局应产生 24 个 dispatch 记录和 1 个 tagged batch 记录，实际 {}",
        report.steps.len()
    );
    assert_eq!(
        report.stats.chain_length, 24,
        "完整 receipt 链应有 24 个真实 dispatch，实际 {}",
        report.stats.chain_length
    );

    let names: Vec<&str> = report.steps.iter().map(|s| s.method.as_str()).collect();
    assert!(
        names.iter().any(|n| n.contains("reveal_showdown[1]")),
        "缺最后一个 showdown reveal"
    );
    assert!(
        report
            .steps
            .iter()
            .any(|step| step.method == "submit_shuffle_v2[seat1]" && step.ok),
        "终结洗牌者必须完成 prove+verify"
    );
    assert!(
        report
            .steps
            .iter()
            .any(|step| step.method == "reveal_showdown[1]" && step.ok),
        "最后一个 showdown reveal 必须完成 prove+verify"
    );
    assert!(report.chain_ok, "state_root 链应衔接");

    let aggregate = plugin
        .aggregate_crypto_proofs()
        .expect("两次独立归档的 shuffle proof 应生成 host-verified outer aggregate");
    assert_eq!(
        aggregate.children().len(),
        2,
        "reveal 已进入 tagged batch，outer aggregate 只包含两个独立归档的 shuffle proof"
    );
    assert_eq!(aggregate.hand_id(), 1);

    let has_dispatch_timing = report.steps.iter().any(|s| s.dispatch.as_micros() > 0);
    assert!(has_dispatch_timing, "应有非零 dispatch 计时");
    let has_prove_timing = report.steps.iter().any(|s| s.prove.as_micros() > 0);
    assert!(has_prove_timing, "应有非零 prove 计时");
}
