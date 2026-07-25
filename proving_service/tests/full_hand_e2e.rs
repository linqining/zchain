//! HandRunner 端到端验收测试。
//!
//! 通过 `proving_service::HandRunner` 跑通一手牌的真实 dispatch + 证明流程：
//! 每步经 poker_l1 dispatch 真实执行，产出 ProveTask，由 Orchestrator prove+verify，
//! 最后校验 state_root 链并尝试聚合。

use proving_service::HandRunner;

/// 一手牌完整跑通：所有步骤 prove+verify 成功，state_root 链衔接，聚合 verify 通过。
#[test]
fn full_hand_runner_proves_every_step() {
    let (_plugin, report) = HandRunner::new()
        .run()
        .expect("HandRunner 应跑通");

    // 每步都成功
    assert!(
        report.steps.iter().all(|(_, ok)| *ok),
        "存在失败的步骤: {:?}",
        report.steps
    );

    // 至少覆盖 7 个方法
    assert!(
        report.steps.len() >= 7,
        "应覆盖 >=7 步，实际 {}",
        report.steps.len()
    );

    // state_root 链衔接
    assert!(report.chain_ok, "state_root 链应衔接");

    // 聚合证明 verify 通过
    assert_eq!(
        report.aggregate_ok,
        Some(true),
        "聚合证明应 verify 通过"
    );

    // prove 次数 == 已证明任务数
    assert!(report.stats.prove_count >= 7);
    assert!(report.stats.chain_length >= 7);
}

/// 验证 HandRunner 覆盖的方法集合（包含 lifecycle + funds + kick）。
#[test]
fn full_hand_runner_covers_expected_methods() {
    let (_plugin, report) = HandRunner::new().run().expect("HandRunner 应跑通");
    let names: Vec<&str> = report.steps.iter().map(|(n, _)| *n).collect();
    assert!(names.contains(&"create_table"), "缺少 create_table: {names:?}");
    assert!(names.contains(&"join_table"), "缺少 join_table: {names:?}");
    assert!(names.contains(&"addon"), "缺少 addon: {names:?}");
    assert!(names.contains(&"rebuy"), "缺少 rebuy: {names:?}");
    assert!(names.contains(&"leave_table"), "缺少 leave_table: {names:?}");
    assert!(names.contains(&"kick_player"), "缺少 kick_player: {names:?}");
    assert!(
        names.contains(&"reset_for_next_hand"),
        "缺少 reset_for_next_hand: {names:?}"
    );
}
