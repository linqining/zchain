//! HandRunner VM→AIR→host verifier 覆盖片段测试。
//!
//! 通过 `proving_service::HandRunner` 跑通一段真实 dispatch + 证明流程：
//! 每步经 poker_l1 dispatch 真实执行，产出 ProveTask，由 Orchestrator prove+verify，
//! 最后校验 state_root 链，并确认 descriptor-only 聚合保持 fail-closed。

use proving_service::HandRunner;

/// 覆盖片段跑通：所有步骤 prove+verify 成功，state_root 链衔接，聚合明确禁用。
#[test]
fn full_hand_runner_proves_every_step() {
    let (_plugin, report) = HandRunner::new().run().expect("HandRunner 应跑通");

    // 每步都成功
    assert!(
        report.steps.iter().all(|(_, ok)| *ok),
        "存在失败的步骤: {:?}",
        report.steps
    );

    // 当前诚实覆盖 6 个真实 dispatch 步骤。
    assert!(
        report.steps.len() >= 6,
        "应覆盖 >=6 步，实际 {}",
        report.steps.len()
    );

    // state_root 链衔接
    assert!(report.chain_ok, "state_root 链应衔接");

    // descriptor-only 聚合必须保持 fail-closed；Some(false) 表示已尝试且被拒绝。
    assert_eq!(
        report.aggregate_ok,
        Some(false),
        "不可信 descriptor-only 聚合不应成功"
    );

    // prove 次数 == 已证明任务数
    assert!(report.stats.prove_count >= 6);
    assert!(report.stats.chain_length >= 6);
}

/// 验证 HandRunner 覆盖的方法集合（可信的 lifecycle + funds 片段）。
#[test]
fn full_hand_runner_covers_expected_methods() {
    let (_plugin, report) = HandRunner::new().run().expect("HandRunner 应跑通");
    let names: Vec<&str> = report.steps.iter().map(|(n, _)| *n).collect();
    assert!(
        names.contains(&"create_table"),
        "缺少 create_table: {names:?}"
    );
    assert!(names.contains(&"join_table"), "缺少 join_table: {names:?}");
    assert!(names.contains(&"addon"), "缺少 addon: {names:?}");
    assert!(names.contains(&"rebuy"), "缺少 rebuy: {names:?}");
    assert!(
        names.contains(&"leave_table"),
        "缺少 leave_table: {names:?}"
    );
    assert!(
        !names.contains(&"kick_player"),
        "WAITING kick/reset 多步路径不应冒充单步 AIR: {names:?}"
    );
}
