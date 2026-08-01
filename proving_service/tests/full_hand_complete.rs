//! FullHandRunner 性能报告测试。
//!
//! 验证 `--full-hand` 模式：完整牌局序列驱动 + 每步计时。
//!
//! 当前因 crypto AIR Gap-6（见 `AIR_GAP.md`）会在终结洗牌者的 submit_shuffle_v2
//! 处停止，故本测试断言「前 5 步全部 prove+verify 成功」并记录 stopped_at，
//! 而非要求整局完整通过。Gap-6 修复后可改为断言整局成功。

use proving_service::full_hand::FullHandRunner;

/// 完整牌局前 5 步（create/join×2/start_hand/非终结 submit_shuffle_v2）应全部
/// prove+verify 成功，state_root 链衔接。终结洗牌者因 Gap-6 停止（已记录）。
#[test]
fn full_hand_proves_pre_shuffle_steps() {
    let (_plugin, report) = FullHandRunner::new().run();

    // 前 5 步全部成功
    let ok_count = report.steps.iter().take(5).filter(|s| s.ok).count();
    assert_eq!(
        ok_count, 5,
        "前 5 步应全部 prove+verify 成功，实际成功 {} 步",
        ok_count
    );

    // 至少包含 create_table / join_table / start_hand / submit_shuffle_v2
    let names: Vec<&str> = report.steps.iter().map(|s| s.method.as_str()).collect();
    assert!(names.iter().any(|n| n.contains("create_table")), "缺 create_table");
    assert!(names.iter().any(|n| n.contains("join_table")), "缺 join_table");
    assert!(names.iter().any(|n| n.contains("start_hand")), "缺 start_hand");
    assert!(
        names.iter().any(|n| n.contains("submit_shuffle_v2")),
        "缺 submit_shuffle_v2"
    );

    // state_root 链衔接（已证明的 5 个 receipt 连续）
    assert!(report.chain_ok, "state_root 链应衔接");
    assert!(
        report.stats.chain_length >= 5,
        "链长应 >=5，实际 {}",
        report.stats.chain_length
    );
}

/// 终结洗牌者的 submit_shuffle_v2 应在 Gap-6 处停止（crypto AIR 完备性缺口）。
///
/// 这是一个**正向回归**：如果 Gap-6 被修复（允许 post-phase=NONE），
/// `stopped_at` 将变为 None，本测试需相应更新。
#[test]
fn full_hand_stops_at_gap6_on_terminal_shuffler() {
    let (_plugin, report) = FullHandRunner::new().run();
    assert!(
        report.stopped_at.is_some(),
        "预期在终结洗牌者处因 Gap-6 停止，但整局跑通了（Gap-6 已修复？需更新本测试）"
    );
    let reason = report.stopped_at.as_ref().unwrap();
    assert!(
        reason.contains("submit_shuffle_v2") && reason.contains("prove"),
        "停止原因应指向 submit_shuffle_v2 prove，实际：{reason}"
    );
}

/// 性能数据存在：每步计时非零，且有 dispatch/prove 合计。
#[test]
fn full_hand_records_timing() {
    let (_plugin, report) = FullHandRunner::new().run();
    // 成功步骤应有非零 dispatch 耗时
    let has_dispatch_timing = report
        .steps
        .iter()
        .filter(|s| s.ok)
        .any(|s| s.dispatch.as_micros() > 0);
    assert!(has_dispatch_timing, "应有非零 dispatch 计时");
    let has_prove_timing = report
        .steps
        .iter()
        .filter(|s| s.ok)
        .any(|s| s.prove.as_micros() > 0);
    assert!(has_prove_timing, "应有非零 prove 计时");
}
