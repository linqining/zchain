# Deprecated Documents Index

> **生成时间**：2026-07-20
> **目的**：记录所有因 v2 迁移路线（递归证明 + 原生 M31 trace）而 deprecated 的旧文档

## 背景

2026-07-20，用户决定切换到 Stwo 递归证明路线，完全放弃 Hypernova 兼容。所有基于 v1 fold 改写路线的文档被标记为 deprecated，但保留作为历史参考和技术决策记录。

**新计划文档**：
- [hypernova_to_stwo_migration_plan_v2.md](hypernova_to_stwo_migration_plan_v2.md) — v2 总迁移计划
- [stwo_phase1_native_trace_design.md](stwo_phase1_native_trace_design.md) — Phase 1 详细设计

## Deprecated 文档清单

| 文档 | 原用途 | Deprecated 原因 |
|------|--------|----------------|
| [hypernova_to_stwo_migration_plan.md](hypernova_to_stwo_migration_plan.md) | v1 总迁移计划（fold 改写） | v2 完全放弃 Hypernova 兼容 |
| [stwo_phase2_2_trace_column_reduction_plan.md](stwo_phase2_2_trace_column_reduction_plan.md) | Phase 2.2 trace 列数精简（47→13） | v2 用 4×8-bit limb，列布局完全重设计 |
| [stwo_phase2_3_4b_limb_decomposition_plan.md](stwo_phase2_3_4b_limb_decomposition_plan.md) | Phase 2.3.4-b limb decomposition（2×30-bit） | v2 用 4×8-bit limb，不再需要 30-bit limb 分解 |
| [stwo_poc_decision_report.md](stwo_poc_decision_report.md) | Phase 1.5 + Phase 2.1-2.3.4 决策门报告 | v1 路线整体废弃 |
| [phase_11_stub_fold_migration_plan.md](phase_11_stub_fold_migration_plan.md) | Phase 11 stub fold 迁移 | Hypernova fold 完全删除 |

## 保留价值

虽然这些文档已 deprecated，但仍有参考价值：

1. **技术决策记录**：记录了 v1 路线的设计权衡和选择理由
2. **Stwo AIR 经验**：Phase 2.3.x 的 Group A/B/C/E/F 约束设计经验可部分复用到 v2
3. **性能基准**：Phase 1.5 POC 的性能数据（1M 步 62014ms）作为 v2 优化对比基线
4. **Lessons Learned**：`row_to_position[bit_reverse(row)]` remapping、padding 冲突等经验适用于 v2

## 注意事项

- **不要**根据这些文档实施代码
- **可以**参考这些文档了解 v1 → v2 的架构演进
- **可以**复用这些文档中的 Stwo API 使用经验（`FrameworkEval`、`EvalAtRow`、`LogupTraceGenerator`）
- **不要**复用这些文档中的列布局（2×30-bit limb