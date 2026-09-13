# M0：GPU 路线探测报告（仅调研，不实施）

> 状态：2026-09-12。对应 plan M0"GPU 路线探测（可选）：stwo GPU prover
> 可行性调研，仅出报告不实施"。本文是调研结论，**不包含任何实现或依赖
> 变更**。结论：v1 不需要 GPU prover；给出重启评估的触发条件。

## 1. 已确认事实

- **本仓库现用证明栈为 CPU 路径**：crates.io `stwo` 2.3（circle-STARK），
  并行化走 `rayon`（`poker-appchain/src/pipeline.rs` worker 池）；手写约束
  AIR 的 canonical 批次证明与验证经 `poker-appchain-texasair` 适配器调用
  `prove_canonical_tagged_batch` / `verify_canonical_tagged_proof`。仓库内
  无任何 GPU 依赖（`grep -ri 'cuda\|metal\|wgpu' Cargo.toml */Cargo.toml`
  零命中）。
- **当前性能基线（CPU，release / pinned nightly）**：批次证明就绪
  p95 = 777.4ms（32 ops/批，n=20 实测，`docs/plan-appchain-perf.md`
  M4-ACC-1 PASS）；M4-ACC-2 吞吐 1/4/16/64 桌呈亚线性（≤1.00）。
- **上游状态（2026-09 检索）**：StarkWare S-two 2.0.0 已于 2026-01 宣布
  全开源并上架 crates.io（starkware.co 博客）。GPU 后端的可用性/成熟度
  **未在本次检索中获得一手确认**——历史上 Cairo 系 GPU 加速由
  Sandstorm/miniSTARK（SHARP 兼容）路线代表，S-two 自带 GPU 后端的
  状态需持续跟踪上游 release notes（plan §4.4 既有跟踪义务）。

## 2. 可行性分析

| 维度 | 评估 |
|---|---|
| 需求侧 | v1 验收门槛：单批证明就绪 ≤3s p95（M4-ACC-1）。CPU 实测 777ms，余量 ~4×；未触发 GPU 需求 |
| 成本结构 | DR-1 结论（perf 文档）：log_size 8 下限使单证明成本与行数解耦，逐街拆分已否决；GPU 只能压常数，不改变该结构性结论 |
| 工程面 | GPU 后端引入非确定性浮点/内核兼容矩阵与新信任面：**验证器仍须 CPU 独立复验**（fail-closed：prover 加速不改变验证路径），引入成本主要是运维与供应链审计，非算法风险 |
| 上游风险 | S-two GPU 后端若为早期实验态，pinned 版本策略（现锁 2.3）与 GPU 路径的版本耦合会破坏可复现构建纪律；引入前需上游 API 稳定承诺 |
| 收益侧 | 64 桌压测（M9-ACC-1 目标）下的证明吞吐缺口尚未实测出现；若出现，优先级更高的手段是按桌并行扩容（M4 已有 worker 池）与批间隔调参 |

## 3. 结论与重启评估触发条件

**结论：v1 不引入 GPU prover。** 当前 CPU 基线对全部已定验收门槛有足量
余量；GPU 的引入成本（供应链审计、双路验证运维、版本钉扎）在无吞吐缺口
时不成立。

**重启评估触发条件（满足其一即重开调研并升级为立项评审）**：
1. M9-ACC-1 64 桌压测中证明就绪 p95 连续超门槛（>3s）且 worker 扩容/
   批参数调优无法回收；
2. 上游 S-two 发布带**稳定承诺**的 GPU 后端（非实验 flag），且验证路径
   保持 CPU 独立；
3. 产品侧把单手证明就绪目标收紧到 <200ms 量级（新需求先入开放问题）。

## 4. 参考

- StarkWare：Introducing S-two 2.0.0 for Developers（2026-01-27）
  https://starkware.co/blog/s-two-2-0-0-prover-for-developers/
- starkware-libs/stone-prover（被 S-two 替代的上一代）
  https://github.com/starkware-libs/stone-prover
- 本仓库性能基线：`docs/plan-appchain-perf.md`（M4-ACC-1/2、DR-1/DR-2）
