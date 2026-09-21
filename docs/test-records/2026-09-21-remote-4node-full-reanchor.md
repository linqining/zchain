# 远程 4 节点全量重锚验收记录（2026-09-21）

前置：共识 wave-3 固定 leader 重构（见
[2026-09-21-consensus-reference-research.md](2026-09-21-consensus-reference-research.md)）。
本文记录远程 stark 服务器 4 validator 链上的全量重锚与三重证据验收。

## 环境

- 服务器：阿里云 stark（4C/7.5G），/opt/zchain-src（新二进制，Sep 21 17:19 构建）、
  /opt/zchain-4node（固定密钥 + genesis 8 账户：4 validator + bridge/bridge2-4）
- 链参数：--block-interval-ms 500 --inclusion-deadline-ms 3000，4 validator
  （quorum 3），epoch 1 起（genesis 修复）
- 访问：SSH 隧道 28545-28548 → 远程 18545-18548
- 锚定器：本地 4 分片桥（scripts/poker_air_bridge.py，--stream-only 串行流 +
  nonce 推进确认 + 全节点 fanout，partition i%4）
- 事实源：/tmp/poker-air-zchain-4node/appchain/sequencer.wal（texas 实测
  1000+ 手全量结算，本轮 3029 条含 binding 的 settlement 记录）

## 过程

1. deploy-record 上链：tx `1e1f583f5807682c…`，included=true，nonce 0。
2. 4 分片桥全量重锚：~3300/h（远程链实测），全程四节点高度一致、
   无 epoch 翻转、服务器内存稳定（available ~6.4G，单节点 RSS ~110MB）。
3. 波决策统计（node_0）：COMMIT 756+ / ABSORB 8 / SKIP 5 —— 未决轮被间接
   裁决治愈，无停摆。
4. 对账修复：首轮存在 10 个「90s 未入块重试窗口」产生的同 nonce 幽灵记录
   （同一 nonce 只可能一笔真实上链）。清理重复组后重锚补齐，终审计
   entries=3029 全部唯一、无同分片 nonce 重复；nonce 空洞（每账户 0-3 个）
   与被替换的孤儿交易一一对应，恒等式 `entries + orphans = chain_nonce`
   逐账户成立（758+3=761 / 757+3=760 / 757+3=760 / 757+1=758）。

## 三重证据验收（全部通过）

1. **链高**：四节点 [5218, 5218, 5218, 5218] 完全一致。
2. **末笔锚定 tx**：binding `d7ff726e3f69fc66bc67…`（nonce 760），
   tx `ed595620f7e479882931385c25ce528d0097898c9505421737f014f12dee0048`，
   get_tx = **FOUND**（跨节点验证于 28548）。
3. **账户 nonce**：bridge/bridge2/bridge3/bridge4 = 761/760/760/758，与
   各分片 state 精确一致；合计 3029 个 binding 全部唯一且全部上链执行。

附加：deploy-record tx get_tx = FOUND。

## 结论

- 远程 4 validator 链在共识重构后持续健康出块（~1 块/s，lag≈3 轮），
  全量 3029 手结算锚定完成（含 1000 手 e2e 测试产生的全部边缘场景：
  全押/边池/平分/弃牌/强制同步等，与本地验证同一 WAL）。
- 验收器要求的三重证据（链高 / get_tx / 账户 nonce）全部满足。
- 遗留修复（已完成，2026-09-21）：桥的「重试窗口同 nonce」竞态已根修——
  机制为 chain_nonce_max 全部读取失败 → sync_nonce 再失败 → 回退陈旧游标，
  陈旧 nonce 的 submit 被四节点静默拒绝后确认判据「chain_nonce > nonce」
  瞬时误判（远程重锚 3029 笔实测 10 条幽灵，含启动期 nonce-0 记录）。
  新增 `strict_chain_nonce`（两路读取退避重试，全部失败返回 None、整轮
  放弃，绝不带陈旧 nonce 提交），stream/batch 两路径接入。本地环 smoke
  验证：3 笔锚定 nonce 严格连续（700/701/702），链上 nonce=703=state。
