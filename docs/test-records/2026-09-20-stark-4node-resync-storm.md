# 事故记录：4 节点 stark 部署 node_1 状态分叉 → 重置引发同步风暴 → 服务器 OOM 挂死

- 日期：2026-09-20
- 环境：stark 服务器（8.218.68.215，4C/7.3G，Alibaba Cloud Linux 4），`scripts/deploy_4node.sh` N=4，
  RPC 0.0.0.0:18545-18548，P2P 127.0.0.1:19000-19003，block-interval 200ms；
  本地 poker_texas_air 全流程经 SSH 隧道提交（poker-air-zchain-4node 运行目录）
- 状态：事故处理中（服务器等控制台重启）；教训与恢复预案见 §4/§5

## 1. 时间线

1. 20:33 部署 4 节点成功，DAG 共识出块正常（~200ms/块）。
2. 21:0x 本地全流程启动（deploy-record 上链 tx `219ba3da…`，texas + gateway + 桥 + 浏览器）。
3. 21:2x 桥已锚定 20 手后，发现 node_1（:18546）高度卡在 481（其余节点 487+），
   node_1 日志连续刷 `P2P put_block 失败：state root mismatch`（最终计数 383 次）。
   其余 3 节点 3/4 多签继续出块，但出块速率从 ~5 块/s 掉到 ~1 块/15s（同步风暴拖累）。
4. 21:1x 处置：kill node_1 → 清数据目录 → 从 genesis 重启（validator key 不变）。
5. 21:1x+ 重启的 node_1 开始全量重同步；4C 机器上"500+ 块回放执行 × 200ms 新块产出 ×
   3 节点响应区块区间请求"叠加，服务器用户态全面饿死（ping 内核仍通）。
6. 21:2x-22:2x sshd banner exchange 超时 >50 分钟，无法 SSH；判定用户态挂死（疑似 OOM）。

## 2. node_1 状态分叉（先行故障）观察

- 分叉表现：其他节点广播的块 node_1 拒收（state root mismatch），其本地高度停在 481。
- 含义：node_1 的执行状态与共识块头不一致——要么它错过了某些块后状态迁移走偏，
  要么存在块执行不确定性（待复现：node_1 重同步到分叉点后是否再次 mismatch）。
- 影响面：链层面 3/4 多签出块不受影响；读层面经 :18546 的查询不可信。
- 桥/网关均固定使用 node_0（:18545），未受该故障影响。

## 3. 解耦架构的容错验证（正面结果）

链中断期间本地全流程持续运行：
- 浏览器 + 扩展继续打牌（打牌不依赖链，只有结算锚定依赖链）；
- 桥按设计容错：提交失败记录日志后继续轮询，WAL 中结算不丢（恢复后增量补锚）；
- gateway/texas/vite/bot 全部无感。

## 4. 教训

1. **低配机器上不要对运行中链做"清数据全量重同步"**：追赶速率低于出块速率时，
   重同步永远追不上且持续满载。正确做法：a) 3 节点继续服务（3/4 多签够出块），
   分叉节点直接停掉；b) 若必须重置，先停链或调大 block-interval（如 2s）再同步。
2. 4C/7.3G 跑 4 节点 + 200ms 出块 + 每块含结算 tx 执行，处于资源边界；
   长期常驻建议 block-interval ≥ 1s。
3. `deploy_4node.sh` 重置单节点时注意旧 socket TIME_WAIT（kill 后 ~60s 内
   bind 会 EADDRINUSE）。

## 5. 恢复预案（/tmp/poker-air-recovery.sh 已部署，SSH 恢复后自动执行）

1. 停 node_1（防再次风暴），保持 3 节点出块（genesis validator set 不变）。
2. 验证链高度增量、内存、磁盘。
3. 本地自愈隧道（/tmp/poker-air-tunnel.sh）自动重连；桥自动补锚 WAL 中全部结算。
4. 若节点数据因宕机损坏：停链 → 调大 block-interval → 以现有 genesis 重启
   （必要时重开 genesis + 清 bridge_state.json 重锚全部结算——WAL 是唯一事实源，手数不丢）。
