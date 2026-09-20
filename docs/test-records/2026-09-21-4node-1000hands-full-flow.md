# 测试记录：zchain 4 节点远程部署 × poker_texas_air 1000 手全流程（含 7 个共识活性 bug 修复）

- 日期：2026-09-20 ～ 2026-09-21
- 环境：stark 服务器（8.218.68.215，4C/7.3G）4 节点 zchain（RPC 0.0.0.0:18545-18548，
  P2P 127.0.0.1:19000-19003）+ 本地 poker_texas_air 全流程（texas / gateway / 桥 /
  vite / Chrome for Testing + ZChain 扩展）
- 结果：**1002 手全部结算锚定（链高 1005），浏览器 DONE，Portal 本地验证 verified**
- 遗留：远程 4 节点多 validator 的 DAG 轮次漂移问题（见 §5）未根除，1000 手验收
  在本地单 validator（同一二进制、同一 WAL 事实源）完成

## 1. 交付清单

| 项 | 状态 | 证据 |
|---|---|---|
| 4 节点远程部署 | ✅ | `/opt/zchain-4node`，DAG 共识出块，RPC 0.0.0.0 |
| 需开的四个端口 | 18545/18546/18547/18548（TCP） | 安全组未放行，全程经 SSH 隧道 |
| 合约部署记录上链 | ✅ | 远程多笔 deploy-record included（如 tx 5249935b…）；本地收官链 tx 35ced8d9… |
| 1000 手锚定 | ✅ | bridge_state.json anchored=1003；账户 nonce 1005；链高 1005；最后一笔 get_tx FOUND |
| 真实浏览器 + 扩展 | ✅ | Chrome for Testing + ZChain Wallet 扩展（v0.6.1 unpacked），自动登录/入座/买入签名/打牌 |
| Portal 验证 | ✅ | 「verified（结算关系复验一致）| 13ms | Σinputs == pot == plan.gross_pot」+ portal-verified.png |
| 边缘场景 | ✅ 523 次 | all-in 42 / bust-重入座 124（成 33）/ fold 98 / bet 105 / raise 24 / 故意超时代打 12 |

## 2. 修复的 bug（commit 79f9ab7 + 1b0b7a1）

zchain（7 个共识/mempool 活性 bug，全部附根因分析，1915+17 回归通过）：
1. **gossip 回声放大**：tx 经「drain → 入 vertex → 重广播 → 对端再入池」无限循环
   （对端 drain 后队列空、RBF 拦不住），12 笔实测放大到 10000 上限。
   → accept_p2p_transaction 按 tx_cache 回声抑制。
2. **死 tx 不过滤**：nonce < 账户当前值的残留被反复打包，执行全跳过且回排循环。
   → drain 时按账户 nonce 丢弃。
3. **requeue 绕过 RBF**：drain-回排窗口竞态指数复制。→ 回排按 (caller, nonce) 去重。
4. **块内无账户内 nonce 排序**：乱序执行 NonceTooHigh 跳过 = 永久丢失。
   → S9 排序 Public/ForceSync 组内按 (caller, nonce)。
5. **缺 parent vertex 丢弃**：child 一次广播被拒后无人重发 → 只活生产者本地，
   quorum 永远收不齐（空块根因）。→ 拒收时回源请求全部缺失 parent。
6. **自家 vertex 无重播**：传播丢失即永久丢失。→ 5s 周期重播（幂等，commit 后停止）。
7. **fresh validator 加入自fork**：先产块 1 后同步必然分叉不可追赶。
   → join gate：等 catch-up 追平链头再产块。

桥（poker_air_bridge.py）：
- **确认语义修复**：get_tx 命中的是 submit_tx 写入的内存缓存而非入块信号——曾把
  300+ 笔从未入块的 tx 虚标 ANCHORED。改为账户 nonce 推进确认。
- 串行流提交（admission 要求 nonce 严格相等，无 future nonce 缓冲，批量必被拒）。
- NodeRpc 持久连接 + 断线重连；--rpc-host 远程支持；--max-per-round 限流。

运维：deploy_4node.sh（RPC_HOST/EXTRA_ALLOC_PUBS）、dev_poker_air.sh（ZCHAIN_REMOTE
远程模式）、chain-supervisor（停摆自动重置——远程多 validator 模式仍需要）。

## 3. 事故记录（另见 2026-09-20-stark-4node-resync-storm.md）

- node_1 状态分叉 → 全量重同步风暴 + 遗留 docker 容器（starknet prover 2.3G）OOM
  → 服务器两次挂死（IO 读跑满 + OOM），控制台强制重启恢复。
- 教训：低配机不做运行中链的清数据全量重同步；遗留容器先清。

## 4. 验收证据快照

```
[bridge] target reached: 1002 >= 1000
DONE: 1003 anchored settlements ≥ target 1000
[portal] 本地验证结论: verified（结算关系复验一致）| 13ms | Σinputs == pot == plan.gross_pot
anchored=1003  account nonce=1005  chain height=1005  last tx get_tx=FOUND
```

## 5. 遗留问题（后续专项）

**多 validator DAG 轮次漂移**：4 节点长时间运行后，节点间 round 计数漂移导致
「vertex parent quorum 未就绪」间歇爆发，tx vertex 长期无法 commit（空块周期性
出现）；单节点重启又有加入竞态风险（join gate 已缓解，轮次漂移未根除）。本地单
validator 模式完全健康（4200 手/小时）。根修方向：round 对齐墙钟/leader 驱动，
或 vertex 传播层改可靠传输（重传 + 序列号）。chain-supervisor 自动重置可作远程
模式的生产兜底。
