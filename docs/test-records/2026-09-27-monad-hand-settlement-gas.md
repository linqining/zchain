# 一手牌结算在 Monad 测试网的费用实测（2026-09-27）

> 问题："一手牌结算在 Monad 上多少钱？"实测口径：在 Monad 测试网
> （chainId 10143，`https://testnet-rpc.monad.xyz`）上把一手牌结算涉及的
> 四条 L1 腿**逐笔真实发送**，回执级测量。结论先行：
>
> - **纯结算锚定（64 手/批摊销）≈ 3.2k 执行 gas/手 ≈ 0.00036 MON/手**；
> - **每手都带赢家提现的上界口径 ≈ 120k 执行 gas/手 ≈ 0.0134 MON/手**
>   （账单口径 @102 gwei）；
> - **Monad 按 `gas_limit × price` 计费、不按 `gas_used`**（对照实验实锤），
>   所以"费用优化"的唯一杠杆是把 limit 收紧到 `est×1.1`——与冷/热访问
>   定价（EIP-2929/MIP-8）无关的另一个维度。

## 1. 一手牌在 L1 上的真实形态

poker-appchain（L2）每手结算产出一个 hand_proof op，按 `batch_size=64`
组批（`poker-appchain/src/pipeline.rs`），`monad_settlementd` 把批次根锚到
Monad（L1）。一手牌永不产生"一笔 L1 结算交易"，而是四条独立节奏的腿：

| 腿 | 交易 | 节奏 | 本次实测 |
| --- | --- | --- | --- |
| 锚定 | `L1Inbox.submitBatch` | 每 64 手 1 笔 | est **81,978** gas |
| 聚合 | `L1Inbox.submitAggregate` | 每聚合窗 1 笔 | est **82,216** gas |
| 买入 | `L1Bridge.depositNative` | 每次买入 1 笔 | est **35,646** gas |
| 提现 | `L1Outbox.commitRoot` + `claim` | commitRoot 随 checkpoint 原子携带（无独立 tx）；claim 每领款人 1 笔 | est **81,087** / **116,429** gas |

负载口径（诚实声明）：批次根为确定性测试向量、提现叶由
`monad-settlement::proof::leaf_hash`（L2 withdrawal_root builder 的逐字节
镜像）构造。L1 gas 只取决于交易形状（calldata 宽度 + 触碰的 storage
slot），与根/叶的语义内容无关——换任何真实一手牌的根，gas 逐 wei 相同。

## 2. 计费模型实锤：按 limit 收费，不按 used

对照实验（自转账，真实执行 21000 gas，`--gas-price 105 gwei` 固定）：

| limit 设置 | 余额扣减 | 折算 |
| --- | --- | --- |
| 21,000 | 2,205,000,000,000,000 wei | **21,000 × 105 gwei** |
| 100,000 | 10,500,000,000,000,000 wei | **100,000 × 105 gwei**（used 仍是 21000） |

→ **账单 = gas_limit × price**。回执的 `gasUsed` 恒等于 limit（不可用作
执行 gas 读数），真实执行 gas 只能从 `eth_estimateGas` 拿（实测自转账
恰好返回 21000，语义正确）。

推论（与 ETH L1 直觉相反，见 §5）：
- **EIP-2930 访问列表在 Monad 上只亏不赚**：预热本身计入 gas，而账单
  按 limit 收，预热只会抬高 limit 下限；
- **limit 填大直接多扣钱**：同一条腿，首跑宽松 limit=200k 账单 0.0224
  MON，紧 limit=90k 账单 0.0092 MON——**2.4 倍差价来自 limit，不是
  opcode**。daemon 必须按 `estimate × ≤1.1` 发交易。

## 3. 逐腿实测（7/7 成功，run 3）

环境：height 66,163,014；节点 gasPrice 102 gwei（测试网地板 ≈100 gwei，
实测账单 = 提交价 102 gwei 全额）；operator
`0xbcd7ecd68d55ca2536f3f50dcbcb44edb0d97aa6`；复用 9-27 验收栈
inbox `0x60ecddd1…` / outbox `0x1f3e8b42…` / bridge `0x67288738…`。

| 腿 | 交易 | estGas（真实执行） | 紧 limit（计费） | 账单 @102 gwei | tx |
| --- | --- | ---: | ---: | ---: | --- |
| 锚定·1手/批 | submitBatch | 81,978 | 90,176 | 0.009198 MON | `0x75985fc4…` |
| 锚定·64手/批 | submitBatch | 81,978 | 90,176 | 0.009198 MON | `0x06543505…` |
| 聚合锚 | submitAggregate | 82,216 | 90,438 | 0.009225 MON | `0x1a1fb933…` |
| 买入 0.01 MON | depositNative | 35,646 | 39,211 | 0.004000 MON | `0x69e173c1…` |
| 运维（非结算腿） | setLargePayoutThreshold | 39,905 | 43,896 | 0.004477 MON | `0xb106ac83…` |
| 提现·窗根 | commitRoot(1叶) | 81,087 | 89,196 | 0.009098 MON | `0xf9a09e22…` |
| 提现·领款 | claim(0.01 MON) | 116,429 | 128,072 | 0.013063 MON | `0xb3ec7895…` |

到账对账：claim 后 Bridge 浮存精确 −0.01 MON ✓（`claim` 的 Merkle 校验 →
台账防重放 → 跨合约 `payoutNative` 打款全链路成功）。

首跑（宽松 limit 200k/400k @112.2 gwei，run 1）同腿账单：
submitBatch 0.0224 / claim 0.0449 MON——差价全部来自 limit。

## 4. 单手费用口径

生产节奏摊销（执行 gas 口径 = 区块打包占用）：

| 成分 | 执行 gas/手 | 计费 gas/手（limit=est×1.1） |
| --- | ---: | ---: |
| 锚定（81,978 / 64 手） | 1,281 | 1,409 |
| 聚合锚（82,216 / 2 批×64 手） | 642 | 707 |
| 提现窗根（生产中随 checkpoint 原子携带 → 不计） | 0 | 0 |
| **纯结算合计** | **≈1,923** | **≈2,116** |
| 赢家每手提现（上界假设：claim 116,429） | 116,429 | 128,072 |
| **每手一提的上界合计** | **≈118,352** | **≈130,188** |

折 MON（@102 gwei）：**纯结算 ≈0.000216 MON/手；每手一提上界
≈0.0133 MON/手**。买入腿另计 0.004 MON/次。

折 USD（按运营方定价参考 **MON = $0.174**）：

| 口径 | MON/手 | @ $0.174 |
| --- | ---: | ---: |
| 纯结算（锚定摊销） | 0.000216 | **$0.0000376** |
| 每手一提上界 | 0.0133 | **$0.00231** |
| 买入腿（每次） | 0.0040 | $0.00070 |

即：**一手牌的链上结算本身 ≈ $0.00004；即使赢家每手都把盈利提回
Monad，单手全成本 ≈ $0.0023**（测试网地板价 102 gwei；主网 base fee
长期贴地板的话同量级）。示例场景（一张桌一天：240 手 + 20 次提现 +
20 次买入）：结算 0.052 MON + 提现 0.261 MON + 买入 0.080 MON
≈ **0.39 MON/桌·天 ≈ $0.068**。

## 5. 冷/热框架下的解读（回应用户的 MIP-8 上下文）

- 这套结算栈**几乎吃不到页模式红利**：submitBatch/commitRoot/claim 都是
  "每 slot 触碰一次"的一次性状态机（index 连续写、checkpoint 防重放、
  request_id 台账），没有"同页 128 slot 连续热读"的访问形状。页模式
  红利属于 L2 侧批量读状态的场景，不属于这几条锚定腿。
- **冷读不可避免但也不贵**：腿的大头是冷 SSTORE（新 slot ~20k）与 claim
  的跨合约打款路径，这在任何 EVM 上都一样；Monad 把冷页定价抬到
  8100/页对此类交易无影响（不触发同页二次访问）。
- **limit 计费盖过一切冷/热优化**：既然按 limit 收费，热/冷与
  EIP-2930 预热都不改变账单（预热只会推高 limit 下限）。运营杠杆只有
  三个：① 紧 limit（est×1.1）；② 少发交易（批大=摊薄锚定腿）；
  ③ gasPrice 贴地板。
- 对比用户给的"64 个连续字段热读省 89%"案例：那是对**合约存储布局**
  的优化建议（结构体连续声明 vs mapping 打散）。本结算栈的存储是
  按序号/台账的 mapping 形态（`roots[index]`、`requestIds[request_id]`），
  天然跨页、各碰一次——无从优化也不需要优化。

## 6. 复现

```bash
cargo run -p monad-settlement --bin monad_hand_gas -- \
  --l1-rpc https://testnet-rpc.monad.xyz --chain-id 10143 \
  --key-file <带水钥文件> \
  --inbox 0x60ecddd1359356a43a69de84a1cf235a69a30e71 \
  --outbox 0x1f3e8b42e5f31f276952ce627d1eeffec8c6ae3b \
  --bridge 0x6728873828dd281d274542eb3e6ba7438c0b96e6 \
  --run-id 4 --out /tmp/monad-hand-gas.json
```

- 执行器：`monad-settlement/src/bin/monad_hand_gas.rs`（新增；两阶段：
  eth_estimateGas → est×1.1 紧 limit 发送；`Receipt` 扩展了
  gasUsed/effectiveGasPrice 字段）。
- 汇总 JSON：run 3 = `/tmp/monad-hand-gas-tight.json`（本记录数据源）；
  run 1（宽松 limit 对照）= `/tmp/monad-hand-gas.json`。
- 注意：重复运行自动用 `--run-id` 派生幂等键（request_id/checkpoint
  高度/批次根），不会撞台账；重复前确认 operator 余额 ≥0.05 MON。
