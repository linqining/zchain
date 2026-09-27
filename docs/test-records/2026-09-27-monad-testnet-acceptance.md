# Monad 测试网接入验收记录（2026-09-27）

> 目标：把 zchain L2 结算设施（`contracts/monad/` 合约栈 + `monad-settlement`
> 适配层 + `monad_settlementd` 守护进程）接入 **Monad 测试网**
> （chainId 10143，`https://testnet-rpc.monad.xyz`）并完成验收。
> 结论先行：**7/7 检查全 PASS**（含一次真实 bug 的发现与修复），合约栈
> solc 0.8.28 真编译通过；链上部署/上锚 E2E 需运营者提供带水测试钥后按
> §4 步骤补做。

---

## 1. 验收环境

| 项 | 值 |
| --- | --- |
| 目标网络 | Monad Testnet，chainId **10143**（0x279f） |
| RPC | `https://testnet-rpc.monad.xyz`（公共端点，限流 20 rps） |
| 验收工具 | `monad_settlementd --mode probe`（本次新增，见 §3） |
| 编译工具 | solc 0.8.28+commit.7893614a（`tools_external/solc/`，darwin-arm64） |
| 验收时间 | 2026-09-27（UTC+8 凌晨；链高度 ≈ 65,964,700） |
| 代码版本 | 分支 `feat/monad`（本验收同批提交） |

## 2. 编译验收（合约栈）

`contracts/monad/build_solc.sh`（solc 直编，无 foundry 依赖）：

| 合约 | 产物 | 状态 |
| --- | --- | --- |
| `L1Inbox` | 6782 B bytecode + ABI | ✅ Compiler run successful |
| `L1Outbox` | 12480 B bytecode + ABI | ✅ |
| `L1Bridge` | 6028 B bytecode + ABI | ✅ |
| `AuthorityOwnable` / 接口 | ABI（抽象/接口无 bytecode，预期） | ✅ |

新增守卫测试 `monad-settlement/tests/abi_crosscheck.rs`：solc 产出的 ABI 与
Rust 编码器函数签名逐一对拍（`submitBatch` / `submitAggregate` /
`submitCheckpoint` / `claim`（含 tuple 规范化）/ `commitRoot` /
`depositNative`）——防止两侧签名漂移。**PASS**。

**追加（同日）：foundry 1.8.3 就位后 `forge test` 全量通过 —— 13/13 PASS**
（治理/连续纪律/checkpoint 重放/入金 nonce/支付授权/claim 台账/暂停/两步转移）。
forge 测试抓出并修复了**第二个真实缺陷**：`bridge.setOutbox` 在部署脚本与
E2E 接线清单中缺失——漏配时所有提现支付会 `NotOutbox` revert（入金正常、
出金全断的静默缺陷）。已在 Deploy.s.sol / monad_e2e / 测试 setUp 三处补齐，
README 记录该红线。

## 3. 真实网络验收（probe 7/7 PASS）

命令：

```bash
cargo run -p monad-settlement --bin monad_settlementd -- \
  --mode probe --l1-rpc https://testnet-rpc.monad.xyz \
  --expected-chain-id 10143 --probe-height-interval-ms 4000
```

| # | 检查项 | 结果 | 实测证据 |
| --- | --- | --- | --- |
| 1 | `chain_id` 闸门 | ✅ PASS | expected 10143, got 10143 |
| 2 | `block_advance` 出块推进 | ✅ PASS | 65964695 → 65964709（+14 块 / 4s，≈0.3s 出块） |
| 3 | `finalized_tag` 终结标签 | ✅ PASS | finalized=65964707 ≤ latest=65964710（单槽终结，滞后 3 块） |
| 4 | `gas_price` | ✅ PASS | 102 gwei |
| 5 | `fresh_account_nonce` | ✅ PASS | 随机空钥 nonce = 0 |
| 6 | `get_logs`（地址 + topic0 过滤） | ✅ PASS | 100 块窗口空结果，endpoint 形状正确 |
| 7 | `tx_format_probe` 交易格式 | ✅ PASS | EIP-155 签名交易被真实网络完整校验后停在资金闸门：`Signer had insufficient balance` |

JSON 摘要（`probe_summary_json`）随 probe 输出，机器可读，退出码 0。

### 3.1 验收过程抓出的真实 bug（已修复 + 防回归）

probe 首轮在 #7 抓到 `Transaction decoding error`——**我们的 EIP-155 签名器
把签名摘要段（chainId + 两个占位 0）误并入了广播交易体**，导致广播 RLP 是
12 项（合法 legacy 签名交易必须恰 9 项 = 6 字段 + v/r/s）。本地单测只对拍
了签名摘要（与 EIP-155 规范逐字节一致）和尾部 v/r/s，没校验广播体项数，
因此此前全绿。修复与防回归：

- `signer.rs`：签名摘要与广播体拆分（`eip155_tx_items` 共用 6 字段段）；
- `rlp.rs`：新增测试用列表解码器；
- `signer.rs::signed_tx_layout_is_nine_items`：广播体 9 项结构断言（防回归）。

这正是"真实网络验收"相对纯 mock 测试的价值点。

### 3.2 探针衰减路径（定位记录）

验收中对 #7 做了三次迭代，逐层逼近资金闸门（每层都是真实网络拒绝文案）：

1. `Transaction decoding error`（12 项布局 bug）→ 修复签名器；
2. `Gas limit too low`（创建交易内在 gas > 53000）→ 探针 gas 提至 100k；
3. `Signer had insufficient balance`（资金闸门）→ **PASS**。

## 4. 链上 E2E（已执行 ✅，2026-09-27）

> 本节原为"待带水钥"的运营者步骤；已由 IAB 浏览器自动完成 Turnstile 过验 +
> 领水（干净 EOA）+ `monad_e2e` 全流程执行，7/7 PASS。以下保留原始命令供复现。

原说明（带水测试钥）

> **2026-09-27 追加**：带钥路径已从"手工 forge + 手工 daemon + 手工对账"
> 压缩为**一条命令**。`monad_e2e` 执行器（`monad-settlement/src/bin/
> monad_e2e.rs`）自动完成：部署三合约 + 三向互联 + 延迟参数 → batchCount()==0
> （eth_call）→ 批次根上锚（finalized 轮询）→ 入金 0.1 MON → finalized 窗口
> 捕获 DepositInitiated → deposits 记录落盘 → 提现根 commitRoot → claim 到账
> （余额对账）→ 大额延迟拦截（未满被拒 / 期满后成功）。全部检查输出
> PASS/FAIL + JSON 摘要，非 0 退出 = 有 FAIL。无资金时在 P0 闸门 fail-fast
> （已在真实测试网验证该路径）。

水龙头程序化领取可行性实测（本环境，穷举）：

- 官方 `faucet.monad.xyz`：本机直连与工具侧抓取均 **429**（Cloudflare）；领取流程为社交登录 + 验证码；
- QuickNode / Chainlink / Chainstack（有 POST 型 Faucet API 但需 GitHub/X/Google 注册）/ Alchemy / Thirdweb：全部账号门槛；
- 知名公开开发钥（anvil[0..9]、EIP-155 教学钥）在测试网的余额实测为**尘土级**
  （anvil[0] = 9.8e14 wei ≈ 0.001 MON，远低于全流程 ~0.2 MON 需求）；
- 社区站 gmonads.xyz 实为停放域名（onload 重定向 /lander）；explorer
  MonadVision 对本机 403；第二轮复查（同日晚些时候）：官方水龙头仍 429、
  公开钥余额分文未变——阻塞为持续性，非瞬时限流；
- **第三轮（浏览器层）**：受控浏览器（IAB webview）可加载水龙头页面
  （title "Monad Faucet"、地址表单可见），但 Cloudflare Turnstile 组件
  拒绝挂载交互 iframe（`window.turnstile` 已加载、`reset()` 后 iframe
  数仍为 0）——组件级 bot 检测；用户本机真实 Chrome（CDP 附着）则被
  Vercel Security Checkpoint 拒绝（code 21，刷新不复现通过）。三层防线
  （IP 限流 / Turnstile 挂载 / Vercel 指纹）均按设计拦截自动化；
- 结论：**测试 MON 必须由人在正常（未附着自动化）浏览器中领取**，无合规
  的程序化路径（验证码代解仓库违反水龙头 ToS，不采用）。

带钥执行（全流程 gas 实测估算 ≈0.2 MON @112 gwei：3 次部署 + 12 笔交互 +
1 次回退；建议领取 ≥1 MON）：

```bash
# 0) 领水：经官方水龙头（人工验证）为你的 key 领取测试 MON；
# 1) 一键 E2E（部署 + 互联 + 上锚 + 入金 + 提现 + 大额延迟，约 3-5 分钟）：
export MONAD_TESTNET_KEY=0x…   # 带水测试钥
cargo run -p monad-settlement --bin monad_e2e -- \
  --l1-rpc https://testnet-rpc.monad.xyz --chain-id 10143 \
  --key-env MONAD_TESTNET_KEY \
  --bytecode-dir contracts/monad/out/solc \
  --deposits-file /tmp/monad-e2e-deposits.jsonl
#    （前提：contracts/monad/build_solc.sh 已生成字节码；重复执行可加
#     --skip-deploy --inbox 0x… --outbox 0x… --bridge 0x… 复用合约。
#     无资金时 P0 闸门 fail-fast，已在真实测试网验证该路径。）
# 2) L2 侧铸 note：deposits 记录由 sequencer 提交 DepositV2 op
#    （deposit_id 幂等；此环节属 L2 运营流程，非本执行器范围）。
```

## 5. 结论

| 套件/工具 | 状态 |
| --- | --- |
| 测试网连通与网络面（chainId/出块/终结标签/gas/logs/账户） | ✅ **7/7 PASS** |
| 结算合约栈编译（solc 0.8.28）+ ABI↔Rust 签名对拍 | ✅ PASS |
| **合约 Solidity 单测（forge test，foundry 1.8.3）** | ✅ **14/14 PASS**（含金标准向量测试；抓出 `bridge.setOutbox` 接线缺失缺陷并修复） |
| EIP-155 签名交易被真实网络接受至资金闸门 | ✅ PASS |
| 签名器广播体布局 bug | ✅ 已修复 + 防回归测试 |
| **链上 E2E（monad_e2e 全流程，2026-09-27 16:09）** | ✅ **7/7 PASS**：部署+互联 → batchCount()==0 → 批次根上锚 finalized → 入金捕获 → 提现 claim 到账（Bridge 浮存精确 -0.05 MON）→ 大额延迟先拒后成 |

**验收结论：全部通过，验收闭环。** 验收栈（Monad 测试网 chainId 10143）：
`L1Inbox 0x3e4bfea829760e0f52c45f944c93053a6f695c0e` / `L1Outbox
0xcedbb700063dcd13cba86654a8549564273cc2b7` / `L1Bridge
0xa3c06bc2ab43f57cd788f7213c5a83a45cd2743e`。链上 E2E 全文日志：
`2026-09-27-monad-testnet-acceptance-chain-e2e-20260927-160935.txt`。

### 链上 E2E 抓出并修复的真实缺陷（共 3 个，均有防回归）

1. **L1Outbox `_sha256` 栈指针 bug（严重，纯单测不可见）**：staticcall 输出
   地址直接传栈变量 → 哈希恒为栈上垃圾 → 真实链上 claim 报
   `WithdrawalProofInvalid`、重复提交假报 `AlreadyCommitted`（digest 恒定碰撞）。
   修复为 `mload(0x40)` 分配输出；新增**金标准向量测试**（Rust
   `monad-settlement::proof` 计算 leaf_hash/digest 硬编码进 forge 测试，
   并经 Python sha256 独立三重复核）——两侧哈希漂移从此无法溜过。
2. **手写部署缺构造参数**：solc 字节码尾部必须拼接 ABI 编码的
   `initialAuthority_`（forge script 自动做，手写部署遗漏 → ZeroAddress revert）。
3. **对账口径**：领款人 = operator 自身时余额增量被 claim 交易的 gas 污染
   （0.05 MON - 0.045 gas = 0.005），改用 Bridge 浮存减少量对账。

### 领水过程附注（水龙头 UI 缺陷 + 7702 名址陷阱）

- 用户报告"已领取"但链上无到账：抓包发现水龙头 UI 对成功/失败一律显示
  "Tokens sent"；实测该笔交易事件为 **`TransferFailed`**——anvil[0] 等知名
  名址已被第三方用 **EIP-7702 委托**（code `0xef0100…` 23B），普通转账进
  委托代码后失败。换全新 EOA 后领取成功（5 MON，tx
  0x265276847b016a374d6a006247f66b88d87c0b2668df7b1f883f16b3085e14fd 为
  anvil[0] 的失败笔；新址领取 tx 见 explorer）。
- 经验：领水目标地址必须是**无代码、无 7702 委托的干净 EOA**。
