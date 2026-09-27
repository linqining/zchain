# contracts/monad — zchain L2 的 Monad(L1) 结算合约栈

zchain 扑克 appchain（poker-appchain，soft-confirm sequencer）作为 **Monad 的 L2**，
本目录是把 Monad 当结算层（settlement layer）的最小合约栈。设计文档与全景见
[docs/monad-l2-settlement.md](../../docs/monad-l2-settlement.md)。

## 合约一览

| 合约 | 职责 | 关键入口 |
| --- | --- | --- |
| `L1Inbox` | L2 批次根/聚合根/checkpoint 锚定（index 连续纪律，checkpoint 按 L2 高度防重放） | `submitBatch` / `submitAggregate` / `submitCheckpoint` |
| `L1Outbox` | 提现根注册 + Merkle 证明领取（逐字节镜像 Rust `withdrawal_root` 树构造） | `commitRoot` / `markFinalized` / `claim` |
| `L1Bridge` | 资产资金库：入金锁仓事件（L2 侧铸 note）、提现支付通道（onlyOutbox） | `depositNative` / `depositToken` / `payoutNative` / `payoutToken` |
| `AuthorityOwnable` | 公共基座：单一 authority（两步转移）+ 全局暂停 | — |

与以太坊 OP-stack 的差异（为什么是自部署而非官方接口）：Monad 是独立 L1，
没有原生 rollup 接口（portal/blob 语义），这套合约栈即"自建 Inbox/Outbox/Bridge"，
对应接入清单的模式 B（Monad = settlement layer）。

## 数据承诺对齐（关键！）

L1Outbox 的树构造与 `poker-appchain/src/withdrawal_root.rs` **逐字节一致**：

- 域标签：`zchain.vault.withdrawal_root.v1`
- 叶哈希：`sha256(DOMAIN ‖ 0x00 ‖ borsh(leaf))`（borsh = 32B request_id ‖ 32B
  external_recipient ‖ 1B asset_tag ‖ 8B LE amount ‖ 32B burned_note_commitment
  ‖ 8B LE checkpoint_height，共 113B）
- 内部节点：`sha256(DOMAIN ‖ 0x01 ‖ l ‖ r)`；不平衡补空叶 `sha256(DOMAIN ‖ 0x00 ‖ "")`
- 根摘要：`sha256(DOMAIN ‖ 0x02 ‖ height_be ‖ leaf_count_be ‖ root)`

两侧一致性由 `monad-settlement` crate 的交叉验证测试锁死（Rust 真实 builder 产根
/证明 → Solidity 等价 verifier 对拍），合约内 `claim` 与 Rust `verify_inclusion`
的 fail-closed 边界（证明深度 ≥64 拒绝、index 越界拒绝）亦对齐。

## 编译与测试

```bash
cd contracts/monad
curl -L https://foundry.paradigm.xyz | bash && foundryup   # 首次装 foundry
forge install --no-git foundry-rs/forge-std                # 首次装依赖
forge test                           # 单元测试：13 项（治理/重放/授权/入金/互联面）
forge build                          # 产出 out/
```

> 无 foundry 的环境可用 `./build_solc.sh`（solc 直编）做编译验收；Merkle/签名
> 字节级正确性由 Rust 侧测试（`monad-settlement/tests/`）与 forge 测试双面保障。
> 合约改动两侧必须同步。

## 部署（Monad 主网 chainId=143 / 测试网 10143）

```bash
export AUTHORITY_ADDRESS=0x…          # L2 sequencer/运营方（生产建议多签）
export MONAD_RPC_URL=https://rpc.monad.xyz
export PRIVATE_KEY=0x…                # 部署私钥
forge script script/Deploy.s.sol \
  --rpc-url monad --broadcast --verify
```

互联调用全部为 `onlyAuthority`，部署脚本会**校验 PRIVATE_KEY 就是 authority**
（不一致直接 revert；生产多签场景把 AUTHORITY_ADDRESS 设为多签地址并以其身份
完成 wire 四步）。脚本自动完成互联（`outbox.setInbox` / `outbox.setBridge` /
`inbox.setOutbox` / `bridge.setOutbox` —— 注意 `bridge.setOutbox` 漏配会导致
所有提现支付 `NotOutbox` 失败，forge 测试已覆盖此缺陷）、大额延迟（默认原生
MON ≥100 时延迟 30 块）与可选代币标签（USDT/USDC）配置。把输出的三个地址写入
`monad_settlementd` / `monad_e2e` 启动参数（见 runbook）。

## 审计关注点（对应接入清单 §6-7）

1. **最终性**：checkpoint 上锚前必须 L2 BFT finalized（daemon 纪律）；Monad 侧
   大额提现默认延迟 30 块（`claimDelayBlocks` + `largePayoutThreshold`）。
2. **重放**：checkpoint 同高度不可覆写；提现 `request_id` 全局记账；入金 nonce
   单调递增，L2 侧 `DepositV2.deposit_id` 幂等。
3. **资金路径**：Bridge 无 owner 提款——资金只能经 Outbox 证明路径流出；支付
   仅限 `onlyOutbox`；claim 先置 claimed 再支付（effects-before-interactions）。
4. **权限**：authority 两步转移；生产建议多签/ timelock；全局 pause 应急。
5. **字节对齐**：Outbox 树构造与 Rust 侧任何一侧改动都必须同步另一侧 + 测试。
