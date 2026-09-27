//! monad-settlement — zchain 扑克 appchain（L2）到 Monad（L1，chainId 143 主网
//! / 10143 测试网）的结算适配层。
//!
//! 定位（docs/monad-l2-settlement.md）：Monad 是独立 EVM 等价 L1，没有以太坊
//! 式原生 rollup 接口，结算走自部署合约栈（`contracts/monad/`：L1Inbox /
//! L1Outbox / L1Bridge）。本 crate 是该合约栈的 Rust 客户端面：
//!
//! | 模块 | 职责 |
//! | --- | --- |
//! | [`rlp`] / [`signer`] | 遗留交易 EIP-155 签名（Monad 全网接受；比 2930/1559 少一套类型面） |
//! | [`abi`] | 结算合约 calldata 编码 + 入金事件解码（函数 selector = keccak4） |
//! | [`proof`] | L1Outbox 树构造的**逐字节镜像**（与 `contracts/monad/src/L1Outbox.sol`、`poker-appchain::withdrawal_root` 三方对齐） |
//! | [`l1`] | Monad JSON-RPC 客户端（reqwest blocking；chainId/finality/receipt/logs） |
//! | [`anchor`] | 批次根/聚合根/checkpoint 上锚：队列 + nonce 管理 + 回执 + **finalized 跟踪** |
//! | [`watcher`] | `DepositInitiated` 事件监听（Monad → L2 铸 note 的触发源） |
//!
//! 最终性纪律（审计清单 §6）：L2 侧 checkpoint 必须 BFT finalized 之后才上锚；
//! Monad 侧以 `eth_getBlockByNumber("finalized")` 为准判定上锚交易不可逆；
//! 大额提现由 L1Outbox 的 `claimDelayBlocks` 出块延迟兜底。
//!
//! 生产装配 = [`bin/monad_settlementd`](../src/bin/monad_settlementd.rs) 守护
//! 进程（anchor / bridge 双模式），消费 explorer_gateway 的只读 API。

pub mod abi;
pub mod adapter;
pub mod anchor;
pub mod error;
pub mod keccak;
pub mod l1;
pub mod proof;
pub mod rlp;
pub mod signer;
pub mod watcher;

pub use abi::{ClaimLeaf, DepositEvent};
pub use anchor::{
    aggregate_task, anchor_task, checkpoint_task, claim_task_key, AnchorKind,
    AnchorState, AnchorSubmitter, AnchorTask,
};
pub use adapter::MonadAdapter;
pub use error::SettlementError;
pub use l1::L1Rpc;
pub use signer::Credentials;
pub use watcher::DepositWatcher;

/// Monad 主网 chainId（官方 docs.monad.xyz）。
pub const MONAD_MAINNET_CHAIN_ID: u64 = 143;
/// Monad 测试网 chainId。
pub const MONAD_TESTNET_CHAIN_ID: u64 = 10143;
