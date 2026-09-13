//! 类型化合约绑定（对标 aztec.js 生成的 `MyContract.at(address, wallet)`）。
//!
//! 每个绑定 = `at(address)` 拿句柄 + 视图读（async，走
//! [`ChainClient::call`]）+ 写调用构造器（`*_call` 产出
//! [`Call`]，可单独发也可与其它调用合并成 [`ChainClient::invoke_batch`] ——
//! 对标 aztec `BatchCall`）。入口名与 ABI 逐字一致（starknet_keccak 侧
//! 由 [`crate::codec::selector`] 统一）。

pub mod dual_settlement;
pub mod settlement;
pub mod strk;
pub mod table_registry;
pub mod vault;
