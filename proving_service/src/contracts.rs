//! 合约插件实现集合。
//!
//! 每个子模块是一个具体合约的插件实现。新合约只需在此新增模块并实现
//! [`crate::plugin::ContractPlugin`]。

pub mod texas_poker;

pub use texas_poker::TexasPokerPlugin;
