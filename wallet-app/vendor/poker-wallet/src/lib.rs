//! # wallet-core — ZChain 共享钱包核心（plan-appchain §6.12.3）
//!
//! 先实现 Rust 核心，再编译为 WASM / 移动 / 桌面库；浏览器扩展、Web 钱包、
//! 桌面与移动应用不得各自实现一套密码学与 Note 逻辑。本 crate 是唯一实现。
//!
//! ## 模块地图
//!
//! - [`key_manager`]：secp256k1 owner key 生成/导入 + delegated/session key
//!   生成与约束执行（scope/限额/桌白名单/有效期/nonce/撤销，fail-closed）
//! - [`keystore`]：Argon2id + ChaCha20-Poly1305 平台无关加密信封；私钥
//!   zeroize；错误口令/篡改 fail-closed
//! - [`note_store`]：note + spend secret + nullifier + 创建帧 + proof 状态的
//!   加密存储；REAL/PLAY **物理分库**；按资产类聚合余额
//! - [`operation_signer`]：只接受结构化 [`operation_signer::SigningRequest`]，
//!   人类可读预览后签名；拒绝任意 bytes 签名、未知域标签、未知 ABI 版本、
//!   金额溢出（M6-ACC-7）与 session 越权（WALLET-ACC-3）
//! - [`account_binding`]：SNIP-12 `AuthorizeZChainKey` / `RevokeZChainKey`
//!   typed data + Poseidon 摘要 + Stark 签名验证 + binding 状态机与 admission
//!   纯函数（Appchain 侧可复用）
//! - [`verifier`]：接入 poker-appchain 校验面（validate_settlement、软确认帧、
//!   批次根 golden 复算），输出 verifier 版本 + digest + 状态层级
//! - [`backup`]：全库加密导出/导入（版本头 + AEAD + 完整性），错误口令/
//!   篡改/未来版本 fail-closed；恢复后索引自检
//! - [`sync`]：checkpoint/owner 索引同步 trait + 内存实现（断点续传、重组检测）
//! - [`vault_adapter`]：外部 Starknet 钱包能力探测（getCapabilities 风格）+
//!   deposit/claim 请求构造；不持有外部私钥
//! - [`display`]：REAL/PLAY 展示门状态机（WALLET-ACC-6，纯逻辑）
//!
//! ## 安全不变量（全 crate 生效）
//!
//! 1. 私钥/spend secret 只存在于 [`key_manager::SecretBytes`]（zeroize on
//!    drop），类型不实现会输出明文的 `Debug`；
//! 2. 任何密文校验失败（口令错、字节篡改、版本未来）一律 fail-closed 拒绝，
//!    不提供"尽力恢复"路径；
//! 3. 签名只对结构化请求 + 重建摘要发生，永远没有 `signBytes` 默认能力；
//! 4. REAL 与 PLAY 是两个物理独立的存储实例，跨库访问在类型层不可达。
//!
//! ## 网络边界
//!
//! 本 crate 不做任何网络 IO。`sync::ChainSource` 与 `vault_adapter::VaultProvider`
//! 是真实网络实现的接入缝，当前只提供内存实现（如实标注，不假装在线）。

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod account_binding;
pub mod backup;
pub mod display;
pub mod error;
pub mod key_manager;
pub mod keystore;
pub mod note_store;
pub mod operation_signer;
pub mod sync;
pub mod vault_adapter;
pub mod verifier;

pub use error::{WalletError, WalletResult};
