//! Mental Poker 密码学层（移植自 `texas_poker_move/sources/bls_*.move` + 7 种 ZK proof）。
//!
//! 模块结构：
//! - `bls_scalar`：G1/Scalar 序列化 + hash_to_scalar + generate_plaintext_cards(52) + verify_dleq
//! - `bls_elgamal`：ElGamal 加密/解密/remask/re_encrypt/gen_reveal_token/add_pk_to_c2
//! - `transcript`：Fiat-Shamir Transcript（SHA3-256 + M-P13 长度前缀编码）
//! - `schnorr_proof`：广义 Schnorr 证明（多基点）
//! - `chaum_pedersen`：Chaum-Pedersen DLEq 证明
//! - `shuffle_proof`：3 层 Schnorr 洗牌证明（最复杂）
//! - `remask_proof`：Remask 操作证明
//! - `reveal_token_proof`：Reveal Token 证明
//! - `reconstruct_proof`：Reconstruct 阶段证明
//! - `leave_proof`：玩家离场证明
//! - `serialization`：proof 字节流 ↔ struct
//! - `zk_verifier`：统一 ZK 验证入口（含 zk_skip 回退）
//!
//! # 链上/链下分离
//!
//! - 链上（节点）：仅 verify（`verify_*` 函数）
//! - 链下（CLI 客户端）：prove（`#[cfg(feature = "client")] prove_*` 函数）
//!
//! # ZK 跳过回退（dev chain）
//!
//! `TableConfig.zk_skip_enabled = true` 时，[`zk_verifier::verify_or_skip`] 直接返回 true，
//! 便于首版跑通流程。mainnet 强制 false。

pub mod bls_elgamal;
pub mod bls_scalar;
pub mod chaum_pedersen;
pub mod leave_proof;
pub mod reconstruct_proof;
pub mod remask_proof;
pub mod reveal_token_proof;
pub mod schnorr_proof;
pub mod serialization;
pub mod shuffle_proof;
pub mod transcript;
pub mod zk_verifier;
