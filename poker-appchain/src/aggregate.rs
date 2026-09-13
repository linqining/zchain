//! M4 outer aggregate：批次根的**定期二级聚合**（outer batch aggregation）。
//!
//! 证明管道按批产出 [`crate::pipeline::BatchRoot`]；本模块把「自上次聚合
//! 以来」的批次根序列折叠为单一 32B **聚合根**，供锚定/观测/审计消费
//! （`AggregateRecord`，由 sequencer sidecar `aggregate.log` 持久化、
//! watcher 独立重算校验、explorer 网关只读展示）。
//!
//! ## 聚合根定义（冻结，见 docs/ABI.md §「聚合根」）
//!
//! 与 [`crate::pipeline::batch_root`] 同构的确定性 Poseidon 折叠（hi/lo
//! 无损拆分），仅域标签不同：
//!
//! ```text
//! fold_0 = 0
//! fold_i = poseidon_hash_many([fold_{i-1}, hi_i, lo_i])   // root 32B → hi/lo
//! aggregate_root = felt_to_bytes32(poseidon_hash_many([D, fold_n]))
//! D = domain_felt("poker-appchain.aggregate_root.v1")
//! ```
//!
//! - 空输入 → Err（空窗口不产生聚合根，fail-closed）；
//! - 单根 → `fold(0, root)` 仍在**独立域**下产生与 batch_root 不同的聚合值；
//! - n ≥ 2 时 fold 严格依赖根序（交换两根得到不同聚合根）。

use starknet_crypto::{FieldElement, poseidon_hash_many};

use crate::error::{AppchainError, AppchainResult};
use crate::felt::{DOMAIN_AGGREGATE_ROOT, bytes32_to_felts, domain_felt, felt_to_bytes32};

/// 聚合根（批次根序列的确定性 Poseidon 折叠，算法见模块文档与
/// docs/ABI.md §「聚合根」）。
///
/// # Errors
/// 空输入 → [`AppchainError::AdmissionRejected`]（空窗口不产生聚合根）。
pub fn aggregate_roots(roots: &[[u8; 32]]) -> AppchainResult<[u8; 32]> {
    if roots.is_empty() {
        return Err(AppchainError::AdmissionRejected("empty aggregate window"));
    }
    let mut fold = FieldElement::ZERO;
    for r in roots {
        let (hi, lo) = bytes32_to_felts(r);
        fold = poseidon_hash_many(&[fold, hi, lo]);
    }
    Ok(felt_to_bytes32(&poseidon_hash_many(&[
        domain_felt(DOMAIN_AGGREGATE_ROOT),
        fold,
    ])))
}

/// 一条聚合记录（`aggregate.log` sidecar 与网关/watcher 的共同数据形状）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregateRecord {
    /// 聚合序号（从 0 起连续递增）。
    pub index: u64,
    /// 覆盖到的最大帧序号（= 本窗口最后一个批次的 `through_op`）。
    pub through_op: u64,
    /// 聚合根（32B）。
    pub root: [u8; 32],
    /// 记录时间（毫秒；由触发方时钟给入）。
    pub ts_ms: u64,
    /// 本窗口折叠的批次根数量。
    pub batch_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// golden：不经 [`aggregate_roots`] 代码路径，手工按文档算法展开算期望，
    /// 并冻结十六进制常量（防 Poseidon 参数/域标签/编码被无声更改）。
    #[test]
    fn aggregate_roots_golden_vector() {
        let r1 = [0xAAu8; 32];
        let r2 = [0xBBu8; 32];
        let (h1, l1) = bytes32_to_felts(&r1);
        let (h2, l2) = bytes32_to_felts(&r2);
        let fold1 = poseidon_hash_many(&[FieldElement::ZERO, h1, l1]);
        let fold2 = poseidon_hash_many(&[fold1, h2, l2]);
        let d = domain_felt(DOMAIN_AGGREGATE_ROOT);
        let expect = felt_to_bytes32(&poseidon_hash_many(&[d, fold2]));
        assert_eq!(aggregate_roots(&[r1, r2]).unwrap(), expect);
        // 冻结 golden 常量
        assert_eq!(
            hex::encode(aggregate_roots(&[r1, r2]).unwrap()),
            "02e0fb4c5fd664605e11765c6ad2928346d4f87fc68971c229354576c069a1bd"
        );
    }

    #[test]
    fn empty_window_rejected_single_root_independent_domain() {
        // 空输入 → Err（fail-closed）
        assert!(matches!(
            aggregate_roots(&[]).unwrap_err(),
            AppchainError::AdmissionRejected("empty aggregate window")
        ));
        // 单根 → 独立域下的聚合值 ≠ batch_root（域分隔生效）
        let root = [0x11u8; 32];
        let agg = aggregate_roots(&[root]).unwrap();
        assert_ne!(agg, [0u8; 32]);
        assert_ne!(agg, crate::pipeline::batch_root(&[root]).unwrap());
    }

    #[test]
    fn order_sensitive_and_distinct_from_batch_root() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        // 根序敏感
        assert_ne!(
            aggregate_roots(&[a, b]).unwrap(),
            aggregate_roots(&[b, a]).unwrap()
        );
        // 与 batch_root 域不同（同输入不同输出）
        assert_ne!(
            aggregate_roots(&[a, b]).unwrap(),
            crate::pipeline::batch_root(&[a, b]).unwrap()
        );
    }
}
