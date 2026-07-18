//! PrecompileCircuitAdapter — 将 zkvm PrecompileCircuit 适配为
//! vm_common::precompile::PrecompileMetadata 元数据接口。
//!
//! # 单向桥接
//!
//! zkvm 电路 → 链上 PrecompileMetadata 元数据接口。
//!
//! 不实现完整 `call()` — 链上调用 zkvm 电路仍走 zkvm 自己的 host 执行路径。
//! adapter 仅提供：
//! 1. 元数据接口（`PrecompileMetadata`）供跨 VM 注册表管理
//! 2. `execute()` 方法（host 路径）供 prover 调用 build_ccs + assign_witness
//!
//! # 设计理由
//!
//! 完整 `call()` 统一需要解决 `ObjectID`/`ObjectDb`/`PokerL1Error` 等类型依赖，
//! 会破坏 vm-common "不含 ISA 语义" 原则或 17 业务合约零修改硬约束。
//! 推迟到有具体业务需求时再实现。当前 adapter 已满足：
//! - 跨 VM 元数据查询（id/name/version/is_gas_free）
//! - host 执行路径统一入口（execute()）

use vm_common::precompile::{PrecompileMetadata, precompile_id_from_name};

use crate::ccs::{Ccs, Fr};
use crate::error::ZkvmError;
use crate::precompiles::PrecompileCircuit;

/// 包装 zkvm PrecompileCircuit，实现 PrecompileMetadata。
///
/// 用法：
/// ```ignore
/// use poker_zkvm::precompiles::adapter::PrecompileCircuitAdapter;
/// use poker_zkvm::precompiles::poseidon::PoseidonCircuit;
///
/// let poseidon = PoseidonCircuit::new_mvp();
/// let adapter = PrecompileCircuitAdapter::new(poseidon);
/// let _metadata: &dyn PrecompileMetadata = &adapter;
/// assert_eq!(adapter.name(), "poseidon");
/// ```
#[derive(Debug)]
pub struct PrecompileCircuitAdapter<T: PrecompileCircuit> {
    circuit: T,
    id_bytes: [u8; 32],
}

impl<T: PrecompileCircuit> PrecompileCircuitAdapter<T> {
    /// 创建 adapter（从 `circuit.name()` 生成稳定 ID）。
    ///
    /// 同名电路生成的 ID 相同（用于跨 VM 注册表查找）。
    #[must_use]
    pub fn new(circuit: T) -> Self {
        // 先计算 id_bytes（借用 circuit），再移动 circuit（避免 E0505）
        let id_bytes = precompile_id_from_name(circuit.name());
        Self {
            circuit,
            id_bytes,
        }
    }

    /// 访问内部电路（用于 host 执行路径直接调用 `build_ccs`/`assign_witness`）。
    pub fn circuit(&self) -> &T {
        &self.circuit
    }

    /// 执行电路（host 路径，不走 PrecompileMetadata 接口）。
    ///
    /// # 步骤
    ///
    /// 1. 调用 `assign_witness(inputs)` 得到 witness
    /// 2. 调用 `build_ccs()` 得到 Ccs
    /// 3. 验证 `ccs.satisfied_by(&witness)`
    /// 4. 返回 `(Ccs, witness)` 供 prover 使用
    ///
    /// # 错误
    ///
    /// - `ZkvmError::Other` — witness 赋值失败 / CCS 构建失败 / CCS 不满足
    pub fn execute(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        let witness = self.circuit.assign_witness(inputs)?;
        let ccs = self.circuit.build_ccs()?;
        if !ccs.satisfied_by(&witness)? {
            return Err(ZkvmError::Other(format!(
                "PrecompileCircuitAdapter: CCS not satisfied for circuit '{}'",
                self.circuit.name()
            )));
        }
        Ok((ccs, witness))
    }
}

impl<T: PrecompileCircuit + Send + Sync> PrecompileMetadata for PrecompileCircuitAdapter<T> {
    fn id_bytes(&self) -> [u8; 32] {
        self.id_bytes
    }

    fn name(&self) -> &str {
        self.circuit.name()
    }

    fn version(&self) -> u32 {
        1
    }

    fn is_gas_free(&self) -> bool {
        // zkvm 电路按 tx gas 计费，GameTurn 走 poker_l1 GamePrecompile（不是 adapter）
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::ZkvmField; // 引入 Fr::one() / Fr::from_u32_with_wrap() trait 方法
    use crate::precompiles::poseidon::PoseidonCircuit;
    use crate::precompiles::sha256::Sha256Circuit;

    #[test]
    fn test_adapter_implements_metadata() {
        let adapter = PrecompileCircuitAdapter::new(PoseidonCircuit::new_mvp());
        // 验证 trait object 可用
        let metadata: &dyn PrecompileMetadata = &adapter;
        assert_eq!(metadata.name(), "poseidon");
        assert_eq!(metadata.id_bytes()[0], 0xFF); // PRECOMPILE_PREFIX
        assert_eq!(metadata.version(), 1);
        assert!(!metadata.is_gas_free());
    }

    #[test]
    fn test_adapter_id_stable_per_name() {
        let a1 = PrecompileCircuitAdapter::new(PoseidonCircuit::new_mvp());
        let a2 = PrecompileCircuitAdapter::new(PoseidonCircuit::new_mvp());
        assert_eq!(
            a1.id_bytes(),
            a2.id_bytes(),
            "同名电路应生成相同 ID"
        );

        let b = PrecompileCircuitAdapter::new(Sha256Circuit::new_mvp());
        assert_ne!(
            a1.id_bytes(),
            b.id_bytes(),
            "不同名电路应生成不同 ID"
        );
    }

    #[test]
    fn test_adapter_circuit_accessor() {
        let adapter = PrecompileCircuitAdapter::new(PoseidonCircuit::new_mvp());
        // circuit() 访问器应返回内部电路
        assert_eq!(adapter.circuit().name(), "poseidon");
        assert_eq!(adapter.circuit().gas_cost(), 200); // MVP gas cost
    }

    #[test]
    fn test_adapter_execute_valid_witness() {
        // 用 Poseidon MVP 电路验证 execute() 返回满足的 CCS
        // MVP 接收 1 个 Fr 输入（单 S-box）
        let adapter = PrecompileCircuitAdapter::new(PoseidonCircuit::new_mvp());
        let inputs = vec![Fr::from_u32_with_wrap(3)];
        let (ccs, witness) = adapter.execute(&inputs).expect("execute 应成功");
        assert!(
            ccs.satisfied_by(&witness).expect("CCS 应满足"),
            "execute 返回的 CCS 应被 witness 满足"
        );
    }

    #[test]
    fn test_adapter_execute_invalid_witness() {
        // Poseidon MVP 期望 1 个输入，传 2 个应失败
        let adapter = PrecompileCircuitAdapter::new(PoseidonCircuit::new_mvp());
        let inputs = vec![Fr::one(), Fr::one()];
        let result = adapter.execute(&inputs);
        assert!(
            result.is_err(),
            "输入长度不符应返回错误"
        );
    }

    #[test]
    fn test_adapter_multiple_circuits_in_collection() {
        // 模拟跨 VM 注册表场景：多个 adapter 共存
        let adapters: Vec<Box<dyn PrecompileMetadata>> = vec![
            Box::new(PrecompileCircuitAdapter::new(PoseidonCircuit::new_mvp())),
            Box::new(PrecompileCircuitAdapter::new(Sha256Circuit::new_mvp())),
        ];

        assert_eq!(adapters.len(), 2);
        assert_eq!(adapters[0].name(), "poseidon");
        assert_eq!(adapters[1].name(), "sha256");

        // 验证 ID 互不相同
        assert_ne!(
            adapters[0].id_bytes(),
            adapters[1].id_bytes()
        );

        // 验证都是 0xFF 前缀
        assert_eq!(adapters[0].id_bytes()[0], 0xFF);
        assert_eq!(adapters[1].id_bytes()[0], 0xFF);
    }
}
