//! Trace → CCS 约束编译器（Phase 5 — Task 5.1）。
//!
//! 严格遵循 spec.md L268-279（v1.4 FROZEN）：
//! - [`compile_trace_to_ccs`] — 主入口，将 trace 按 `batch_size` 分批编译为 CCS 实例
//! - **Batching 策略**：每 K = [`ZKVM_BATCH_SIZE`]（默认 1024）步生成 1 个 CCS 实例
//! - **实例数上限**：≤ [`MAX_FOLD_STEP_COUNT`] = 1000（即 N ≤ 1,024,000 ≈ MAX_ZKVM_TRACE_STEPS）
//! - **连续性约束**：batch 内 step_index 单调递增（`idx_{i+1} - idx_i - 1 = 0`）
//! - **batch 间连续性**：通过 public_inputs 传递（前一 batch 末步 idx + 1 == 后一 batch 首步 idx）
//!
//! ## MVP 范围（Step 8）
//!
//! Step 8 仅实现 batching 框架 + step_index 连续性约束。
//! 指令子电路（算术 / 内存 / 控制流 / syscall）在 Step 9-12 实现，
//! 届时每步指令的语义约束将附加到本框架生成的 CCS 实例中。
//!
//! ## 子模块
//!
//! - [`algebra`] — 算术指令子电路（Step 9 实现）
//! - [`memory`] — 内存访问与一致性电路（Step 10 实现）
//! - [`control_flow`] — 控制流指令子电路（Step 11 实现）
//! - [`syscall_circuit`] — Syscall 子电路（Step 12 实现）
//! - [`lookup`] — LogUp lookup 协议（Step 13 实现）

pub mod algebra;
pub mod control_flow;
pub mod lookup;
pub mod memory;
pub mod syscall_circuit;

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::trace::Trace;

/// 默认 batch 大小（spec L276：K = 1024）。
///
/// 每 K 步执行生成 1 个 CCS 实例。
pub const ZKVM_BATCH_SIZE: usize = 1024;

/// 最大折叠步数（spec L277：MAX_FOLD_STEP_COUNT = 1000）。
///
/// `compile_trace_to_ccs` 返回的 CCS 实例数上限。
/// 即 trace 步数 N ≤ 1000 × 1024 = 1,024,000 ≈ MAX_ZKVM_TRACE_STEPS。
pub const MAX_FOLD_STEP_COUNT: usize = 1000;

/// 将 execution trace 编译为 CCS 实例列表（spec L268-279）。
///
/// 每 `batch_size` 步生成 1 个 CCS 实例，返回 ⌈N/K⌉ 个实例。
/// 实例数 ≤ [`MAX_FOLD_STEP_COUNT`]，超出返回 [`ZkvmError::FoldStepCountExceeded`]。
///
/// # 参数
/// - `trace` — 执行轨迹
/// - `batch_size` — 每批步数（须 > 0，默认用 [`ZKVM_BATCH_SIZE`]）
///
/// # 返回
/// - `Ok(Vec<CcsInstance>)` — CCS 实例列表（长度 = ⌈N/K⌉）
/// - `Err(ZkvmError)` — batch_size 为 0 / 实例数超限 / 内部编译错误
///
/// # 闭环验证
///
/// ```text
/// let instances = compile_trace_to_ccs(&trace, ZKVM_BATCH_SIZE)?;
/// assert!(instances.len() <= MAX_FOLD_STEP_COUNT);
/// for inst in &instances {
///     assert!(inst.is_satisfied()?);
/// }
/// ```
///
/// # 错误
/// - `ZkvmError::Other` — batch_size 为 0 或 trace 为空
/// - `ZkvmError::FoldStepCountExceeded` — 实例数 > MAX_FOLD_STEP_COUNT
pub fn compile_trace_to_ccs(
    trace: &Trace,
    batch_size: usize,
) -> Result<Vec<CcsInstance>, ZkvmError> {
    if batch_size == 0 {
        return Err(ZkvmError::Other(
            "compile_trace_to_ccs: batch_size 须 > 0".to_string(),
        ));
    }
    if trace.is_empty() {
        return Err(ZkvmError::Other(
            "compile_trace_to_ccs: trace 为空".to_string(),
        ));
    }

    let num_steps = trace.len();
    let num_batches = num_steps.div_ceil(batch_size);

    if num_batches > MAX_FOLD_STEP_COUNT {
        return Err(ZkvmError::FoldStepCountExceeded {
            actual: num_batches as u32,
            limit: MAX_FOLD_STEP_COUNT as u32,
        });
    }

    let mut instances = Vec::with_capacity(num_batches);
    for batch_id in 0..num_batches {
        let start = batch_id * batch_size;
        let end = usize::min(start + batch_size, num_steps);
        let batch_steps: Vec<&crate::trace::Step> =
            (start..end).map(|i| trace.step(i)).collect::<Result<Vec<_>, _>>()?;
        let instance = compile_batch_to_ccs(&batch_steps, batch_id as u64)?;
        instances.push(instance);
    }

    Ok(instances)
}

/// 编译单个 batch 为 CCS 实例（Step 8 MVP）。
///
/// # MVP 约束设计
///
/// witness 布局：`z = [1, idx_0, idx_1, ..., idx_{K-1}]`（长度 = K+1）
/// - `z[0] = 1`（常数项）
/// - `z[i+1] = step[i].step_index`（第 i 步的 step_index，i = 0..K-1）
///
/// 约束（K-1 行）：step_index 单调递增
/// ```text
/// Row i (i = 0..K-2): idx_{i+1} - idx_i - 1 = 0
/// ```
///
/// 矩阵（3 个，每个 (K-1) × (K+1)）：
/// - `M_plus`：row i, col i+2 = +1（idx_{i+1}）
/// - `M_minus`：row i, col i+1 = -1（idx_i）
/// - `M_const`：row i, col 0 = -1（常数 -1）
///
/// 子集：`S_0 = {0}, S_1 = {1}, S_2 = {2}`（线性约束，每个子集单矩阵）
/// 系数：`c_0 = 1, c_1 = 1, c_2 = 1`
///
/// public_inputs：`[batch_id, first_idx, last_idx]`（用于 batch 间连续性）
fn compile_batch_to_ccs(
    steps: &[&crate::trace::Step],
    batch_id: u64,
) -> Result<CcsInstance, ZkvmError> {
    let k = steps.len();
    if k == 0 {
        return Err(ZkvmError::Other(
            "compile_batch_to_ccs: batch 为空".to_string(),
        ));
    }

    let num_vars = k + 1;
    let num_rows = k.saturating_sub(1);

    // witness: z = [1, idx_0, idx_1, ..., idx_{K-1}]
    let mut witness = Vec::with_capacity(num_vars);
    witness.push(Fr::one());
    for step in steps {
        witness.push(Fr::from_u64(step.step_index));
    }

    // 3 个矩阵
    let mut m_plus = SparseMatrix::new(num_rows, num_vars);
    let mut m_minus = SparseMatrix::new(num_rows, num_vars);
    let mut m_const = SparseMatrix::new(num_rows, num_vars);

    let neg_one = Fr::zero().sub(&Fr::one());

    for i in 0..num_rows {
        // M_plus: row i, col (i+2) = +1
        m_plus.add_entry(i, i + 2, Fr::one())?;
        // M_minus: row i, col (i+1) = -1
        m_minus.add_entry(i, i + 1, neg_one)?;
        // M_const: row i, col 0 = -1
        m_const.add_entry(i, 0, neg_one)?;
    }

    let ccs = Ccs::new(
        num_vars,
        vec![m_plus, m_minus, m_const],
        vec![vec![0], vec![1], vec![2]],
        vec![Fr::one(), Fr::one(), Fr::one()],
    )?;

    // public_inputs: [batch_id, first_idx, last_idx]
    let first_idx = steps
        .first()
        .ok_or_else(|| ZkvmError::Other("batch 为空".to_string()))?
        .step_index;
    let last_idx = steps
        .last()
        .ok_or_else(|| ZkvmError::Other("batch 为空".to_string()))?
        .step_index;
    let public_inputs = vec![
        Fr::from_u64(batch_id),
        Fr::from_u64(first_idx),
        Fr::from_u64(last_idx),
    ];

    CcsInstance::new(ccs, witness, public_inputs)
}

/// 校验 batch 间连续性（前一 batch 末步 idx + 1 == 后一 batch 首步 idx）。
///
/// 每组 public_inputs 格式为 `[batch_id, first_idx, last_idx]`。
/// 校验：对相邻两组，`prev.last_idx + 1 == next.first_idx`。
///
/// 此函数由 verifier 在 fold 验证后调用，确保 batch 序列连续无间断。
pub fn verify_batch_continuity(public_inputs: &[Vec<Fr>]) -> bool {
    for w in public_inputs.windows(2) {
        let prev_last = &w[0];
        let next_first = &w[1];
        // public_inputs: [batch_id, first_idx, last_idx]
        if prev_last.len() < 3 || next_first.len() < 3 {
            return false;
        }
        // prev.last_idx + 1 == next.first_idx
        let expected_next = prev_last[2].add(&Fr::one());
        if expected_next != next_first[1] {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Instruction;
    use crate::trace::{MemAccess, MemOp, Step};

    /// 构造测试用 Step（step_index 可控，其余默认）。
    fn make_step(step_index: u64) -> Step {
        Step {
            step_index,
            pc: (step_index * 4) as u32,
            instruction: Instruction::Ecall,
            registers: [0u32; 32],
            mem_access: vec![],
        }
    }

    /// 构造测试用 Trace（n 步，step_index = 0..n-1）。
    fn make_trace(n: usize) -> Trace {
        let mut trace = Trace::new();
        for i in 0..n {
            trace.push_step(make_step(i as u64));
        }
        trace
    }

    #[test]
    fn test_compile_trace_empty_trace_errors() {
        let trace = Trace::new();
        let err = compile_trace_to_ccs(&trace, ZKVM_BATCH_SIZE).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("为空")));
    }

    #[test]
    fn test_compile_trace_zero_batch_size_errors() {
        let trace = make_trace(10);
        let err = compile_trace_to_ccs(&trace, 0).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("batch_size")));
    }

    #[test]
    fn test_compile_trace_single_batch() {
        let trace = make_trace(5);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 1);

        let inst = &instances[0];
        // num_vars = 5 + 1 = 6
        assert_eq!(inst.ccs.num_vars, 6);
        // 4 个连续性约束行（5-1=4）
        assert_eq!(inst.ccs.num_rows(), 4);
        // 3 个矩阵
        assert_eq!(inst.ccs.num_matrices(), 3);
        // witness 满足约束
        assert!(inst.is_satisfied().expect("应满足"));
        // public_inputs: [batch_id=0, first_idx=0, last_idx=4]
        assert_eq!(inst.public_inputs.len(), 3);
    }

    #[test]
    fn test_compile_trace_multiple_batches() {
        let trace = make_trace(25);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 3); // ⌈25/10⌉ = 3

        // batch 0: steps 0-9
        assert_eq!(instances[0].public_inputs[1], Fr::from_u64(0)); // first_idx
        assert_eq!(instances[0].public_inputs[2], Fr::from_u64(9)); // last_idx

        // batch 1: steps 10-19
        assert_eq!(instances[1].public_inputs[1], Fr::from_u64(10));
        assert_eq!(instances[1].public_inputs[2], Fr::from_u64(19));

        // batch 2: steps 20-24（部分 batch）
        assert_eq!(instances[2].public_inputs[1], Fr::from_u64(20));
        assert_eq!(instances[2].public_inputs[2], Fr::from_u64(24));

        // 全部满足约束
        for inst in &instances {
            assert!(inst.is_satisfied().expect("应满足"));
        }
    }

    #[test]
    fn test_compile_trace_default_batch_size() {
        let trace = make_trace(ZKVM_BATCH_SIZE + 1);
        let instances = compile_trace_to_ccs(&trace, ZKVM_BATCH_SIZE).expect("应成功");
        assert_eq!(instances.len(), 2);
    }

    #[test]
    fn test_compile_trace_exceeds_fold_step_count() {
        // 构造 trace 使 num_batches > MAX_FOLD_STEP_COUNT
        // batch_size=1 → num_batches = num_steps
        let n = MAX_FOLD_STEP_COUNT + 1;
        let trace = make_trace(n);
        let err = compile_trace_to_ccs(&trace, 1).unwrap_err();
        assert!(matches!(
            err,
            ZkvmError::FoldStepCountExceeded {
                actual,
                limit
            } if actual as usize == n && limit as usize == MAX_FOLD_STEP_COUNT
        ));
    }

    #[test]
    fn test_compile_trace_at_fold_step_limit() {
        // 恰好等于上限应成功
        let trace = make_trace(MAX_FOLD_STEP_COUNT);
        let instances = compile_trace_to_ccs(&trace, 1).expect("应成功");
        assert_eq!(instances.len(), MAX_FOLD_STEP_COUNT);
    }

    #[test]
    fn test_batch_continuity_constraint_satisfied() {
        // step_index 连续递增的 trace 应满足约束
        let trace = make_trace(10);
        let instances = compile_trace_to_ccs(&trace, 5).expect("应成功");
        assert_eq!(instances.len(), 2);

        // batch 0: steps 0-4
        assert!(instances[0].is_satisfied().expect("batch 0 应满足"));
        // batch 1: steps 5-9
        assert!(instances[1].is_satisfied().expect("batch 1 应满足"));

        // batch 间连续性：batch 0 last_idx(4) + 1 == batch 1 first_idx(5)
        let public_inputs: Vec<Vec<Fr>> = instances.iter().map(|i| i.public_inputs.clone()).collect();
        assert!(verify_batch_continuity(&public_inputs));
    }

    #[test]
    fn test_continuity_constraint_violated_by_gap() {
        // 构造 step_index 不连续的 trace（手动构造非连续 step_index）
        let mut trace = Trace::new();
        trace.push_step(make_step(0));
        trace.push_step(make_step(5)); // 跳跃！idx 0 → 5，差 5 不是 1
        trace.push_step(make_step(6));

        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 1);

        // 约束应不满足（idx_1 - idx_0 - 1 = 5 - 0 - 1 = 4 ≠ 0）
        let inst = &instances[0];
        assert!(!inst.is_satisfied().expect("应返回 false"));
    }

    #[test]
    fn test_batch_continuity_between_batches_violated() {
        // 构造 trace 使 batch 间不连续（通过手动修改 step_index）
        let mut trace = Trace::new();
        // batch 0 (batch_size=5): steps 0-4
        for i in 0..5 {
            trace.push_step(make_step(i));
        }
        // batch 1: steps 100-104（与 batch 0 末步 4 不连续）
        for i in 0..5 {
            trace.push_step(make_step(100 + i));
        }

        let instances = compile_trace_to_ccs(&trace, 5).expect("应成功");
        assert_eq!(instances.len(), 2);

        // batch 内部约束各自满足
        assert!(instances[0].is_satisfied().expect("batch 0 应满足"));
        assert!(instances[1].is_satisfied().expect("batch 1 应满足"));

        // batch 间连续性应失败：batch 0 last_idx(4) + 1 = 5 ≠ batch 1 first_idx(100)
        let public_inputs: Vec<Vec<Fr>> = instances.iter().map(|i| i.public_inputs.clone()).collect();
        assert!(!verify_batch_continuity(&public_inputs));
    }

    #[test]
    fn test_single_step_batch_no_continuity_constraint() {
        // 单步 batch（K=1）没有连续性约束（K-1=0 行）
        let trace = make_trace(1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 1);

        let inst = &instances[0];
        // num_vars = 1 + 1 = 2
        assert_eq!(inst.ccs.num_vars, 2);
        // 0 个约束行
        assert_eq!(inst.ccs.num_rows(), 0);
        // 仍然满足（空约束 vacuously true）
        assert!(inst.is_satisfied().expect("应满足"));
    }

    #[test]
    fn test_witness_layout() {
        // 验证 witness 布局：z = [1, idx_0, idx_1, ..., idx_{K-1}]
        let trace = make_trace(3);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        let inst = &instances[0];

        // z[0] = 1
        assert_eq!(inst.witness[0], Fr::one());
        // z[1] = idx_0 = 0
        assert_eq!(inst.witness[1], Fr::from_u64(0));
        // z[2] = idx_1 = 1
        assert_eq!(inst.witness[2], Fr::from_u64(1));
        // z[3] = idx_2 = 2
        assert_eq!(inst.witness[3], Fr::from_u64(2));
    }

    #[test]
    fn test_public_inputs_contain_batch_metadata() {
        let trace = make_trace(10);
        let instances = compile_trace_to_ccs(&trace, 4).expect("应成功");
        assert_eq!(instances.len(), 3); // ⌈10/4⌉ = 3

        // batch 0: [batch_id=0, first_idx=0, last_idx=3]
        assert_eq!(instances[0].public_inputs[0], Fr::from_u64(0)); // batch_id
        assert_eq!(instances[0].public_inputs[1], Fr::from_u64(0)); // first_idx
        assert_eq!(instances[0].public_inputs[2], Fr::from_u64(3)); // last_idx

        // batch 1: [batch_id=1, first_idx=4, last_idx=7]
        assert_eq!(instances[1].public_inputs[0], Fr::from_u64(1));
        assert_eq!(instances[1].public_inputs[1], Fr::from_u64(4));
        assert_eq!(instances[1].public_inputs[2], Fr::from_u64(7));

        // batch 2: [batch_id=2, first_idx=8, last_idx=9]
        assert_eq!(instances[2].public_inputs[0], Fr::from_u64(2));
        assert_eq!(instances[2].public_inputs[1], Fr::from_u64(8));
        assert_eq!(instances[2].public_inputs[2], Fr::from_u64(9));
    }

    #[test]
    fn test_batch_with_memory_access_steps() {
        // 含内存访问的 step 也应正确编译（MVP 不约束内存，仅约束 step_index 连续性）
        let mut trace = Trace::new();
        for i in 0..5 {
            let mut step = make_step(i);
            step.mem_access.push(MemAccess {
                addr: 0x100 + i as u32,
                op: MemOp::Write,
                value: i as u32,
                size: 4,
            });
            trace.push_step(step);
        }

        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 1);
        assert!(instances[0].is_satisfied().expect("应满足"));
    }

    #[test]
    fn test_large_batch_default_size() {
        // 测试默认 batch_size=1024 的边界
        let trace = make_trace(ZKVM_BATCH_SIZE);
        let instances = compile_trace_to_ccs(&trace, ZKVM_BATCH_SIZE).expect("应成功");
        assert_eq!(instances.len(), 1);
        // 1023 个连续性约束
        assert_eq!(instances[0].ccs.num_rows(), ZKVM_BATCH_SIZE - 1);
        assert!(instances[0].is_satisfied().expect("应满足"));
    }

    #[test]
    fn test_compile_trace_returns_correct_instance_count() {
        // 边界测试：N % K == 0
        let trace = make_trace(20);
        let instances = compile_trace_to_ccs(&trace, 5).expect("应成功");
        assert_eq!(instances.len(), 4);

        // N % K != 0
        let trace = make_trace(22);
        let instances = compile_trace_to_ccs(&trace, 5).expect("应成功");
        assert_eq!(instances.len(), 5); // ⌈22/5⌉ = 5
    }

    #[test]
    fn test_batch_id_monotonic() {
        let trace = make_trace(30);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 3);

        for (i, inst) in instances.iter().enumerate() {
            assert_eq!(inst.public_inputs[0], Fr::from_u64(i as u64));
        }
    }

    // ===== Phase 5 集成测试 =====

    #[test]
    fn test_phase5_integration_all_subcircuits_satisfied() {
        // 验证所有 Phase 5 子电路的 CCS 实例可独立构造且满足约束
        use crate::constraints::algebra::{AddCircuit, AndCircuit, SubCircuit};
        use crate::constraints::control_flow::{JalCircuit, LuiCircuit};
        use crate::constraints::lookup::LogUpProof;
        use crate::constraints::syscall_circuit::SyscallAbiCircuit;
        use crate::field::ZkvmField;

        // 算术子电路（associated function 调用，u32 参数）
        let add_witness = AddCircuit::assign_witness(100, 200);
        assert!(
            AddCircuit::build_ccs()
                .satisfied_by(&add_witness)
                .expect("Add CCS")
        );

        let sub_witness = SubCircuit::assign_witness(300, 100);
        assert!(
            SubCircuit::build_ccs()
                .satisfied_by(&sub_witness)
                .expect("Sub CCS")
        );

        let and_witness = AndCircuit::assign_witness(0b1010, 0b1100);
        assert!(
            AndCircuit::build_ccs()
                .satisfied_by(&and_witness)
                .expect("And CCS")
        );

        // 控制流子电路（associated function 调用）
        let jal_witness = JalCircuit::assign_witness(0x1000, 0x20);
        assert!(
            JalCircuit::build_ccs()
                .satisfied_by(&jal_witness)
                .expect("Jal CCS")
        );

        let lui_witness = LuiCircuit::assign_witness(0xABCDE);
        assert!(
            LuiCircuit::build_ccs()
                .satisfied_by(&lui_witness)
                .expect("Lui CCS")
        );

        // Syscall 子电路（实例方法，u32 参数）
        let syscall_abi = SyscallAbiCircuit::new(crate::syscalls::SyscallId::Poseidon);
        let abi_witness = syscall_abi.assign_witness(0x03);
        assert!(
            SyscallAbiCircuit::build_ccs()
                .satisfied_by(&abi_witness)
                .expect("SyscallAbi CCS")
        );

        // LogUp lookup 子电路
        let table = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(2)];
        let witness = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(2)];
        let multiplicity = vec![Fr::one(), Fr::one()];
        let (proof, commits) =
            LogUpProof::create(table, witness, multiplicity).expect("LogUp create");
        assert!(proof.verify(&commits).expect("LogUp verify"));
        let logup_instance = proof.to_ccs_instance().expect("LogUp CCS instance");
        assert!(logup_instance.is_satisfied().expect("LogUp is_satisfied"));
    }

    #[test]
    fn test_phase5_integration_memory_byte_expansion() {
        // 内存子电路：byte-level permutation 展开
        use crate::constraints::memory::expand_to_bytes;
        use crate::trace::{MemAccess, MemOp};

        // LW 4 字节写
        let lw_access = MemAccess {
            addr: 0x1000,
            op: MemOp::Write,
            value: 0xDEADBEEF,
            size: 4,
        };
        let bytes = expand_to_bytes(&lw_access, 42).expect("expand_to_bytes");
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0].byte_addr, 0x1000);
        assert_eq!(bytes[0].byte_val, 0xEF); // little-endian
        assert_eq!(bytes[1].byte_val, 0xBE);
        assert_eq!(bytes[2].byte_val, 0xAD);
        assert_eq!(bytes[3].byte_val, 0xDE);
        assert_eq!(bytes[0].step_index, 42);

        // LB 1 字节读
        let lb_access = MemAccess {
            addr: 0x1000,
            op: MemOp::Read,
            value: 0xEF,
            size: 1,
        };
        let bytes = expand_to_bytes(&lb_access, 43).expect("expand_to_bytes");
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0].byte_val, 0xEF);
    }

    #[test]
    fn test_phase5_integration_memory_uninitialized_read_detection() {
        // 内存子电路：未初始化读取检测
        use crate::constraints::memory::{check_uninitialized_read, ByteAccess};

        // write 在 step 10，read 在 step 20 → 合法
        let writes = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 42,
            step_index: 10,
        }];
        let reads = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 42,
            step_index: 20,
        }];
        assert!(
            check_uninitialized_read(&reads, &writes).is_ok(),
            "read-after-write 应合法"
        );

        // read 在 step 5，write 在 step 10 → 未初始化读取
        let reads_early = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 42,
            step_index: 5,
        }];
        assert!(
            check_uninitialized_read(&reads_early, &writes).is_err(),
            "write-before-read 应检测为未初始化读取"
        );
    }

    #[test]
    fn test_phase5_integration_logup_with_u8_range() {
        // 端到端：u8 range table + 多个 witness 值
        use crate::constraints::lookup::{compute_multiplicity, LogUpProof, LookupTable};
        use crate::field::ZkvmField;

        let table = LookupTable::u8_range();
        let witness: Vec<Fr> = [0, 1, 127, 128, 255, 42, 42, 100]
            .iter()
            .map(|v| Fr::from_u32_with_wrap(*v))
            .collect();
        let multiplicity = compute_multiplicity(&table, &witness);

        // 验证 multiplicity 正确性
        assert_eq!(multiplicity[0], Fr::one(), "0 出现 1 次");
        assert_eq!(multiplicity[1], Fr::one(), "1 出现 1 次");
        assert_eq!(multiplicity[42], Fr::from_u32_with_wrap(2), "42 出现 2 次");

        let (proof, commits) =
            LogUpProof::create(table.entries, witness, multiplicity).expect("LogUp create");
        assert!(proof.verify(&commits).expect("LogUp verify 应通过"));
    }

    #[test]
    fn test_phase5_integration_logup_with_truth_tables() {
        // 端到端：AND/OR/XOR 真值表 lookup
        use crate::constraints::lookup::{compute_multiplicity, LogUpProof, LookupTable};

        for table in [
            LookupTable::and_truth_table(),
            LookupTable::or_truth_table(),
            LookupTable::xor_truth_table(),
        ] {
            // witness = 所有表项（每个引用 1 次）
            let witness = table.entries.clone();
            let multiplicity = compute_multiplicity(&table, &witness);

            let (proof, commits) =
                LogUpProof::create(table.entries, witness, multiplicity).expect("LogUp create");
            assert!(
                proof.verify(&commits).expect("LogUp verify"),
                "真值表 lookup 应通过"
            );
        }
    }

    #[test]
    fn test_phase5_integration_compile_trace_with_ecall() {
        // 集成测试：compile_trace_to_ccs 处理含 ECALL 指令的 trace
        let trace = make_trace(10);
        let instances = compile_trace_to_ccs(&trace, ZKVM_BATCH_SIZE).expect("应成功");
        assert_eq!(instances.len(), 1, "10 步 / 1024 batch = 1 实例");
        // 每个 instance 的 witness 应非空
        assert!(!instances[0].witness.is_empty());
        // 每个 instance 应满足 CCS 约束
        assert!(
            instances[0].is_satisfied().expect("is_satisfied"),
            "batch CCS 实例应满足约束"
        );
    }

    #[test]
    fn test_phase5_integration_multiple_batches_continuity() {
        // 集成测试：多 batch 连续性 — batch_id 单调递增
        let trace = make_trace(2500);
        let instances = compile_trace_to_ccs(&trace, 1024).expect("应成功");
        assert_eq!(instances.len(), 3, "2500 步 / 1024 = 3 batches");

        // batch_id 单调递增
        for (i, inst) in instances.iter().enumerate() {
            assert_eq!(inst.public_inputs[0], Fr::from_u64(i as u64));
        }

        // 所有 batch 的 CCS 实例应满足约束
        for inst in &instances {
            assert!(inst.is_satisfied().expect("is_satisfied"));
        }
    }

    #[test]
    fn test_phase5_integration_logup_ccs_foldable() {
        // 验证 LogUp 的 CCS 实例结构可被 Hypernova 折叠
        // （num_vars / num_matrices / num_rows 合理）
        use crate::constraints::lookup::LogUpProof;
        use crate::field::ZkvmField;

        let table = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(2)];
        let witness = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(2)];
        let multiplicity = vec![Fr::one(), Fr::one()];

        let (proof, _) = LogUpProof::create(table, witness, multiplicity).expect("create");
        let instance = proof.to_ccs_instance().expect("to_ccs_instance");

        // CCS 结构合理性
        assert!(instance.ccs.num_vars >= 3, "num_vars 应 >= 3");
        assert!(instance.ccs.num_matrices() >= 2, "num_matrices 应 >= 2");
        assert!(instance.ccs.num_constraints() >= 2, "num_constraints 应 >= 2");
        assert!(instance.ccs.num_rows() >= 1, "num_rows 应 >= 1");

        // witness 长度 = num_vars
        assert_eq!(instance.witness.len(), instance.ccs.num_vars);

        // CCS 满足
        assert!(instance.is_satisfied().expect("is_satisfied"));
    }
}
