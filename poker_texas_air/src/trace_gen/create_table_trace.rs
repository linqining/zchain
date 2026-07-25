//! `create_table` 方法的 trace 生成器。
//!
//! 从 [`CreateTableInput`] + pre/post state 直接构造 trace（不经 RV32IM 执行）。

use stwo::core::fields::m31::M31;

use crate::airs::common::ZERO;
use crate::airs::lifecycle::create_table::{
    CreateTableAir, CreateTableInput, CreateTableRow,
};
use crate::error::TexasAirResult;
use crate::state_root::{compute_state_root, StateRoot};
use crate::trace_gen::MethodTrace;

/// `create_table` trace 生成器输出。
#[derive(Debug, Clone)]
pub struct CreateTableTrace {
    /// 业务 trace 数据。
    pub trace: MethodTrace,
    /// 配套的 AIR 公开输入。
    pub air: CreateTableAir,
}

/// 生成 `create_table` trace。
///
/// # 参数
/// - `input`: create_table 输入参数
/// - `pre_table`: 调用前的 TexasPokerTable
/// - `post_table`: 调用后的 TexasPokerTable（执行 `TexasPokerTable::new` + `bump_version` 后）
/// - `table_id`: 表台 ID
/// - `hand_id`: 手牌序号
/// - `call_seq`: 调用序号
///
/// # 返回
/// `CreateTableTrace`，含 trace 数据与 AIR 公开输入。
///
/// # Errors
///
/// 当 state_root 计算失败或 trace 写入失败时返回错误。
pub fn gen_create_table_trace(
    input: CreateTableInput,
    pre_table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
    post_table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
    table_id: u64,
    hand_id: u32,
    call_seq: u32,
) -> TexasAirResult<CreateTableTrace> {
    // 1. 计算 pre/post state_root
    let pre_root: StateRoot = compute_state_root(pre_table)?;
    let post_root: StateRoot = compute_state_root(post_table)?;

    // 2. 选择 log_size
    // create_table 是单步操作，trace 行数 = 1 + padding。
    // Stwo 要求 log_size >= 10 (1024 行)，所以 padding 到 log_size=10。
    let log_size: u32 = 10;

    // 3. 构造 active 行
    let active_row = CreateTableRow::active(
        &input,
        starknet_field_to_m31_limbs(pre_root.field()),
        starknet_field_to_m31_limbs(post_root.field()),
        table_id,
        hand_id,
        call_seq,
        pre_table.version,
        post_table.version,
    );

    // 4. 构造 trace
    let mut trace = MethodTrace::new(log_size, CreateTableAir::num_columns());
    trace.write_row(0, &active_row.to_vec())?;
    // 行 1..1024 为 padding
    let padding_row = CreateTableRow::padding();
    for i in 1..(1usize << log_size) {
        trace.write_row(i, &padding_row.to_vec())?;
    }

    // 5. 构造 AIR
    let air = CreateTableAir::new(
        log_size,
        input,
        starknet_field_to_m31_limbs(pre_root.field()),
        starknet_field_to_m31_limbs(post_root.field()),
        table_id,
        hand_id,
        call_seq,
        pre_table.version,
        post_table.version,
    );

    Ok(CreateTableTrace { trace, air })
}

/// 把 Starknet FieldElement 转为 4 个 M31 limb（简化版）。
///
/// 完整实现需要 8 limb（Starknet Fr 模数 ~2^252），
/// 阶段 1 PoC 用 4 limb 简化（覆盖 ~124 bit 范围）。
/// TODO 阶段 2：扩展为 8 limb 完整表示。
fn starknet_field_to_m31_limbs(f: starknet_ff::FieldElement) -> [M31; 4] {
    // 暂时用 0 占位（阶段 2 接入完整 Poseidon252 AIR 时实现）
    let _ = f;
    [ZERO; 4]
}
