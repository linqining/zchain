//! Trace 数据结构（Phase 3 — Task 3.4 实现）。
//!
//! 本模块提供：
//! - [`Trace`] — 执行轨迹（`Vec<Step>`）
//! - [`Step`] — 单步记录（含 step_index / pc / instruction / registers / mem_access）
//! - [`StepLog`] — `execute()` 返回值（不含 step_index）
//! - [`MemAccess`] — 内存访问记录（含 `size` 字段防 LB 1B vs LW 4B aliasing）
//! - [`MemOp`] — 内存操作类型（Read / Write）
//!
//! 序列化采用自定义二进制流式格式（magic "TRCE" + version + steps），
//! 反序列化用 `checked_mul` 防 u64 溢出 + 超 `MAX_TRACE_HOST_MEMORY` 早夭。

use crate::error::ZkvmError;
use crate::isa::Instruction;

/// Trace host 内存上限（512MB，spec L258）。
pub const MAX_TRACE_HOST_MEMORY: usize = 512 * 1024 * 1024;

/// Trace 二进制格式 magic 头。
const TRACE_MAGIC: &[u8; 4] = b"TRCE";

/// Trace 二进制格式版本号。
const TRACE_VERSION: u32 = 1;

// ===========================================================================
// MemOp
// ===========================================================================

/// 内存操作类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemOp {
    /// 读
    Read,
    /// 写
    Write,
}

impl MemOp {
    /// 序列化为 1 byte（0=Read, 1=Write）。
    fn to_byte(self) -> u8 {
        match self {
            MemOp::Read => 0,
            MemOp::Write => 1,
        }
    }

    /// 从 1 byte 反序列化。
    fn from_byte(b: u8) -> Result<Self, ZkvmError> {
        match b {
            0 => Ok(MemOp::Read),
            1 => Ok(MemOp::Write),
            _ => Err(ZkvmError::InvalidZkProofFormat(format!(
                "invalid MemOp byte: {b}"
            ))),
        }
    }
}

// ===========================================================================
// MemAccess
// ===========================================================================

/// 内存访问记录（spec L256, L293）。
///
/// `size` 字段必须存在，防 LB 1B vs LW 4B aliasing（Phase 5 byte-level
/// permutation 的关键）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemAccess {
    /// 访问地址
    pub addr: u32,
    /// 读 / 写
    pub op: MemOp,
    /// 读 / 写的值
    pub value: u32,
    /// 访问尺寸（1 / 2 / 4 字节）
    pub size: u8,
}

impl MemAccess {
    /// 序列化为字节向量（10 bytes: 4+1+4+1）。
    fn serialize_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.addr.to_le_bytes());
        out.push(self.op.to_byte());
        out.extend_from_slice(&self.value.to_le_bytes());
        out.push(self.size);
    }

    /// 从字节切片反序列化（消耗 10 bytes）。
    fn deserialize_from(bytes: &[u8]) -> Result<(Self, usize), ZkvmError> {
        if bytes.len() < 10 {
            return Err(ZkvmError::InvalidZkProofFormat(
                "MemAccess too short".to_string(),
            ));
        }
        let addr = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let op = MemOp::from_byte(bytes[4])?;
        let value = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        let size = bytes[9];
        Ok((MemAccess { addr, op, value, size }, 10))
    }
}

// ===========================================================================
// StepLog
// ===========================================================================

/// 单步执行日志（`execute()` 返回值，不含 step_index）。
///
/// `execute()` 是纯单步函数，不感知全局 step_index。
/// executor 负责组装 [`Step`]（含 step_index）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepLog {
    /// 执行前 PC
    pub pc: u32,
    /// 执行的指令
    pub instruction: Instruction,
    /// 执行后寄存器快照（post-state）
    pub registers: [u32; 32],
    /// 本步触发的内存访问（读在前、写在后）
    pub mem_access: Vec<MemAccess>,
}

// ===========================================================================
// Step
// ===========================================================================

/// Trace 中的单步记录（executor 组装，含 step_index）。
///
/// 字段与 spec L256 一致：`(step_index, pc, instruction, registers[32], memory_access_log)`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// 步序号（从 0 开始单调递增）
    pub step_index: u64,
    /// 执行前 PC
    pub pc: u32,
    /// 执行的指令
    pub instruction: Instruction,
    /// 执行后寄存器快照
    pub registers: [u32; 32],
    /// 本步内存访问
    pub mem_access: Vec<MemAccess>,
}

impl Step {
    /// 由 executor 从 [`StepLog`] 组装。
    ///
    /// # Arguments
    /// * `step_index` — 步序号
    /// * `log` — `execute()` 返回的单步日志
    #[must_use]
    pub fn from_log(step_index: u64, log: StepLog) -> Self {
        Self {
            step_index,
            pc: log.pc,
            instruction: log.instruction,
            registers: log.registers,
            mem_access: log.mem_access,
        }
    }

    /// 估算单步的 host 内存占用（字节）。
    ///
    /// step_index(8) + pc(4) + insn_tag(1) + insn_fields(≤16) + registers(128) + mem_count(4) + mem_access(10×n)
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        8 + 4 + 1 + 16 + 128 + 4 + self.mem_access.len() * 10
    }
}

// ===========================================================================
// Trace
// ===========================================================================

/// 执行轨迹（spec L253-259）。
///
/// 包含 `Vec<Step>`，支持序列化/反序列化与 host 内存估算。
/// 步数上限 `MAX_ZKVM_TRACE_STEPS = 1_048_576`（spec L257）。
/// host 内存上限 `MAX_TRACE_HOST_MEMORY = 512MB`（spec L258）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    /// 步记录列表
    steps: Vec<Step>,
}

impl Trace {
    /// 创建空 Trace。
    #[must_use]
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// 返回步数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// 追加一步。
    pub fn push_step(&mut self, step: Step) {
        self.steps.push(step);
    }

    /// 获取第 `i` 步的引用。
    ///
    /// # Errors
    /// 越界返回 `ZkvmError::Other`。
    pub fn step(&self, i: usize) -> Result<&Step, ZkvmError> {
        self.steps
            .get(i)
            .ok_or_else(|| ZkvmError::Other(format!("step index {i} out of range")))
    }

    /// 返回步迭代器。
    pub fn iter(&self) -> impl Iterator<Item = &Step> {
        self.steps.iter()
    }

    /// 估算 host 内存占用（字节）。
    ///
    /// 用于 `execute_elf` 循环中检查 `MAX_TRACE_HOST_MEMORY` 上限。
    #[must_use]
    pub fn host_memory_usage(&self) -> usize {
        self.steps.iter().map(Step::estimated_size).sum()
    }

    /// 序列化为二进制格式。
    ///
    /// 格式：`[4B magic][4B version][8B num_steps][steps...]`
    /// 每 step：`[8B step_index][4B pc][1B insn_tag][insn fields][128B registers][4B mem_count][mem_access...]`
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.steps.len() * 160);
        out.extend_from_slice(TRACE_MAGIC);
        out.extend_from_slice(&TRACE_VERSION.to_le_bytes());
        out.extend_from_slice(&(self.steps.len() as u64).to_le_bytes());
        for step in &self.steps {
            serialize_step(step, &mut out);
        }
        out
    }

    /// 从二进制反序列化。
    ///
    /// 三步法：
    /// 1. 校验 magic + version
    /// 2. 读 num_steps，`checked_mul` 估算总大小，超 `MAX_TRACE_HOST_MEMORY` 早夭
    /// 3. 逐 step 解析
    ///
    /// # Errors
    /// - `ZkvmError::InvalidZkProofFormat` — magic/version 错误或数据截断
    /// - `ZkvmError::TraceHostMemoryExceeded` — 估算总大小超 512MB
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ZkvmError> {
        // 第 0 步：magic + version
        if bytes.len() < 16 {
            return Err(ZkvmError::InvalidZkProofFormat(
                "trace too short for header".to_string(),
            ));
        }
        if &bytes[0..4] != TRACE_MAGIC {
            return Err(ZkvmError::InvalidZkProofFormat(
                "bad magic: expected TRCE".to_string(),
            ));
        }
        let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if version != TRACE_VERSION {
            return Err(ZkvmError::InvalidZkProofFormat(format!(
                "unsupported trace version: {version}"
            )));
        }

        let num_steps = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);

        // 第 1 步：总大小估算 + 早夭
        let step_estimate = 160usize; // 每步估算上限
        let total_estimate = (num_steps as usize)
            .checked_mul(step_estimate)
            .ok_or(ZkvmError::TraceHostMemoryExceeded {
                actual: usize::MAX,
                limit: MAX_TRACE_HOST_MEMORY,
            })?;
        if total_estimate > MAX_TRACE_HOST_MEMORY {
            return Err(ZkvmError::TraceHostMemoryExceeded {
                actual: total_estimate,
                limit: MAX_TRACE_HOST_MEMORY,
            });
        }

        // 第 2 步：逐 step 解析
        let mut offset = 16usize;
        let mut steps = Vec::with_capacity(num_steps as usize);
        for i in 0..num_steps {
            let (step, consumed) = deserialize_step(&bytes[offset..])
                .map_err(|e| ZkvmError::InvalidZkProofFormat(format!("step {i}: {e}")))?;
            steps.push(step);
            offset += consumed;
        }

        Ok(Self { steps })
    }
}

impl Default for Trace {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// 序列化辅助函数
// ===========================================================================

/// 序列化单个 Step 到 `out`。
fn serialize_step(step: &Step, out: &mut Vec<u8>) {
    out.extend_from_slice(&step.step_index.to_le_bytes());
    out.extend_from_slice(&step.pc.to_le_bytes());
    serialize_instruction(&step.instruction, out);
    for &reg in &step.registers {
        out.extend_from_slice(&reg.to_le_bytes());
    }
    out.extend_from_slice(&(step.mem_access.len() as u32).to_le_bytes());
    for ma in &step.mem_access {
        ma.serialize_to(out);
    }
}

/// 反序列化单个 Step，返回 (Step, consumed_bytes)。
fn deserialize_step(bytes: &[u8]) -> Result<(Step, usize), ZkvmError> {
    let mut offset = 0;

    // step_index (8 bytes)
    if bytes.len() < offset + 8 {
        return Err(ZkvmError::InvalidZkProofFormat(
            "Step: step_index truncated".to_string(),
        ));
    }
    let step_index = u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]);
    offset += 8;

    // pc (4 bytes)
    if bytes.len() < offset + 4 {
        return Err(ZkvmError::InvalidZkProofFormat(
            "Step: pc truncated".to_string(),
        ));
    }
    let pc = u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]);
    offset += 4;

    // instruction
    let (instruction, insn_len) = deserialize_instruction(&bytes[offset..])?;
    offset += insn_len;

    // registers (128 bytes)
    if bytes.len() < offset + 128 {
        return Err(ZkvmError::InvalidZkProofFormat(
            "Step: registers truncated".to_string(),
        ));
    }
    let mut registers = [0u32; 32];
    for i in 0..32 {
        registers[i] = u32::from_le_bytes([
            bytes[offset + i * 4],
            bytes[offset + i * 4 + 1],
            bytes[offset + i * 4 + 2],
            bytes[offset + i * 4 + 3],
        ]);
    }
    offset += 128;

    // mem_access_count (4 bytes)
    if bytes.len() < offset + 4 {
        return Err(ZkvmError::InvalidZkProofFormat(
            "Step: mem_count truncated".to_string(),
        ));
    }
    let mem_count = u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]) as usize;
    offset += 4;

    // mem_access entries
    let mut mem_access = Vec::with_capacity(mem_count);
    for _ in 0..mem_count {
        let (ma, ma_len) = MemAccess::deserialize_from(&bytes[offset..])?;
        mem_access.push(ma);
        offset += ma_len;
    }

    Ok((
        Step {
            step_index,
            pc,
            instruction,
            registers,
            mem_access,
        },
        offset,
    ))
}

/// 序列化 Instruction 为 `[1B tag][fields]`。
///
/// tag 按枚举声明顺序（0=Lui, 1=Auipc, ..., 39=Ebreak）。
fn serialize_instruction(insn: &Instruction, out: &mut Vec<u8>) {
    macro_rules! w {
        ($tag:expr, $($field:expr),*) => {{
            out.push($tag);
            $(
                out.extend_from_slice(&$field.to_le_bytes());
            )*
        }};
    }
    match insn {
        Instruction::Lui { rd, imm } => w!(0, *rd as u32, *imm),
        Instruction::Auipc { rd, imm } => w!(1, *rd as u32, *imm),
        Instruction::Jal { rd, imm } => w!(2, *rd as u32, *imm),
        Instruction::Jalr { rd, rs1, imm } => w!(3, *rd as u32, *rs1 as u32, *imm),
        Instruction::Beq { rs1, rs2, imm } => w!(4, *rs1 as u32, *rs2 as u32, *imm),
        Instruction::Bne { rs1, rs2, imm } => w!(5, *rs1 as u32, *rs2 as u32, *imm),
        Instruction::Blt { rs1, rs2, imm } => w!(6, *rs1 as u32, *rs2 as u32, *imm),
        Instruction::Bge { rs1, rs2, imm } => w!(7, *rs1 as u32, *rs2 as u32, *imm),
        Instruction::Bltu { rs1, rs2, imm } => w!(8, *rs1 as u32, *rs2 as u32, *imm),
        Instruction::Bgeu { rs1, rs2, imm } => w!(9, *rs1 as u32, *rs2 as u32, *imm),
        Instruction::Lb { rd, rs1, imm } => w!(10, *rd as u32, *rs1 as u32, *imm),
        Instruction::Lh { rd, rs1, imm } => w!(11, *rd as u32, *rs1 as u32, *imm),
        Instruction::Lw { rd, rs1, imm } => w!(12, *rd as u32, *rs1 as u32, *imm),
        Instruction::Lbu { rd, rs1, imm } => w!(13, *rd as u32, *rs1 as u32, *imm),
        Instruction::Lhu { rd, rs1, imm } => w!(14, *rd as u32, *rs1 as u32, *imm),
        Instruction::Sb { rs1, rs2, imm } => w!(15, *rs1 as u32, *rs2 as u32, *imm),
        Instruction::Sh { rs1, rs2, imm } => w!(16, *rs1 as u32, *rs2 as u32, *imm),
        Instruction::Sw { rs1, rs2, imm } => w!(17, *rs1 as u32, *rs2 as u32, *imm),
        Instruction::Addi { rd, rs1, imm } => w!(18, *rd as u32, *rs1 as u32, *imm),
        Instruction::Slti { rd, rs1, imm } => w!(19, *rd as u32, *rs1 as u32, *imm),
        Instruction::Sltiu { rd, rs1, imm } => w!(20, *rd as u32, *rs1 as u32, *imm),
        Instruction::Xori { rd, rs1, imm } => w!(21, *rd as u32, *rs1 as u32, *imm),
        Instruction::Ori { rd, rs1, imm } => w!(22, *rd as u32, *rs1 as u32, *imm),
        Instruction::Andi { rd, rs1, imm } => w!(23, *rd as u32, *rs1 as u32, *imm),
        Instruction::Slli { rd, rs1, shamt } => w!(24, *rd as u32, *rs1 as u32, *shamt as u32),
        Instruction::Srli { rd, rs1, shamt } => w!(25, *rd as u32, *rs1 as u32, *shamt as u32),
        Instruction::Srai { rd, rs1, shamt } => w!(26, *rd as u32, *rs1 as u32, *shamt as u32),
        Instruction::Add { rd, rs1, rs2 } => w!(27, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Sub { rd, rs1, rs2 } => w!(28, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Sll { rd, rs1, rs2 } => w!(29, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Slt { rd, rs1, rs2 } => w!(30, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Sltu { rd, rs1, rs2 } => w!(31, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Xor { rd, rs1, rs2 } => w!(32, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Srl { rd, rs1, rs2 } => w!(33, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Sra { rd, rs1, rs2 } => w!(34, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Or { rd, rs1, rs2 } => w!(35, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::And { rd, rs1, rs2 } => w!(36, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Mul { rd, rs1, rs2 } => w!(37, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Mulh { rd, rs1, rs2 } => w!(38, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Mulhsu { rd, rs1, rs2 } => w!(39, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Mulhu { rd, rs1, rs2 } => w!(40, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Div { rd, rs1, rs2 } => w!(41, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Divu { rd, rs1, rs2 } => w!(42, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Rem { rd, rs1, rs2 } => w!(43, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Remu { rd, rs1, rs2 } => w!(44, *rd as u32, *rs1 as u32, *rs2 as u32),
        Instruction::Fence => out.push(45),
        Instruction::Ecall => out.push(46),
        Instruction::Ebreak => out.push(47),
    }
}

/// 反序列化 Instruction，返回 (Instruction, consumed_bytes)。
fn deserialize_instruction(bytes: &[u8]) -> Result<(Instruction, usize), ZkvmError> {
    if bytes.is_empty() {
        return Err(ZkvmError::InvalidZkProofFormat(
            "Instruction: tag truncated".to_string(),
        ));
    }
    let tag = bytes[0];
    let rest = &bytes[1..];

    macro_rules! rd_u32 {
        ($offset:expr) => {{
            if rest.len() < $offset + 4 {
                return Err(ZkvmError::InvalidZkProofFormat(
                    "Instruction: field truncated".to_string(),
                ));
            }
            u32::from_le_bytes([
                rest[$offset],
                rest[$offset + 1],
                rest[$offset + 2],
                rest[$offset + 3],
            ])
        }};
    }
    macro_rules! rd_u8 {
        ($offset:expr) => {{
            if rest.len() < $offset + 4 {
                return Err(ZkvmError::InvalidZkProofFormat(
                    "Instruction: field truncated".to_string(),
                ));
            }
            u32::from_le_bytes([
                rest[$offset],
                rest[$offset + 1],
                rest[$offset + 2],
                rest[$offset + 3],
            ]) as u8
        }};
    }

    // 辅助：读 2 个 u32 字段（imm 类型）
    macro_rules! r2 {
        () => {{
            let f0 = rd_u32!(0);
            let f1 = rd_u32!(4);
            (f0 as u8, f1)
        }};
    }
    // 辅助：读 3 个 u32 字段（第 3 个为 imm，保持 u32）
    macro_rules! r3 {
        () => {{
            let f0 = rd_u32!(0);
            let f1 = rd_u32!(4);
            let f2 = rd_u32!(8);
            (f0 as u8, f1 as u8, f2)
        }};
    }
    // 辅助：读 3 个 u32 字段，全部转 u8（R-type：rd + rs1 + rs2）
    macro_rules! r3r {
        () => {{
            let f0 = rd_u32!(0);
            let f1 = rd_u32!(4);
            let f2 = rd_u32!(8);
            (f0 as u8, f1 as u8, f2 as u8)
        }};
    }
    // 辅助：读 rd + rs1 + shamt（3 个 u32，但 shamt 是 u8）
    macro_rules! r3s {
        () => {{
            let f0 = rd_u32!(0);
            let f1 = rd_u32!(4);
            let f2 = rd_u8!(8);
            (f0 as u8, f1 as u8, f2)
        }};
    }

    match tag {
        0 => {
            let (rd, imm) = r2!();
            Ok((Instruction::Lui { rd, imm }, 1 + 8))
        }
        1 => {
            let (rd, imm) = r2!();
            Ok((Instruction::Auipc { rd, imm }, 1 + 8))
        }
        2 => {
            let (rd, imm) = r2!();
            Ok((Instruction::Jal { rd, imm }, 1 + 8))
        }
        3 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Jalr { rd, rs1, imm }, 1 + 12))
        }
        4 => {
            let (rs1, rs2, imm) = r3!();
            Ok((Instruction::Beq { rs1, rs2, imm }, 1 + 12))
        }
        5 => {
            let (rs1, rs2, imm) = r3!();
            Ok((Instruction::Bne { rs1, rs2, imm }, 1 + 12))
        }
        6 => {
            let (rs1, rs2, imm) = r3!();
            Ok((Instruction::Blt { rs1, rs2, imm }, 1 + 12))
        }
        7 => {
            let (rs1, rs2, imm) = r3!();
            Ok((Instruction::Bge { rs1, rs2, imm }, 1 + 12))
        }
        8 => {
            let (rs1, rs2, imm) = r3!();
            Ok((Instruction::Bltu { rs1, rs2, imm }, 1 + 12))
        }
        9 => {
            let (rs1, rs2, imm) = r3!();
            Ok((Instruction::Bgeu { rs1, rs2, imm }, 1 + 12))
        }
        10 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Lb { rd, rs1, imm }, 1 + 12))
        }
        11 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Lh { rd, rs1, imm }, 1 + 12))
        }
        12 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Lw { rd, rs1, imm }, 1 + 12))
        }
        13 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Lbu { rd, rs1, imm }, 1 + 12))
        }
        14 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Lhu { rd, rs1, imm }, 1 + 12))
        }
        15 => {
            let (rs1, rs2, imm) = r3!();
            Ok((Instruction::Sb { rs1, rs2, imm }, 1 + 12))
        }
        16 => {
            let (rs1, rs2, imm) = r3!();
            Ok((Instruction::Sh { rs1, rs2, imm }, 1 + 12))
        }
        17 => {
            let (rs1, rs2, imm) = r3!();
            Ok((Instruction::Sw { rs1, rs2, imm }, 1 + 12))
        }
        18 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Addi { rd, rs1, imm }, 1 + 12))
        }
        19 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Slti { rd, rs1, imm }, 1 + 12))
        }
        20 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Sltiu { rd, rs1, imm }, 1 + 12))
        }
        21 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Xori { rd, rs1, imm }, 1 + 12))
        }
        22 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Ori { rd, rs1, imm }, 1 + 12))
        }
        23 => {
            let (rd, rs1, imm) = r3!();
            Ok((Instruction::Andi { rd, rs1, imm }, 1 + 12))
        }
        24 => {
            let (rd, rs1, shamt) = r3s!();
            Ok((Instruction::Slli { rd, rs1, shamt }, 1 + 12))
        }
        25 => {
            let (rd, rs1, shamt) = r3s!();
            Ok((Instruction::Srli { rd, rs1, shamt }, 1 + 12))
        }
        26 => {
            let (rd, rs1, shamt) = r3s!();
            Ok((Instruction::Srai { rd, rs1, shamt }, 1 + 12))
        }
        27 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Add { rd, rs1, rs2 }, 1 + 12))
        }
        28 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Sub { rd, rs1, rs2 }, 1 + 12))
        }
        29 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Sll { rd, rs1, rs2 }, 1 + 12))
        }
        30 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Slt { rd, rs1, rs2 }, 1 + 12))
        }
        31 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Sltu { rd, rs1, rs2 }, 1 + 12))
        }
        32 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Xor { rd, rs1, rs2 }, 1 + 12))
        }
        33 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Srl { rd, rs1, rs2 }, 1 + 12))
        }
        34 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Sra { rd, rs1, rs2 }, 1 + 12))
        }
        35 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Or { rd, rs1, rs2 }, 1 + 12))
        }
        36 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::And { rd, rs1, rs2 }, 1 + 12))
        }
        37 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Mul { rd, rs1, rs2 }, 1 + 12))
        }
        38 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Mulh { rd, rs1, rs2 }, 1 + 12))
        }
        39 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Mulhsu { rd, rs1, rs2 }, 1 + 12))
        }
        40 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Mulhu { rd, rs1, rs2 }, 1 + 12))
        }
        41 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Div { rd, rs1, rs2 }, 1 + 12))
        }
        42 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Divu { rd, rs1, rs2 }, 1 + 12))
        }
        43 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Rem { rd, rs1, rs2 }, 1 + 12))
        }
        44 => {
            let (rd, rs1, rs2) = r3r!();
            Ok((Instruction::Remu { rd, rs1, rs2 }, 1 + 12))
        }
        45 => Ok((Instruction::Fence, 1)),
        46 => Ok((Instruction::Ecall, 1)),
        47 => Ok((Instruction::Ebreak, 1)),
        _ => Err(ZkvmError::InvalidZkProofFormat(format!(
            "invalid Instruction tag: {tag}"
        ))),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_new_empty() {
        let trace = Trace::new();
        assert_eq!(trace.len(), 0);
        assert!(trace.is_empty());
    }

    #[test]
    fn test_trace_push_and_step() {
        let mut trace = Trace::new();
        let step = Step {
            step_index: 0,
            pc: 0x1000,
            instruction: Instruction::Ecall,
            registers: [0u32; 32],
            mem_access: vec![],
        };
        trace.push_step(step);
        assert_eq!(trace.len(), 1);
        assert!(!trace.is_empty());
        assert_eq!(trace.step(0).unwrap().pc, 0x1000);
        assert!(trace.step(1).is_err());
    }

    #[test]
    fn test_trace_iter() {
        let mut trace = Trace::new();
        trace.push_step(Step {
            step_index: 0,
            pc: 0,
            instruction: Instruction::Ecall,
            registers: [0; 32],
            mem_access: vec![],
        });
        trace.push_step(Step {
            step_index: 1,
            pc: 4,
            instruction: Instruction::Ebreak,
            registers: [0; 32],
            mem_access: vec![],
        });
        let pcs: Vec<u32> = trace.iter().map(|s| s.pc).collect();
        assert_eq!(pcs, vec![0, 4]);
    }

    #[test]
    fn test_mem_access_size_field() {
        let ma_write = MemAccess {
            addr: 0x100,
            op: MemOp::Write,
            value: 0xDEADBEEF,
            size: 4,
        };
        assert_eq!(ma_write.size, 4);
        let ma_read = MemAccess {
            addr: 0x100,
            op: MemOp::Read,
            value: 0xBE,
            size: 1,
        };
        assert_eq!(ma_read.size, 1);
        assert_ne!(ma_write, ma_read);
    }

    #[test]
    fn test_trace_serialize_roundtrip_simple() {
        let mut trace = Trace::new();
        trace.push_step(Step {
            step_index: 0,
            pc: 0x1000,
            instruction: Instruction::Addi { rd: 1, rs1: 0, imm: 42 },
            registers: {
                let mut r = [0u32; 32];
                r[1] = 42;
                r
            },
            mem_access: vec![],
        });
        let bytes = trace.serialize();
        let trace2 = Trace::deserialize(&bytes).expect("deserialize");
        assert_eq!(trace, trace2);
    }

    #[test]
    fn test_trace_serialize_roundtrip_with_mem() {
        let mut trace = Trace::new();
        trace.push_step(Step {
            step_index: 5,
            pc: 0x2000,
            instruction: Instruction::Sw { rs1: 1, rs2: 2, imm: 0x10 },
            registers: [0u32; 32],
            mem_access: vec![
                MemAccess { addr: 0x2010, op: MemOp::Write, value: 0xABCD, size: 4 },
                MemAccess { addr: 0x2014, op: MemOp::Read, value: 0x1234, size: 2 },
            ],
        });
        let bytes = trace.serialize();
        let trace2 = Trace::deserialize(&bytes).expect("deserialize");
        assert_eq!(trace, trace2);
    }

    #[test]
    fn test_trace_serialize_roundtrip_multiple_steps() {
        let mut trace = Trace::new();
        for i in 0..10 {
            trace.push_step(Step {
                step_index: i,
                pc: (i * 4) as u32,
                instruction: Instruction::Add { rd: i as u8 % 31 + 1, rs1: 0, rs2: 0 },
                registers: [0; 32],
                mem_access: vec![],
            });
        }
        let bytes = trace.serialize();
        let trace2 = Trace::deserialize(&bytes).expect("deserialize");
        assert_eq!(trace, trace2);
        assert_eq!(trace2.len(), 10);
    }

    #[test]
    fn test_trace_deserialize_bad_magic() {
        let mut bad = vec![0x00, 0x00, 0x00, 0x00]; // bad magic
        bad.extend(&1u32.to_le_bytes());
        bad.extend(&0u64.to_le_bytes());
        let err = Trace::deserialize(&bad).unwrap_err();
        assert!(matches!(err, ZkvmError::InvalidZkProofFormat(_)));
    }

    #[test]
    fn test_trace_deserialize_bad_version() {
        let mut bad = b"TRCE".to_vec();
        bad.extend(&999u32.to_le_bytes()); // bad version
        bad.extend(&0u64.to_le_bytes());
        let err = Trace::deserialize(&bad).unwrap_err();
        assert!(matches!(err, ZkvmError::InvalidZkProofFormat(_)));
    }

    #[test]
    fn test_trace_deserialize_step_overflow_rejected() {
        let mut bad = b"TRCE".to_vec();
        bad.extend(&1u32.to_le_bytes());
        bad.extend(&u64::MAX.to_le_bytes()); // num_steps = u64::MAX
        let err = Trace::deserialize(&bad).unwrap_err();
        assert!(matches!(err, ZkvmError::TraceHostMemoryExceeded { .. }));
    }

    #[test]
    fn test_trace_host_memory_usage() {
        let mut trace = Trace::new();
        trace.push_step(Step {
            step_index: 0,
            pc: 0,
            instruction: Instruction::Ecall,
            registers: [0; 32],
            mem_access: vec![],
        });
        let usage = trace.host_memory_usage();
        // 每步至少 8+4+1+16+128+4 = 161 bytes
        assert!(usage >= 161, "usage should be >= 161, got {usage}");
        assert!(usage < 1024, "single step no mem should be < 1KB, got {usage}");
    }

    #[test]
    fn test_step_from_log() {
        let log = StepLog {
            pc: 0x1000,
            instruction: Instruction::Add { rd: 1, rs1: 2, rs2: 3 },
            registers: {
                let mut r = [0u32; 32];
                r[1] = 42;
                r
            },
            mem_access: vec![MemAccess { addr: 0x200, op: MemOp::Write, value: 0xAB, size: 1 }],
        };
        let step = Step::from_log(7, log);
        assert_eq!(step.step_index, 7);
        assert_eq!(step.pc, 0x1000);
        assert_eq!(step.registers[1], 42);
        assert_eq!(step.mem_access.len(), 1);
    }

    #[test]
    fn test_mem_op_roundtrip() {
        assert_eq!(MemOp::Read.to_byte(), 0);
        assert_eq!(MemOp::Write.to_byte(), 1);
        assert_eq!(MemOp::from_byte(0).unwrap(), MemOp::Read);
        assert_eq!(MemOp::from_byte(1).unwrap(), MemOp::Write);
        assert!(MemOp::from_byte(2).is_err());
    }
}
