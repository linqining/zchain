//! Raw RV32I ecall 包装。每个函数对应一个 host SyscallId。
//!
//! ABI: a7=syscall号, a0-a3 入参, a0 返回值。

#![allow(unsafe_code)]

/// syscall 号常量（与 host `poker_zkvm/src/syscalls/mod.rs::SyscallId` 一一对应）。
pub mod id {
    pub const READ_INPUT: u32 = 0x01;
    pub const COMMIT_OUTPUT: u32 = 0x02;
    pub const POSEIDON: u32 = 0x03;
    pub const SHA256: u32 = 0x04;
    pub const ECDSA_VERIFY: u32 = 0x05;
    pub const EMIT_EVENT: u32 = 0x06;
    pub const LOG: u32 = 0x07;
    pub const PANIC: u32 = 0x08;
    pub const GET_RANDOMNESS: u32 = 0x09;
    pub const READ_STATE: u32 = 0x0A;
    pub const KECCAK256: u32 = 0x0B;
    pub const BLS_HASH_TO_CURVE: u32 = 0x10;
    pub const BLS_SCALAR_MUL: u32 = 0x11;
    pub const BLS_G1_ADD: u32 = 0x12;
    pub const BLS_G1_MUL: u32 = 0x13;
    pub const BLS_PAIRING: u32 = 0x14;
    pub const BLS_HASH_TO_SCALAR: u32 = 0x15;
    // ===== Phase 3.2 扩展（D2 决策）=====
    pub const BLS_SCALAR_ADD: u32 = 0x16;
    pub const BLS_SCALAR_SUB: u32 = 0x17;
    pub const BLS_SCALAR_NEG: u32 = 0x18;
    pub const BLS_SCALAR_INV: u32 = 0x19;
    pub const BLS_G1_SUB: u32 = 0x1A;
    pub const BLS_G1_GENERATOR: u32 = 0x1B;
    pub const GAME_STATE_READ: u32 = 0x20;
    pub const GAME_STATE_WRITE: u32 = 0x21;
    pub const CARD_ENCODE: u32 = 0x30;
    pub const CARD_DECODE: u32 = 0x31;
    pub const SHUFFLE_VERIFY: u32 = 0x32;
    // ===== Phase 4: Mental Poker proof verify + hash syscall（0x33-0x36）=====
    pub const BLAKE2B_256: u32 = 0x33;
    pub const VERIFY_DLEQ_PROOF: u32 = 0x34;
    pub const VERIFY_RECONSTRUCT_PROOF: u32 = 0x35;
    pub const VERIFY_REVEAL_TOKEN_PROOF: u32 = 0x36;
}

/// 通用 3 参数 syscall。a7=num, a0-a2 入参，返回 a0。
///
/// # Safety
/// 调用者须保证指针参数指向合法内存。
#[cfg(target_arch = "riscv32")]
#[inline(always)]
pub unsafe fn syscall3(num: u32, a0: u32, a1: u32, a2: u32) -> u32 {
    let ret: u32;
    core::arch::asm!(
        "ecall",
        inlateout("a0") a0 => ret,
        in("a1") a1,
        in("a2") a2,
        in("a7") num,
        options(nostack, preserves_flags),
    );
    ret
}

/// 非 riscv32 target 的 stub（仅用于 std-test 模式编译，不应被调用）。
#[cfg(not(target_arch = "riscv32"))]
#[inline(always)]
pub unsafe fn syscall3(_num: u32, _a0: u32, _a1: u32, _a2: u32) -> u32 {
    unreachable!("syscall3 must not be called on non-riscv32 target (std-test mode)")
}

/// 通用 4 参数 syscall。a7=num, a0-a3 入参，返回 a0。
#[cfg(target_arch = "riscv32")]
#[inline(always)]
pub unsafe fn syscall4(num: u32, a0: u32, a1: u32, a2: u32, a3: u32) -> u32 {
    let ret: u32;
    core::arch::asm!(
        "ecall",
        inlateout("a0") a0 => ret,
        in("a1") a1,
        in("a2") a2,
        in("a3") a3,
        in("a7") num,
        options(nostack, preserves_flags),
    );
    ret
}

/// 非 riscv32 target 的 stub（仅用于 std-test 模式编译，不应被调用）。
#[cfg(not(target_arch = "riscv32"))]
#[inline(always)]
pub unsafe fn syscall4(_num: u32, _a0: u32, _a1: u32, _a2: u32, _a3: u32) -> u32 {
    unreachable!("syscall4 must not be called on non-riscv32 target (std-test mode)")
}

// ===== 高层封装 =====

/// `read_input(buf: &mut [u8])` — 从 host input buffer 读取数据到 buf。
///
/// host 会写入 min(ctx.input.len(), buf.len()) 字节。
/// 返回 host 写入的 a0 值（当前为 write_addr，guest 通常忽略此值）。
///
/// 注意：guest 应通过输入数据自带的长度前缀获取实际数据长度。
#[inline]
pub fn read_input_raw(buf: &mut [u8]) -> u32 {
    unsafe { syscall3(id::READ_INPUT, buf.as_mut_ptr() as u32, buf.len() as u32, 0) }
}

/// `commit_output(buf: &[u8])` — 写入 host output buffer 并终止执行。
///
/// 调用后不会返回。
#[inline]
pub fn commit_output(buf: &[u8]) -> ! {
    unsafe { syscall3(id::COMMIT_OUTPUT, buf.as_ptr() as u32, buf.len() as u32, 0) };
    // commit_output 会导致 VM 停止，但编译器需要一个不返回标记
    core::hint::spin_loop();
    unreachable!("commit_output must halt the VM")
}

/// `panic_msg(msg: &str) -> !` — 终止执行并报告错误。
#[inline]
pub fn panic_msg(msg: &str) -> ! {
    unsafe { syscall3(id::PANIC, msg.as_ptr() as u32, msg.len() as u32, 0) };
    core::hint::spin_loop();
    unreachable!("panic syscall must halt the VM")
}

/// `log(msg: &str)` — 写入 host event log（syscall 0x07），不终止执行。
///
/// 诊断用：guest 在关键函数入口/调用边界输出标记，host 端可在 `ExecuteResult.logs`
/// 或崩溃日志中查看执行轨迹。`&str` 字面量存储在 .rodata，`(ptr, len)` ABI
/// 不触发 sret。
#[inline]
pub fn log(msg: &str) {
    unsafe { syscall3(id::LOG, msg.as_ptr() as u32, msg.len() as u32, 0) };
}

/// `poseidon(data: &[u8], out: &mut [u8; 32])` — Poseidon 哈希。
#[inline]
pub fn poseidon(data: &[u8], out: &mut [u8; 32]) {
    unsafe { syscall3(id::POSEIDON, data.as_ptr() as u32, data.len() as u32, out.as_mut_ptr() as u32) };
}

/// `sha256(data: &[u8], out: &mut [u8; 32])` — SHA-256 哈希。
#[inline]
pub fn sha256(data: &[u8], out: &mut [u8; 32]) {
    unsafe { syscall3(id::SHA256, data.as_ptr() as u32, data.len() as u32, out.as_mut_ptr() as u32) };
}

/// `keccak256(data: &[u8], out: &mut [u8; 32])` — Keccak-256 哈希。
#[inline]
pub fn keccak256(data: &[u8], out: &mut [u8; 32]) {
    unsafe { syscall3(id::KECCAK256, data.as_ptr() as u32, data.len() as u32, out.as_mut_ptr() as u32) };
}

/// `bls_hash_to_curve(msg: &[u8], out: &mut [u8; 48])` — BLS12-381 hash-to-G1。
#[inline]
pub fn bls_hash_to_curve(msg: &[u8], out: &mut [u8; 48]) {
    unsafe { syscall3(id::BLS_HASH_TO_CURVE, msg.as_ptr() as u32, msg.len() as u32, out.as_mut_ptr() as u32) };
}

/// `bls_hash_to_scalar(msg: &[u8], out: &mut [u8; 32])` — BLS12-381 hash-to-scalar。
#[inline]
pub fn bls_hash_to_scalar(msg: &[u8], out: &mut [u8; 32]) {
    unsafe { syscall3(id::BLS_HASH_TO_SCALAR, msg.as_ptr() as u32, msg.len() as u32, out.as_mut_ptr() as u32) };
}

/// `bls_scalar_mul(a, b, out)` — BLS12-381 标量乘法 a*b mod p（syscall 0x11）。
#[inline]
pub fn bls_scalar_mul(a: &[u8; 32], b: &[u8; 32], out: &mut [u8; 32]) {
    unsafe { syscall3(id::BLS_SCALAR_MUL, a.as_ptr() as u32, b.as_ptr() as u32, out.as_mut_ptr() as u32) };
}

/// `bls_g1_add(a: &[u8;48], b: &[u8;48], out: &mut [u8;48])` — BLS12-381 G1 点加。
#[inline]
pub fn bls_g1_add(a: &[u8; 48], b: &[u8; 48], out: &mut [u8; 48]) {
    unsafe { syscall3(id::BLS_G1_ADD, a.as_ptr() as u32, b.as_ptr() as u32, out.as_mut_ptr() as u32) };
}

/// `bls_g1_mul(p: &[u8;48], s: &[u8;32], out: &mut [u8;48])` — BLS12-381 G1 标量乘。
#[inline]
pub fn bls_g1_mul(p: &[u8; 48], s: &[u8; 32], out: &mut [u8; 48]) {
    unsafe { syscall3(id::BLS_G1_MUL, p.as_ptr() as u32, s.as_ptr() as u32, out.as_mut_ptr() as u32) };
}

/// `bls_pairing(a, b, c, d) -> bool` — 验证 e(a,b) == e(c,d)。
#[inline]
pub fn bls_pairing(a: &[u8; 48], b: &[u8; 48], c: &[u8; 48], d: &[u8; 48]) -> bool {
    let ret = unsafe {
        syscall4(id::BLS_PAIRING, a.as_ptr() as u32, b.as_ptr() as u32, c.as_ptr() as u32, d.as_ptr() as u32)
    };
    ret != 0
}

// ===== Phase 3.2 扩展 BLS syscall wrapper（D2 决策）=====
// 标量算术 + G1 辅助，供 texas_poker crypto utils 移植使用。

/// `bls_scalar_add(a, b, out)` — BLS12-381 标量加法 a+b mod p（syscall 0x16）。
#[inline]
pub fn bls_scalar_add(a: &[u8; 32], b: &[u8; 32], out: &mut [u8; 32]) {
    unsafe { syscall3(id::BLS_SCALAR_ADD, a.as_ptr() as u32, b.as_ptr() as u32, out.as_mut_ptr() as u32) };
}

/// `bls_scalar_sub(a, b, out)` — BLS12-381 标量减法 a-b mod p（syscall 0x17）。
#[inline]
pub fn bls_scalar_sub(a: &[u8; 32], b: &[u8; 32], out: &mut [u8; 32]) {
    unsafe { syscall3(id::BLS_SCALAR_SUB, a.as_ptr() as u32, b.as_ptr() as u32, out.as_mut_ptr() as u32) };
}

/// `bls_scalar_neg(a, out)` — BLS12-381 标量取负 -a mod p（syscall 0x18）。
#[inline]
pub fn bls_scalar_neg(a: &[u8; 32], out: &mut [u8; 32]) {
    unsafe { syscall3(id::BLS_SCALAR_NEG, a.as_ptr() as u32, out.as_mut_ptr() as u32, 0) };
}

/// `bls_scalar_inv(a, out)` — BLS12-381 标量求逆 a^(-1) mod p（syscall 0x19）。
/// a=0 时返回 0（与 utils.rs::scalar_inv 行为一致）。
#[inline]
pub fn bls_scalar_inv(a: &[u8; 32], out: &mut [u8; 32]) {
    unsafe { syscall3(id::BLS_SCALAR_INV, a.as_ptr() as u32, out.as_mut_ptr() as u32, 0) };
}

/// `bls_g1_sub(a, b, out)` — BLS12-381 G1 点减 a-b（syscall 0x1A）。
#[inline]
pub fn bls_g1_sub(a: &[u8; 48], b: &[u8; 48], out: &mut [u8; 48]) {
    unsafe { syscall3(id::BLS_G1_SUB, a.as_ptr() as u32, b.as_ptr() as u32, out.as_mut_ptr() as u32) };
}

/// `bls_g1_generator(out)` — 返回 G1 生成元（48 字节 compressed，syscall 0x1B）。
#[inline]
pub fn bls_g1_generator(out: &mut [u8; 48]) {
    unsafe { syscall3(id::BLS_G1_GENERATOR, out.as_mut_ptr() as u32, 0, 0) };
}

/// `shuffle_verify(deck, proof) -> bool` — ZKShuffle 验证。
#[inline]
pub fn shuffle_verify(deck: &[u8], proof: &[u8]) -> bool {
    let ret = unsafe {
        syscall4(id::SHUFFLE_VERIFY, deck.as_ptr() as u32, deck.len() as u32, proof.as_ptr() as u32, proof.len() as u32)
    };
    ret != 0
}

/// `game_state_read(slot, out_ptr, out_len)` — 读取 GameState slot。
#[inline]
pub fn game_state_read(slot: u32, out: &mut [u8]) -> u32 {
    unsafe { syscall3(id::GAME_STATE_READ, slot, out.as_mut_ptr() as u32, out.len() as u32) }
}

/// `game_state_write(slot, in_ptr, in_len)` — 写入 GameState slot。
#[inline]
pub fn game_state_write(slot: u32, data: &[u8]) {
    unsafe { syscall3(id::GAME_STATE_WRITE, slot, data.as_ptr() as u32, data.len() as u32) };
}

/// `card_encode(rank, suit, out_ptr)` — 扑克牌编码。
#[inline]
pub fn card_encode(rank: u8, suit: u8, out: &mut [u8; 1]) {
    unsafe { syscall3(id::CARD_ENCODE, rank as u32, suit as u32, out.as_mut_ptr() as u32) };
}

/// `card_decode(byte, out_rank_ptr, out_suit_ptr)` — 扑克牌解码。
#[inline]
pub fn card_decode(byte: u8, out_rank: &mut [u8; 1], out_suit: &mut [u8; 1]) {
    unsafe { syscall3(id::CARD_DECODE, byte as u32, out_rank.as_mut_ptr() as u32, out_suit.as_mut_ptr() as u32) };
}

// ===== Phase 4: Mental Poker proof verify + hash syscall wrapper（0x33-0x36）=====

/// `blake2b_256(data, out)` — Blake2b-256 变长哈希（syscall 0x33）。
///
/// 输出 32 字节，与 `dispatch.rs::compute_method_selector` 算法一致。
#[inline]
pub fn blake2b_256(data: &[u8], out: &mut [u8; 32]) {
    unsafe { syscall3(id::BLAKE2B_256, data.as_ptr() as u32, data.len() as u32, out.as_mut_ptr() as u32) };
}

/// `verify_dleq_proof(kind, buf) -> bool` — DLEq/ZKShuffle proof 验证（syscall 0x34）。
///
/// `kind`：0=remask, 1=leave, 2=shuffle。
/// `buf` 为 length-prefixed 单缓冲区，格式见 host `proof_verify.rs` 文档。
#[inline]
pub fn verify_dleq_proof(kind: u32, buf: &[u8]) -> bool {
    let ret = unsafe { syscall3(id::VERIFY_DLEQ_PROOF, kind, buf.as_ptr() as u32, buf.len() as u32) };
    ret != 0
}

/// `verify_reconstruct_proof(buf) -> bool` — Reconstruct proof 验证（syscall 0x35）。
///
/// `buf` 为 length-prefixed 单缓冲区，格式见 host `proof_verify.rs` 文档。
#[inline]
pub fn verify_reconstruct_proof(buf: &[u8]) -> bool {
    let ret = unsafe { syscall3(id::VERIFY_RECONSTRUCT_PROOF, buf.as_ptr() as u32, buf.len() as u32, 0) };
    ret != 0
}

/// `verify_reveal_token_proof(buf) -> bool` — Reveal token proof 验证（syscall 0x36）。
///
/// `buf` 为 length-prefixed 单缓冲区，格式见 host `proof_verify.rs` 文档。
#[inline]
pub fn verify_reveal_token_proof(buf: &[u8]) -> bool {
    let ret = unsafe { syscall3(id::VERIFY_REVEAL_TOKEN_PROOF, buf.as_ptr() as u32, buf.len() as u32, 0) };
    ret != 0
}
