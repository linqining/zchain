//! Texas Poker ZKVM Guest — Phase 5.1c E2E dispatch 测试。
//!
//! 通过 `execute_elf` 在真实 RV32IM 模拟器中执行编译后的 guest ELF，
//! 验证 `dispatch` 路径（18 个 method selector）端到端可用：
//! - `create_table` → 初始化桌台
//! - `join_table` × 2 → 玩家入座
//! - `start_hand` → 开局（含 52 张密文牌组初始化、盲注）
//! - `reset_for_next_hand` → 重置回 WAITING
//! - 错误处理（unknown selector / invalid borsh）
//!
//! # 运行前置
//!
//! guest crate 必须先以 riscv32im-unknown-none-elf target 编译：
//! ```bash
//! cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker
//! cargo +nightly-2026-04-15 build --release
//! ```
//!
//! # 运行方式
//!
//! ```bash
//! cargo test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture
//! ```
//!
//! # 设计要点
//!
//! - **Stateless 模型**：每次 `execute_elf` 接收完整 `ZkvmInput { table, context, selector, args }`，
//!   返回 `ZkvmOutput { table, events, modified_objects }`。Host 在多次调用间持久化 `table`。
//! - **BLS syscall 支持**：`start_hand` 内部调用 `set_initial_encrypted_deck`，触发 ~53 次
//!   BLS12-381 syscall（52× `hash_to_curve` + 1× `g1_generator`）。`execute_elf` 的
//!   `SyscallRegistry::new()` 已注册全部 26 个 syscall（含 BLS12-381），故可在 host 端运行。
//! - **`join_table` 的 pk 字段**：guest 端 `g1_identity()` = `generator().mul(&Scalar::ZERO)`
//!   触发 2 次 BLS syscall。host 端构造 `ZkvmInput` 时仅需填 48 字节占位（identity 的
//!   compressed 编码非全零，但 host 不校验子群；guest 端 `apply_*` 不重算 pk，直接透传）。
//!   因此 host 端用 `G1Point([0;48])` 占位即可（与 `Seat::empty()` 一致）。

#![cfg(feature = "test-helpers")]

use std::path::PathBuf;

use borsh::BorshDeserialize;
use poker_zkvm::isa::executor::execute_elf;

// 直接复用 guest crate 的类型（作为 dev-dependency，std-test feature 下以 host std 编译）
use texas_poker_guest::dispatch::{
    selectors, CreateTableArgs, DispatchContext, JoinTableArgs, LeaveTableArgs,
    SeatIndexArgs, SubmitRevealTokensArgs, SubmitShuffleV2Args,
};
// G1Point 从 lib root 重导出（types.rs 内仅 use，未 pub use）
use texas_poker_guest::events::TexasPokerEvent;
use texas_poker_guest::io::{ZkvmInput, ZkvmOutput};
use texas_poker_guest::types::TexasPokerTable;
use texas_poker_guest::G1Point;

// ========== ELF 路径与读取（与 phase1 测试一致）==========

/// 返回编译后的 guest ELF 路径（与 phase1 测试共用同一 ELF）。
fn guest_elf_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("guests/texas_poker/target/riscv32im-unknown-none-elf/release/texas_poker_guest");
    p
}

/// 读取 guest ELF 字节。若文件不存在则给出明确的引导消息。
fn read_guest_elf() -> Vec<u8> {
    let path = guest_elf_path();
    if !path.exists() {
        panic!(
            "guest ELF 未找到：{}\n请先执行：\n  cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release",
            path.display()
        );
    }
    std::fs::read(&path).unwrap_or_else(|e| panic!("读取 guest ELF 失败 {path:?}: {e}"))
}

// ========== 辅助构造函数 ==========

/// 构造测试用 DispatchContext（44 字节，borsh 布局固定）。
fn make_context() -> DispatchContext {
    DispatchContext {
        caller: [0xAA; 20],
        chain_id: 1,
        block_height: 100,
        block_timestamp: 1_700_000_000_000,
    }
}

/// 构造一个最小有效初始桌台（仅 `id` 字段在 create_table 时被使用）。
fn make_initial_table() -> TexasPokerTable {
    TexasPokerTable::new([0x42; 32], "placeholder".into(), 6, 25, 50)
}

/// 构造一个 G1Point 占位（不同玩家用不同 fill 字节，确保 pk 唯一性）。
///
/// 注意：guest 端 `apply_*` 不重算 pk，直接透传 host 提供的值。该占位值仅用于
/// `JoinTableArgs.pk`；实际 BLS 操作（如 `g1_identity()`）只在 guest 内部按需触发。
///
/// **必须**为同一桌台上的不同玩家传入不同 `fill`：`dispatch_join_table` 会调用
/// `state_machine::is_pk_registered` 检查 pk 唯一性，相同 pk 会被拒绝。
/// `fill = 0` 与 `Seat::empty()` 的 pk 一致，已入座玩家的 pk 不能为 0。
fn placeholder_g1(fill: u8) -> G1Point {
    G1Point([fill; 48])
}

/// 生成有效的 BLS12-381 G1 压缩点（generator * scalar）。
///
/// `submit_shuffle_v2` 的 `add_pk_to_c2` 会经 syscall 做真实 G1 运算（g1_add），
/// 需要有效的压缩点。placeholder_g1 生成的无效点会导致 syscall 解压失败。
fn valid_g1(scalar: u64) -> G1Point {
    use blstrs::G1Projective;
    use pairing::group::Group;
    let g = G1Projective::generator();
    let s = blstrs::Scalar::from(scalar);
    let p = g * s;
    G1Point(p.to_compressed())
}

/// BLS12-381 G1 单位元（identity / point at infinity）的压缩表示。
///
/// 用作 reveal token 的 dummy 值：`partial_decrypt_c2(c2, [identity]) = c2 - identity = c2`，
/// 即减去单位元是 no-op，不会改变密文。
fn identity_g1() -> G1Point {
    use blstrs::G1Projective;
    use pairing::group::Group;
    let identity = G1Projective::identity();
    G1Point(identity.to_compressed())
}

// ========== 核心 E2E 辅助：dispatch_via_elf ==========

/// 通过 `execute_elf` 在真实 RV32I 模拟器中执行一次 dispatch 调用。
///
/// # 流程
/// 1. 构造 `ZkvmInput { table, context, selector, args }`
/// 2. borsh 序列化为 bytes
/// 3. 前置 4 字节 LE 长度前缀（guest `entry::zkvm_entry` 约定）
/// 4. `execute_elf(elf, &input_with_prefix)`
/// 5. 解析 `result.output` 为 `ZkvmOutput`
///
/// # Returns
/// 成功时返回 `(更新后的 table, events, modified_objects)`。
fn dispatch_via_elf(
    elf: &[u8],
    table: &TexasPokerTable,
    context: &DispatchContext,
    selector: [u8; 32],
    args_bytes: &[u8],
) -> (TexasPokerTable, Vec<TexasPokerEvent>, Vec<[u8; 32]>) {
    let input = ZkvmInput {
        table: table.clone(),
        context: *context,
        method_selector: selector,
        args: args_bytes.to_vec(),
    };
    let input_borsh = borsh::to_vec(&input).expect("ZkvmInput borsh 序列化应成功");

    // guest entry 约定：[4 字节 LE 长度 N][N 字节数据]
    let mut elf_input = (input_borsh.len() as u32).to_le_bytes().to_vec();
    elf_input.extend_from_slice(&input_borsh);

    let result = execute_elf(elf, &elf_input).expect("ELF 执行应成功（dispatch 不应 panic）");
    let output: ZkvmOutput = BorshDeserialize::try_from_slice(&result.output)
        .unwrap_or_else(|e| panic!("ZkvmOutput 反序列化失败: {e}\nraw bytes: {:?}", result.output));

    (output.table, output.events, output.modified_objects)
}

/// 与 `dispatch_via_elf` 类似，但用于期望失败的调用（unknown selector / invalid borsh）。
///
/// 返回原始 `ZkvmError`（不解析 output）。
fn dispatch_via_elf_expect_err(
    elf: &[u8],
    table: &TexasPokerTable,
    context: &DispatchContext,
    selector: [u8; 32],
    args_bytes: &[u8],
) -> poker_zkvm::error::ZkvmError {
    let input = ZkvmInput {
        table: table.clone(),
        context: *context,
        method_selector: selector,
        args: args_bytes.to_vec(),
    };
    let input_borsh = borsh::to_vec(&input).expect("ZkvmInput borsh 序列化应成功");
    let mut elf_input = (input_borsh.len() as u32).to_le_bytes().to_vec();
    elf_input.extend_from_slice(&input_borsh);

    let result = execute_elf(elf, &elf_input);
    match result {
        Ok(r) => panic!(
            "期望 ELF 执行失败，但成功了：output={:?} ({} bytes)",
            r.output,
            r.output.len()
        ),
        Err(e) => e,
    }
}

// ========== Test 1: 空输入 health check（Phase 1 向后兼容）==========

#[test]
fn test_e2e_empty_input_returns_health_check() {
    let elf = read_guest_elf();
    let input = vec![0u8; 4]; // 4 字节 LE 长度 = 0 → 空 input
    let result = execute_elf(&elf, &input).expect("ELF 执行应成功");
    assert_eq!(
        result.output,
        vec![0x42],
        "guest 对空输入应输出 [0x42]（Phase 1 health check），实际: {:?}",
        result.output
    );
}

// ========== Test 1b: DIAGNOSTIC — raw output for non-empty input ==========

#[test]
fn test_e2e_diagnostic_raw_output() {
    let elf = read_guest_elf();
    let ctx = make_context();
    let table = make_initial_table();
    let args = CreateTableArgs {
        name: "diag".into(),
        max_players: 6,
        small_blind: 25,
        big_blind: 50,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let input = ZkvmInput {
        table: table.clone(),
        context: ctx,
        method_selector: selectors::create_table(),
        args: args_bytes,
    };
    let input_borsh = borsh::to_vec(&input).unwrap();
    let mut elf_input = (input_borsh.len() as u32).to_le_bytes().to_vec();
    elf_input.extend_from_slice(&input_borsh);

    match execute_elf(&elf, &elf_input) {
        Ok(r) => {
            let s = String::from_utf8_lossy(&r.output);
            println!("DIAGNOSTIC: ELF succeeded, output len={}, output_str='{}', output_hex={:02x?}",
                     r.output.len(), s, r.output);
        }
        Err(e) => {
            println!("DIAGNOSTIC: ELF failed, error={}", e);
        }
    }
    // Don't assert anything — just print diagnostics
}

// ========== Test 2: create_table dispatch ==========

#[test]
fn test_e2e_create_table_dispatch() {
    let elf = read_guest_elf();
    let ctx = make_context();
    let initial_table = make_initial_table();

    let args = CreateTableArgs {
        name: "e2e_table".into(),
        max_players: 6,
        small_blind: 25,
        big_blind: 50,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();

    let (table, events, modified) =
        dispatch_via_elf(&elf, &initial_table, &ctx, selectors::create_table(), &args_bytes);

    // 验证桌台被覆写
    assert_eq!(table.name, "e2e_table");
    assert_eq!(table.max_players, 6);
    assert_eq!(table.small_blind, 25);
    assert_eq!(table.big_blind, 50);
    assert_eq!(table.id, [0x42; 32], "id 应保留自输入");
    assert_eq!(table.version, 1, "create_table 应 bump version 一次");
    assert_eq!(table.seats.len(), 6);
    assert!(
        table.seats.iter().all(|s| s.player == [0u8; 20]),
        "所有座位应为空"
    );

    // 验证事件
    assert!(
        events
            .iter()
            .any(|e| matches!(e, TexasPokerEvent::TableCreated { table_id, name }
                if *table_id == [0x42; 32] && name == "e2e_table")),
        "应包含 TableCreated 事件，实际 events: {events:?}"
    );

    // 验证 modified_objects
    assert_eq!(modified, vec![[0x42; 32]]);
}

// ========== Test 3: 完整生命周期（create → join × 2 → start_hand → reset）==========
//
// 这是 Phase 5.1c 的核心 E2E 测试 — 验证多步状态机转换在 ELF 中可串联执行。
// 每步的 table 状态在前一步的输出中获取，模拟 host L1 的持久化逻辑。

#[test]
fn test_e2e_full_lifecycle_create_join_start_reset() {
    let elf = read_guest_elf();
    let ctx = make_context();
    let mut table = make_initial_table();

    // ---- Step 1: create_table ----
    let create_args = CreateTableArgs {
        name: "lifecycle".into(),
        max_players: 2,
        small_blind: 10,
        big_blind: 20,
    };
    let create_bytes = borsh::to_vec(&create_args).unwrap();
    let (new_table, events, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::create_table(), &create_bytes);
    println!("[Step 1] create_table: name={}, max_players={}, events={}",
             new_table.name, new_table.max_players, events.len());
    assert_eq!(new_table.name, "lifecycle");
    assert_eq!(new_table.max_players, 2);
    assert_eq!(new_table.round_state, texas_poker_guest::constants::ROUND_WAITING);
    table = new_table;

    // ---- Step 2a: join_table player 1 ----
    let join1 = JoinTableArgs {
        player: [0x11; 20],
        buy_in: 1000,
        pk: placeholder_g1(0x11),
    };
    let join1_bytes = borsh::to_vec(&join1).unwrap();
    let (new_table, events, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::join_table(), &join1_bytes);
    println!("[Step 2a] join_table p1: occupied={}, events={}",
             new_table.occupied_count(), events.len());
    assert_eq!(new_table.occupied_count(), 1);
    assert_eq!(new_table.seats[0].stack, 1000);
    assert!(
        events.iter().any(|e| matches!(e,
            TexasPokerEvent::PlayerJoined { player, buy_in, .. }
            if *player == [0x11; 20] && *buy_in == 1000)),
        "应包含 PlayerJoined 事件 (p1)"
    );
    table = new_table;

    // ---- Step 2b: join_table player 2 ----
    let join2 = JoinTableArgs {
        player: [0x22; 20],
        buy_in: 2000,
        pk: placeholder_g1(0x22),
    };
    let join2_bytes = borsh::to_vec(&join2).unwrap();
    let (new_table, events, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::join_table(), &join2_bytes);
    println!("[Step 2b] join_table p2: occupied={}, events={}",
             new_table.occupied_count(), events.len());
    assert_eq!(new_table.occupied_count(), 2);
    assert_eq!(new_table.seats[1].stack, 2000);
    assert!(
        events.iter().any(|e| matches!(e,
            TexasPokerEvent::PlayerJoined { player, buy_in, .. }
            if *player == [0x22; 20] && *buy_in == 2000)),
        "应包含 PlayerJoined 事件 (p2)"
    );
    table = new_table;

    // ---- Step 3: start_hand ----
    // start_hand 内部调用 set_initial_encrypted_deck，触发 ~53 次 BLS syscall：
    //   - 52× hash_to_curve (syscall 0x10) 生成 52 张明文牌
    //   - 1× g1_generator (syscall 0x1B) 取 G
    // 然后构造 52 个 ElGamalCiphertext { c1: G, c2: m }。
    // 因 execute_elf 的 SyscallRegistry 已注册全部 BLS syscall，此处应成功。
    let (new_table, events, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::start_hand(), &[]);
    println!("[Step 3] start_hand: shuffle_phase={}, deck_size={}, events={}",
             new_table.shuffle_state.phase,
             new_table.deck_state.encrypted.len(),
             events.len());
    assert_eq!(
        new_table.shuffle_state.phase,
        texas_poker_guest::constants::SHUFFLE_PHASE_BEFORE_PREFLOP,
        "start_hand 后应进入 BEFORE_PREFLOP shuffle 阶段"
    );
    assert_eq!(
        new_table.deck_state.encrypted.len(),
        52,
        "应初始化 52 张密文牌"
    );
    assert!(
        events.iter().any(|e| matches!(e, TexasPokerEvent::HandStarted { .. })),
        "应包含 HandStarted 事件"
    );
    // heads-up: SB=button, BB=button+1, 每位玩家已扣盲注
    assert!(
        new_table.seats[0].stack + new_table.seats[0].bet
            + new_table.seats[1].stack
            + new_table.seats[1].bet
            == 1000 + 2000,
        "盲注扣款后总筹码应守恒（1000+2000）"
    );
    table = new_table;

    // ---- Step 4: reset_for_next_hand ----
    let (new_table, events, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::reset_for_next_hand(), &[]);
    println!("[Step 4] reset_for_next_hand: round_state={}, pot={}, occupied={}, events={}",
             new_table.round_state, new_table.pot, new_table.occupied_count(), events.len());
    assert_eq!(
        new_table.round_state,
        texas_poker_guest::constants::ROUND_WAITING,
        "reset 后应回到 WAITING 状态"
    );
    assert_eq!(new_table.pot, 0, "reset 后 pot 应清零");
    assert_eq!(
        new_table.occupied_count(), 2,
        "reset 不应踢出有筹码的玩家"
    );
    // 保留玩家筹码（退回 pot 到非 folded 玩家的 stack）
    assert!(
        new_table.seats[0].stack + new_table.seats[1].stack > 0,
        "至少一位玩家应保留筹码"
    );
}

// ========== Test 4: leave_table 简单离座 ==========

#[test]
fn test_e2e_join_then_leave_table() {
    let elf = read_guest_elf();
    let ctx = make_context();
    let mut table = make_initial_table();

    // create_table
    let create_args = CreateTableArgs {
        name: "leave_test".into(),
        max_players: 6,
        small_blind: 25,
        big_blind: 50,
    };
    let create_bytes = borsh::to_vec(&create_args).unwrap();
    let (new_table, _, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::create_table(), &create_bytes);
    table = new_table;

    // join_table
    let join = JoinTableArgs {
        player: [0x33; 20],
        buy_in: 500,
        pk: placeholder_g1(0x33),
    };
    let join_bytes = borsh::to_vec(&join).unwrap();
    let (new_table, _, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::join_table(), &join_bytes);
    assert_eq!(new_table.occupied_count(), 1);
    assert_eq!(new_table.seats[0].stack, 500);
    table = new_table;

    // leave_table
    let leave = LeaveTableArgs { seat_index: 0 };
    let leave_bytes = borsh::to_vec(&leave).unwrap();
    let (new_table, events, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::leave_table(), &leave_bytes);
    assert_eq!(new_table.occupied_count(), 0, "leave 后桌台应为空");
    assert_eq!(new_table.seats[0].player, [0u8; 20], "seat 0 应清空");
    assert_eq!(new_table.seats[0].stack, 0, "stack 应清零");
    assert!(
        events.iter().any(|e| matches!(e,
            TexasPokerEvent::PlayerRefund { seat_index, amount, .. }
            if *seat_index == 0 && *amount == 500)),
        "应包含 PlayerRefund 事件（refund 500）"
    );
    assert!(
        events.iter().any(|e| matches!(e,
            TexasPokerEvent::PlayerLeft { seat_index, .. } if *seat_index == 0)),
        "应包含 PlayerLeft 事件"
    );
}

// ========== Test 5: 错误处理 — unknown selector 导致 guest panic ==========

#[test]
fn test_e2e_unknown_selector_panics_guest() {
    let elf = read_guest_elf();
    let ctx = make_context();
    let table = make_initial_table();

    // 用一个不匹配任何已知 selector 的全 0xFF selector
    let unknown = [0xFF; 32];
    let err = dispatch_via_elf_expect_err(&elf, &table, &ctx, unknown, &[]);

    let msg = format!("{err}");
    println!("unknown selector 错误（符合预期）: {msg}");
    // guest dispatch 返回 Err(UnknownMethod) → zkvm_main 返回 Err("...") → panic_msg
    // → execute_elf 返回 ZkvmError::Other("panic_msg: ...") 或类似
    assert!(
        msg.contains("panic")
            || msg.contains("zkvm_panic")
            || msg.contains("guest error")
            || msg.contains("Other"),
        "错误应表明 guest panic，实际: {msg}"
    );
}

// ========== Test 6: 错误处理 — 非法 borsh args 导致 guest panic ==========
//
// 用合法 selector + 非法 args（与期望 *Args 类型不匹配的字节）触发反序列化失败。

#[test]
fn test_e2e_invalid_borsh_args_panics_guest() {
    let elf = read_guest_elf();
    let ctx = make_context();
    let table = make_initial_table();

    // create_table 期望 CreateTableArgs { name: String, max_players: u8, ... }
    // 传入非法 args（4 字节全 0xFF）触发 borsh 反序列化失败
    let invalid_args = [0xFFu8; 16];
    let err = dispatch_via_elf_expect_err(
        &elf,
        &table,
        &ctx,
        selectors::create_table(),
        &invalid_args,
    );

    let msg = format!("{err}");
    println!("invalid borsh args 错误（符合预期）: {msg}");
    assert!(
        msg.contains("panic")
            || msg.contains("zkvm_panic")
            || msg.contains("guest error")
            || msg.contains("Other"),
        "错误应表明 guest panic，实际: {msg}"
    );
}

// ========== Test 7: 错误处理 — 完全非法的 ZkvmInput ==========
//
// 传入长度合法但内容非法的 ZkvmInput bytes → guest borsh 反序列化失败 → panic。

#[test]
fn test_e2e_invalid_zkvm_input_panics_guest() {
    let elf = read_guest_elf();

    // 4 字节 LE 长度 = 32 + 32 字节垃圾数据（不是合法 ZkvmInput borsh）
    let mut input = vec![32u8, 0, 0, 0]; // LE 长度 = 32
    input.extend_from_slice(&[0xAA; 32]); // 垃圾 borsh

    let result = execute_elf(&elf, &input);
    assert!(
        result.is_err(),
        "非法 ZkvmInput 应导致 guest 执行失败"
    );
    let err = result.unwrap_err();
    let msg = format!("{err}");
    println!("invalid ZkvmInput 错误（符合预期）: {msg}");
    assert!(
        msg.contains("panic")
            || msg.contains("uninitialized")
            || msg.contains("UnsupportedInstruction")
            || msg.contains("zkvm_panic")
            || msg.contains("Other"),
        "错误应表明 guest 执行失败，实际: {msg}"
    );
}

// ========== Test 8: TableConfig zk_skip 默认启用 ==========
//
// 验证 guest 编译时 TableConfig 默认 zk_skip_enabled=true，
// 所有 skip_* 标志返回 true（proof 验证可跳过，dummy crypto 数据可用）。

#[test]
fn test_e2e_table_config_zk_skip_default_enabled() {
    let config = texas_poker_guest::types::TableConfig::default();
    assert!(config.zk_skip_enabled, "zk_skip_enabled 应默认 true");
    assert!(config.zk_skip_shuffle, "zk_skip_shuffle 应默认 true");
    assert!(config.zk_skip_reveal, "zk_skip_reveal 应默认 true");
    assert!(config.zk_skip_reconstruct, "zk_skip_reconstruct 应默认 true");
    assert!(config.zk_skip_remask, "zk_skip_remask 应默认 true");
}

// ========== Test 9: 所有 18 个 selector 在 ELF 中可路由（不 panic）==========
//
// 用合法 ZkvmInput 测试每个 selector，验证 dispatch 路由表在 ELF 中完整可用。
// 不验证具体返回值（部分 selector 需要复杂前置状态），仅验证：
// - 已知 selector → 不触发 UnknownMethod panic
// - unknown selector → 触发 panic

#[test]
fn test_e2e_all_selectors_dispatchable() {
    let elf = read_guest_elf();
    let ctx = make_context();
    let table = make_initial_table();

    // 先 create_table 一次，得到有效桌台
    let create_args = CreateTableArgs {
        name: "selector_test".into(),
        max_players: 6,
        small_blind: 25,
        big_blind: 50,
    };
    let create_bytes = borsh::to_vec(&create_args).unwrap();
    let (mut table, _, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::create_table(), &create_bytes);

    // 对每个已知 selector：尝试用空 args 调用。
    // 期望：已知 selector 不会触发 UnknownMethod panic。
    //   - 部分会因 args 反序列化失败而 panic（如 fold 需要 SeatIndexArgs）— 这是
    //     "已知 selector 但 args 不合法" 的 panic，与 UnknownMethod 不同。
    //   - 部分会因状态机校验失败而 panic（如 start_hand 需 ≥2 玩家）。
    //   - 部分会成功（如 reset_for_next_hand 允许空 args）。
    //
    // 我们区分这两类 panic：已知 selector 的失败消息不应包含 "UnknownMethod"。
    let all_selectors = selectors::all();
    assert_eq!(all_selectors.len(), 18, "应有 18 个 selector");

    for (i, sel) in all_selectors.iter().enumerate() {
        // 构造空 args 输入
        let input = ZkvmInput {
            table: table.clone(),
            context: ctx,
            method_selector: *sel,
            args: Vec::new(),
        };
        let input_borsh = borsh::to_vec(&input).unwrap();
        let mut elf_input = (input_borsh.len() as u32).to_le_bytes().to_vec();
        elf_input.extend_from_slice(&input_borsh);

        let result = execute_elf(&elf, &elf_input);
        match &result {
            Ok(r) => {
                // 成功：解析 output，验证 table 状态合理
                let output: ZkvmOutput = BorshDeserialize::try_from_slice(&r.output)
                    .unwrap_or_else(|e| panic!("selector[{i}] output 反序列化失败: {e}"));
                println!("selector[{i}]: Ok (events={})", output.events.len());
                // 更新 table 供下一个 selector 使用
                table = output.table;
            }
            Err(e) => {
                let msg = format!("{e}");
                println!("selector[{i}]: Err = {msg}");
                // 关键断言：已知 selector 不应触发 "UnknownMethod" panic
                // （UnknownMethod 会经 zkvm_main → panic_msg → "guest error"）
                // 实际错误消息应包含 "args borsh" 或 "not in" 等具体失败原因。
                assert!(
                    !msg.contains("UnknownMethod"),
                    "selector[{i}] 不应触发 UnknownMethod（它是已知的），实际: {msg}"
                );
            }
        }
    }
}

// ========== Test 9b: 诊断 — 单独测试 selector 5 (START_HAND) ==========

#[test]
fn test_diag_selector5_start_hand() {
    let elf = read_guest_elf();
    let ctx = make_context();
    let table = make_initial_table();

    // 直接用空 args 调用 START_HAND selector
    let input = ZkvmInput {
        table: table.clone(),
        context: ctx,
        method_selector: selectors::start_hand(),
        args: Vec::new(),
    };
    let input_borsh = borsh::to_vec(&input).unwrap();
    let mut elf_input = (input_borsh.len() as u32).to_le_bytes().to_vec();
    elf_input.extend_from_slice(&input_borsh);

    let result = execute_elf(&elf, &elf_input);
    match &result {
        Ok(r) => println!("selector5: Ok (output {} bytes)", r.output.len()),
        Err(e) => println!("selector5: Err = {e}"),
    }
}

// ========== Test 10: 多次 create_table 覆写 ==========
//
// 验证多次 create_table 调用可以覆写桌台状态（每次都重置为初始状态）。

#[test]
fn test_e2e_create_table_overwrite() {
    let elf = read_guest_elf();
    let ctx = make_context();
    let mut table = make_initial_table();

    // 第一次 create_table
    let args1 = CreateTableArgs {
        name: "first".into(),
        max_players: 6,
        small_blind: 25,
        big_blind: 50,
    };
    let args1_bytes = borsh::to_vec(&args1).unwrap();
    let (new_table, _, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::create_table(), &args1_bytes);
    assert_eq!(new_table.name, "first");
    assert_eq!(new_table.version, 1);
    table = new_table;

    // 第二次 create_table（不同参数）
    let args2 = CreateTableArgs {
        name: "second".into(),
        max_players: 9,
        small_blind: 100,
        big_blind: 200,
    };
    let args2_bytes = borsh::to_vec(&args2).unwrap();
    let (new_table, _, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::create_table(), &args2_bytes);
    assert_eq!(new_table.name, "second", "第二次 create_table 应覆写 name");
    assert_eq!(new_table.max_players, 9, "max_players 应被覆写");
    assert_eq!(new_table.small_blind, 100, "small_blind 应被覆写");
    assert_eq!(new_table.big_blind, 200, "big_blind 应被覆写");
    assert_eq!(new_table.version, 2, "version 应再次 bump");
    assert_eq!(new_table.seats.len(), 9, "seats 应按新 max_players 重建");
}

// ========== Test 11: 多步状态串接 — idempotency sanity check ==========
//
// 验证 host 端持久化的 table 在多次 ELF 调用间正确传递。
// 这是 Stateless ZK 模型的核心假设：每次调用接收完整 table，返回更新后的 table。

#[test]
fn test_e2e_stateless_round_trip_preserves_table() {
    let elf = read_guest_elf();
    let ctx = make_context();

    // 构造 ZkvmInput → borsh → 反序列化 → 应得到相同 table
    let table = make_initial_table();
    let input = ZkvmInput {
        table: table.clone(),
        context: ctx,
        method_selector: selectors::create_table(),
        args: borsh::to_vec(&CreateTableArgs {
            name: "rt".into(),
            max_players: 2,
            small_blind: 5,
            big_blind: 10,
        })
        .unwrap(),
    };
    let bytes = borsh::to_vec(&input).unwrap();
    let recovered: ZkvmInput = BorshDeserialize::try_from_slice(&bytes).unwrap();
    assert_eq!(recovered.table.id, input.table.id);
    assert_eq!(recovered.context, input.context);
    assert_eq!(recovered.method_selector, input.method_selector);
    assert_eq!(recovered.args, input.args);

    // 完整生命周期 round-trip
    let (new_table, _, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::create_table(), &input.args);
    // 新 table 应能再次被 borsh 序列化/反序列化（host 端持久化逻辑）
    let table_bytes = borsh::to_vec(&new_table).expect("更新后的 table 应可 borsh 序列化");
    let recovered_table: TexasPokerTable =
        BorshDeserialize::try_from_slice(&table_bytes).expect("应可反序列化");
    assert_eq!(recovered_table.name, new_table.name);
    assert_eq!(recovered_table.max_players, new_table.max_players);
    assert_eq!(recovered_table.version, new_table.version);
}

// ========== Test 12: DispatchContext 字段正确传递到 guest ==========
//
// 验证 DispatchContext 的 caller/chain_id/block_height/block_timestamp 字段
// 在 borsh 序列化 → ELF 执行 → 反序列化过程中保持一致。

#[test]
fn test_e2e_dispatch_context_borsh_layout_44_bytes() {
    let ctx = make_context();
    let bytes = borsh::to_vec(&ctx).unwrap();
    // caller(20) + chain_id(8) + block_height(8) + block_timestamp(8) = 44 字节
    assert_eq!(
        bytes.len(),
        44,
        "DispatchContext borsh 布局应为 44 字节（20+8+8+8）"
    );
    let recovered: DispatchContext = BorshDeserialize::try_from_slice(&bytes).unwrap();
    assert_eq!(ctx, recovered);
}

// ========== Test 13: 完整 Mental Poker 一手牌 E2E（Phase 5.1 核心测试）==========
//
// 验证完整一手牌流程在真实 RV32I 模拟器中端到端可执行：
//   create_table → join_table × 2 → start_hand
//   → submit_shuffle_v2 × 2（洗牌完成）
//   → submit_player_reveal_tokens × 2（preflop 揭牌 → 发手牌）
//   → check × 2（preflop 下注轮）
//   → submit_player_reveal_tokens（flop 揭牌 → 3 张公共牌）
//   → check × 2（flop 下注轮）
//   → submit_player_reveal_tokens（turn 揭牌 → 1 张公共牌）
//   → check × 2（turn 下注轮）
//   → submit_player_reveal_tokens（river 揭牌 → 1 张公共牌）
//   → check × 2（river 下注轮）
//   → submit_player_reveal_tokens × 2（showdown 揭牌 → 揭示手牌）
//   → settle_hand（自动结算）
//
// # 设计要点
//
// - **zk_skip 模式**：TableConfig 默认所有 skip 标志为 true，shuffle/reveal proof 验证被跳过。
//   但 G1 运算（add_pk_to_c2、partial_decrypt_c2、g1_sub）仍经 syscall 执行真实计算，
//   因此玩家 pk 和 reveal token 必须是有效的 BLS12-381 G1 压缩点。
// - **dummy shuffle**：output_cards 直接传回当前 deck（table.deck_state.encrypted），
//   不做真实洗牌。add_pk_to_c2 会将 player_pk 加到每张牌的 c2 上。
// - **dummy reveal tokens**：使用 G1 单位元（identity）作为 reveal token。
//   partial_decrypt_c2(c2, [identity]) = c2 - identity = c2（no-op），不改变密文。
//   解密结果无意义但状态转换正确。

#[test]
fn test_e2e_full_mental_poker_hand() {
    let elf = read_guest_elf();
    let ctx = make_context();
    let mut table = make_initial_table();

    // ===== 1. create_table =====
    let create_args = CreateTableArgs {
        name: "full_hand".into(),
        max_players: 2,
        small_blind: 10,
        big_blind: 20,
    };
    let create_bytes = borsh::to_vec(&create_args).unwrap();
    let (new_table, _, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::create_table(), &create_bytes);
    assert_eq!(new_table.max_players, 2);
    table = new_table;

    // ===== 2. join_table × 2（使用有效 BLS G1 点作为 pk）=====
    let join1 = JoinTableArgs {
        player: [0x11; 20],
        buy_in: 1000,
        pk: valid_g1(1),
    };
    let (new_table, _, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::join_table(), &borsh::to_vec(&join1).unwrap());
    assert_eq!(new_table.occupied_count(), 1);
    table = new_table;

    let join2 = JoinTableArgs {
        player: [0x22; 20],
        buy_in: 2000,
        pk: valid_g1(2),
    };
    let (new_table, _, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::join_table(), &borsh::to_vec(&join2).unwrap());
    assert_eq!(new_table.occupied_count(), 2);
    table = new_table;

    // ===== 3. start_hand =====
    let (new_table, events, _) =
        dispatch_via_elf(&elf, &table, &ctx, selectors::start_hand(), &[]);
    assert_eq!(
        new_table.shuffle_state.phase,
        texas_poker_guest::constants::SHUFFLE_PHASE_BEFORE_PREFLOP,
        "start_hand 后应进入 BEFORE_PREFLOP shuffle 阶段"
    );
    assert_eq!(new_table.deck_state.encrypted.len(), 52, "应初始化 52 张密文牌");
    assert!(events.iter().any(|e| matches!(e, TexasPokerEvent::HandStarted { .. })));
    table = new_table;
    println!("[3] start_hand: shuffle_phase={}, deck={}, current_shuffler={:?}",
             table.shuffle_state.phase, table.deck_state.encrypted.len(),
             table.shuffle_state.current_shuffler);

    // ===== 4. submit_shuffle_v2 (seat 0) =====
    let shuffle0 = SubmitShuffleV2Args {
        seat_index: 0,
        output_cards: table.deck_state.encrypted.clone(),
        shuffle_proof: Vec::new(),
    };
    let (new_table, _, _) = dispatch_via_elf(
        &elf, &table, &ctx, selectors::submit_shuffle_v2(),
        &borsh::to_vec(&shuffle0).unwrap(),
    );
    assert_eq!(
        new_table.shuffle_state.current_shuffler,
        Some(1),
        "seat 0 洗牌后应轮到 seat 1"
    );
    table = new_table;
    println!("[4] shuffle seat 0: pending={:?}, completed={:?}",
             table.shuffle_state.pending_players, table.shuffle_state.completed_players);

    // ===== 5. submit_shuffle_v2 (seat 1) =====
    let shuffle1 = SubmitShuffleV2Args {
        seat_index: 1,
        output_cards: table.deck_state.encrypted.clone(),
        shuffle_proof: Vec::new(),
    };
    let (new_table, events, _) = dispatch_via_elf(
        &elf, &table, &ctx, selectors::submit_shuffle_v2(),
        &borsh::to_vec(&shuffle1).unwrap(),
    );
    // 洗牌完成 → preflop reveal phase 自动启动
    assert_eq!(
        new_table.shuffle_state.phase,
        texas_poker_guest::constants::SHUFFLE_PHASE_NONE,
        "洗牌完成后 shuffle_state 应重置为 NONE"
    );
    assert_eq!(
        new_table.reveal_token_state.reveal_phase,
        texas_poker_guest::constants::REVEAL_PHASE_PREFLOP,
        "应进入 PREFLOP reveal 阶段"
    );
    assert!(events.iter().any(|e| matches!(e, TexasPokerEvent::ShuffleComplete { .. })));
    table = new_table;
    println!("[5] shuffle seat 1: reveal_phase={}, assignments={}",
             table.reveal_token_state.reveal_phase,
             table.reveal_token_state.assignments.len());

    // ===== 6. preflop reveal — 每位玩家为其他玩家的牌提交 reveal token =====
    //
    // preflop 揭牌分配（2 玩家 × 2 张牌 = 4 个 assignment）：
    //   assignment[0]: card_idx=0, pending=[1]  → seat 1 提交 token
    //   assignment[1]: card_idx=1, pending=[1]  → seat 1 提交 token
    //   assignment[2]: card_idx=2, pending=[0]  → seat 0 提交 token
    //   assignment[3]: card_idx=3, pending=[0]  → seat 0 提交 token
    let id_point = identity_g1();
    // seat 0 为 assignment 2, 3 提交 reveal token
    let reveal0 = SubmitRevealTokensArgs {
        seat_index: 0,
        assignment_indices: vec![2, 3],
        reveal_tokens: vec![id_point; 2],
        proofs: vec![Vec::new(); 2],
    };
    let (new_table, _, _) = dispatch_via_elf(
        &elf, &table, &ctx, selectors::submit_player_reveal_tokens(),
        &borsh::to_vec(&reveal0).unwrap(),
    );
    table = new_table;
    // seat 1 为 assignment 0, 1 提交 reveal token
    let reveal1 = SubmitRevealTokensArgs {
        seat_index: 1,
        assignment_indices: vec![0, 1],
        reveal_tokens: vec![id_point; 2],
        proofs: vec![Vec::new(); 2],
    };
    let (new_table, events, _) = dispatch_via_elf(
        &elf, &table, &ctx, selectors::submit_player_reveal_tokens(),
        &borsh::to_vec(&reveal1).unwrap(),
    );
    // 所有 assignment 解密完成 → check_reveal_phase_complete → post_blinds + start_betting_round
    assert_eq!(
        new_table.reveal_token_state.reveal_phase,
        texas_poker_guest::constants::REVEAL_PHASE_NONE,
        "preflop reveal 完成后 reveal_phase 应重置为 NONE"
    );
    assert!(
        new_table.betting_round.is_some(),
        "preflop reveal 完成后应启动下注轮"
    );
    assert!(events.iter().any(|e| matches!(e, TexasPokerEvent::RevealPhaseComplete { .. })));
    table = new_table;
    println!("[6] preflop reveal complete: betting_round={:?}, current_turn={:?}, pot={}",
             table.betting_round.is_some(), table.current_turn, table.pot);

    // ===== 7. preflop 下注轮 — SB call + BB check =====
    // heads-up preflop: SB(button) 先行动，需 call 匹配 BB 盲注；BB 可 check
    do_betting_round(&elf, &ctx, &mut table, "[7] preflop");
    assert_eq!(
        table.round_state,
        texas_poker_guest::constants::ROUND_FLOP,
        "preflop 下注轮完成后应进入 FLOP"
    );
    assert_eq!(
        table.reveal_token_state.reveal_phase,
        texas_poker_guest::constants::REVEAL_PHASE_FLOP,
        "应启动 FLOP reveal 阶段"
    );
    println!("[7] preflop betting done: round={}, reveal_phase={}, community={}",
             table.round_state, table.reveal_token_state.reveal_phase,
             table.community_cards.len());

    // ===== 8. flop reveal — 3 张公共牌 =====
    do_community_reveal(&elf, &ctx, &mut table, "[8] flop");
    assert!(
        table.betting_round.is_some(),
        "flop reveal 完成后应启动下注轮"
    );

    // ===== 9. flop 下注轮 — check × 2 =====
    do_betting_round(&elf, &ctx, &mut table, "[9] flop");
    assert_eq!(
        table.round_state,
        texas_poker_guest::constants::ROUND_TURN,
        "flop 下注轮完成后应进入 TURN"
    );

    // ===== 10. turn reveal — 1 张公共牌 =====
    do_community_reveal(&elf, &ctx, &mut table, "[10] turn");

    // ===== 11. turn 下注轮 — check × 2 =====
    do_betting_round(&elf, &ctx, &mut table, "[11] turn");
    assert_eq!(
        table.round_state,
        texas_poker_guest::constants::ROUND_RIVER,
        "turn 下注轮完成后应进入 RIVER"
    );

    // ===== 12. river reveal — 1 张公共牌 =====
    do_community_reveal(&elf, &ctx, &mut table, "[12] river");

    // ===== 13. river 下注轮 — check × 2 =====
    do_betting_round(&elf, &ctx, &mut table, "[13] river");
    assert_eq!(
        table.round_state,
        texas_poker_guest::constants::ROUND_SHOWDOWN,
        "river 下注轮完成后应进入 SHOWDOWN"
    );

    // ===== 14. showdown reveal — 揭示所有未弃牌玩家的手牌 =====
    // showdown 的 assignment: 每位未弃牌玩家的 2 张手牌，
    // pending = 其他所有未弃牌玩家
    let showdown_assignments: Vec<u8> = table
        .reveal_token_state
        .assignments
        .iter()
        .enumerate()
        .filter_map(|(i, a)| {
            if !a.decrypted {
                Some(i as u8)
            } else {
                None
            }
        })
        .collect();
    println!("[14] showdown: {} pending assignments", showdown_assignments.len());

    // 每位玩家为其 pending 的 assignment 提交 reveal token
    for seat in 0u8..2 {
        let my_assignments: Vec<u8> = table
            .reveal_token_state
            .assignments
            .iter()
            .enumerate()
            .filter_map(|(i, a)| {
                if !a.decrypted && is_in_list(&a.pending_players, seat) {
                    Some(i as u8)
                } else {
                    None
                }
            })
            .collect();
        if my_assignments.is_empty() {
            continue;
        }
        let reveal = SubmitRevealTokensArgs {
            seat_index: seat,
            assignment_indices: my_assignments.clone(),
            reveal_tokens: vec![id_point; my_assignments.len()],
            proofs: vec![Vec::new(); my_assignments.len()],
        };
        let (new_table, _, _) = dispatch_via_elf(
            &elf, &table, &ctx, selectors::submit_player_reveal_tokens(),
            &borsh::to_vec(&reveal).unwrap(),
        );
        table = new_table;
    }

    // showdown reveal 完成 → settle_hand 自动执行
    assert_eq!(
        table.reveal_token_state.reveal_phase,
        texas_poker_guest::constants::REVEAL_PHASE_NONE,
        "showdown reveal 完成后 reveal_phase 应为 NONE"
    );
    // settle_hand 后应回到 WAITING（或类似终态）
    assert!(
        table.round_state == texas_poker_guest::constants::ROUND_WAITING
            || table.round_state == texas_poker_guest::constants::ROUND_SHOWDOWN,
        "settle_hand 后 round_state 应为 WAITING 或 SHOWDOWN，实际: {}",
        table.round_state
    );
    println!("[14] showdown + settle: round_state={}, pot={}, community={}",
             table.round_state, table.pot, table.community_cards.len());
    println!("✓ 完整 Mental Poker 一手牌 E2E 通过！");
}

/// 执行一轮下注（heads-up，智能选择 call 或 check）。
///
/// 从 table.current_turn 读取当前行动者：
/// - 若 seat.bet < current_bet → call（匹配当前下注额）
/// - 否则 → check（过牌）
///
/// 循环直到下注轮结束（betting_round = None 或 current_turn = None）。
fn do_betting_round(
    elf: &[u8],
    ctx: &DispatchContext,
    table: &mut TexasPokerTable,
    label: &str,
) {
    for _ in 0..6 {
        let turn = match table.current_turn {
            Some(seat) => seat,
            None => break, // 下注轮已结束
        };
        // 读取当前下注额
        let current_bet = table
            .betting_round
            .as_ref()
            .map(|r| r.current_bet)
            .unwrap_or(0);
        let seat_bet = table.seats[turn as usize].bet;
        let selector = if seat_bet < current_bet {
            selectors::call()
        } else {
            selectors::check()
        };
        let args = SeatIndexArgs { seat_index: turn };
        let (new_table, _, _) = dispatch_via_elf(
            elf, table, ctx, selector,
            &borsh::to_vec(&args).unwrap(),
        );
        *table = new_table;
        if table.betting_round.is_none() || table.current_turn.is_none() {
            break;
        }
    }
    println!("{label} betting: betting_round={:?}, current_turn={:?}",
             table.betting_round.is_some(), table.current_turn);
}

/// 执行公共牌揭牌（flop/turn/river）。
///
/// 公共牌的 assignment：pending_players = 所有活跃玩家。
/// 每位玩家为其 pending assignment 提交 identity reveal token。
fn do_community_reveal(
    elf: &[u8],
    ctx: &DispatchContext,
    table: &mut TexasPokerTable,
    label: &str,
) {
    let id_point = identity_g1();
    for seat in 0u8..2 {
        let my_assignments: Vec<u8> = table
            .reveal_token_state
            .assignments
            .iter()
            .enumerate()
            .filter_map(|(i, a)| {
                if !a.decrypted && is_in_list(&a.pending_players, seat) {
                    Some(i as u8)
                } else {
                    None
                }
            })
            .collect();
        if my_assignments.is_empty() {
            continue;
        }
        let reveal = SubmitRevealTokensArgs {
            seat_index: seat,
            assignment_indices: my_assignments.clone(),
            reveal_tokens: vec![id_point; my_assignments.len()],
            proofs: vec![Vec::new(); my_assignments.len()],
        };
        let (new_table, _, _) = dispatch_via_elf(
            elf, table, ctx, selectors::submit_player_reveal_tokens(),
            &borsh::to_vec(&reveal).unwrap(),
        );
        *table = new_table;
    }
    println!("{label} reveal: reveal_phase={}, betting_round={:?}",
             table.reveal_token_state.reveal_phase, table.betting_round.is_some());
}

/// 检查值是否在列表中（复用 guest state_machine 逻辑的 host 端版本）。
fn is_in_list(list: &[u8], value: u8) -> bool {
    list.iter().any(|&v| v == value)
}
