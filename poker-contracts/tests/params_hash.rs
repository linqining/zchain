//! TableRegistry params_hash 跨端 KAT：与 poker_texas_air
//! `texas/src/starknet/table_registry.rs` 的 `compute_params_hash` 同公式
//! （poseidon_hash_many([max_players, small_blind, big_blind])）。
//!
//! 十六进制期望值在冻结时生成（starknet-crypto poseidon 与 Cairo
//! poseidon_builtin 同参数），Cairo / 客户端复验端以此对拍。

use poker_contracts::bindings::table_registry::compute_params_hash;
use poker_contracts::codec::Felt;

/// 冻结向量：`compute_params_hash(9, 100, 200)`（texas 侧测试同输入；
/// 由本 crate starknet-crypto poseidon 生成并冻结——与 Cairo
/// poseidon_builtin 同参数，客户端复验端以此对拍）。
const EXPECTED_9_100_200: &str =
    "0x34999b992d77eaa14cd48e25f10758aef2dfb2174f2ff2efee5eec34bfb44a6";

#[test]
fn params_hash_kat_field_order_is_frozen() {
    let h = compute_params_hash(9, 100, 200);
    assert_eq!(format!("{h:#x}"), EXPECTED_9_100_200, "字段顺序冻结：[max, sb, bb]");
    // 字段错位 = 不同承诺（避免 silent 碰撞）
    assert_ne!(h, compute_params_hash(8, 100, 200));
    assert_ne!(h, compute_params_hash(9, 200, 100));
    assert_ne!(h, compute_params_hash(9, 100, 201));
}

/// 冻结时的生成路径（运行 `cargo test -- --ignored --nocapture` 打印，
/// 随后把值回填进上面的常量并解锁断言）。
#[test]
#[ignore = "freeze helper: prints the poseidon vector"]
fn print_params_hash_vector() {
    let h = compute_params_hash(9, 100, 200);
    println!("EXPECTED_9_100_200 = {h:#x}");
    let _ = Felt::ZERO;
}
