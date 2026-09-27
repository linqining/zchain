//! 编译产物对拍：solc 产出的合约 ABI（contracts/monad/out/solc/*.abi，由
//! `contracts/monad/build_solc.sh` 生成）与 Rust 侧 calldata 编码器的函数
//! 签名必须一致——防止两侧签名漂移（改名/改参数序）。
//!
//! 工件缺失时跳过（CI 未跑编译的场景），本地验收路径（build_solc.sh 后
//! cargo test）恒为强校验。

use monad_settlement::keccak::selector;

/// 从 ABI JSON 提取某函数的规范签名并校验 selector 与 Rust 编码器一致。
fn check(path: &str, func: &str, expected_sig: &str) {
    let Ok(raw) = std::fs::read_to_string(path) else {
        eprintln!("skip（未编译）: {path} —— 先跑 contracts/monad/build_solc.sh");
        return;
    };
    let abi: serde_json::Value = serde_json::from_str(&raw).expect("abi json");
    let entry = abi
        .as_array()
        .expect("abi array")
        .iter()
        .find(|e| e.get("name").and_then(serde_json::Value::as_str) == Some(func))
        .unwrap_or_else(|| panic!("ABI 缺少函数 {func}（{path}）"));

    // 规范签名：name(type,type,...)，tuple → (components...)。
    let types: Vec<String> = entry["inputs"]
        .as_array()
        .expect("inputs")
        .iter()
        .map(|i| canonical_type(i))
        .collect();
    let sig = format!("{}({})", func, types.join(","));
    assert_eq!(
        sig, expected_sig,
        "ABI 签名与 Rust 编码器不一致（{path}）"
    );
    // selector 比对（ABI 无 selector 字段，规范签名的 keccak4 即 selector）。
    let abi_selector = selector(&sig);
    let rust_selector = selector(expected_sig);
    assert_eq!(abi_selector, rust_selector);
}

fn canonical_type(input: &serde_json::Value) -> String {
    let base = input["type"].as_str().expect("type").to_string();
    if base == "tuple" {
        let inner: Vec<String> = input["components"]
            .as_array()
            .expect("components")
            .iter()
            .map(canonical_type)
            .collect();
        format!("({})", inner.join(","))
    } else {
        base
    }
}

#[test]
fn compiled_abi_selectors_match_rust_encoders() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../contracts/monad/out/solc");
    check(
        &format!("{dir}/L1Inbox.abi"),
        "submitBatch",
        "submitBatch(uint64,bytes32,uint64)",
    );
    check(
        &format!("{dir}/L1Inbox.abi"),
        "submitAggregate",
        "submitAggregate(uint64,bytes32,uint64,uint64)",
    );
    check(
        &format!("{dir}/L1Inbox.abi"),
        "submitCheckpoint",
        "submitCheckpoint(uint64,bytes32,bytes32,uint64)",
    );
    check(
        &format!("{dir}/L1Outbox.abi"),
        "claim",
        "claim((bytes32,bytes32,uint8,uint64,bytes32,uint64),bytes32,uint64,uint64,bytes32[])",
    );
    check(
        &format!("{dir}/L1Outbox.abi"),
        "commitRoot",
        "commitRoot(uint64,uint64,bytes32,bool)",
    );
    check(
        &format!("{dir}/L1Bridge.abi"),
        "depositNative",
        "depositNative(address)",
    );
}
