//! devnet 一手牌全链路端到端（#[ignore]：需本地 starknet-devnet + 已部署套件）。
//!
//! 前置：
//! 1. `starknet-devnet --seed 0 --port 5051 --accounts 3`
//! 2. `poker-contracts deploy --network devnet --with-registry`（注册表含全部地址）
//!
//! 流程（legacy 线性结算，与主网 v1 接线惯例一致）：
//! vault.settlement → legacy PokerSettlement → 两玩家 approve+deposit →
//! operator `register_aggregate`（离线 `settlement_root` 计算承诺，链上重算
//! 对拍）→ `settle_hand`（零和校验 + `vault.apply_settlement` 划转）→
//! 余额/状态断言。
//!
//! ```bash
//! cargo test -p poker-contracts --test devnet_hand_e2e -- --ignored --nocapture
//! ```
use poker_contracts::bindings::settlement::settlement_root;
use poker_contracts::bindings::strk::StrkToken;
use poker_contracts::bindings::vault::Vault;
use poker_contracts::client::ChainClient;
use poker_contracts::codec::{i128_to_felt, parse_felt, Felt, Uint256};
use poker_contracts::config::{ContractsConfig, Network};
use poker_contracts::error::ContractsResult;
use poker_contracts::registry::CanonicalAddressRegistry;

/// devnet `--seed 0` 预充值账号（确定性；见 DEPLOYMENTS.md devnet 节）。
const OPERATOR: (&str, &str) = (
    "0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691",
    "0x71d7bb07b9a64f6f78ac4c816aff4da9",
);
const PLAYER_A: (&str, &str) = (
    "0x078662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1",
    "0x0e1406455b7d66b1690803be066cbe5e",
);
const PLAYER_B: (&str, &str) = (
    "0x049dfb8ce986e21d354ac93ea65e6a11f639c1934ea253e5ff14ca62eca0f38e",
    "0xa20a02f0ac53692d144b20cb371a60d7",
);

/// chip 口径与 texas 服务端一致（WEI_PER_CHIP = 1e14）。
const CHIP_WEI: i128 = 100_000_000_000_000;
const DEPOSIT_A: i128 = 1000 * CHIP_WEI; // 1000 chips
const DEPOSIT_B: i128 = 800 * CHIP_WEI; // 800 chips
const A_WINS: i128 = 300 * CHIP_WEI; // 手牌结算：A +300 / B -300（合约要求 |delta| ≤ u64）

fn hand_id_now() -> u64 {
    // 可重复执行：hand_id 随运行递增（链上 last_hand_id 单调约束）
    std::env::var("HAND_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(1)
        })
}

async fn client_for(cfg: &ContractsConfig, who: (&str, &str)) -> ContractsResult<ChainClient> {
    let mut c = cfg.clone();
    c.account_address = Some(parse_felt(who.0)?);
    c.private_key = Some(parse_felt(who.1)?);
    ChainClient::connect(&c).await
}

#[tokio::test]
#[ignore = "requires local starknet-devnet + deployed suite"]
async fn devnet_full_hand_settlement() {
    let mut cfg = ContractsConfig::default();
    cfg.network = Network::Devnet;
    let reg = CanonicalAddressRegistry::load(
        &CanonicalAddressRegistry::path_for(
            &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("registry"),
            Network::Devnet,
        ),
    )
    .expect("registry/devnet.json（先执行 poker-contracts deploy）");
    cfg.addresses = reg.to_deployed_addresses();
    let vault_addr = cfg.addresses.vault.expect("vault in registry");
    let settle_addr = cfg.addresses.settlement.expect("settlement in registry");
    let strk_addr = parse_felt(&reg.constants["strk"]).expect("strk const");

    let operator = client_for(&cfg, OPERATOR).await.expect("operator client");
    let player_a = client_for(&cfg, PLAYER_A).await.expect("player A client");
    let player_b = client_for(&cfg, PLAYER_B).await.expect("player B client");
    let a_addr = parse_felt(PLAYER_A.0).unwrap();
    let b_addr = parse_felt(PLAYER_B.0).unwrap();

    // [0] owner：vault.settlement 绑定切到 legacy PokerSettlement
    //     （主网 v1 接线惯例；apply_settlement 只认当前绑定合约）
    let vault_owner = Vault::at(vault_addr);
    let tx = operator
        .invoke_batch(vec![vault_owner.set_settlement_contract_call(settle_addr)])
        .await
        .expect("rewire vault→legacy settlement");
    operator.wait_default(tx).await.expect("rewire accepted");
    println!("[0] vault.settlement → legacy {settle_addr:#x} (tx {tx:#x})");

    // [1] 玩家入金：approve、deposit 分两笔（1:1 STRK → chips；断言用增量，
    //     测试可在同一 devnet 上重复执行）
    let before_a = vault_owner.chip_balance(&operator, a_addr).await.unwrap();
    let before_b = vault_owner.chip_balance(&operator, b_addr).await.unwrap();
    let strk = StrkToken::at(strk_addr);
    for (client, name, _addr, amount) in [
        (&player_a, "A", a_addr, DEPOSIT_A),
        (&player_b, "B", b_addr, DEPOSIT_B),
    ] {
        let amount = amount.unsigned_abs();
        let tx = client
            .invoke_batch(vec![strk.approve_call(vault_addr, Uint256::from_u128(amount))])
            .await
            .unwrap_or_else(|e| panic!("{name} approve: {e}"));
        client.wait_default(tx).await.expect("approve accepted");
        let tx = client
            .invoke_batch(vec![vault_owner.deposit_call(Uint256::from_u128(amount))])
            .await
            .unwrap_or_else(|e| panic!("{name} deposit: {e}"));
        client.wait_default(tx).await.expect("deposit accepted");
        println!("[1] player {name} deposit {amount} wei (deposit tx {tx:#x})");
    }
    let after_deposit_a = vault_owner.chip_balance(&operator, a_addr).await.unwrap();
    let after_deposit_b = vault_owner.chip_balance(&operator, b_addr).await.unwrap();
    assert_eq!(
        after_deposit_a,
        before_a + Uint256::from_u128(DEPOSIT_A as u128),
        "A chip += deposit"
    );
    assert_eq!(
        after_deposit_b,
        before_b + Uint256::from_u128(DEPOSIT_B as u128),
        "B chip += deposit"
    );

    // [2] 手牌结果：A 胜 300 chips → deltas [+300, -300]（零和）
    let hand_id = hand_id_now();
    let action_log = parse_felt(&format!("{hand_id:#x}a11ce")).unwrap_or_else(|_| parse_felt("0xa11ce").unwrap());
    let root = settlement_root(hand_id, &[(a_addr, A_WINS), (b_addr, -A_WINS)], action_log);
    println!("[2] hand_id = {hand_id}, action_log = {action_log:#x}");
    println!("[2] settlement_root = {root:#x}");

    // [3] operator：register_aggregate（(digest), first, last, pre, post, roots）
    let register_calldata = vec![
        Felt::from(hand_id),
        Felt::from(hand_id),
        Felt::from(hand_id),
        Felt::from(hand_id),
        Felt::from(1_u64),
        Felt::from(1_u64),
        Felt::from(1_u64),
        Felt::from(2_u64),
        Felt::from(1_u64),
        root,
    ];
    let tx = operator
        .invoke(settle_addr, "register_aggregate", register_calldata)
        .await
        .expect("register_aggregate");
    operator.wait_default(tx).await.expect("register accepted");
    println!("[3] register_aggregate tx {tx:#x}");

    // [4] operator：settle_hand（链上重算承诺 + 零和 + vault.apply_settlement）
    let settle_calldata = vec![
        Felt::from(hand_id),
        Felt::from(hand_id),
        Felt::from(hand_id),
        action_log,
        Felt::from(2_u64),
        a_addr,
        b_addr,
        Felt::from(2_u64),
        i128_to_felt(A_WINS),
        i128_to_felt(-A_WINS),
    ];
    let tx = operator
        .invoke(settle_addr, "settle_hand", settle_calldata)
        .await
        .expect("settle_hand");
    operator.wait_default(tx).await.expect("settle accepted");
    println!("[4] settle_hand tx {tx:#x}");

    // [5] 链上核验：筹码精确划转 + 结算状态（相对入金后的增量）
    let chips_a = vault_owner.chip_balance(&operator, a_addr).await.unwrap();
    let chips_b = vault_owner.chip_balance(&operator, b_addr).await.unwrap();
    assert_eq!(
        chips_a,
        after_deposit_a + Uint256::from_u128(A_WINS.unsigned_abs()),
        "A: +300 chips"
    );
    assert_eq!(
        chips_b,
        after_deposit_b - Uint256::from_u128(A_WINS.unsigned_abs()),
        "B: -300 chips"
    );
    let settled = poker_contracts::bindings::settlement::Settlement::at(settle_addr)
        .hand_settled(&operator, hand_id)
        .await
        .unwrap();
    assert!(settled, "hand_settled({hand_id})");
    let digest = poker_contracts::bindings::settlement::Settlement::at(settle_addr)
        .settlement_digest(&operator, hand_id)
        .await
        .unwrap();
    assert_eq!(digest, root, "链上承诺 == 离线计算（poseidon 对拍）");
    println!(
        "[5] ✅ 结算完成（hand {hand_id}）：A chips = {} wei, B chips = {} wei, hand_settled = true, 承诺对拍一致",
        chips_a.low, chips_b.low
    );
}
