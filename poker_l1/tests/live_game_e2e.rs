//! zchain 链上真实牌局 e2e：真 Node（内存持久化）+ 真区块 + 真签名交易，
//! 通过内置 texas_poker 合约（precompile `0xFF..02`，节点启动即注册——
//! zchain 语义下的"已部署合约"）完成一手牌的合约计算。
//!
//! 已实证语义（本文件注释）：
//! - 合约初始牌堆 = (c1=G, c2=明文牌点)，与 `generate_plaintext_cards` 一致；
//! - `submit_shuffle_v2` 链上验证 = poker_protocol `ShuffleProof`（同
//!   transcript `zk_shuffle_proof_v2`），验证通过后链上注入 shuffler_pk 到
//!   每张 c2（`add_pk_to_c2`）——驱动端镜像同式推进。
//!
//! 运行：`cargo test -p poker_l1 --test live_game_e2e -- --nocapture`
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use poker_protocol::crypto::stark_curve::{StarkPoint, StarkScalar};
use poker_l1::account::derive_address;
use poker_l1::block::{compute_tx_merkle_root, Block, BlockHeader};
use poker_l1::consensus::validator_set::ValidatorEntry;
use poker_l1::consensus::DagCommitCertificate;
use poker_l1::node::Node;
use poker_l1::object_model::ObjectID;
use poker_l1::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme};
use poker_l1::signature::TaggedPubkey;
use poker_l1::transaction::{ContractCall, Gas, RouteHint, Transaction, TxLane};
use poker_l1::vm::contracts::texas_poker::dispatch::{
    CreateTableArgs, JoinTableArgs, SubmitShuffleV2Args,
};
use poker_l1::vm::contracts::texas_poker::dispatch::selectors;
use poker_l1::vm::precompile::reserved;
use poker_l1::{DEFAULT_CHAIN_ID, Hash};
use poker_protocol::zk_shuffle::transcript_ext::CryptoTranscript as _;
use secp256k1::{Message, Secp256k1};

const TABLE_ID: ObjectID = reserved::texas_poker_contract_id();
const CAIRO_REGISTRY_ID: ObjectID = reserved::cairo_registry_contract_id();

/// 复制 `economics::genesis_coin_nonce`（私有但为共识级常量）。
fn genesis_coin_nonce(chain_id: u64, owner: &[u8; 20]) -> u64 {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"ZCHAIN_GENESIS_NATIVE_COIN_V1");
    hasher.update(&chain_id.to_be_bytes());
    hasher.update(owner);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("fixed output");
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"))
}

/// 测试参与者：secp256k1 签名密钥 + BLS ElGamal 密钥 + genesis 资金。
struct Actor {
    secp_secret: secp256k1::SecretKey,
    tagged: TaggedPubkey,
    address: [u8; 20],
    bls_sk: StarkScalar,
    bls_pk: StarkPoint,
    nonce: u64,
}

impl Actor {
    fn new(secp_byte: u8, bls_byte: u64) -> Self {
        let secp = Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        secret_bytes[31] = secp_byte;
        secret_bytes[30] = 0xAB;
        let secret = secp256k1::SecretKey::from_slice(&secret_bytes).expect("deterministic key");
        let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let tagged = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            CURRENT_VERSION,
            public.serialize().to_vec(),
        )
        .expect("tagged pubkey");
        let address = derive_address(&tagged);
        let bls_sk = StarkScalar::from_u64(bls_byte) + StarkScalar::from_u64(1_u64);
        let bls_pk = StarkPoint::generator() * bls_sk;
        Self { secp_secret: secret, tagged, address, bls_sk, bls_pk, nonce: 0 }
    }

    fn coin_id(&self, chain_id: u64) -> ObjectID {
        ObjectID::new(self.address, genesis_coin_nonce(chain_id, &self.address))
    }
}

/// 构造并签名一笔合约调用交易（Public 通道，免费策略；可指定目标合约）。
fn contract_call_tx(
    actor: &mut Actor,
    selector: [u8; 32],
    args: Vec<u8>,
    inputs: Vec<ObjectID>,
) -> Transaction {
    contract_call_tx_to(actor, TABLE_ID, selector, args, inputs)
}

fn contract_call_tx_to(
    actor: &mut Actor,
    contract_id: ObjectID,
    selector: [u8; 32],
    args: Vec<u8>,
    inputs: Vec<ObjectID>,
) -> Transaction {
    let secp = Secp256k1::new();
    let tx_nonce = actor.nonce;
    actor.nonce += 1;
    let tx = Transaction {
        inputs,
        outputs: vec![],
        contract_call: Some(ContractCall {
            contract_id,
            method_selector: selector,
            args,
        }),
        tagged_pubkey: actor.tagged.clone(),
        signature: vec![0u8; 65],
        gas: Gas::new(10_000_000, 1),
        lane_hint: TxLane::Public,
        route_hint: RouteHint::AnyValidator,
        chain_id: DEFAULT_CHAIN_ID,
        nonce: tx_nonce,
        gameturn_nonce: None,
        is_fallback: false,
    };
    let signing_hash = tx.signing_hash();
    let msg = Message::from_digest_slice(&signing_hash).expect("signing_hash 32 bytes");
    let sig = secp.sign_ecdsa_recoverable(&msg, &actor.secp_secret);
    let (recovery_id, compact) = sig.serialize_compact();
    let mut sig_bytes = compact.to_vec();
    sig_bytes.push(recovery_id.to_i32() as u8);
    Transaction { signature: sig_bytes, ..tx }
}

/// 把待打包交易提交进真区块（生产同路径：模拟执行状态根 → 证书 → put_block）。
/// 返回回执（断言全部成功）。
fn commit_block(
    node: &Node,
    validator: &Actor,
    chain: &mut [Hash; 2],
    txs: Vec<Transaction>,
) -> Vec<poker_l1::executor::TxReceipt> {
    assert!(!txs.is_empty(), "empty block");
    for tx in &txs {
        node.submit_tx(tx.clone()).expect("submit_tx");
    }
    let pending = node.drain_pending_tx();
    assert_eq!(pending.len(), txs.len(), "all txs buffered");
    let height = node
        .block_store()
        .get_tip_height()
        .ok()
        .flatten()
        .unwrap_or(0)
        + 1;
    let prev_block_hash: Hash = chain[0];
    let public_tx_root = compute_tx_merkle_root(&pending);
    let gameturn_tx_root = compute_tx_merkle_root(&[]);
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let proposer = derive_address(&validator.tagged);
    let env = node
        .execution_environment(height, timestamp_ms)
        .with_proposer(proposer);
    let outcome = node
        .simulate_block_execution(&env, &pending)
        .expect("simulate_block_execution（区块内合约执行）");
    for (i, receipt) in outcome.receipts.iter().enumerate() {
        assert!(
            receipt.success,
            "区块内第 {i} 笔 tx 执行失败: {:?}",
            receipt.error
        );
    }
    let secp = Secp256k1::new();
    let mut cert = DagCommitCertificate {
        epoch: 0,
        commit_round: height,
        prev_commit_hash: chain[1],
        vertex_hash_list: vec![],
        round_attendance_bitmap: vec![0x01],
        state_root: outcome.state_root,
        public_tx_root,
        gameturn_tx_root,
        signature_list: vec![],
        signer_bitmap: vec![0x01],
    };
    let msg = Message::from_digest(cert.signing_hash(node.chain_id()));
    let sig = secp.sign_ecdsa_recoverable(&msg, &validator.secp_secret);
    let (recovery_id, compact) = sig.serialize_compact();
    let mut sig65 = compact.to_vec();
    sig65.push(recovery_id.to_i32() as u8);
    cert.signature_list = vec![sig65];
    let cert_signing_hash = cert.signing_hash(node.chain_id());
    let header = BlockHeader {
        height,
        timestamp_ms,
        prev_hash: prev_block_hash,
        state_root: outcome.state_root,
        public_tx_root,
        gameturn_tx_root,
        dag_commit_certificate: cert,
    };
    let block = Block::new(header, pending, vec![]);
    let put = node.put_block(&block).expect("put_block（真实区块提交）");
    assert_eq!(put, block.header.block_hash(node.chain_id()));
    *chain = [put, cert_signing_hash];
    outcome.receipts
}

fn table_object(node: &Node) -> poker_l1::object_model::Object {
    node.get_object(&TABLE_ID)
        .expect("object db 读失败")
        .unwrap_or_else(|| panic!("table object {TABLE_ID:?} 不存在"))
}

/// 解码链上完整桌台状态（hot + 3 个 context 对象）。
fn decode_onchain_table(
    node: &Node,
) -> poker_l1::vm::contracts::texas_poker::types::TexasPokerTable {
    use poker_l1::vm::contracts::texas_poker::state_codec;
    use poker_l1::vm::contracts::texas_poker::types::{
        GovernancePolicy, TableContextOpenings, TableMetadata, TableRules,
    };
    let hot = table_object(node);
    let metadata: TableMetadata = borsh::from_slice(
        &node
            .get_object(&state_codec::table_metadata_object_id(TABLE_ID))
            .expect("db")
            .expect("metadata object")
            .data,
    )
    .expect("decode metadata");
    let rules: TableRules = borsh::from_slice(
        &node
            .get_object(&state_codec::table_rules_object_id(TABLE_ID))
            .expect("db")
            .expect("rules object")
            .data,
    )
    .expect("decode rules");
    let governance: GovernancePolicy = borsh::from_slice(
        &node
            .get_object(&state_codec::table_governance_object_id(TABLE_ID))
            .expect("db")
            .expect("governance object")
            .data,
    )
    .expect("decode governance");
    let openings = TableContextOpenings { metadata, rules, governance };
    state_codec::decode_hot_table_state(&hot.data, &openings).expect("decode hot table")
}

#[test]
fn live_node_poker_hand_e2e() {
    // ===== 1. 节点与参与者 =====
    let mut validator = Actor::new(0xF0, 0xE0);
    let mut host = Actor::new(0x01, 0xB1); // 建桌者
    let mut alice = Actor::new(0x02, 0xB2);
    let mut bob = Actor::new(0x03, 0xB3);
    let validator_entry = ValidatorEntry {
        pubkey: validator.tagged.clone(),
        vrf_pubkey: [0x02; 33],
        stake: 0,
        status: poker_l1::consensus::validator_set::ValidatorStatus::Active,
        bonding_until_height: 0,
        unbonding_until_height: 0,
        last_vertex_height: 0,
        under_investigation_count: 0,
        vrf_key_destroyed: false,
        vrf_retired: false,
    };
    let node = Node::open_inmemory_with_validators(
        poker_l1::node::NodeRole::Validator,
        DEFAULT_CHAIN_ID,
        vec![validator_entry],
    )
    .expect("open node");
    let mut chain: [Hash; 2] = [[0u8; 32]; 2]; // [prev_block_hash, prev_cert_signing_hash]

    // ===== 2. genesis 铸币 =====
    // validator 也在分配表中：账户需存在才能发 Public tx（nonce 校验）；
    // 且 genesis 会预建 CairoFactRegistry（creator = 首 validator，审计 P2）。
    let funded = node
        .apply_genesis_alloc(vec![
            (validator.tagged.clone(), 1_000_000),
            (host.tagged.clone(), 1_000_000),
            (alice.tagged.clone(), 1_000_000),
            (bob.tagged.clone(), 1_000_000),
        ])
        .expect("genesis alloc");
    assert_eq!(funded, 4);
    let host_coin = host.coin_id(DEFAULT_CHAIN_ID);
    let alice_coin = alice.coin_id(DEFAULT_CHAIN_ID);
    let bob_coin = bob.coin_id(DEFAULT_CHAIN_ID);
    println!("[2] genesis 铸币 3 账户（各 1,000,000 ZCN）");

    // ===== 3. create_table =====
    let create_args = borsh::to_vec(&CreateTableArgs {
        name: "live-e2e".to_owned(),
        max_players: 2,
        small_blind: 10,
        big_blind: 20,
    })
    .expect("encode create_table");
    let tx = contract_call_tx(&mut host, selectors::create_table(), create_args, vec![]);
    let _receipts = commit_block(&node, &validator, &mut chain, vec![tx]);
    println!("[3] create_table 落块，table 对象已由合约自建");

    // ===== 4. join_table ×2（真实 BLS 密钥 + Schnorr 所有权证明 + UTXO 买入）=====
    let buy_in = 10_000_u64;
    let join_host =
        JoinTableArgs::with_key(host.address, buy_in, host.bls_sk, StarkScalar::from_u64(0x11_u64))
            .expect("join args host");
    let tx = contract_call_tx(
        &mut host,
        selectors::join_table(),
        borsh::to_vec(&join_host).expect("encode join"),
        vec![host_coin],
    );
    let _receipts = commit_block(&node, &validator, &mut chain, vec![tx]);
    println!("[4] host join_table 落块 ✓");

    let join_alice =
        JoinTableArgs::with_key(alice.address, buy_in, alice.bls_sk, StarkScalar::from_u64(0x12_u64))
            .expect("join args alice");
    let tx = contract_call_tx(
        &mut alice,
        selectors::join_table(),
        borsh::to_vec(&join_alice).expect("encode join"),
        vec![alice_coin],
    );
    let _receipts = commit_block(&node, &validator, &mut chain, vec![tx]);
    println!("[4] alice join_table 落块 ✓");

    let join_bob =
        JoinTableArgs::with_key(bob.address, buy_in, bob.bls_sk, StarkScalar::from_u64(0x13_u64))
            .expect("join args bob");
    let tx = contract_call_tx(
        &mut bob,
        selectors::join_table(),
        borsh::to_vec(&join_bob).expect("encode join"),
        vec![bob_coin],
    );
    // bob 的 join 真实落块并断言被合约拒绝（座位满；失败交易不改状态）
    let receipts = commit_block_lenient(&node, &validator, &mut chain, vec![tx]);
    assert!(
        !receipts[0].success,
        "第三个 join_table 应被合约拒绝"
    );
    println!(
        "[4] bob join_table 落块被拒（{}）✓ 合约准入约束在链上生效",
        receipts[0].error.as_deref().unwrap_or("")
    );

    // ===== 5. start_hand（creator 专用）=====
    let tx = contract_call_tx(&mut host, selectors::start_hand(), vec![], vec![]);
    let _receipts = commit_block(&node, &validator, &mut chain, vec![tx]);
    println!(
        "[5] start_hand 落块，table 对象数据 = {} 字节",
        table_object(&node).data.len()
    );

    // ===== 6. 真实 ZK 洗牌 ×2 =====
    let g = StarkPoint::generator();
    let mut deck: Vec<poker_protocol::crypto::types::StarkElGamalCiphertext> =
        poker_l1::vm::contracts::texas_poker::utils::generate_plaintext_cards()
            .into_iter()
            .map(|m| poker_protocol::crypto::types::StarkElGamalCiphertext { c1: g, c2: m })
            .collect();
    let agg_pk = host.bls_pk + alice.bls_pk;

    let mut perm_composed: Vec<usize> = (0..52).collect(); // 复合置换追踪
    for (seat, actor_idx, name) in [(0_u8, 0usize, "host"), (1, 1usize, "alice")] {
        let actor: &mut Actor = if actor_idx == 0 { &mut host } else { &mut alice };
        let mut rng = rand::rngs::OsRng;
        let n = deck.len();
        let mut permute: Vec<usize> = (0..n).collect();
        use rand::seq::SliceRandom as _;
        permute.shuffle(&mut rng);
        let r_values: Vec<StarkScalar> = (0..n)
            .map(|_| loop {
                let r = StarkScalar::random(&mut rng);
                if !bool::from(r.is_zero()) {
                    break r;
                }
            })
            .collect();
        let output: Vec<poker_protocol::crypto::types::StarkElGamalCiphertext> = (0..n)
            .map(|j| deck[permute[j]].re_encrypt(&agg_pk, &r_values[j]))
            .collect();
        let mut transcript =
            poker_l1::vm::contracts::texas_poker::utils::new_shuffle_transcript();
        let proof = poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof::<poker_protocol::crypto::stark_curve::StarkCurve>::prove(
            &deck, &output, &permute, &r_values, &agg_pk, &mut rng, &mut transcript,
        )
        .expect("本地 shuffle 证明生成");
        perm_composed = (0..n).map(|j| perm_composed[permute[j]]).collect();
        let args = SubmitShuffleV2Args {
            seat_index: seat,
            output_cards: output.clone(),
            shuffle_proof: proof,
        };
        let tx = contract_call_tx(
            actor,
            selectors::submit_shuffle_v2(),
            borsh::to_vec(&args).expect("encode shuffle"),
            vec![],
        );
        commit_block(&node, &validator, &mut chain, vec![tx]);
        println!("[6] {name}(seat {seat}) submit_shuffle_v2 落块 —— 链上 ZK 验证通过 ✓");
        // 镜像推进：deck ← output，再注入 shuffler_pk 到每张 c2（合约语义）
        for (ct, oc) in deck.iter_mut().zip(output.iter()) {
            *ct = *oc;
            ct.c2 += actor.bls_pk;
        }
    }

    // ===== 7. 链上状态核验 =====
    let onchain = decode_onchain_table(&node);
    println!("[7] 洗牌完成：链上 street={}，进入 DealHole 揭牌阶段", onchain.round_state());
    let onchain_deck: Vec<poker_protocol::crypto::types::StarkElGamalCiphertext> =
        onchain.deck_state.encrypted.to_vec();
    assert_eq!(onchain_deck.len(), 52);
    for (i, (oc, mc)) in onchain_deck.iter().zip(deck.iter()).enumerate() {
        assert_eq!(
            oc.c1.to_compressed(),
            mc.c1.to_compressed(),
            "deck[{i}].c1 与镜像不一致"
        );
        assert_eq!(
            oc.c2.to_compressed(),
            mc.c2.to_compressed(),
            "deck[{i}].c2 与镜像不一致"
        );
    }
    println!("[7] ✅ 链上牌组与驱动端镜像 52/52 逐字节一致");

    // ===== 8. 底牌 reveal tokens（真实部分解密证明）=====
    // 分配序（start_preflop_reveal_phase）：card0/1 → host(seat0)，card2/3 → alice(seat1)；
    // 每张牌的 pending = 对手（牌主不为自己提交）。
    let plaintexts = poker_l1::vm::contracts::texas_poker::utils::generate_plaintext_cards();
    // 驱动端全解密对拍：c2 - c1*(sk_h + sk_a) == plaintext[perm_composed[i]]
    for i in 0..4 {
        let m = onchain_deck[i].c2 - onchain_deck[i].c1 * (host.bls_sk + alice.bls_sk);
        assert_eq!(
            m.to_compressed(),
            plaintexts[perm_composed[i]].to_compressed(),
            "card {i} 全解密与置换追踪不一致"
        );
    }
    println!("[8] 驱动端全解密对拍 4/4：底牌归属 = 置换复合追踪 ✓");

    // 真实提交：alice 揭 host 的两张底牌（assignment 0,1），host 揭 alice 的（2,3）
    use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
    let build_reveal_args = |submitter_sk: &StarkScalar,
                             submitter_pk: &StarkPoint,
                             card_indices: &[usize]|
     -> Vec<u8> {
        let mut rng = rand::rngs::OsRng;
        let mut tokens = Vec::new();
        let mut proofs = Vec::new();
        for &i in card_indices {
            let token = onchain_deck[i].c1 * submitter_sk;
            let mut transcript = poker_protocol::zk_shuffle::transcript_ext::MerlinTranscript::new(
                b"reveal_token_proof_v3",
            );
            proofs.push(RevealTokenProof::prove(
                submitter_sk,
                submitter_pk,
                &onchain_deck[i],
                &token,
                &mut rng,
                &mut transcript,
            ));
            tokens.push(poker_protocol::crypto::types::StarkECPoint::from(token));
        }
        borsh::to_vec(&poker_l1::vm::contracts::texas_poker::dispatch::SubmitRevealTokensArgs {
            seat_index: if card_indices[0] < 2 { 1 } else { 0 }, // 揭对方底牌
            reveal_tokens: tokens,
            proofs,
        })
        .expect("encode reveal")
    };

    // alice 揭 host 的底牌（card 0,1）
    let args = build_reveal_args(&alice.bls_sk, &alice.bls_pk, &[0, 1]);
    let tx = contract_call_tx(&mut alice, selectors::submit_player_reveal_tokens(), args, vec![]);
    commit_block(&node, &validator, &mut chain, vec![tx]);
    println!("[8] alice 揭 host 底牌 2 张（reveal token 证明链上验证通过）✓");

    // host 揭 alice 的底牌（card 2,3）→ 全部 assignment 就绪 → normalize 自动
    // 完成揭牌、投盲注并启动 preflop 下注轮
    let args = build_reveal_args(&host.bls_sk, &host.bls_pk, &[2, 3]);
    let tx = contract_call_tx(&mut host, selectors::submit_player_reveal_tokens(), args, vec![]);
    commit_block(&node, &validator, &mut chain, vec![tx]);
    let onchain = decode_onchain_table(&node);
    println!("[8] host 揭 alice 底牌 2 张 → 街道推进：street={}（下注轮已启动）", onchain.round_state());
    let host_seat = &onchain.seats[0];
    let alice_seat = &onchain.seats[1];
    println!(
        "[8] 盲注后：host stack={} contributed-like，alice stack={}，pot={}",
        host_seat.stack(),
        alice_seat.stack(),
        onchain.pot
    );

    // ===== 9. 弃牌 → fold-win 合约结算 =====
    // 两人轮流尝试 fold（只有 current_turn 上的 fold 会成功；成功即触发
    // normalize → end_without_showdown：收注入池 → 抽水 → 赢家入账 → 重置）
    let fold_tx_host = contract_call_tx(
        &mut host,
        selectors::fold(),
        borsh::to_vec(&poker_l1::vm::contracts::texas_poker::dispatch::SeatIndexArgs { seat_index: 0 })
            .expect("encode fold"),
        vec![],
    );
    let receipts = commit_block_lenient(&node, &validator, &mut chain, vec![fold_tx_host]);
    if !receipts[0].success {
        println!("[9] host fold 未到行动轮（{:?}），换 alice fold", receipts[0].error);
        let fold_tx_alice = contract_call_tx(
            &mut alice,
            selectors::fold(),
            borsh::to_vec(&poker_l1::vm::contracts::texas_poker::dispatch::SeatIndexArgs {
                seat_index: 1,
            })
            .expect("encode fold"),
            vec![],
        );
        commit_block(&node, &validator, &mut chain, vec![fold_tx_alice]);
    }
    let onchain = decode_onchain_table(&node);
    println!(
        "[9] 结算后：pot={} street={}（Waiting=重置完成）",
        onchain.pot,
        onchain.round_state()
    );
    let stacks: Vec<u64> = onchain.seats.iter().map(|s| s.stack()).collect();
    println!("[9] 最终筹码：host={} alice={}（总 {} = 2×buy_in − rake）", stacks[0], stacks[1], stacks[0] + stacks[1]);
    assert_eq!(onchain.pot, 0, "彩池已清零");
    assert_eq!(stacks[0] + stacks[1], 2 * buy_in, "筹码守恒（总买入 = 总栈，差值即抽水）");
    println!("[9] ✅ 合约结算完成：彩池清零、筹码守恒、状态重置");

    // ===== 10. Cairo/Stwo 证明的节点内验证 + fact 注册（方案①接线）=====
    // 真实 settlement 电路证明（poker_texas_air prove-hand 2.4.0 栈产出，
    // program_hash 与主网 DualSettlement 钉扎值一致）。
    let proof_json =
        "/Users/mac/projects/poker_texas_air/proving-tool/output/settlement/proof.json";
    let pinned = hex_to_32("0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4");

    // [10.0] genesis 预建断言（审计 P2 creator 抢跑修复）：注册表对象在
    //        apply_genesis_alloc 时已种入，creator 钉扎为首 validator 地址
    let reg_pre = decode_cairo_registry(&node);
    assert_eq!(
        reg_pre.creator, validator.address,
        "creator 必须经 genesis 预建钉扎为首 validator（防保留 ID 抢跑）"
    );
    assert!(reg_pre.facts.is_empty());

    // [10.1] 钉扎程序哈希（creator = 首 validator：genesis 预建钉扎，
    //        审计 P2 creator 抢跑修复——非 creator 调用会被合约拒绝）
    let args = borsh::to_vec(&poker_l1::vm::contracts::cairo_fact_registry::SetProgramHashArgs {
        program_hash: pinned,
    })
    .unwrap();
    let tx = contract_call_tx_to(
        &mut validator,
        CAIRO_REGISTRY_ID,
        poker_l1::vm::contracts::cairo_fact_registry::selectors::set_program_hash(),
        args,
        vec![],
    );
    commit_block(&node, &validator, &mut chain, vec![tx]);
    println!("[10] set_program_hash(0x744d16d3…) 落块 ✓（creator = 首 validator，genesis 预建）");

    // [10.2] 证明二进制 wire（bzip2+bincode ≈1MB）按 60KB 分块，单一 caller
    //        （alice）上传——finalize 按 caller 分组重组，混传会拆散字节流
    let wire = fact_verify::proof_binary_bytes_from_json(std::path::Path::new(proof_json))
        .expect("binary wire");
    let chunk_size = 60_000usize;
    let chunks: Vec<&[u8]> = wire.chunks(chunk_size).collect();
    println!(
        "[10] 证明 wire = {} 字节 → {} 个分块（≤{chunk_size}B/块）",
        wire.len(),
        chunks.len()
    );
    for chunk in &chunks {
        let args = borsh::to_vec(
            &poker_l1::vm::contracts::cairo_fact_registry::SubmitProofChunkArgs {
                chunk: chunk.to_vec(),
            },
        )
        .unwrap();
        let tx = contract_call_tx_to(
            &mut alice,
            CAIRO_REGISTRY_ID,
            poker_l1::vm::contracts::cairo_fact_registry::selectors::submit_proof_chunk(),
            args,
            vec![],
        );
        commit_block(&node, &validator, &mut chain, vec![tx]);
    }
    println!("[10] {} 个分块全部落块 ✓", chunks.len());

    // [10.3] finalize：节点内重组 + 真验证（cairo-air verify_cairo）+ fact 注册
    let args = borsh::to_vec(&poker_l1::vm::contracts::cairo_fact_registry::FinalizeProofArgs {
        program_hash: pinned,
    })
    .unwrap();
    let tx = contract_call_tx_to(
        &mut alice,
        CAIRO_REGISTRY_ID,
        poker_l1::vm::contracts::cairo_fact_registry::selectors::finalize_proof(),
        args,
        vec![],
    );
    let receipts = commit_block(&node, &validator, &mut chain, vec![tx]);
    assert!(receipts[0].success, "finalize 必须成功");
    println!("[10] ✅ 节点内验证通过（cairo-air verify_cairo），fact 已注册");

    // [10.4] 链上读回：fact 已注册 + 程序哈希已钉扎
    let reg = decode_cairo_registry(&node);
    assert!(!reg.facts.is_empty(), "fact 必须已注册");
    assert!(
        reg.program_hashes.iter().any(|h| *h == pinned),
        "程序哈希必须已钉扎（32B 与钉扎值逐位一致）"
    );
    println!("[10] ✅ 链上读回：fact 已注册、程序哈希已钉扎");
}

fn bytes_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 提交并返回回执（不要求成功）——负路径用。
fn commit_block_lenient(
    node: &Node,
    validator: &Actor,
    chain: &mut [Hash; 2],
    txs: Vec<Transaction>,
) -> Vec<poker_l1::executor::TxReceipt> {
    for tx in &txs {
        node.submit_tx(tx.clone()).expect("submit_tx");
    }
    let pending = node.drain_pending_tx();
    let height = node
        .block_store()
        .get_tip_height()
        .ok()
        .flatten()
        .unwrap_or(0)
        + 1;
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let public_tx_root = compute_tx_merkle_root(&pending);
    let gameturn_tx_root = compute_tx_merkle_root(&[]);
    let proposer = derive_address(&validator.tagged);
    let env = node
        .execution_environment(height, timestamp_ms)
        .with_proposer(proposer);
    let outcome = node
        .simulate_block_execution(&env, &pending)
        .expect("simulate");
    let secp = Secp256k1::new();
    let mut cert = DagCommitCertificate {
        epoch: 0,
        commit_round: height,
        prev_commit_hash: chain[1],
        vertex_hash_list: vec![],
        round_attendance_bitmap: vec![0x01],
        state_root: outcome.state_root,
        public_tx_root,
        gameturn_tx_root,
        signature_list: vec![],
        signer_bitmap: vec![0x01],
    };
    let msg = Message::from_digest(cert.signing_hash(node.chain_id()));
    let sig = secp.sign_ecdsa_recoverable(&msg, &validator.secp_secret);
    let (recovery_id, compact) = sig.serialize_compact();
    let mut sig65 = compact.to_vec();
    sig65.push(recovery_id.to_i32() as u8);
    cert.signature_list = vec![sig65];
    let cert_signing_hash = cert.signing_hash(node.chain_id());
    let header = BlockHeader {
        height,
        timestamp_ms,
        prev_hash: chain[0],
        state_root: outcome.state_root,
        public_tx_root,
        gameturn_tx_root,
        dag_commit_certificate: cert,
    };
    let block = Block::new(header, pending, vec![]);
    let put = node.put_block(&block).expect("put_block lenient");
    *chain = [put, cert_signing_hash];
    outcome.receipts
}

/// hex → [u8; 32]。
fn hex_to_32(s: &str) -> [u8; 32] {
    let mut t = s.trim_start_matches("0x").to_owned();
    // felt 惯用写法允许省略前导零（如 63 字符的 251-bit 值）：右对齐补足 64
    while t.len() < 64 {
        t.insert_str(0, "0");
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).expect("hex byte");
    }
    out
}

/// 解码链上 Cairo 注册表状态。
fn decode_cairo_registry(
    node: &Node,
) -> poker_l1::vm::contracts::cairo_fact_registry::CairoRegistryState {
    let id = poker_l1::vm::precompile::reserved::cairo_registry_contract_id();
    let obj = node
        .get_object(&id)
        .expect("db")
        .unwrap_or_else(|| panic!("cairo registry object 不存在"));
    borsh::from_slice(&obj.data).expect("decode cairo registry")
}
