//! fact-bridge 提交计划测试（证明验证拒绝 + 分块边界 + 签名/nonce 语义）。
//!
//! 真实 settlement 证明夹具沿用 fact-verify 测试口径（prove-hand 2.4.0
//! 栈产出）。fact-bridge 是 workspace 成员且其 fact-verify 为 path 依赖，
//! 夹具路径缺失即编译环境不完整——与其他门的硬依赖一致。

use std::path::Path;

/// 真实 settlement 证明（= fact-verify src/lib.rs REAL_PROOF 的同一路径，
/// 以 fact-bridge crate 根为基准）。
const REAL_PROOF: &str = "../../poker_texas_air/proving-tool/output/settlement/proof.json";

fn any_key_hex() -> String {
    // 任意合法 secp256k1 私钥（确定性，测试只关心解析/签名一致性）。
    "aa".repeat(32)
}

#[test]
fn submitter_key_parsing_rejects_bad_input() {
    // 正常：同一 hex 两次派生同一地址（确定性）
    let a = fact_bridge::Submitter::from_key_hex(&any_key_hex()).expect("valid key");
    let b = fact_bridge::Submitter::from_key_hex(&any_key_hex()).expect("valid key");
    assert_eq!(a.address, b.address);
    assert_eq!(a.tagged.raw, b.tagged.raw);
    assert_eq!(a.nonce, 0);

    // 奇数长度 / 非 hex / 短字节 / 零私钥 → 全部拒绝
    assert!(fact_bridge::Submitter::from_key_hex("abc").is_err(), "非 hex");
    assert!(fact_bridge::Submitter::from_key_hex(&"z".repeat(64)).is_err(), "非 hex 字符");
    assert!(fact_bridge::Submitter::from_key_hex(&"aa".repeat(31)).is_err(), "31 字节");
    assert!(fact_bridge::Submitter::from_key_hex(&"00".repeat(32)).is_err(), "零私钥");
    // 0x 前缀容忍
    assert!(fact_bridge::Submitter::from_key_hex(&format!("0x{}", any_key_hex())).is_ok());
}

#[test]
fn sign_registry_call_nonce_sequence_and_signature_recovers() {
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
    use secp256k1::{Message, Secp256k1, VerifyOnly};

    let mut s = fact_bridge::Submitter::from_key_hex(&any_key_hex()).expect("key");
    s.nonce = 7; // 基线 nonce
    let args: Vec<u8> = (0u8..40).collect();

    let txs: Vec<_> = (0..3)
        .map(|_| {
            s.sign_registry_call(
                poker_l1::vm::contracts::cairo_fact_registry::selectors::submit_proof_chunk(),
                args.clone(),
            )
        })
        .collect();

    // nonce 严格连续（链按 nonce 序执行；断号 = 堵死后继 tx）
    assert_eq!(txs.iter().map(|t| t.nonce).collect::<Vec<_>>(), vec![7, 8, 9]);
    assert_eq!(s.nonce, 10);

    let secp: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
    for tx in &txs {
        // 交易语义：Public 通道 + CairoFactRegistry 合约 + args 透传
        let call = tx.contract_call.as_ref().expect("contract_call");
        assert_eq!(call.contract_id, fact_bridge::CAIRO_REGISTRY_ID);
        assert_eq!(call.args, args);
        assert_eq!(tx.lane_hint, poker_l1::transaction::TxLane::Public);

        // 签名可恢复出提交者公钥（65B r||s||v recoverable）
        assert_eq!(tx.signature.len(), 65);
        let rid = RecoveryId::from_i32(tx.signature[64] as i32).expect("recovery id");
        let sig = RecoverableSignature::from_compact(&tx.signature[..64], rid)
            .expect("compact sig");
        let msg = Message::from_digest_slice(&tx.signing_hash()).expect("hash 32B");
        let pk = secp.recover_ecdsa(&msg, &sig).expect("recover");
        assert_eq!(pk.serialize().to_vec(), s.tagged.raw, "恢复公钥必须是提交者");
    }
}

#[test]
fn chunk_size_within_chain_budget() {
    // CHUNK_SIZE 必须留出 borsh/对象开销余量且 < 链上 64KB 参数上限
    assert!(fact_bridge::CHUNK_SIZE < 64 * 1024);
    assert_eq!(fact_bridge::CHUNK_SIZE, 60_000);
}

/// 真实证明 → 计划形状：钉扎 1 笔 + ceil(wire/CHUNK) 分块 + finalize 1 笔；
/// 分块重组必须逐字节还原 wire（整除/余数两种边界都被真实夹具覆盖：
/// 12.2MB JSON 压缩后非 CHUNK 整数倍）。
#[test]
fn build_proof_plan_real_proof_shape_and_chunk_reassembly() {
    use poker_l1::vm::contracts::cairo_fact_registry::{
        selectors, FinalizeProofArgs, SetProgramHashArgs, SubmitProofChunkArgs,
    };

    let proof = Path::new(REAL_PROOF);
    let plan =
        fact_bridge::build_proof_plan(&any_key_hex(), proof, 0).expect("real proof must verify");

    let wire = fact_verify::proof_binary_bytes_from_json(proof).expect("wire bytes");
    let expect_chunks = wire.len().div_ceil(fact_bridge::CHUNK_SIZE);
    assert_eq!(plan.txs.len(), expect_chunks + 2, "钉扎1+分块N+finalize1");

    // nonce 从 base_nonce 起严格连续
    let nonces: Vec<u64> = plan.txs.iter().map(|t| t.nonce).collect();
    assert_eq!(nonces, (0..plan.txs.len() as u64).collect::<Vec<_>>());

    // 首笔钉扎、末笔 finalize、中间逐块
    let first = plan.txs[0].contract_call.as_ref().unwrap();
    assert_eq!(first.method_selector, selectors::set_program_hash());
    let sph: SetProgramHashArgs = borsh::from_slice(&first.args).expect("decode set_program_hash");
    assert_eq!(sph.program_hash, plan.program_hash);

    let last = plan.txs.last().unwrap().contract_call.as_ref().unwrap();
    assert_eq!(last.method_selector, selectors::finalize_proof());
    let fin: FinalizeProofArgs = borsh::from_slice(&last.args).expect("decode finalize");
    assert_eq!(fin.program_hash, plan.program_hash);

    // 分块重组 == 原 wire（边界完整性：拼回无缺口、无重复、顺序正确）
    let mut reassembled = Vec::with_capacity(wire.len());
    for tx in &plan.txs[1..plan.txs.len() - 1] {
        let call = tx.contract_call.as_ref().unwrap();
        assert_eq!(call.method_selector, selectors::submit_proof_chunk());
        let c: SubmitProofChunkArgs = borsh::from_slice(&call.args).expect("decode chunk");
        assert!(c.chunk.len() <= fact_bridge::CHUNK_SIZE, "单块超限");
        reassembled.extend_from_slice(&c.chunk);
    }
    assert_eq!(reassembled.len(), wire.len(), "重组长度必须一致");
    assert_eq!(reassembled, wire, "重组必须逐字节还原 wire");
}

/// 证明验证失败必须拒绝构造提交计划（fail-closed：伪造/损坏证明不上链）。
#[test]
fn build_proof_plan_rejects_bad_proofs() {
    let tmp = std::env::temp_dir().join("fact_bridge_bad_proof_test.json");

    // 1. 文件不存在
    let missing = tmp.with_extension("missing.json");
    assert!(fact_bridge::build_proof_plan(&any_key_hex(), &missing, 0).is_err());

    // 2. 非 JSON
    std::fs::write(&tmp, b"not a proof at all").unwrap();
    assert!(
        fact_bridge::build_proof_plan(&any_key_hex(), &tmp, 0).is_err(),
        "非 JSON 必须拒绝"
    );

    // 3. 合法 JSON 但非证明结构
    std::fs::write(&tmp, br#"{"looks":"like json","but":"not a proof"}"#).unwrap();
    assert!(
        fact_bridge::build_proof_plan(&any_key_hex(), &tmp, 0).is_err(),
        "结构不符必须拒绝"
    );
    let _ = std::fs::remove_file(&tmp);
}

/// 节点侧重组后验证：wire 中段翻转单字节 → 验证必须失败（分块传输出错
/// 不能导致假 fact 注册）。
#[test]
fn corrupted_wire_reassembly_is_rejected() {
    let proof = Path::new(REAL_PROOF);
    let mut wire = fact_verify::proof_binary_bytes_from_json(proof).expect("wire");
    let mid = wire.len() / 2;
    wire[mid] ^= 0xFF;
    assert!(
        fact_verify::verify_cairo_proof_bytes(&wire).is_err(),
        "损坏的 wire 必须验证失败"
    );
}
