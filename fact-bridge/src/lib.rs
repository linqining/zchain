//! fact-bridge — texas 手牌结算证明 → 4 节点 zchain 链上 fact 注册的桥接库。
//!
//! 流程：prove-hand 产物 proof.json → fact-verify 全量 Stwo 验证
//! （cairo-air 2.4.0 生产同源）→ 证明二进制 wire 按 60KB 分块 →
//! 逐块构造签名 zchain 合约调用交易（`CairoFactRegistry` @ 0xFF..05）→
//! `submit_tx` 提交 4 节点网络 → 节点内 `verify_cairo` 真验证 →
//! 双 fact（fact_c 降级门 / fact_s36 SNIP-36 对齐）注册上链。

use poker_l1::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme};
use poker_l1::signature::TaggedPubkey;
use poker_l1::transaction::{ContractCall, Gas, RouteHint, Transaction, TxLane};
use poker_l1::{DEFAULT_CHAIN_ID, Hash};
use secp256k1::{Message, Secp256k1};
use std::path::Path;

/// CairoFactRegistry 预编译 ObjectID（0xFF..05）。
pub const CAIRO_REGISTRY_ID: poker_l1::object_model::ObjectID =
    poker_l1::vm::precompile::reserved::cairo_registry_contract_id();

/// tx args 单块字节数上限（与链上 64KB 对象/参数上限对齐，留 borsh 余量）。
pub const CHUNK_SIZE: usize = 60_000;

/// 提交者：secp256k1 密钥 + 派生地址 + nonce 计数。
pub struct Submitter {
    pub secret: secp256k1::SecretKey,
    pub tagged: TaggedPubkey,
    pub address: [u8; 20],
    pub nonce: u64,
}

impl Submitter {
    /// 从 32B hex 私钥构造（如部署目录 validator_0.key）。
    pub fn from_key_hex(secret_hex: &str) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let t = secret_hex.trim().trim_start_matches("0x");
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(t, &mut bytes).map_err(|e| format!("key hex: {e}"))?;
        let secret =
            secp256k1::SecretKey::from_slice(&bytes).map_err(|e| format!("secret key: {e}"))?;
        let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let tagged = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            CURRENT_VERSION,
            public.serialize().to_vec(),
        )
        .map_err(|e| format!("tagged pubkey: {e}"))?;
        let address = poker_l1::account::derive_address(&tagged);
        Ok(Self { secret, tagged, address, nonce: 0 })
    }

    /// 构造并签名一笔 CairoFactRegistry 合约调用交易（Public 通道）。
    pub fn sign_registry_call(&mut self, selector: [u8; 32], args: Vec<u8>) -> Transaction {
        let secp = Secp256k1::new();
        let tx_nonce = self.nonce;
        self.nonce += 1;
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: Some(ContractCall {
                contract_id: CAIRO_REGISTRY_ID,
                method_selector: selector,
                args,
            }),
            tagged_pubkey: self.tagged.clone(),
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
        let sig = secp.sign_ecdsa_recoverable(&msg, &self.secret);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut sig_bytes = compact.to_vec();
        sig_bytes.push(recovery_id.to_i32() as u8);
        Transaction { signature: sig_bytes, ..tx }
    }
}

/// 证明提交计划：验证结果 + 完整的待提交交易序列。
pub struct ProofPlan {
    /// 程序哈希（32B BE，= 链上钉扎值）。
    pub program_hash: [u8; 32],
    /// 公开输出（segment）。
    pub output: Vec<[u8; 32]>,
    /// 降级门 fact：`poseidon([program_hash, output…])`。
    pub expected_fact_c: [u8; 32],
    /// 交易序列：set_program_hash → submit_proof_chunk ×N → finalize_proof。
    pub txs: Vec<Transaction>,
}

/// 从 prove-hand 产物构造完整提交计划（离线：验证 + 交易构造，不连链）。
pub fn build_proof_plan(
    submitter_key_hex: &str,
    proof_json_path: &Path,
    base_nonce: u64,
) -> Result<ProofPlan, String> {
    use poker_l1::vm::contracts::cairo_fact_registry::{
        selectors, FinalizeProofArgs, SetProgramHashArgs, SubmitProofChunkArgs,
    };

    let verified = fact_verify::verify_cairo_proof_file(proof_json_path)
        .map_err(|e| format!("proof verify: {e}"))?;
    let program_hash = verified.program_hash.to_bytes_be();
    let output: Vec<[u8; 32]> = verified.output.iter().map(|f| f.to_bytes_be()).collect();
    let expected_fact_c = fact_verify::fact_for_segment_bytes(program_hash, &output);

    let mut submitter =
        Submitter::from_key_hex(submitter_key_hex).map_err(|e| format!("submitter key: {e}"))?;
    submitter.nonce = base_nonce;

    let mut txs = Vec::new();
    txs.push(submitter.sign_registry_call(
        selectors::set_program_hash(),
        borsh::to_vec(&SetProgramHashArgs { program_hash }).expect("encode set_program_hash"),
    ));

    let wire = fact_verify::proof_binary_bytes_from_json(proof_json_path)
        .map_err(|e| format!("binary wire: {e}"))?;
    for chunk in wire.chunks(CHUNK_SIZE) {
        txs.push(submitter.sign_registry_call(
            selectors::submit_proof_chunk(),
            borsh::to_vec(&SubmitProofChunkArgs { chunk: chunk.to_vec() }).expect("encode chunk"),
        ));
    }
    txs.push(submitter.sign_registry_call(
        selectors::finalize_proof(),
        borsh::to_vec(&FinalizeProofArgs { program_hash }).expect("encode finalize"),
    ));

    Ok(ProofPlan {
        program_hash,
        output,
        expected_fact_c,
        txs,
    })
}
