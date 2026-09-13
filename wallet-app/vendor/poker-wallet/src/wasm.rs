//! wallet-core 的 WASM 绑定（plan-appchain §6.12.4 Extension 0.1）。
//!
//! # 纪律
//!
//! 本文件是 wallet-core 公开 API 之上的**纯 JSON 前端**：不含任何密码学实现。
//! 摘要（blake2s/poseidon）、签名（secp256k1）、加密（Argon2id + ChaCha20-Poly1305）
//! 全部由 `wallet_core`（以及它复用的 `poker_appchain` 校验面）完成。浏览器扩展
//! 的 JS 侧（`extension/background/`）不得自行实现任何原语，一律经本模块。
//!
//! # 构建（feature `wasm` 门控；默认构建/测试/CLI 完全不受影响）
//!
//! ```text
//! CC_wasm32_unknown_unknown=<支持 wasm32 的 clang> \
//! cargo build -p poker-wallet --target wasm32-unknown-unknown \
//!             --features wasm --release --bin wallet_core_wasm
//! wasm-bindgen --target web --out-dir <repo>/extension/vendor/wallet-core \
//!     target/wasm32-unknown-unknown/release/wallet_core_wasm.wasm
//! ```
//!
//! `required-features = ["wasm"]`（Cargo.toml）+ 本文件的
//! `#[cfg(target_arch = "wasm32")]` 双重门控：native 下该 bin 不会被构建
//! （`required-features`），带 `--features wasm` 的 native 构建也只会得到
//! 空桩（见文件底部）。
//!
//! # ABI 约定（所有入口均为 `String -> String`，JSON）
//!
//! - 金额一律**十进制字符串**（JS Number 只有 2^53 安全整数，u64 金额必须绕开）；
//! - 公钥（33B）/承诺/nullifier/摘要（32B）一律小写 hex；
//! - `SealedEnvelope`/`SettlementRecord`/`FeePolicy` 用 borsh（稳定字节 ABI）+
//!   hex 传输，与账本层逐字节一致（WALLET-ACC-2 的逻辑前提）；
//! - 错误统一 `{"error": "<STABLE_CODE>", "detail": "..."}`；detail 来自
//!   wallet-core 的 `WalletError` Display，不含任何密钥材料。
//!
//! # 会话模型
//!
//! 单会话槽（`SESSION`）：解锁后 owner key / DEK / 双 note 库 / nonce 账本
//! 只存在于 wasm 线性内存中，`wallet_lock()` 即整体 drop；持久化形态只有
//! 密文（口令信封 + DEK 信封 + 加密 note 库快照），由 JS 侧落 chrome.storage。
//! 私钥/DEK/spend secret **永不**跨越 wasm 边界输出。

#[cfg(not(target_arch = "wasm32"))]
fn main() {}

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(target_arch = "wasm32")]
mod imp {
    use std::sync::Mutex;

    use borsh::BorshDeserialize;
    use serde_json::{json, Value};
    use wasm_bindgen::prelude::wasm_bindgen;

    use poker_appchain::fee::FeePolicy;
    use poker_appchain::note::{AssetClass, Note};
    use poker_appchain::settlement::SettlementRecord;
    use poker_appchain::soft_confirm::genesis_prev_hash;

    use wallet_core::error::{WalletError, WalletResult};
    use wallet_core::key_manager::OwnerKeyPair;
    use wallet_core::keystore::{self, SealedEnvelope};
    use wallet_core::note_store::{NoteRecord, OriginFrame, ProofState, WalletStores};
    use wallet_core::operation_signer::{
        parse_domain, NetworkCtx, NonceTracker, OutputSpec, RequestContext, Signer, SigningRequest,
        DOMAIN_OPERATION_DIGEST, SUPPORTED_ABI_VERSION,
    };

    /// Extension 0.1 唯一网络（devnet；换网是 0.2 交付）。
    pub const DEFAULT_CHAIN_ID: &str = "zchain-devnet-1";

    /// console.error（避免依赖 wasm-bindgen 的 console 特性开关）。
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = console)]
        fn log_error(s: &str);
    }

    /// 解锁会话：内存态，锁定即 drop。明文密钥材料不出本结构。
    struct Session {
        key: OwnerKeyPair,
        dek: wallet_core::key_manager::SecretBytes,
        stores: WalletStores,
        nonces: NonceTracker,
        /// 持久化所需的密文形态（owner/DEK 信封 borsh hex；解锁时原样保留）。
        owner_envelope_hex: String,
        dek_envelope_hex: String,
        chain_id: String,
    }

    static SESSION: Mutex<Option<Session>> = Mutex::new(None);

    fn set_panic_hook() {
        use std::sync::Once;
        static HOOK: Once = Once::new();
        HOOK.call_once(|| {
            std::panic::set_hook(Box::new(|info| {
                log_error(&format!("wallet_core_wasm panic: {info}"));
            }));
        });
    }

    fn lock_session() -> std::sync::MutexGuard<'static, Option<Session>> {
        SESSION.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// WalletError → 稳定错误码（extension 校验层与 UI 依赖这些码，不解析文本）。
    fn error_code(e: &WalletError) -> &'static str {
        match e {
            WalletError::BadPassword => "BadPassword",
            WalletError::Tampered(_) => "Tampered",
            WalletError::UnsupportedVersion { .. } => "UnsupportedVersion",
            WalletError::UnknownDomainTag(_) => "UnknownDomainTag",
            WalletError::UnknownAbiVersion(_) => "UnknownAbiVersion",
            WalletError::AmountOverflow(_) => "AmountOverflow",
            WalletError::RawBytesRejected => "RawBytesRejected",
            WalletError::SessionRejected(_) => "SessionRejected",
            WalletError::Expired { .. } => "Expired",
            WalletError::NonceReplay { .. } => "NonceReplay",
            WalletError::NoteNotFound(_) => "NoteNotFound",
            WalletError::AssetClassMismatch(_) => "AssetClassMismatch",
            WalletError::VerifierRejected(_) => "VerifierRejected",
            WalletError::Codec(_) => "Codec",
            WalletError::InvalidArgument(_) => "InvalidArgument",
            WalletError::BadKeyMaterial(_) => "BadKeyMaterial",
            WalletError::ReorgDetected { .. } => "ReorgDetected",
            WalletError::VaultRejected(_) => "VaultRejected",
            WalletError::Io(_) => "Io",
        }
    }

    fn err_json(e: &WalletError) -> String {
        json!({ "error": error_code(e), "detail": e.to_string() }).to_string()
    }

    fn parse_json(s: &str) -> Result<Value, WalletError> {
        serde_json::from_str(s).map_err(|e| WalletError::Codec(format!("bad json: {e}")))
    }

    /// 金额解析（fail-closed）：只接受十进制整数（字符串优先），拒绝负数/
    /// 小数/非安全数值/u64 溢出/0。
    fn amount_u64(v: &Value, field: &'static str) -> Result<u64, WalletError> {
        let s = match v.as_str() {
            Some(s) => s.to_string(),
            None => match v.as_u64() {
                Some(n) => n.to_string(),
                None => {
                    return Err(WalletError::InvalidArgument(field));
                }
            },
        };
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(WalletError::InvalidArgument(field));
        }
        let n: u64 = s.parse().map_err(|_| WalletError::AmountOverflow(field))?;
        if n == 0 {
            return Err(WalletError::AmountOverflow(field));
        }
        Ok(n)
    }

    fn u64_field(v: &Value, field: &'static str) -> Result<u64, WalletError> {
        let n = amount_u64(v, field)?;
        Ok(n)
    }

    fn hex_field(v: &Value, field: &'static str, len: usize) -> Result<Vec<u8>, WalletError> {
        let bytes = hex_var(v, field)?;
        if bytes.len() != len {
            return Err(WalletError::InvalidArgument(field));
        }
        Ok(bytes)
    }

    /// 变长 hex（borsh 载荷；长度 sanity 上限 4 KiB，防异常输入）。
    fn hex_var(v: &Value, field: &'static str) -> Result<Vec<u8>, WalletError> {
        let s = v.as_str().ok_or(WalletError::InvalidArgument(field))?;
        if s.len() > 8192 {
            return Err(WalletError::InvalidArgument(field));
        }
        let bytes = hex::decode(s).map_err(|_| WalletError::InvalidArgument(field))?;
        if bytes.is_empty() {
            return Err(WalletError::InvalidArgument(field));
        }
        Ok(bytes)
    }

    fn hex32(v: &Value, field: &'static str) -> Result<[u8; 32], WalletError> {
        let b = hex_field(v, field, 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&b);
        Ok(out)
    }

    fn hex33(v: &Value, field: &'static str) -> Result<[u8; 33], WalletError> {
        let b = hex_field(v, field, 33)?;
        let mut out = [0u8; 33];
        out.copy_from_slice(&b);
        Ok(out)
    }

    fn asset_class(v: &Value) -> Result<AssetClass, WalletError> {
        match v.as_str() {
            Some("REAL") => Ok(AssetClass::Real),
            Some("PLAY") => Ok(AssetClass::Play),
            _ => Err(WalletError::InvalidArgument("asset_class")),
        }
    }

    /// 请求上下文（network + nonce + expiry）。
    fn parse_ctx(req: &Value) -> Result<RequestContext, WalletError> {
        let chain_id = req
            .get("chain_id")
            .and_then(Value::as_str)
            .ok_or(WalletError::InvalidArgument("chain_id"))?
            .to_string();
        if chain_id.is_empty() {
            return Err(WalletError::InvalidArgument("chain_id"));
        }
        let domain = parse_domain(
            req.get("domain")
                .and_then(Value::as_str)
                .ok_or(WalletError::InvalidArgument("domain"))?,
        )?;
        let abi_version = req.get("abi_version").and_then(Value::as_u64).ok_or(
            WalletError::InvalidArgument("abi_version"),
        )? as u32;
        let nonce = u64_field(req.get("nonce").ok_or(WalletError::InvalidArgument("nonce"))?, "nonce")?;
        let expiry =
            u64_field(req.get("expiry").ok_or(WalletError::InvalidArgument("expiry"))?, "expiry")?;
        Ok(RequestContext {
            network: NetworkCtx { domain, chain_id, abi_version },
            nonce,
            expiry,
        })
    }

    /// JSON 请求 → 结构化 SigningRequest（封闭映射；未知 kind 拒绝）。
    fn parse_request(req: &Value) -> Result<SigningRequest, WalletError> {
        let ctx = parse_ctx(req)?;
        let class = asset_class(req.get("asset_class").ok_or(WalletError::InvalidArgument("asset_class"))?)?;
        let kind = req
            .get("kind")
            .and_then(Value::as_str)
            .ok_or(WalletError::InvalidArgument("kind"))?;
        match kind {
            "transfer" => {
                let inputs = parse_commitment_list(req.get("inputs"))?;
                let outputs = req
                    .get("outputs")
                    .and_then(Value::as_array)
                    .ok_or(WalletError::InvalidArgument("outputs"))?
                    .iter()
                    .map(|o| {
                        Ok(OutputSpec {
                            owner: hex33(o.get("owner").ok_or(WalletError::InvalidArgument("outputs[].owner"))?, "outputs[].owner")?,
                            amount: amount_u64(o.get("amount").ok_or(WalletError::InvalidArgument("outputs[].amount"))?, "outputs[].amount")?,
                        })
                    })
                    .collect::<Result<Vec<OutputSpec>, WalletError>>()?;
                Ok(SigningRequest::Transfer { ctx, asset_class: class, inputs, outputs })
            }
            "buy_in" => {
                let table_id =
                    u64_field(req.get("table_id").ok_or(WalletError::InvalidArgument("table_id"))?, "table_id")?;
                let seat_owner =
                    hex33(req.get("seat_owner").ok_or(WalletError::InvalidArgument("seat_owner"))?, "seat_owner")?;
                let inputs = parse_commitment_list(req.get("inputs"))?;
                Ok(SigningRequest::BuyIn { ctx, asset_class: class, table_id, seat_owner, inputs })
            }
            "settle" => {
                let policy_bytes = hex_var(
                    req.get("policy_borsh").ok_or(WalletError::InvalidArgument("policy_borsh"))?,
                    "policy_borsh",
                )?;
                let policy =
                    FeePolicy::try_from_slice(&policy_bytes).map_err(|e| WalletError::Codec(format!("policy: {e}")))?;
                let record_bytes = hex_var(
                    req.get("record_borsh").ok_or(WalletError::InvalidArgument("record_borsh"))?,
                    "record_borsh",
                )?;
                let record =
                    SettlementRecord::try_from_slice(&record_bytes).map_err(|e| WalletError::Codec(format!("record: {e}")))?;
                Ok(SigningRequest::Settle { ctx, policy, record })
            }
            // 0.1 不开放 withdraw/key_rotation（提现预览与密钥轮换是 0.2/0.3 交付；
            // provider 层同时拒，这里再拒一次：纵深防御）。
            "withdraw" | "key_rotation" => Err(WalletError::InvalidArgument("kind disabled in extension 0.1")),
            _ => Err(WalletError::InvalidArgument("kind")),
        }
    }

    fn parse_commitment_list(v: Option<&Value>) -> Result<Vec<[u8; 32]>, WalletError> {
        let arr = v
            .and_then(Value::as_array)
            .ok_or(WalletError::InvalidArgument("inputs"))?;
        if arr.is_empty() {
            return Err(WalletError::InvalidArgument("inputs"));
        }
        arr.iter().map(|c| hex32(c, "inputs[]")).collect()
    }

    /// SigningPreview → JSON（金额转十进制字符串，避免 JS 精度损失）。
    fn preview_json(p: &wallet_core::operation_signer::SigningPreview) -> Value {
        json!({
            "kind": p.kind,
            "domain": p.domain,
            "chain_id": p.chain_id,
            "abi_version": p.abi_version,
            "asset_class": p.asset_class,
            "amount_in": p.amount_in.to_string(),
            "amount_out": p.amount_out.to_string(),
            "rake": p.rake.to_string(),
            "table_id": p.table_id.map(|t| t.to_string()),
            "outputs": p.outputs.iter().map(|o| json!({
                "owner": o.owner, "amount": o.amount.to_string(),
            })).collect::<Vec<_>>(),
            "request_id": p.request_id,
            "hand_binding": p.hand_binding,
            "proof_states": p.proof_states,
            "expiry": p.expiry.to_string(),
            "nonce": p.nonce.to_string(),
            "digest": p.digest,
        })
    }

    fn keystore_json(session: &Session, play_store_hex: String) -> Value {
        json!({
            "version": 1,
            "chain_id": session.chain_id,
            "owner_envelope": session.owner_envelope_hex,
            "dek_envelope": session.dek_envelope_hex,
            "play_store": play_store_hex,
        })
    }

    fn now_u64(now: &str) -> Result<u64, WalletError> {
        let n: u64 = now.parse().map_err(|_| WalletError::InvalidArgument("now"))?;
        Ok(n)
    }

    // -----------------------------------------------------------------------
    // 入口 0：元信息
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_core_meta() -> String {
        set_panic_hook();
        json!({
            "crate_version": env!("CARGO_PKG_VERSION"),
            "abi_version": SUPPORTED_ABI_VERSION,
            "domain": "zchain",
            "preview_domain": hex::encode(DOMAIN_OPERATION_DIGEST),
            "default_chain_id": DEFAULT_CHAIN_ID,
        })
        .to_string()
    }

    // -----------------------------------------------------------------------
    // 入口 1：创建（真实 Argon2id + ChaCha20-Poly1305 + secp256k1，全在 wallet-core）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_create(password: String, profile: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let (m, t, p) = match profile.as_str() {
                "interactive" => keystore::params_interactive(),
                // 仅测试/冒烟；生产路径必须 interactive。
                "test" => keystore::params_test(),
                _ => return Err(WalletError::InvalidArgument("profile")),
            };
            if password.is_empty() {
                return Err(WalletError::InvalidArgument("password"));
            }
            let key = OwnerKeyPair::generate();
            let dek = keystore::generate_dek();
            let owner_env = keystore::seal_owner_key(&key, password.as_bytes(), (m, t, p))?;
            let dek_env = keystore::seal_dek(&dek, password.as_bytes(), (m, t, p))?;
            let stores = WalletStores::new();
            let play_store_hex = hex::encode(stores.play().seal(&dek)?);
            let session = Session {
                key,
                dek,
                stores,
                nonces: NonceTracker::new(),
                owner_envelope_hex: hex::encode(borsh::to_vec(&owner_env).map_err(|e| WalletError::Codec(format!("owner env: {e}")))?),
                dek_envelope_hex: hex::encode(borsh::to_vec(&dek_env).map_err(|e| WalletError::Codec(format!("dek env: {e}")))?),
                chain_id: DEFAULT_CHAIN_ID.to_string(),
            };
            let public_key = hex::encode(session.key.public_bytes());
            let ks = keystore_json(&session, play_store_hex);
            *lock_session() = Some(session);
            Ok(json!({ "public_key": public_key, "keystore": ks }).to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 2：解锁（口令错 → BadPassword fail-closed）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_unlock(keystore: String, password: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let ks = parse_json(&keystore)?;
            let owner_env: SealedEnvelope = SealedEnvelope::try_from_slice(&hex_var(
                ks.get("owner_envelope").ok_or(WalletError::InvalidArgument("owner_envelope"))?,
                "owner_envelope",
            )?)
            .map_err(|e| WalletError::Codec(format!("owner_envelope: {e}")))?;
            let dek_env: SealedEnvelope = SealedEnvelope::try_from_slice(&hex_var(
                ks.get("dek_envelope").ok_or(WalletError::InvalidArgument("dek_envelope"))?,
                "dek_envelope",
            )?)
            .map_err(|e| WalletError::Codec(format!("dek_envelope: {e}")))?;
            let play_blob = hex_var(
                ks.get("play_store").ok_or(WalletError::InvalidArgument("play_store"))?,
                "play_store",
            )?;
            let chain_id = ks
                .get("chain_id")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_CHAIN_ID)
                .to_string();

            let key = keystore::open_owner_key(&owner_env, password.as_bytes())?;
            let dek = keystore::open_dek(&dek_env, password.as_bytes())?;
            let play = wallet_core::note_store::NoteStore::open(&dek, AssetClass::Play, &play_blob)?;
            let mut stores = WalletStores::new();
            stores.set_play(play);
            stores.verify_indexes()?;
            let balances = stores.balances();
            let public_key = hex::encode(key.public_bytes());
            let notes = stores.play().len();
            let session = Session {
                key,
                dek,
                stores,
                nonces: NonceTracker::new(),
                owner_envelope_hex: hex::encode(borsh::to_vec(&owner_env).map_err(|e| WalletError::Codec(format!("owner env: {e}")))?),
                dek_envelope_hex: hex::encode(borsh::to_vec(&dek_env).map_err(|e| WalletError::Codec(format!("dek env: {e}")))?),
                chain_id: chain_id.clone(),
            };
            *lock_session() = Some(session);
            Ok(json!({
                "public_key": public_key,
                "chain_id": chain_id,
                "play_free": balances.play_free.to_string(),
                "play_locked": balances.play_locked.to_string(),
                "notes": notes,
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 3：锁定 + 持久化快照
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_lock() -> String {
        set_panic_hook();
        *lock_session() = None;
        json!({ "locked": true }).to_string()
    }

    /// 当前状态 → 持久化密文快照（note 库变化后调用；全部为密文）。
    #[wasm_bindgen]
    pub fn wallet_persist() -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let mut guard = lock_session();
            let s = guard.as_mut().ok_or(WalletError::InvalidArgument("locked"))?;
            let play_store_hex = hex::encode(s.stores.play().seal(&s.dek)?);
            Ok(keystore_json(s, play_store_hex).to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 4：devnet PLAY 本地水龙头（Extension 0.1 专用 stub，如实标注）
    // -----------------------------------------------------------------------

    /// 本地铸造一张 PLAY 余额 note（devnet 水龙头 stub：无网络、无链上 mint，
    /// 仅用于 0.1 桌面/买入/结算签名链路演示；真实同步在 0.2 接 `sync` trait）。
    #[wasm_bindgen]
    pub fn wallet_faucet_play(amount: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let n: u64 = amount.parse().map_err(|_| WalletError::InvalidArgument("amount"))?;
            let mut nonce = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let mut guard = lock_session();
            let s = guard.as_mut().ok_or(WalletError::InvalidArgument("locked"))?;
            let note = Note::new(AssetClass::Play, n, s.key.public_bytes(), nonce, None)
                .map_err(|e| WalletError::Codec(format!("note: {e}")))?;
            let rec = NoteRecord::new(
                note,
                OriginFrame { op_index: 0, frame_hash: genesis_prev_hash() },
                ProofState::Soft,
            );
            let commitment = s.stores.store(AssetClass::Play).insert(rec)?;
            let balances = s.stores.balances();
            Ok(json!({
                "commitment": hex::encode(commitment),
                "play_free": balances.play_free.to_string(),
                "faucet": "local-devnet-stub",
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 5：note 列表（脱敏：无 spend secret、无 nullifier）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_get_notes() -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let guard = lock_session();
            let s = guard.as_ref().ok_or(WalletError::InvalidArgument("locked"))?;
            let notes: Vec<Value> = s
                .stores
                .play()
                .records()
                .map(|(commitment, r)| {
                    json!({
                        "commitment": hex::encode(commitment),
                        "amount": r.note.amount.to_string(),
                        "table_id": r.note.table_id.map(|t| t.to_string()),
                        "proof": match r.proof {
                            ProofState::Pending => "pending",
                            ProofState::Soft => "soft",
                            ProofState::Proven { .. } => "proven",
                            ProofState::Finalized => "finalized",
                        },
                        "spendable": r.spendable(),
                    })
                })
                .collect();
            Ok(json!({ "notes": notes }).to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 6：预览（不占用 nonce；签名前 UI 用）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_preview(req: String, now: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let parsed = parse_json(&req)?;
            let request = parse_request(&parsed)?;
            let now = now_u64(&now)?;
            let guard = lock_session();
            let s = guard.as_ref().ok_or(WalletError::InvalidArgument("locked"))?;
            // 预览用一次性 nonce 账本：preview 不占用会话 nonce。
            let mut scratch = NonceTracker::new();
            let mut signer = Signer::new(&s.stores, now, &mut scratch);
            let preview = signer.preview(&request)?;
            Ok(json!({ "preview": preview_json(&preview) }).to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 7：签名（owner 路径；占用 nonce；全拒绝面生效）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_sign(req: String, now: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let parsed = parse_json(&req)?;
            let request = parse_request(&parsed)?;
            let now = now_u64(&now)?;
            let mut guard = lock_session();
            let s = guard.as_mut().ok_or(WalletError::InvalidArgument("locked"))?;
            let mut signer = Signer::new(&s.stores, now, &mut s.nonces);
            let signed = signer.sign(&request, &s.key)?;
            let op_borsh = borsh::to_vec(&signed.operation)
                .map_err(|e| WalletError::Codec(format!("operation: {e}")))?;
            Ok(json!({
                "operation_borsh": hex::encode(op_borsh),
                "digest": hex::encode(signed.digest),
                "preview": preview_json(&signed.preview),
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 8：结算单输入补签（多人桌路径；operator 收集 SpendAuth）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_sign_settle_input(record_borsh: String, input_index: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let bytes = hex::decode(&record_borsh).map_err(|_| WalletError::InvalidArgument("record_borsh"))?;
            let record =
                SettlementRecord::try_from_slice(&bytes).map_err(|e| WalletError::Codec(format!("record: {e}")))?;
            let idx: usize = input_index.parse().map_err(|_| WalletError::InvalidArgument("input_index"))?;
            let guard = lock_session();
            let s = guard.as_ref().ok_or(WalletError::InvalidArgument("locked"))?;
            let mut scratch = NonceTracker::new();
            let signer = Signer::new(&s.stores, 0, &mut scratch);
            let auth = signer.sign_settle_input(&record, idx, &s.key)?;
            Ok(json!({
                "commitment": hex::encode(auth.commitment),
                "nullifier": hex::encode(auth.nullifier),
                "sig": hex::encode(auth.sig.bytes),
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }
}
