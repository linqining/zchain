//! poker-wallet — 独立 CLI 钱包最小可用版本（plan §6.12.5，JSON 文件驱动，离线可用）。
//!
//! 全部密码学/Note/校验逻辑都在 `wallet_core`；本 bin 只做参数解析、文件
//! IO 与人类可读输出（钱包壳层纪律：不重复实现任何协议逻辑）。
//!
//! 数据目录布局（`--dir`，默认 `zchain-wallet`）：
//!
//! ```text
//! keystore.json          owner key 信封（口令 Argon2id → AEAD）
//! dek.json               DEK 信封（同一口令；note 库/会话密钥的加密根）
//! notes_real.json        REAL 物理分库快照（DEK AEAD，AAD 钉 REAL）
//! notes_play.json        PLAY 物理分库快照（AAD 钉 PLAY——互不能打开）
//! sessions.json          会话 binding 登记表（borsh hex）
//! session_<id>.json      会话密钥（DEK 封装）
//! checkpoint.json        同步断点
//! nonces.json            已用签名 nonce
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::PathBuf;

use borsh::BorshDeserialize as _;
use poker_appchain::fee::FeePolicy;
use poker_appchain::note::AssetClass;
use poker_appchain::soft_confirm::{genesis_prev_hash, SignedFrame};
use wallet_core::account_binding::{
    authorize_message_hash, constraints_from_message, BindingRegistry, SessionBinding,
    Snip12Domain,
};
use wallet_core::backup::{
    collect_indexes, export_backup, import_backup, BackupPayloadV1, EncryptedBackup,
};
use wallet_core::error::WalletError;
use wallet_core::key_manager::{OwnerKeyPair, Scope, SecretBytes, SessionKey};
use wallet_core::keystore::{
    generate_dek, open_blob, open_dek, open_owner_key, params_interactive, seal_blob, seal_dek,
    seal_owner_key, SealedEnvelope, DOMAIN_SESSION_KEY,
};
use wallet_core::note_store::{NoteRecord, OriginFrame, ProofState, WalletStores};
use wallet_core::operation_signer::{
    parse_domain, NetworkCtx, NonceTracker, RequestContext, SigningRequest,
};
use wallet_core::sync::SyncCheckpoint;

/// 现在的 unix 秒。
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn die<T>(e: WalletError) -> T {
    eprintln!("error: {e}");
    std::process::exit(1);
}

/// 语句位置的退出（无返回值上下文）。
fn bail(e: WalletError) {
    die::<()>(e);
}

fn die_io<T>(e: std::io::Error) -> T {
    eprintln!("error: io: {e}");
    std::process::exit(1);
}

/// CLI 参数。
struct Args {
    dir: PathBuf,
    password: Option<String>,
    command: String,
    rest: Vec<String>,
}

fn parse_args() -> Args {
    let mut it = std::env::args().skip(1);
    let mut dir = PathBuf::from("zchain-wallet");
    let mut password = None;
    let mut positional = Vec::new();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dir" => dir = PathBuf::from(it.next().expect("--dir needs a value")),
            "--password" => password = Some(it.next().expect("--password needs a value")),
            other => positional.push(other.to_string()),
        }
    }
    if positional.is_empty() {
        usage();
    }
    Args { dir, password, command: positional.remove(0), rest: positional }
}

fn usage() -> ! {
    eprintln!(
        "poker-wallet — ZChain CLI wallet (wallet-core)\n\
\n\
USAGE:\n\
  poker-wallet [--dir DIR] [--password PW] <command> [...]\n\
\n\
COMMANDS:\n\
  init [--secret-hex HEX] [--chain ID]      创建钱包（或导入 owner 私钥）\n\
  unlock                                    校验口令并显示钱包信息\n\
  balances                                  REAL/PLAY 余额\n\
  notes                                     note 列表（REAL/PLAY 分栏）\n\
  faucet-play --amount N                    本地铸造 PLAY 测试 note\n\
  sign --file REQ.json [--yes] [--now S]    结构化签名（预览 + 确认）\n\
        [--session BINDING_HEX]             走会话密钥路径\n\
  backup --out FILE                         加密备份导出\n\
  restore --in FILE                         从备份恢复（覆盖本目录）\n\
  verify --file PROOF.json                  本地验证 settlement/chain/batch\n\
  session new-key                           生成 delegated 密钥（演示便利）\n\
  session authorize --file MSG.json --pk HEX --r HEX --s HEX --delegated-secret HEX\n\
  session revoke --id HEX [--nonce N]       撤销会话授权（粘滞）\n\
  session list                              会话授权列表\n"
    );
    std::process::exit(2);
}

/// 钱包数据目录内的固定文件布局。
struct WalletPaths {
    dir: PathBuf,
}

impl WalletPaths {
    fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn keystore(&self) -> PathBuf {
        self.dir.join("keystore.json")
    }

    fn dek(&self) -> PathBuf {
        self.dir.join("dek.json")
    }

    fn stores(&self, class: AssetClass) -> PathBuf {
        // 物理分库：REAL/PLAY 是两个文件，互相打不开（AAD 钉类）。
        self.dir.join(format!("notes_{}.json", class.name().to_lowercase()))
    }

    fn sessions(&self) -> PathBuf {
        self.dir.join("sessions.json")
    }

    fn session_key(&self, binding_id: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("session_{}.json", hex::encode(binding_id)))
    }

    fn checkpoint(&self) -> PathBuf {
        self.dir.join("checkpoint.json")
    }

    fn nonces(&self) -> PathBuf {
        self.dir.join("nonces.json")
    }

    fn read_json<T: serde::de::DeserializeOwned>(&self, p: &PathBuf) -> Option<T> {
        let bytes = std::fs::read(p).ok()?;
        serde_json::from_slice(&bytes).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())))
    }

    fn write_json<T: serde::Serialize>(&self, p: &PathBuf, v: &T) {
        std::fs::create_dir_all(&self.dir).unwrap_or_else(die_io);
        let bytes = serde_json::to_vec_pretty(v).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
        std::fs::write(p, bytes).unwrap_or_else(die_io);
    }
}

/// hex 容器（文件 JSON 通用）。
#[derive(serde::Serialize, serde::Deserialize)]
struct HexBlob {
    data: Vec<u8>,
}

/// 读信封文件（borsh hex JSON）。
fn read_envelope(paths: &WalletPaths, p: &PathBuf) -> SealedEnvelope {
    let blob: HexBlob = paths
        .read_json(p)
        .unwrap_or_else(|| die(WalletError::NoteNotFound("envelope file (run init)".into())));
    SealedEnvelope::try_from_slice(&blob.data).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())))
}

/// 写信封文件（borsh hex JSON）。
fn write_envelope(paths: &WalletPaths, p: &PathBuf, env: &SealedEnvelope) {
    let data = borsh::to_vec(env).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
    paths.write_json(p, &HexBlob { data });
}

/// 解锁后的钱包（内存态；secret 均 zeroize 管理）。
struct Unlocked {
    owner: OwnerKeyPair,
    dek: SecretBytes,
    stores: WalletStores,
    registry: BindingRegistry,
    checkpoint: Option<SyncCheckpoint>,
    nonces: NonceTracker,
    chains: BTreeSet<String>,
}

fn read_password(args: &Args) -> Vec<u8> {
    if let Some(p) = &args.password {
        return p.clone().into_bytes();
    }
    if let Ok(p) = std::env::var("ZCHAIN_WALLET_PASSWORD") {
        return p.into_bytes();
    }
    eprint!("passphrase: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim_end_matches(['\n', '\r']).to_string().into_bytes()
}

fn load_unlocked(paths: &WalletPaths, password: &[u8]) -> Unlocked {
    let keystore_env = read_envelope(paths, &paths.keystore());
    let dek_env = read_envelope(paths, &paths.dek());
    let owner = open_owner_key(&keystore_env, password).unwrap_or_else(die);
    let dek = open_dek(&dek_env, password).unwrap_or_else(die);
    let mut stores = WalletStores::new();
    for class in [AssetClass::Real, AssetClass::Play] {
        if let Some(blob) = paths.read_json::<HexBlob>(&paths.stores(class)) {
            let store = wallet_core::note_store::NoteStore::open(&dek, class, &blob.data).unwrap_or_else(die);
            match class {
                AssetClass::Real => stores.set_real(store),
                AssetClass::Play => stores.set_play(store),
            }
        }
    }
    let registry = paths
        .read_json::<HexBlob>(&paths.sessions())
        .and_then(|f| Some(BindingRegistry::try_from_slice(&f.data).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())))))
        .unwrap_or_default();
    let checkpoint = paths
        .read_json::<HexBlob>(&paths.checkpoint())
        .and_then(|f| Some(SyncCheckpoint::try_from_slice(&f.data).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())))));
    let nonces = paths
        .read_json::<BTreeMap<String, Vec<u64>>>(&paths.nonces())
        .map(NonceTracker::from_used)
        .unwrap_or_default();
    Unlocked {
        owner,
        dek,
        stores,
        registry,
        checkpoint,
        nonces,
        chains: ["zchain-devnet-1".to_string()].into_iter().collect(),
    }
}

fn persist(paths: &WalletPaths, w: &Unlocked) {
    for class in [AssetClass::Real, AssetClass::Play] {
        let sealed = match class {
            AssetClass::Real => w.stores.real().seal(&w.dek),
            AssetClass::Play => w.stores.play().seal(&w.dek),
        }
        .unwrap_or_else(die);
        paths.write_json(&paths.stores(class), &HexBlob { data: sealed });
    }
    let reg_bytes = borsh::to_vec(&w.registry).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
    paths.write_json(&paths.sessions(), &HexBlob { data: reg_bytes });
    if let Some(cp) = &w.checkpoint {
        let cp_bytes = borsh::to_vec(cp).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
        paths.write_json(&paths.checkpoint(), &HexBlob { data: cp_bytes });
    }
    paths.write_json(&paths.nonces(), &w.nonces.used_map());
}

fn asset_from_str(s: &str) -> AssetClass {
    match s.to_ascii_uppercase().as_str() {
        "REAL" => AssetClass::Real,
        "PLAY" => AssetClass::Play,
        _ => die(WalletError::InvalidArgument("asset class (REAL|PLAY)")),
    }
}

fn parse_hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s.trim_start_matches("0x")).unwrap_or_else(|_| die(WalletError::BadKeyMaterial("hex32")));
    v.try_into().unwrap_or_else(|_| die(WalletError::BadKeyMaterial("hex32 len")))
}

fn parse_hex33(s: &str) -> [u8; 33] {
    let v = hex::decode(s.trim_start_matches("0x")).unwrap_or_else(|_| die(WalletError::BadKeyMaterial("hex33")));
    v.try_into().unwrap_or_else(|_| die(WalletError::BadKeyMaterial("hex33 len")))
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn proof_name(p: &ProofState) -> &'static str {
    match p {
        ProofState::Pending => "pending",
        ProofState::Soft => "soft",
        ProofState::Proven { .. } => "proven",
        ProofState::Finalized => "finalized",
    }
}

fn main() {
    let args = parse_args();
    let paths = WalletPaths::new(args.dir.clone());
    match args.command.as_str() {
        "init" => cmd_init(&paths, &args),
        "unlock" => {
            let w = load_unlocked(&paths, &read_password(&args));
            println!("ok: owner={}", hex::encode(w.owner.public_bytes()));
            let b = w.stores.balances();
            println!("REAL: free={} locked={}", b.real_free, b.real_locked);
            println!("PLAY: free={} locked={}", b.play_free, b.play_locked);
        }
        "balances" => {
            let w = load_unlocked(&paths, &read_password(&args));
            let b = w.stores.balances();
            println!("REAL: free={} locked={}", b.real_free, b.real_locked);
            println!("PLAY: free={} locked={}", b.play_free, b.play_locked);
        }
        "notes" => {
            let w = load_unlocked(&paths, &read_password(&args));
            for (name, store) in [("REAL", w.stores.real()), ("PLAY", w.stores.play())] {
                println!("== {name} ==");
                for (c, r) in store.records() {
                    println!(
                        "  {} amount={} table={:?} proof={} spent_by_op={:?} nullifier={}",
                        hex::encode(c),
                        r.note.amount,
                        r.note.table_id,
                        proof_name(&r.proof),
                        r.spent_by_op,
                        hex::encode(r.nullifier())
                    );
                }
                if store.is_empty() {
                    println!("  (empty)");
                }
            }
        }
        "faucet-play" => cmd_faucet(&paths, &args),
        "sign" => cmd_sign(&paths, &args),
        "backup" => cmd_backup(&paths, &args),
        "restore" => cmd_restore(&paths, &args),
        "verify" => cmd_verify(&args),
        "session" => cmd_session(&paths, &args),
        other => {
            eprintln!("unknown command: {other}");
            usage();
        }
    }
}

fn cmd_init(paths: &WalletPaths, args: &Args) {
    if paths.keystore().exists() {
        bail(WalletError::InvalidArgument("wallet already initialized"));
    }
    let password = read_password(args);
    let owner = match flag_value(&args.rest, "--secret-hex") {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap_or_else(|_| die(WalletError::BadKeyMaterial("secret hex")));
            let arr: [u8; 32] = bytes.try_into().unwrap_or_else(|_| die(WalletError::BadKeyMaterial("secret len")));
            OwnerKeyPair::from_secret_bytes(&arr).unwrap_or_else(die)
        }
        None => OwnerKeyPair::generate(),
    };
    let chain = flag_value(&args.rest, "--chain").unwrap_or_else(|| "zchain-devnet-1".to_string());
    let params = params_interactive();
    let keystore_env = seal_owner_key(&owner, &password, params).unwrap_or_else(die);
    let dek = generate_dek();
    let dek_env = seal_dek(&dek, &password, params).unwrap_or_else(die);
    write_envelope(paths, &paths.keystore(), &keystore_env);
    write_envelope(paths, &paths.dek(), &dek_env);
    let w = Unlocked {
        owner,
        dek,
        stores: WalletStores::new(),
        registry: BindingRegistry::new(),
        checkpoint: Some(SyncCheckpoint { last_op_index: 0, head_hash: genesis_prev_hash() }),
        nonces: NonceTracker::new(),
        chains: [chain].into_iter().collect(),
    };
    persist(paths, &w);
    println!("init ok: owner={}", hex::encode(w.owner.public_bytes()));
}

fn cmd_faucet(paths: &WalletPaths, args: &Args) {
    let amount: u64 = flag_value(&args.rest, "--amount")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| die(WalletError::InvalidArgument("--amount")));
    let mut w = load_unlocked(paths, &read_password(args));
    let mut nonce = [0u8; 32];
    let tick = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nonce[..8].copy_from_slice(&tick.to_be_bytes());
    let note = poker_appchain::note::Note::new(AssetClass::Play, amount, w.owner.public_bytes(), nonce, None)
        .unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
    let rec = NoteRecord::new(
        note,
        OriginFrame { op_index: w.checkpoint.as_ref().map(|c| c.last_op_index + 1).unwrap_or(0), frame_hash: genesis_prev_hash() },
        ProofState::Soft,
    );
    w.stores.store(AssetClass::Play).insert(rec).unwrap_or_else(die);
    persist(paths, &w);
    println!("faucet ok: +{amount} PLAY");
}

/// 签名请求 JSON 镜像（CLI 文件驱动；hex 字段）。
#[derive(serde::Deserialize)]
struct RequestJson {
    kind: String,
    chain_id: String,
    #[serde(default = "default_domain")]
    domain: String,
    #[serde(default = "default_abi")]
    abi_version: u32,
    nonce: u64,
    expiry: u64,
    asset_class: Option<String>,
    #[serde(default)]
    inputs: Vec<String>,
    #[serde(default)]
    outputs: Vec<OutputJson>,
    #[serde(default)]
    table_id: Option<u64>,
    #[serde(default)]
    seat_owner: Option<String>,
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    vault_target: Option<String>,
    #[serde(default)]
    new_owner: Option<String>,
    #[serde(default)]
    record_borsh: Option<String>,
    #[serde(default)]
    policy_borsh: Option<String>,
}

fn default_domain() -> String {
    "zchain".into()
}

fn default_abi() -> u32 {
    1
}

#[derive(serde::Deserialize)]
struct OutputJson {
    owner: String,
    amount: u64,
}

fn build_request(r: &RequestJson) -> SigningRequest {
    let domain = parse_domain(&r.domain).unwrap_or_else(die);
    let ctx = RequestContext {
        network: NetworkCtx { domain, chain_id: r.chain_id.clone(), abi_version: r.abi_version },
        nonce: r.nonce,
        expiry: r.expiry,
    };
    let asset = r.asset_class.as_deref().map(asset_from_str).unwrap_or(AssetClass::Play);
    let inputs: Vec<[u8; 32]> = r.inputs.iter().map(|s| parse_hex32(s)).collect();
    match r.kind.as_str() {
        "transfer" => SigningRequest::Transfer {
            ctx,
            asset_class: asset,
            inputs,
            outputs: r
                .outputs
                .iter()
                .map(|o| wallet_core::operation_signer::OutputSpec {
                    owner: parse_hex33(&o.owner),
                    amount: o.amount,
                })
                .collect(),
        },
        "buy_in" => SigningRequest::BuyIn {
            ctx,
            asset_class: asset,
            table_id: r.table_id.unwrap_or_else(|| die(WalletError::InvalidArgument("table_id"))),
            seat_owner: r.seat_owner.as_deref().map(parse_hex33).unwrap_or_else(|| die(WalletError::InvalidArgument("seat_owner"))),
            inputs,
        },
        "withdraw" => SigningRequest::Withdraw {
            ctx,
            asset_class: asset,
            input: r.input.as_deref().map(parse_hex32).unwrap_or_else(|| die(WalletError::InvalidArgument("input"))),
            request_id: r.request_id.as_deref().map(parse_hex32).unwrap_or_else(|| die(WalletError::InvalidArgument("request_id"))),
            vault_target: r.vault_target.clone().unwrap_or_default(),
        },
        "key_rotation" => SigningRequest::KeyRotation {
            ctx,
            asset_class: asset,
            inputs,
            new_owner: r.new_owner.as_deref().map(parse_hex33).unwrap_or_else(|| die(WalletError::InvalidArgument("new_owner"))),
        },
        "settle" => {
            let record_bytes = hex::decode(r.record_borsh.as_deref().unwrap_or("").trim_start_matches("0x"))
                .unwrap_or_else(|_| die(WalletError::InvalidArgument("record_borsh")));
            let record = poker_appchain::settlement::SettlementRecord::try_from_slice(&record_bytes)
                .unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
            let policy_bytes = hex::decode(r.policy_borsh.as_deref().unwrap_or("").trim_start_matches("0x"))
                .unwrap_or_else(|_| die(WalletError::InvalidArgument("policy_borsh")));
            let policy = FeePolicy::try_from_slice(&policy_bytes).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
            SigningRequest::Settle { ctx, policy, record }
        }
        _ => die(WalletError::InvalidArgument("request kind (transfer|buy_in|withdraw|settle|key_rotation)")),
    }
}

fn cmd_sign(paths: &WalletPaths, args: &Args) {
    let file = flag_value(&args.rest, "--file").unwrap_or_else(|| die(WalletError::InvalidArgument("--file")));
    let now = flag_value(&args.rest, "--now").and_then(|v| v.parse().ok()).unwrap_or_else(unix_now);
    let raw = std::fs::read(&file).unwrap_or_else(die_io);
    let req_json: RequestJson =
        serde_json::from_slice(&raw).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
    let req = build_request(&req_json);
    let mut w = load_unlocked(paths, &read_password(args));
    let mut signer = wallet_core::operation_signer::Signer::new(&w.stores, now, &mut w.nonces);
    let signed = if let Some(binding_hex) = flag_value(&args.rest, "--session") {
        let binding_id = parse_hex32(&binding_hex);
        let binding = w
            .registry
            .get(&binding_id)
            .cloned()
            .unwrap_or_else(|| die(WalletError::NoteNotFound("binding".into())));
        let session = load_session_key(paths, &w.dek, &binding_id);
        let result =
            signer.sign_with_session(&req, &session, binding.revoked, (binding.daily_used_day, binding.daily_used_amount));
        let signed = result.unwrap_or_else(die);
        // 记账日限额聚合
        if let Some(b) = w.registry.get_mut(&binding_id) {
            b.record_spend(signed.preview.amount_out.min(u64::MAX as u128) as u64, now);
        }
        signed
    } else {
        signer.sign(&req, &w.owner).unwrap_or_else(die)
    };
    println!("{}", signed.preview);
    if !has_flag(&args.rest, "--yes") {
        eprint!("sign? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        if !line.trim().eq_ignore_ascii_case("y") {
            eprintln!("aborted");
            std::process::exit(1);
        }
    }
    let op_hex = hex::encode(borsh::to_vec(&signed.operation).unwrap_or_else(|e| die(WalletError::Codec(e.to_string()))));
    println!("digest: {}", hex::encode(signed.digest));
    println!("operation_borsh: {op_hex}");
    persist(paths, &w);
}

fn load_session_key(paths: &WalletPaths, dek: &SecretBytes, binding_id: &[u8; 32]) -> SessionKey {
    let blob = paths
        .read_json::<HexBlob>(&paths.session_key(binding_id))
        .unwrap_or_else(|| die(WalletError::NoteNotFound("session key file (session authorize first)".into())));
    let plain = open_blob(dek, DOMAIN_SESSION_KEY, &blob.data).unwrap_or_else(die);
    SessionKey::try_from_slice(&plain).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())))
}

fn cmd_backup(paths: &WalletPaths, args: &Args) {
    let out = flag_value(&args.rest, "--out").unwrap_or_else(|| die(WalletError::InvalidArgument("--out")));
    let password = read_password(args);
    let w = load_unlocked(paths, &password);
    let keystore_env = read_envelope(paths, &paths.keystore());
    let dek_env = read_envelope(paths, &paths.dek());
    let payload = BackupPayloadV1 {
        keystore: Some(keystore_env),
        dek_envelope: Some(dek_env),
        real_store: Some(w.stores.real().seal(&w.dek).unwrap_or_else(die)),
        play_store: Some(w.stores.play().seal(&w.dek).unwrap_or_else(die)),
        bindings: w.registry.clone(),
        checkpoint: w.checkpoint.clone(),
        indexes: collect_indexes(&w.stores),
        created_unix: unix_now(),
    };
    let backup = export_backup(&payload, &password, params_interactive()).unwrap_or_else(die);
    let bytes = backup.to_bytes().unwrap_or_else(die);
    std::fs::write(&out, &bytes).unwrap_or_else(die_io);
    println!("backup written: {out} ({} bytes)", bytes.len());
}

fn cmd_restore(paths: &WalletPaths, args: &Args) {
    let input = flag_value(&args.rest, "--in").unwrap_or_else(|| die(WalletError::InvalidArgument("--in")));
    let password = read_password(args);
    let bytes = std::fs::read(&input).unwrap_or_else(die_io);
    let backup = EncryptedBackup::from_bytes(&bytes).unwrap_or_else(die);
    // import_backup 内部执行全链路自检（口令 → DEK 信封 → 双库解密 →
    // 索引重建与声明索引比对）；任何环节失败 fail-closed。
    let payload = import_backup(&backup, &password).unwrap_or_else(die);
    let keystore_env = payload.keystore.clone().unwrap_or_else(|| die(WalletError::Tampered("no keystore")));
    let dek_env = payload.dek_envelope.clone().unwrap_or_else(|| die(WalletError::Tampered("no dek envelope")));
    let owner = open_owner_key(&keystore_env, &password).unwrap_or_else(die);
    let dek = open_dek(&dek_env, &password).unwrap_or_else(die);
    let mut stores = WalletStores::new();
    if let Some(blob) = &payload.real_store {
        stores.set_real(wallet_core::note_store::NoteStore::open(&dek, AssetClass::Real, blob).unwrap_or_else(die));
    }
    if let Some(blob) = &payload.play_store {
        stores.set_play(wallet_core::note_store::NoteStore::open(&dek, AssetClass::Play, blob).unwrap_or_else(die));
    }
    write_envelope(paths, &paths.keystore(), &keystore_env);
    write_envelope(paths, &paths.dek(), &dek_env);
    let w = Unlocked {
        owner,
        dek,
        stores,
        registry: payload.bindings.clone(),
        checkpoint: payload.checkpoint.clone(),
        nonces: NonceTracker::new(),
        chains: ["zchain-devnet-1".to_string()].into_iter().collect(),
    };
    persist(paths, &w);
    println!(
        "restore ok: notes real={} play={} bindings={} index_self_check=passed",
        w.stores.real().len(),
        w.stores.play().len(),
        w.registry.entries().count()
    );
}

/// 验证请求 JSON。
#[derive(serde::Deserialize)]
struct VerifyJson {
    kind: String,
    #[serde(default)]
    record_borsh: Option<String>,
    #[serde(default)]
    policy_borsh: Option<String>,
    #[serde(default)]
    frames_borsh: Option<String>,
    #[serde(default)]
    sequencer_public: Option<String>,
    #[serde(default)]
    bindings: Vec<String>,
    #[serde(default)]
    root: Option<String>,
}

fn hex_vec(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap_or_else(|_| die(WalletError::BadKeyMaterial("hex")))
}

fn cmd_verify(args: &Args) {
    let file = flag_value(&args.rest, "--file").unwrap_or_else(|| die(WalletError::InvalidArgument("--file")));
    let raw = std::fs::read(&file).unwrap_or_else(die_io);
    let v: VerifyJson = serde_json::from_slice(&raw).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
    match v.kind.as_str() {
        "settlement" => {
            let record = poker_appchain::settlement::SettlementRecord::try_from_slice(&hex_vec(v.record_borsh.as_deref().unwrap_or("")))
                .unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
            let policy = FeePolicy::try_from_slice(&hex_vec(v.policy_borsh.as_deref().unwrap_or("")))
                .unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
            match wallet_core::verifier::verify_settlement(&record, &policy) {
                Ok(verdict) => println!(
                    "OK level={} inputs={} payouts={} binding={}",
                    verdict.level.name(),
                    verdict.inputs,
                    verdict.payouts,
                    hex::encode(verdict.binding)
                ),
                Err(e) => {
                    println!("REJECTED: {e}");
                    std::process::exit(1);
                }
            }
        }
        "chain" => {
            let frames: Vec<SignedFrame> = borsh::from_slice(&hex_vec(v.frames_borsh.as_deref().unwrap_or("")))
                .unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
            let seq: [u8; 32] = hex_vec(v.sequencer_public.as_deref().unwrap_or(""))
                .try_into()
                .unwrap_or_else(|_| die(WalletError::BadKeyMaterial("sequencer public")));
            match wallet_core::verifier::verify_soft_chain(&frames, &seq) {
                Ok(verdict) => println!(
                    "OK level={} frames={} head={}",
                    verdict.level.name(),
                    verdict.frames,
                    hex::encode(verdict.head)
                ),
                Err(e) => {
                    println!("REJECTED: {e}");
                    std::process::exit(1);
                }
            }
        }
        "batch" => {
            let bindings: Vec<[u8; 32]> = v
                .bindings
                .iter()
                .map(|s| hex_vec(s).try_into().unwrap_or_else(|_| die(WalletError::BadKeyMaterial("binding len"))))
                .collect();
            let root: [u8; 32] = hex_vec(v.root.as_deref().unwrap_or(""))
                .try_into()
                .unwrap_or_else(|_| die(WalletError::BadKeyMaterial("root len")));
            match wallet_core::verifier::verify_batch_root(&bindings, &root) {
                Ok(()) => println!("OK batch root verified"),
                Err(e) => {
                    println!("REJECTED: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => die(WalletError::InvalidArgument("verify kind (settlement|chain|batch)")),
    }
}

/// 会话授权请求 JSON（SNIP-12 AuthorizeZChainKey 镜像）。
#[derive(serde::Deserialize)]
struct SessionAuthorizeJson {
    chain_id: String,
    account_address: String,
    delegated_public: String,
    #[serde(default = "default_scheme")]
    signature_scheme: String,
    allowed_scopes: Vec<String>,
    #[serde(default)]
    per_tx_limit: Option<u64>,
    #[serde(default)]
    per_day_limit: Option<u64>,
    #[serde(default)]
    table_allowlist: Option<Vec<u64>>,
    binding_id: String,
    nonce: u64,
    valid_after: u64,
    valid_until: u64,
    /// 外部钱包（Starknet 账户）签名公钥（felt hex）。
    account_public: String,
    /// 外部钱包签名 (r, s)（felt hex）。
    sig_r: String,
    sig_s: String,
}

fn default_scheme() -> String {
    "secp256k1".into()
}

fn felt_from_hex(s: &str) -> starknet_crypto::FieldElement {
    let bytes = hex_vec(s);
    let mut buf = [0u8; 32];
    if bytes.len() > 32 {
        bail(WalletError::BadKeyMaterial("felt len"));
    }
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    starknet_crypto::FieldElement::from_bytes_be(&buf).unwrap_or_else(|_| die(WalletError::BadKeyMaterial("felt")))
}

fn cmd_session(paths: &WalletPaths, args: &Args) {
    let sub = args.rest.first().cloned().unwrap_or_default();
    let now = flag_value(&args.rest, "--now").and_then(|v| v.parse().ok()).unwrap_or_else(unix_now);
    let mut w = load_unlocked(paths, &read_password(args));
    match sub.as_str() {
        // 演示便利：生成 delegated 密钥对（secret 由调用方保管/填入 msg.json）。
        "new-key" => {
            let key = OwnerKeyPair::generate();
            println!("delegated_secret: {}", hex::encode(key.secret_bytes()));
            println!("delegated_public: {}", hex::encode(key.public_bytes()));
        }
        "authorize" => {
            let file = flag_value(&args.rest, "--file").unwrap_or_else(|| die(WalletError::InvalidArgument("--file")));
            let raw = std::fs::read(&file).unwrap_or_else(die_io);
            let m: SessionAuthorizeJson = serde_json::from_slice(&raw).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
            let secret_hex = flag_value(&args.rest, "--delegated-secret").unwrap_or_else(|| die(WalletError::InvalidArgument("--delegated-secret")));
            let delegated_secret = OwnerKeyPair::from_secret_bytes(&parse_hex32(&secret_hex)).unwrap_or_else(die);
            let scopes = m
                .allowed_scopes
                .iter()
                .map(|s| Scope::from_name(s).unwrap_or_else(die))
                .collect();
            let msg = wallet_core::account_binding::AuthorizeZChainKeyMessage {
                zchain_chain_id: m.chain_id.clone(),
                account_address: parse_hex32(&m.account_address),
                delegated_public_key: parse_hex33(&m.delegated_public),
                signature_scheme: m.signature_scheme.clone(),
                allowed_scopes: scopes,
                per_tx_limit: m.per_tx_limit,
                per_day_limit: m.per_day_limit,
                table_allowlist: m.table_allowlist.clone(),
                binding_id: parse_hex32(&m.binding_id),
                nonce: m.nonce,
                valid_after: m.valid_after,
                valid_until: m.valid_until,
            };
            // 本地 delegated 密钥必须与授权消息一致（fail-closed）。
            if delegated_secret.public_bytes() != msg.delegated_public_key {
                bail(WalletError::InvalidArgument("delegated secret does not match message"));
            }
            let domain = Snip12Domain::zchain(&m.chain_id);
            let hash = authorize_message_hash(&domain, &msg).unwrap_or_else(die);
            let account_public = felt_from_hex(&m.account_public);
            let sig = wallet_core::account_binding::StarkSignature {
                r: felt_from_hex(&m.sig_r),
                s: felt_from_hex(&m.sig_s),
            };
            match wallet_core::account_binding::verify_account_signature(&account_public, &hash, &sig) {
                Ok(true) => {}
                Ok(false) => die(WalletError::VerifierRejected("account signature invalid".into())),
                Err(e) => die(e),
            }
            let binding = SessionBinding::new(constraints_from_message(&msg));
            let session = SessionKey::from_secret(binding.constraints.clone(), secp256k1::SecretKey::from_slice(delegated_secret.secret_bytes().as_ref()).unwrap_or_else(|_| die(WalletError::BadKeyMaterial("delegated secret"))));
            let key_bytes = borsh::to_vec(&session).unwrap_or_else(|e| die(WalletError::Codec(e.to_string())));
            let blob = seal_blob(&w.dek, DOMAIN_SESSION_KEY, &key_bytes).unwrap_or_else(die);
            paths.write_json(&paths.session_key(&binding.constraints.binding_id), &HexBlob { data: blob });
            println!("authorized: binding={} (account signature verified)", hex::encode(binding.constraints.binding_id));
            w.registry.authorize(binding);
            persist(paths, &w);
        }
        "revoke" => {
            let id = flag_value(&args.rest, "--id").map(|s| parse_hex32(&s)).unwrap_or_else(|| die(WalletError::InvalidArgument("--id")));
            let nonce: u64 = flag_value(&args.rest, "--nonce").and_then(|v| v.parse().ok()).unwrap_or(0);
            let chain = w.chains.iter().next().cloned().unwrap_or_else(|| "zchain-devnet-1".into());
            let domain = Snip12Domain::zchain(&chain);
            let digest = wallet_core::account_binding::revoke_digest_for(&domain, &chain, &id, nonce, now).unwrap_or_else(die);
            w.registry.revoke(&id).unwrap_or_else(die);
            persist(paths, &w);
            println!("revoked: {} revoke_digest={}", hex::encode(id), hex::encode(digest.to_bytes_be()));
        }
        "list" => {
            for b in w.registry.entries() {
                println!(
                    "binding={} scopes={:?} tables={} window=[{}, {}) revoked={} used_day={} used={}",
                    hex::encode(b.constraints.binding_id),
                    b.constraints.allowed_scopes.iter().map(|s| s.name()).collect::<Vec<_>>(),
                    b.constraints.table_allowlist.clone().map(|t| format!("{t:?}")).unwrap_or_else(|| "all".into()),
                    b.constraints.valid_after,
                    b.constraints.valid_until,
                    b.revoked,
                    b.daily_used_day,
                    b.daily_used_amount,
                );
            }
        }
        _ => die(WalletError::InvalidArgument("session subcommand (new-key|authorize|revoke|list)")),
    }
}
