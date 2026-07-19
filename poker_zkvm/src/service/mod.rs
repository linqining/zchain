//! Phase 3.1 — zkvm 服务化核心：ProverService。
//!
//! 提供线程安全的 prove/verify 服务，支持：
//! - proof_cache（按 ELF+input 哈希缓存，LRU 淘汰）
//! - 统计计数（请求数 / proof 数 / 平均延迟）
//! - `tokio::task::spawn_blocking` 包装阻塞 prove，避免阻塞 async runtime
//!
//! ## 子模块
//!
//! - [`types`] — HTTP API 请求/响应类型
//! - [`http`] — axum HTTP server
//! - [`client`] — reqwest 客户端 SDK
//!
//! ## 使用示例
//!
//! ```no_run
//! use poker_zkvm::service::{ProverService, ProverServiceConfig};
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let service = ProverService::new(ProverServiceConfig::default())?;
//! let elf = b"...";
//! let input = b"...";
//! let resp = service.prove(elf, input).await?;
//! println!("proof size: {} bytes, cache_hit: {}", resp.proof_size, resp.cache_hit);
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod http;
pub mod types;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

use crate::ccs::Ccs;
use crate::error::ZkvmError;
use crate::prover::{self, ZkPublicIo, default_ccs_registry};
use crate::verifier::verify_production;
pub use types::{
    ErrorResponse, HealthResponse, ProveRequest, ProveResponse, ShutdownResponse, StatsResponse,
    VerifyRequest, VerifyResponse, from_hex, to_hex,
};

// ===========================================================================
// ProverServiceConfig
// ===========================================================================

/// ProverService 配置。
#[derive(Debug, Clone)]
pub struct ProverServiceConfig {
    /// 每 batch 步数（默认 256）。
    pub batch_size: usize,
    /// IPA PCS 最大变量数（默认 20）。
    pub max_n_vars: usize,
    /// proof 字节数上限（默认 64KB）。
    pub proof_size_limit: usize,
    /// CycleFold 递归深度上限（默认 16）。
    pub max_recursion_depth: u32,
    /// proof_cache 容量（默认 16，LRU 淘汰）。
    pub proof_cache_capacity: usize,
    /// Phase 5.3 — 是否启用并行 CCS 编译（默认 `true`，透传给 `ProverConfig`）。
    ///
    /// 详见 [`prover::ProverConfig::parallel_ccs_compile`]。
    pub parallel_ccs_compile: bool,
    /// Phase 5.3 — rayon 线程池线程数（默认 `None` = 全局 `RAYON_NUM_THREADS`）。
    ///
    /// 详见 [`prover::ProverConfig::rayon_threads`]。
    pub rayon_threads: Option<usize>,
}

impl Default for ProverServiceConfig {
    fn default() -> Self {
        Self {
            batch_size: 256,
            max_n_vars: 20,
            proof_size_limit: prover::MAX_ZKVM_PROOF_SIZE,
            max_recursion_depth: prover::MAX_RECURSION_DEPTH,
            proof_cache_capacity: 16,
            // Phase 5.3 — 默认与 ProverConfig::default() 保持一致
            parallel_ccs_compile: true,
            rayon_threads: None,
        }
    }
}

impl ProverServiceConfig {
    /// 转换为底层 `ProverConfig`（用于调用 `prover::prove`）。
    ///
    /// Phase 5.3 — 透传 `parallel_ccs_compile` 与 `rayon_threads`，
    /// 使 service 层可控制底层 prove 的并行行为。
    #[must_use]
    pub fn to_prover_config(&self) -> prover::ProverConfig {
        prover::ProverConfig {
            batch_size: self.batch_size,
            max_n_vars: self.max_n_vars,
            proof_size_limit: self.proof_size_limit,
            max_recursion_depth: self.max_recursion_depth,
            randomness_seed: crate::field::ZkvmField::zero(),
            initial_commitment: crate::field::ZkvmField::zero(),
            final_commitment: crate::field::ZkvmField::zero(),
            parallel_ccs_compile: self.parallel_ccs_compile,
            rayon_threads: self.rayon_threads,
        }
    }

    /// Phase 5.3 — 校验配置合法性（委托给 `ProverConfig::validate`）。
    ///
    /// # 错误
    /// 与 [`prover::ProverConfig::validate`] 相同，外加 `proof_cache_capacity == 0` 校验。
    pub fn validate(&self) -> Result<(), ZkvmError> {
        if self.proof_cache_capacity == 0 {
            return Err(ZkvmError::Other(
                "ProverServiceConfig: proof_cache_capacity 须 > 0".to_string(),
            ));
        }
        self.to_prover_config().validate()
    }
}

// ===========================================================================
// ProofCache
// ===========================================================================

/// proof_cache 单条记录。
#[derive(Clone)]
struct ProofCacheEntry {
    proof: Vec<u8>,
    public_io: ZkPublicIo,
    last_access: Instant,
}

/// proof_cache key — Blake2b-256(elf || input)。
type CacheKey = [u8; 32];

/// LRU proof_cache（按容量淘汰最久未访问）。
struct ProofCache {
    entries: HashMap<CacheKey, ProofCacheEntry>,
    capacity: usize,
}

impl ProofCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }

    fn get(&mut self, key: &CacheKey) -> Option<(Vec<u8>, ZkPublicIo)> {
        let entry = self.entries.get_mut(key)?;
        entry.last_access = Instant::now();
        Some((entry.proof.clone(), entry.public_io.clone()))
    }

    fn put(&mut self, key: CacheKey, proof: Vec<u8>, public_io: ZkPublicIo) {
        // 容量超限时淘汰最久未访问
        while self.entries.len() >= self.capacity {
            if let Some((&oldest_key, _)) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.last_access)
            {
                self.entries.remove(&oldest_key);
            } else {
                break;
            }
        }
        self.entries.insert(
            key,
            ProofCacheEntry {
                proof,
                public_io,
                last_access: Instant::now(),
            },
        );
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

// ===========================================================================
// ProverStats
// ===========================================================================

/// ProverService 统计计数器（atomic，线程安全）。
#[derive(Debug)]
pub struct ProverStats {
    /// 累计 prove 请求数。
    pub prove_count: AtomicU64,
    /// 累计 verify 请求数。
    pub verify_count: AtomicU64,
    /// 累计生成 proof 数（不含 cache hit）。
    pub proofs_generated: AtomicU64,
    /// 累计 prove 耗时（毫秒）。
    pub prove_total_ms: AtomicU64,
    /// 累计 verify 耗时（毫秒）。
    pub verify_total_ms: AtomicU64,
    /// 服务启动时间。
    pub started_at: Instant,
}

impl Default for ProverStats {
    fn default() -> Self {
        Self {
            prove_count: AtomicU64::new(0),
            verify_count: AtomicU64::new(0),
            proofs_generated: AtomicU64::new(0),
            prove_total_ms: AtomicU64::new(0),
            verify_total_ms: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }
}

impl ProverStats {
    /// 返回当前快照。
    #[must_use]
    pub fn snapshot(&self) -> ProverStatsSnapshot {
        ProverStatsSnapshot {
            prove_count: self.prove_count.load(Ordering::Relaxed),
            verify_count: self.verify_count.load(Ordering::Relaxed),
            proofs_generated: self.proofs_generated.load(Ordering::Relaxed),
            prove_total_ms: self.prove_total_ms.load(Ordering::Relaxed),
            verify_total_ms: self.verify_total_ms.load(Ordering::Relaxed),
            uptime_s: self.started_at.elapsed().as_secs(),
        }
    }
}

/// ProverStats 快照（用于响应）。
#[derive(Debug, Clone)]
pub struct ProverStatsSnapshot {
    /// 累计 prove 请求数。
    pub prove_count: u64,
    /// 累计 verify 请求数。
    pub verify_count: u64,
    /// 累计生成 proof 数（不含 cache hit）。
    pub proofs_generated: u64,
    /// 累计 prove 耗时（毫秒）。
    pub prove_total_ms: u64,
    /// 累计 verify 耗时（毫秒）。
    pub verify_total_ms: u64,
    /// 服务运行时长（秒）。
    pub uptime_s: u64,
}

// ===========================================================================
// ProverService
// ===========================================================================

/// zkvm 证明服务（线程安全，可在 tokio runtime 中共享）。
pub struct ProverService {
    /// CCS registry（启动时构造，只读）。
    ccs_registry: Arc<Vec<Ccs>>,
    /// proof_cache（按 ELF+input 哈希缓存）。
    proof_cache: Arc<Mutex<ProofCache>>,
    /// 服务配置。
    config: ProverServiceConfig,
    /// 统计计数器。
    stats: Arc<ProverStats>,
}

impl ProverService {
    /// 创建新的 ProverService。
    ///
    /// Phase 5.3 — 会先调用 `ProverServiceConfig::validate()` 校验配置合法性，
    /// 包括 `parallel_ccs_compile` / `rayon_threads` 等 Phase 5.2 新增字段的约束。
    ///
    /// # Errors
    /// - `ProverServiceConfig::validate` 失败（batch_size=0 / rayon_threads=Some(0) 等）
    /// - `prover::default_ccs_registry` 内部错误（CCS 构造失败等）
    pub fn new(config: ProverServiceConfig) -> Result<Self, ZkvmError> {
        config.validate()?;
        let ccs_registry = Arc::new(default_ccs_registry());
        let proof_cache = Arc::new(Mutex::new(ProofCache::new(config.proof_cache_capacity)));
        let stats = Arc::new(ProverStats {
            started_at: Instant::now(),
            ..Default::default()
        });
        Ok(Self {
            ccs_registry,
            proof_cache,
            config,
            stats,
        })
    }

    /// 返回服务配置的只读引用。
    #[must_use]
    pub fn config(&self) -> &ProverServiceConfig {
        &self.config
    }

    /// 返回统计快照。
    #[must_use]
    pub fn stats(&self) -> ProverStatsSnapshot {
        self.stats.snapshot()
    }

    /// 返回 proof_cache 当前大小。
    #[must_use]
    pub fn proof_cache_size(&self) -> usize {
        self.proof_cache
            .lock()
            .expect("proof_cache poisoned")
            .len()
    }

    /// 返回 CCS registry 大小。
    #[must_use]
    pub fn ccs_registry_size(&self) -> usize {
        self.ccs_registry.len()
    }

    /// 执行 prove（异步，spawn_blocking 包装阻塞 prove）。
    ///
    /// # Errors
    /// - `ZkvmError` 透传 `prover::prove` 错误
    pub async fn prove(&self, elf: &[u8], input: &[u8]) -> Result<ProveResponse, ZkvmError> {
        self.stats.prove_count.fetch_add(1, Ordering::Relaxed);

        let cache_key = compute_cache_key(elf, input);
        let started = Instant::now();

        // 1. 检查 cache
        {
            let mut cache = self.proof_cache.lock().expect("proof_cache poisoned");
            if let Some((proof, public_io)) = cache.get(&cache_key) {
                let elapsed_ms = started.elapsed().as_millis() as u64;
                return Ok(ProveResponse {
                    proof_hex: to_hex(&proof),
                    public_io_hex: to_hex(&public_io.to_bytes()),
                    elapsed_ms,
                    cache_hit: true,
                    proof_size: proof.len(),
                });
            }
        }

        // 2. spawn_blocking 调用同步 prove
        let config = self.config.to_prover_config();
        let elf_owned = elf.to_vec();
        let input_owned = input.to_vec();

        let (proof, public_io) = tokio::task::spawn_blocking(move || {
            prover::prove(&elf_owned, &input_owned, &config)
        })
        .await
        .map_err(|e| ZkvmError::Other(format!("spawn_blocking join error: {e}")))??;

        let elapsed_ms = started.elapsed().as_millis() as u64;
        self.stats
            .proofs_generated
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .prove_total_ms
            .fetch_add(elapsed_ms, Ordering::Relaxed);

        // 3. 写入 cache
        {
            let mut cache = self.proof_cache.lock().expect("proof_cache poisoned");
            cache.put(cache_key, proof.clone(), public_io.clone());
        }

        Ok(ProveResponse {
            proof_hex: to_hex(&proof),
            public_io_hex: to_hex(&public_io.to_bytes()),
            elapsed_ms,
            cache_hit: false,
            proof_size: proof.len(),
        })
    }

    /// 执行 verify（异步，spawn_blocking 包装阻塞 verify）。
    ///
    /// # Errors
    /// - `ZkvmError` 透传 `verify_production` 错误
    pub async fn verify(
        &self,
        proof: &[u8],
        public_io: &ZkPublicIo,
    ) -> Result<VerifyResponse, ZkvmError> {
        self.stats.verify_count.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();

        let registry = self.ccs_registry.clone();
        let proof_owned = proof.to_vec();
        let public_io_owned = public_io.clone();

        let valid = tokio::task::spawn_blocking(move || {
            verify_production(&proof_owned, &public_io_owned, &registry)
        })
        .await
        .map_err(|e| ZkvmError::Other(format!("spawn_blocking join error: {e}")))??;

        let elapsed_ms = started.elapsed().as_millis() as u64;
        self.stats
            .verify_total_ms
            .fetch_add(elapsed_ms, Ordering::Relaxed);

        Ok(VerifyResponse {
            valid,
            elapsed_ms,
        })
    }
}

// ===========================================================================
// 辅助函数
// ===========================================================================

/// 计算 proof_cache key — Blake2b-256(elf || input)。
fn compute_cache_key(elf: &[u8], input: &[u8]) -> CacheKey {
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
    hasher.update(b"poker_zkvm_prove_cache");
    hasher.update(&(elf.len() as u64).to_le_bytes());
    hasher.update(elf);
    hasher.update(&(input.len() as u64).to_le_bytes());
    hasher.update(input);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("Blake2bVar finalize 不应失败");
    out
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{build_nop_elf, build_texas_poker_full_hand_elf, make_full_hand_input};

    #[test]
    fn test_prover_service_new_default() {
        let service = ProverService::new(ProverServiceConfig::default())
            .expect("ProverService::new 应成功");
        assert!(service.ccs_registry_size() > 0, "CCS registry 不应为空");
        assert_eq!(service.proof_cache_size(), 0, "初始 cache 应为空");
        assert_eq!(service.stats().prove_count, 0);
    }

    #[test]
    fn test_prover_service_config_to_prover_config() {
        let config = ProverServiceConfig::default();
        let prover_config = config.to_prover_config();
        assert_eq!(prover_config.batch_size, 256);
        assert_eq!(prover_config.max_n_vars, 20);
        assert_eq!(prover_config.proof_size_limit, 64 * 1024);
        assert_eq!(prover_config.max_recursion_depth, 16);
        // Phase 5.3 — 新字段透传校验
        assert!(
            prover_config.parallel_ccs_compile,
            "parallel_ccs_compile 应透传 default(true)"
        );
        assert!(
            prover_config.rayon_threads.is_none(),
            "rayon_threads 应透传 default(None)"
        );
    }

    /// Phase 5.3 — 验证 `ProverServiceConfig::validate` 拒绝非法配置。
    #[test]
    fn test_prover_service_config_validate_rejects_invalid() {
        // rayon_threads = Some(0) 应被拒绝
        let config = ProverServiceConfig {
            rayon_threads: Some(0),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref m) if m.contains("rayon_threads")),
            "expected rayon_threads validation error, got {err:?}"
        );

        // proof_cache_capacity = 0 应被拒绝
        let config = ProverServiceConfig {
            proof_cache_capacity: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref m) if m.contains("proof_cache_capacity")),
            "expected proof_cache_capacity validation error, got {err:?}"
        );

        // batch_size = 0 应被拒绝（透传 ProverConfig::validate）
        let config = ProverServiceConfig {
            batch_size: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref m) if m.contains("batch_size")),
            "expected batch_size validation error, got {err:?}"
        );
    }

    /// Phase 5.3 — 验证 `ProverService::new` 在非法配置下返回错误。
    #[test]
    fn test_prover_service_new_rejects_invalid_config() {
        let config = ProverServiceConfig {
            rayon_threads: Some(0),
            ..Default::default()
        };
        let result = ProverService::new(config);
        assert!(
            matches!(result, Err(ZkvmError::Other(ref m)) if m.contains("rayon_threads")),
            "ProverService::new 应拒绝 rayon_threads=Some(0)"
        );
    }

    /// Phase 5.3 — 验证 `ProverServiceConfig` 的 `parallel_ccs_compile` / `rayon_threads`
    /// 字段能正确透传到底层 `ProverConfig` 并影响 prove 行为。
    #[test]
    fn test_prover_service_config_parallel_fields_propagate() {
        let config = ProverServiceConfig {
            parallel_ccs_compile: false, // 顺序路径
            rayon_threads: Some(2),
            ..Default::default()
        };
        let prover_config = config.to_prover_config();
        assert!(
            !prover_config.parallel_ccs_compile,
            "parallel_ccs_compile=false 应透传"
        );
        assert_eq!(
            prover_config.rayon_threads,
            Some(2),
            "rayon_threads=Some(2) 应透传"
        );
    }

    #[tokio::test]
    async fn test_prover_service_prove_nop() {
        let service = ProverService::new(ProverServiceConfig::default())
            .expect("ProverService::new 应成功");
        let elf = build_nop_elf(10);
        let input: Vec<u8> = vec![];
        let resp = service.prove(&elf, &input).await.expect("prove 应成功");
        assert!(!resp.cache_hit, "首次 prove 不应命中 cache");
        assert!(resp.proof_size > 0, "proof 不应为空");
        assert_eq!(resp.proof_hex.len(), resp.proof_size * 2, "hex 长度应为字节数的 2 倍");

        // 统计应更新
        let stats = service.stats();
        assert_eq!(stats.prove_count, 1);
        assert_eq!(stats.proofs_generated, 1);
    }

    #[tokio::test]
    async fn test_prover_service_cache_hit() {
        let service = ProverService::new(ProverServiceConfig::default())
            .expect("ProverService::new 应成功");
        let elf = build_nop_elf(10);
        let input: Vec<u8> = vec![];

        // 首次 prove
        let resp1 = service.prove(&elf, &input).await.expect("prove #1 应成功");
        assert!(!resp1.cache_hit, "首次 prove 不应命中 cache");

        // 二次 prove 同一 elf+input → cache hit
        let resp2 = service.prove(&elf, &input).await.expect("prove #2 应成功");
        assert!(resp2.cache_hit, "二次 prove 应命中 cache");
        assert_eq!(resp1.proof_hex, resp2.proof_hex, "cache 命中应返回相同 proof");

        // proofs_generated 不应增加（cache hit 不重新生成）
        let stats = service.stats();
        assert_eq!(stats.prove_count, 2, "prove_count 应为 2");
        assert_eq!(stats.proofs_generated, 1, "proofs_generated 应仍为 1");
    }

    #[tokio::test]
    async fn test_prover_service_verify_roundtrip() {
        let service = ProverService::new(ProverServiceConfig::default())
            .expect("ProverService::new 应成功");
        let elf = build_nop_elf(10);
        let input: Vec<u8> = vec![];

        // prove
        let prove_resp = service.prove(&elf, &input).await.expect("prove 应成功");
        let proof = from_hex(&prove_resp.proof_hex).expect("decode proof hex");
        let public_io_bytes = from_hex(&prove_resp.public_io_hex).expect("decode public_io hex");
        let public_io = ZkPublicIo::from_bytes(&public_io_bytes).expect("deserialize public_io");

        // verify
        let verify_resp = service.verify(&proof, &public_io).await.expect("verify 应成功");
        assert!(verify_resp.valid, "verify 应通过");

        let stats = service.stats();
        assert_eq!(stats.verify_count, 1, "verify_count 应为 1");
    }

    #[tokio::test]
    async fn test_prover_service_texas_poker_full_hand() {
        // 端到端：texas_poker 完整一手牌 ELF → prove → verify
        let service = ProverService::new(ProverServiceConfig::default())
            .expect("ProverService::new 应成功");
        let elf = build_texas_poker_full_hand_elf();
        let input = make_full_hand_input([14, 13, 12, 11, 10], [2, 2, 3, 4, 5]);

        let prove_resp = service.prove(&elf, &input).await.expect("prove 应成功");
        assert!(prove_resp.proof_size > 0);
        assert!(prove_resp.proof_size <= 64 * 1024, "proof 应在 64KB 上链限制内");

        let proof = from_hex(&prove_resp.proof_hex).expect("decode proof hex");
        let public_io_bytes = from_hex(&prove_resp.public_io_hex).expect("decode public_io hex");
        let public_io = ZkPublicIo::from_bytes(&public_io_bytes).expect("deserialize public_io");

        // 校验 output
        assert_eq!(public_io.output.len(), 1, "texas_poker 输出应为 1 字节 winner");
        assert_eq!(public_io.output[0], 1, "P1 应胜");

        // verify
        let verify_resp = service.verify(&proof, &public_io).await.expect("verify 应成功");
        assert!(verify_resp.valid, "verify 应通过");
    }

    #[test]
    fn test_proof_cache_lru_eviction() {
        let mut cache = ProofCache::new(2);
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let key3 = [3u8; 32];
        let dummy_proof = vec![0u8; 10];
        let dummy_io = ZkPublicIo {
            input: vec![],
            output: vec![],
            randomness_seed: crate::field::ZkvmField::zero(),
            initial_commitment: crate::field::ZkvmField::zero(),
            final_commitment: crate::field::ZkvmField::zero(),
            event_hashes: vec![],
        };

        cache.put(key1, dummy_proof.clone(), dummy_io.clone());
        cache.put(key2, dummy_proof.clone(), dummy_io.clone());
        assert_eq!(cache.len(), 2);

        // 访问 key1 让 key2 变为最久未访问
        std::thread::sleep(std::time::Duration::from_millis(1));
        let _ = cache.get(&key1);

        // 插入 key3 应淘汰 key2
        cache.put(key3, dummy_proof, dummy_io);
        assert_eq!(cache.len(), 2, "cache 容量应仍为 2");
        assert!(cache.get(&key1).is_some(), "key1 应仍存在（最近访问）");
        assert!(cache.get(&key2).is_none(), "key2 应被淘汰");
        assert!(cache.get(&key3).is_some(), "key3 应存在");
    }

    #[test]
    fn test_compute_cache_key_deterministic() {
        let elf = b"hello";
        let input = b"world";
        let key1 = compute_cache_key(elf, input);
        let key2 = compute_cache_key(elf, input);
        assert_eq!(key1, key2, "相同输入应产生相同 cache key");
    }

    #[test]
    fn test_compute_cache_key_input_sensitive() {
        let elf = b"hello";
        let key1 = compute_cache_key(elf, b"input1");
        let key2 = compute_cache_key(elf, b"input2");
        assert_ne!(key1, key2, "不同 input 应产生不同 cache key");
    }
}
