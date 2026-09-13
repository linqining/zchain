/* tslint:disable */
/* eslint-disable */

/**
 * 备份导出（需解锁会话）：REAL/PLAY 双库快照 + keystore/DEK 信封 +
 * 声明索引 → 口令加密的 EncryptedBackup（borsh hex 传输；JS 侧转二进制
 * 文件下载）。profile 同 wallet_create："interactive"（生产 Argon2id
 * 参数）或 "test"（仅测试/冒烟）。
 */
export function wallet_backup_export(password: string, profile: string, now: string): string;

/**
 * 备份导入（**无会话**：恢复路径在锁定态可用）。拒绝面：结构/魔数篡改
 * （Tampered）、未来版本（UnsupportedVersion，解密前拒绝）、错误口令
 * （AEAD 认证失败 → BadPassword）、声明索引与重建索引不一致
 * （Tampered）。成功时 keystore 信封再用同一口令开启校验一次
 * （fail-closed 快路径）并回 public_key；恢复数据以密文+信封 hex 返回，
 * 由 JS 侧落为新账户，**不**自动替换当前会话。
 */
export function wallet_backup_import(backup_hex: string, password: string): string;

/**
 * binding 状态查询（撤销粘滞/时间窗/日限；无会话依赖）。
 */
export function wallet_binding_status(binding: string, now: string): string;

export function wallet_core_meta(): string;

export function wallet_create(password: string, profile: string): string;

/**
 * UI 展示门视图（claim 门 + 托管风险提示）。Extension 0.2 的就绪态恒为
 * offline（Vault/verifier/BFT finality 均未接入）→ REAL 页无 claim 操作、
 * 常显托管风险提示；PLAY 页无任何 REAL 字段。UI 壳层只消费本输出，
 * 不得自行决定（display.rs 是唯一事实源）。
 */
export function wallet_display_views(): string;

/**
 * 本地铸造一张 PLAY 余额 note（devnet 水龙头 stub：无网络、无链上 mint，
 * 仅用于 0.1 桌面/买入/结算签名链路演示；真实同步在 0.2 接 `sync` trait）。
 */
export function wallet_faucet_play(amount: string): string;

/**
 * REAL/PLAY 分库 note 列表 + 按资产类余额（脱敏：无 spend secret/nullifier）。
 * REAL 侧同样只出承诺/金额/proof 状态——REAL 操作面（提现/claim）0.2 不开放。
 */
export function wallet_get_all_notes(): string;

export function wallet_get_notes(): string;

export function wallet_lock(): string;

/**
 * 当前状态 → 持久化密文快照（note 库变化后调用；全部为密文）。
 */
export function wallet_persist(): string;

export function wallet_preview(req: string, now: string): string;

/**
 * 限额/约束 enforcement（Extension 0.4 签名路径第二层；无会话依赖）。
 * 输出 `{admitted, rejected_reason, status}`（拒绝是 verdict，非 error）。
 */
export function wallet_session_admit(binding: string, req: string, now: string): string;

/**
 * 生成满足约束的 delegated key（OS 随机源；wallet-core 单实现）。
 * 输入 = session_check 模块文档中的 binding 形状，其中
 * `delegatedPublicKey` **不可提供**（由本入口生成后返回）；
 * `bindingId` 可缺省（缺省时用 OS 随机源生成 32B）。
 * 返回 binding 摘要（公钥级信息）；私钥不入返回值。
 */
export function wallet_session_key_create(req: string): string;

/**
 * 本会话内生成的 delegated key 列表（仅公钥级字段；锁定/切换账户即清空，
 * 如实反映"私钥不持久化"边界）。
 */
export function wallet_session_key_list(): string;

export function wallet_sign(req: string, now: string): string;

export function wallet_sign_settle_input(record_borsh: string, input_index: string): string;

/**
 * SNIP-12 `AuthorizeZChainKey` 摘要（revision 1；授权确认页展示面）。
 */
export function wallet_snip12_authorize_digest(msg: string): string;

export function wallet_unlock(keystore: string, password: string): string;

export function wallet_verify_settlement_detail(detail: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly wallet_backup_export: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly wallet_backup_import: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wallet_binding_status: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wallet_core_meta: () => [number, number];
    readonly wallet_create: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wallet_display_views: () => [number, number];
    readonly wallet_faucet_play: (a: number, b: number) => [number, number];
    readonly wallet_get_all_notes: () => [number, number];
    readonly wallet_get_notes: () => [number, number];
    readonly wallet_lock: () => [number, number];
    readonly wallet_persist: () => [number, number];
    readonly wallet_preview: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wallet_session_admit: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly wallet_session_key_create: (a: number, b: number) => [number, number];
    readonly wallet_session_key_list: () => [number, number];
    readonly wallet_sign: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wallet_sign_settle_input: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wallet_snip12_authorize_digest: (a: number, b: number) => [number, number];
    readonly wallet_unlock: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wallet_verify_settlement_detail: (a: number, b: number) => [number, number];
    readonly main: (a: number, b: number) => number;
    readonly rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
    readonly rustsecp256k1_v0_10_0_context_create: (a: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
