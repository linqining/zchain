/* tslint:disable */
/* eslint-disable */

export function wallet_core_meta(): string;

export function wallet_create(password: string, profile: string): string;

/**
 * 本地铸造一张 PLAY 余额 note（devnet 水龙头 stub：无网络、无链上 mint，
 * 仅用于 0.1 桌面/买入/结算签名链路演示；真实同步在 0.2 接 `sync` trait）。
 */
export function wallet_faucet_play(amount: string): string;

export function wallet_get_notes(): string;

export function wallet_lock(): string;

/**
 * 当前状态 → 持久化密文快照（note 库变化后调用；全部为密文）。
 */
export function wallet_persist(): string;

export function wallet_preview(req: string, now: string): string;

export function wallet_sign(req: string, now: string): string;

export function wallet_sign_settle_input(record_borsh: string, input_index: string): string;

export function wallet_unlock(keystore: string, password: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly wallet_core_meta: () => [number, number];
    readonly wallet_create: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wallet_faucet_play: (a: number, b: number) => [number, number];
    readonly wallet_get_notes: () => [number, number];
    readonly wallet_lock: () => [number, number];
    readonly wallet_persist: () => [number, number];
    readonly wallet_preview: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wallet_sign: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wallet_sign_settle_input: (a: number, b: number, c: number, d: number) => [number, number];
    readonly wallet_unlock: (a: number, b: number, c: number, d: number) => [number, number];
    readonly main: (a: number, b: number) => number;
    readonly rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
    readonly rustsecp256k1_v0_10_0_context_create: (a: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
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
