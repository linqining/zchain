/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const wallet_core_meta: () => [number, number];
export const wallet_create: (a: number, b: number, c: number, d: number) => [number, number];
export const wallet_faucet_play: (a: number, b: number) => [number, number];
export const wallet_get_notes: () => [number, number];
export const wallet_lock: () => [number, number];
export const wallet_persist: () => [number, number];
export const wallet_preview: (a: number, b: number, c: number, d: number) => [number, number];
export const wallet_sign: (a: number, b: number, c: number, d: number) => [number, number];
export const wallet_sign_settle_input: (a: number, b: number, c: number, d: number) => [number, number];
export const wallet_unlock: (a: number, b: number, c: number, d: number) => [number, number];
export const main: (a: number, b: number) => number;
export const rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
export const rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
export const rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
export const rustsecp256k1_v0_10_0_context_create: (a: number) => number;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_start: () => void;
