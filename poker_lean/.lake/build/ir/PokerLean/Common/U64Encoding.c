// Lean compiler output
// Module: PokerLean.Common.U64Encoding
// Imports: Init PokerLean.Common.M31
#include <lean/lean.h>
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-label"
#elif defined(__GNUC__) && !defined(__CLANG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif
#ifdef __cplusplus
extern "C" {
#endif
LEAN_EXPORT lean_object* l_PokerLean_U64_ofNat(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_decodeU64(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_U64__MAX;
LEAN_EXPORT lean_object* l_PokerLean_decodeLimb4(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_decodeLimb4___boxed(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_natToM31___boxed(lean_object*, lean_object*);
lean_object* lean_nat_div(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_U64_toNat(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_decodeU64___boxed(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_natToM31(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_LIMB__SIZE;
static lean_object* l_PokerLean_U64__MAX___closed__1;
LEAN_EXPORT lean_object* l_PokerLean_limbsToU64___boxed(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_limbsToU64(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_U64_ofNat___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_u64ToLimbs___boxed(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_U64_toNat___boxed(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_u64ToLimbs(lean_object*);
lean_object* lean_nat_mod(lean_object*, lean_object*);
lean_object* lean_nat_mul(lean_object*, lean_object*);
lean_object* lean_nat_add(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_U64_ofNat(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_inc(x_1);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_U64_ofNat___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_PokerLean_U64_ofNat(x_1, x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_PokerLean_U64_toNat(lean_object* x_1) {
_start:
{
lean_inc(x_1);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_U64_toNat___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_PokerLean_U64_toNat(x_1);
lean_dec(x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l_PokerLean_u64ToLimbs(lean_object* x_1) {
_start:
{
lean_object* x_2; lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; 
x_2 = lean_unsigned_to_nat(65536u);
x_3 = lean_nat_mod(x_1, x_2);
x_4 = lean_nat_div(x_1, x_2);
x_5 = lean_nat_mod(x_4, x_2);
lean_dec(x_4);
x_6 = lean_cstr_to_nat("4294967296");
x_7 = lean_nat_div(x_1, x_6);
x_8 = lean_nat_mod(x_7, x_2);
lean_dec(x_7);
x_9 = lean_cstr_to_nat("281474976710656");
x_10 = lean_nat_div(x_1, x_9);
x_11 = lean_nat_mod(x_10, x_2);
lean_dec(x_10);
x_12 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_12, 0, x_8);
lean_ctor_set(x_12, 1, x_11);
x_13 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_13, 0, x_5);
lean_ctor_set(x_13, 1, x_12);
x_14 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_14, 0, x_3);
lean_ctor_set(x_14, 1, x_13);
return x_14;
}
}
LEAN_EXPORT lean_object* l_PokerLean_u64ToLimbs___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_PokerLean_u64ToLimbs(x_1);
lean_dec(x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l_PokerLean_limbsToU64(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4, lean_object* x_5, lean_object* x_6, lean_object* x_7, lean_object* x_8) {
_start:
{
lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; 
x_9 = lean_unsigned_to_nat(65536u);
x_10 = lean_nat_mul(x_2, x_9);
x_11 = lean_nat_add(x_1, x_10);
lean_dec(x_10);
x_12 = lean_cstr_to_nat("4294967296");
x_13 = lean_nat_mul(x_3, x_12);
x_14 = lean_nat_add(x_11, x_13);
lean_dec(x_13);
lean_dec(x_11);
x_15 = lean_cstr_to_nat("281474976710656");
x_16 = lean_nat_mul(x_4, x_15);
x_17 = lean_nat_add(x_14, x_16);
lean_dec(x_16);
lean_dec(x_14);
return x_17;
}
}
LEAN_EXPORT lean_object* l_PokerLean_limbsToU64___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4, lean_object* x_5, lean_object* x_6, lean_object* x_7, lean_object* x_8) {
_start:
{
lean_object* x_9; 
x_9 = l_PokerLean_limbsToU64(x_1, x_2, x_3, x_4, x_5, x_6, x_7, x_8);
lean_dec(x_4);
lean_dec(x_3);
lean_dec(x_2);
lean_dec(x_1);
return x_9;
}
}
LEAN_EXPORT lean_object* l_PokerLean_decodeU64(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; 
x_5 = lean_unsigned_to_nat(65536u);
x_6 = lean_nat_mul(x_2, x_5);
x_7 = lean_nat_add(x_1, x_6);
lean_dec(x_6);
x_8 = lean_cstr_to_nat("4294967296");
x_9 = lean_nat_mul(x_3, x_8);
x_10 = lean_nat_add(x_7, x_9);
lean_dec(x_9);
lean_dec(x_7);
x_11 = lean_cstr_to_nat("281474976710656");
x_12 = lean_nat_mul(x_4, x_11);
x_13 = lean_nat_add(x_10, x_12);
lean_dec(x_12);
lean_dec(x_10);
return x_13;
}
}
LEAN_EXPORT lean_object* l_PokerLean_decodeU64___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; 
x_5 = l_PokerLean_decodeU64(x_1, x_2, x_3, x_4);
lean_dec(x_4);
lean_dec(x_3);
lean_dec(x_2);
lean_dec(x_1);
return x_5;
}
}
LEAN_EXPORT lean_object* l_PokerLean_decodeLimb4(lean_object* x_1) {
_start:
{
lean_object* x_2; lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; 
x_2 = lean_ctor_get(x_1, 0);
x_3 = lean_ctor_get(x_1, 1);
x_4 = lean_ctor_get(x_3, 0);
x_5 = lean_ctor_get(x_3, 1);
x_6 = lean_ctor_get(x_5, 0);
x_7 = lean_ctor_get(x_5, 1);
x_8 = l_PokerLean_decodeU64(x_2, x_4, x_6, x_7);
return x_8;
}
}
LEAN_EXPORT lean_object* l_PokerLean_decodeLimb4___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_PokerLean_decodeLimb4(x_1);
lean_dec(x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l_PokerLean_natToM31(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_inc(x_1);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_natToM31___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_PokerLean_natToM31(x_1, x_2);
lean_dec(x_1);
return x_3;
}
}
static lean_object* _init_l_PokerLean_U64__MAX___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_cstr_to_nat("18446744073709551616");
return x_1;
}
}
static lean_object* _init_l_PokerLean_U64__MAX() {
_start:
{
lean_object* x_1; 
x_1 = l_PokerLean_U64__MAX___closed__1;
return x_1;
}
}
static lean_object* _init_l_PokerLean_LIMB__SIZE() {
_start:
{
lean_object* x_1; 
x_1 = lean_unsigned_to_nat(65536u);
return x_1;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_M31(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_Common_U64Encoding(uint8_t builtin, lean_object* w) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Common_M31(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l_PokerLean_U64__MAX___closed__1 = _init_l_PokerLean_U64__MAX___closed__1();
lean_mark_persistent(l_PokerLean_U64__MAX___closed__1);
l_PokerLean_U64__MAX = _init_l_PokerLean_U64__MAX();
lean_mark_persistent(l_PokerLean_U64__MAX);
l_PokerLean_LIMB__SIZE = _init_l_PokerLean_LIMB__SIZE();
lean_mark_persistent(l_PokerLean_LIMB__SIZE);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
