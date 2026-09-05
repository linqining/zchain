// Lean compiler output
// Module: PokerLean.Common.M31
// Imports: Init Mathlib
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
LEAN_EXPORT lean_object* l_PokerLean_M31_ofNat___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_M31_zero;
lean_object* l_instReprSubtype___rarg(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_M31_eq___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_M31_two;
LEAN_EXPORT lean_object* l_PokerLean_M31_add(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_M31_ne___boxed(lean_object*, lean_object*);
lean_object* l_instReprNat___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_M31_sub___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_M31_ofNat(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_instM31Repr;
uint8_t l_instDecidableNot___rarg(uint8_t);
LEAN_EXPORT lean_object* l_PokerLean_M31_one;
LEAN_EXPORT lean_object* l_PokerLean_M31_toNat___boxed(lean_object*);
LEAN_EXPORT uint8_t l_PokerLean_M31_M31__P__prime___nativeDecide__1;
LEAN_EXPORT uint8_t l_PokerLean_M31_ne(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_M31_sub(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_M31_mul___boxed(lean_object*, lean_object*);
LEAN_EXPORT uint8_t l_PokerLean_M31_eq(lean_object*, lean_object*);
static lean_object* l_PokerLean_M31__P___closed__1;
static lean_object* l_PokerLean_instM31Repr___closed__2;
uint8_t lean_nat_dec_eq(lean_object*, lean_object*);
uint8_t lean_nat_dec_lt(lean_object*, lean_object*);
lean_object* lean_nat_mod(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_M31_mul(lean_object*, lean_object*);
lean_object* lean_nat_sub(lean_object*, lean_object*);
lean_object* lean_nat_mul(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_M31__P;
LEAN_EXPORT lean_object* l_PokerLean_M31_toNat(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_M31_add___boxed(lean_object*, lean_object*);
uint8_t lean_nat_dec_le(lean_object*, lean_object*);
lean_object* lean_nat_add(lean_object*, lean_object*);
static lean_object* l_PokerLean_instM31Repr___closed__1;
uint8_t l_Nat_decidablePrime(lean_object*);
static uint8_t l_PokerLean_M31_M31__P__prime___nativeDecide__1___closed__1;
static lean_object* _init_l_PokerLean_M31__P___closed__1() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = lean_unsigned_to_nat(2147483648u);
x_2 = lean_unsigned_to_nat(1u);
x_3 = lean_nat_sub(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_PokerLean_M31__P() {
_start:
{
lean_object* x_1; 
x_1 = l_PokerLean_M31__P___closed__1;
return x_1;
}
}
static lean_object* _init_l_PokerLean_instM31Repr___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_alloc_closure((void*)(l_instReprNat___boxed), 2, 0);
return x_1;
}
}
static lean_object* _init_l_PokerLean_instM31Repr___closed__2() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l_PokerLean_instM31Repr___closed__1;
x_2 = lean_alloc_closure((void*)(l_instReprSubtype___rarg), 3, 1);
lean_closure_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l_PokerLean_instM31Repr() {
_start:
{
lean_object* x_1; 
x_1 = l_PokerLean_instM31Repr___closed__2;
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_ofNat(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_inc(x_1);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_ofNat___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_PokerLean_M31_ofNat(x_1, x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_toNat(lean_object* x_1) {
_start:
{
lean_inc(x_1);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_toNat___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_PokerLean_M31_toNat(x_1);
lean_dec(x_1);
return x_2;
}
}
static lean_object* _init_l_PokerLean_M31_zero() {
_start:
{
lean_object* x_1; 
x_1 = lean_unsigned_to_nat(0u);
return x_1;
}
}
static lean_object* _init_l_PokerLean_M31_one() {
_start:
{
lean_object* x_1; 
x_1 = lean_unsigned_to_nat(1u);
return x_1;
}
}
static lean_object* _init_l_PokerLean_M31_two() {
_start:
{
lean_object* x_1; 
x_1 = lean_unsigned_to_nat(2u);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_add(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; lean_object* x_4; uint8_t x_5; 
x_3 = lean_nat_add(x_1, x_2);
x_4 = l_PokerLean_M31__P;
x_5 = lean_nat_dec_lt(x_3, x_4);
if (x_5 == 0)
{
lean_object* x_6; 
x_6 = lean_nat_sub(x_3, x_4);
lean_dec(x_3);
return x_6;
}
else
{
return x_3;
}
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_add___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_PokerLean_M31_add(x_1, x_2);
lean_dec(x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_sub(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; 
x_3 = lean_nat_dec_le(x_2, x_1);
if (x_3 == 0)
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; 
x_4 = lean_nat_sub(x_2, x_1);
x_5 = l_PokerLean_M31__P;
x_6 = lean_nat_sub(x_5, x_4);
lean_dec(x_4);
return x_6;
}
else
{
lean_object* x_7; 
x_7 = lean_nat_sub(x_1, x_2);
return x_7;
}
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_sub___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_PokerLean_M31_sub(x_1, x_2);
lean_dec(x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_mul(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; lean_object* x_4; lean_object* x_5; 
x_3 = lean_nat_mul(x_1, x_2);
x_4 = l_PokerLean_M31__P;
x_5 = lean_nat_mod(x_3, x_4);
lean_dec(x_3);
return x_5;
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_mul___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_PokerLean_M31_mul(x_1, x_2);
lean_dec(x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT uint8_t l_PokerLean_M31_eq(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; 
x_3 = lean_nat_dec_eq(x_1, x_2);
return x_3;
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_eq___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; lean_object* x_4; 
x_3 = l_PokerLean_M31_eq(x_1, x_2);
lean_dec(x_2);
lean_dec(x_1);
x_4 = lean_box(x_3);
return x_4;
}
}
LEAN_EXPORT uint8_t l_PokerLean_M31_ne(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; uint8_t x_4; 
x_3 = lean_nat_dec_eq(x_1, x_2);
x_4 = l_instDecidableNot___rarg(x_3);
return x_4;
}
}
LEAN_EXPORT lean_object* l_PokerLean_M31_ne___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; lean_object* x_4; 
x_3 = l_PokerLean_M31_ne(x_1, x_2);
lean_dec(x_2);
lean_dec(x_1);
x_4 = lean_box(x_3);
return x_4;
}
}
static uint8_t _init_l_PokerLean_M31_M31__P__prime___nativeDecide__1___closed__1() {
_start:
{
lean_object* x_1; uint8_t x_2; 
x_1 = l_PokerLean_M31__P___closed__1;
x_2 = l_Nat_decidablePrime(x_1);
return x_2;
}
}
static uint8_t _init_l_PokerLean_M31_M31__P__prime___nativeDecide__1() {
_start:
{
uint8_t x_1; 
x_1 = l_PokerLean_M31_M31__P__prime___nativeDecide__1___closed__1;
return x_1;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_Mathlib(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_Common_M31(uint8_t builtin, lean_object* w) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Mathlib(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l_PokerLean_M31__P___closed__1 = _init_l_PokerLean_M31__P___closed__1();
lean_mark_persistent(l_PokerLean_M31__P___closed__1);
l_PokerLean_M31__P = _init_l_PokerLean_M31__P();
lean_mark_persistent(l_PokerLean_M31__P);
l_PokerLean_instM31Repr___closed__1 = _init_l_PokerLean_instM31Repr___closed__1();
lean_mark_persistent(l_PokerLean_instM31Repr___closed__1);
l_PokerLean_instM31Repr___closed__2 = _init_l_PokerLean_instM31Repr___closed__2();
lean_mark_persistent(l_PokerLean_instM31Repr___closed__2);
l_PokerLean_instM31Repr = _init_l_PokerLean_instM31Repr();
lean_mark_persistent(l_PokerLean_instM31Repr);
l_PokerLean_M31_zero = _init_l_PokerLean_M31_zero();
lean_mark_persistent(l_PokerLean_M31_zero);
l_PokerLean_M31_one = _init_l_PokerLean_M31_one();
lean_mark_persistent(l_PokerLean_M31_one);
l_PokerLean_M31_two = _init_l_PokerLean_M31_two();
lean_mark_persistent(l_PokerLean_M31_two);
l_PokerLean_M31_M31__P__prime___nativeDecide__1___closed__1 = _init_l_PokerLean_M31_M31__P__prime___nativeDecide__1___closed__1();
l_PokerLean_M31_M31__P__prime___nativeDecide__1 = _init_l_PokerLean_M31_M31__P__prime___nativeDecide__1();
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
