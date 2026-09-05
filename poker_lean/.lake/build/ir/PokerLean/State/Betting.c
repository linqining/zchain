// Lean compiler output
// Module: PokerLean.State.Betting
// Imports: Init Mathlib PokerLean.State.Constants PokerLean.State.Types
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
LEAN_EXPORT uint8_t l_TexasPoker_BettingRound_can__call(lean_object*, lean_object*, lean_object*);
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__10;
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_can__call___boxed(lean_object*, lean_object*, lean_object*);
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__13;
LEAN_EXPORT uint8_t l_TexasPoker_BettingRound_can__raise(lean_object*, lean_object*, lean_object*);
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__5;
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__14;
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_process__raise___boxed(lean_object*, lean_object*, lean_object*, lean_object*);
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__9;
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_process__raise(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_process__call(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_process__call___boxed(lean_object*, lean_object*, lean_object*);
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__2;
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__1;
extern lean_object* l_TexasPoker_Constants_ACTION__FOLD;
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_available__actions(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_chips__to__call(lean_object*, lean_object*);
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__4;
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__3;
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_chips__to__call___boxed(lean_object*, lean_object*);
uint8_t lean_nat_dec_eq(lean_object*, lean_object*);
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__6;
uint8_t lean_nat_dec_lt(lean_object*, lean_object*);
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__7;
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__12;
lean_object* lean_nat_sub(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_available__actions___boxed(lean_object*, lean_object*, lean_object*);
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__8;
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_can__raise___boxed(lean_object*, lean_object*, lean_object*);
uint8_t lean_nat_dec_le(lean_object*, lean_object*);
extern lean_object* l_TexasPoker_Constants_ACTION__CALL;
extern lean_object* l_TexasPoker_Constants_ACTION__RAISE;
extern lean_object* l_TexasPoker_Constants_ACTION__CHECK;
static lean_object* l_TexasPoker_BettingRound_available__actions___closed__11;
LEAN_EXPORT uint8_t l_TexasPoker_BettingRound_can__check(lean_object*, lean_object*);
lean_object* lean_nat_lor(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_can__check___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_chips__to__call(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; lean_object* x_4; 
x_3 = lean_ctor_get(x_1, 0);
x_4 = lean_nat_sub(x_3, x_2);
return x_4;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_chips__to__call___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_BettingRound_chips__to__call(x_1, x_2);
lean_dec(x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT uint8_t l_TexasPoker_BettingRound_can__check(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; lean_object* x_4; uint8_t x_5; 
x_3 = l_TexasPoker_BettingRound_chips__to__call(x_1, x_2);
x_4 = lean_unsigned_to_nat(0u);
x_5 = lean_nat_dec_eq(x_3, x_4);
lean_dec(x_3);
return x_5;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_can__check___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; lean_object* x_4; 
x_3 = l_TexasPoker_BettingRound_can__check(x_1, x_2);
lean_dec(x_2);
lean_dec(x_1);
x_4 = lean_box(x_3);
return x_4;
}
}
LEAN_EXPORT uint8_t l_TexasPoker_BettingRound_can__call(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; lean_object* x_5; uint8_t x_6; 
x_4 = l_TexasPoker_BettingRound_chips__to__call(x_1, x_2);
x_5 = lean_unsigned_to_nat(0u);
x_6 = lean_nat_dec_lt(x_5, x_4);
lean_dec(x_4);
if (x_6 == 0)
{
uint8_t x_7; 
x_7 = 0;
return x_7;
}
else
{
uint8_t x_8; 
x_8 = lean_nat_dec_lt(x_5, x_3);
return x_8;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_can__call___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
uint8_t x_4; lean_object* x_5; 
x_4 = l_TexasPoker_BettingRound_can__call(x_1, x_2, x_3);
lean_dec(x_3);
lean_dec(x_2);
lean_dec(x_1);
x_5 = lean_box(x_4);
return x_5;
}
}
LEAN_EXPORT uint8_t l_TexasPoker_BettingRound_can__raise(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; uint8_t x_5; 
x_4 = l_TexasPoker_BettingRound_chips__to__call(x_1, x_2);
x_5 = lean_nat_dec_lt(x_4, x_3);
lean_dec(x_4);
return x_5;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_can__raise___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
uint8_t x_4; lean_object* x_5; 
x_4 = l_TexasPoker_BettingRound_can__raise(x_1, x_2, x_3);
lean_dec(x_3);
lean_dec(x_2);
lean_dec(x_1);
x_5 = lean_box(x_4);
return x_5;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__1() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_Constants_ACTION__FOLD;
x_2 = lean_unsigned_to_nat(0u);
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__2() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__1;
x_2 = lean_unsigned_to_nat(0u);
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__3() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__2;
x_2 = lean_unsigned_to_nat(0u);
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__4() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__2;
x_2 = l_TexasPoker_Constants_ACTION__RAISE;
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__5() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__1;
x_2 = l_TexasPoker_Constants_ACTION__CALL;
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__6() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__5;
x_2 = lean_unsigned_to_nat(0u);
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__7() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__5;
x_2 = l_TexasPoker_Constants_ACTION__RAISE;
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__8() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_Constants_ACTION__FOLD;
x_2 = l_TexasPoker_Constants_ACTION__CHECK;
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__9() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__8;
x_2 = lean_unsigned_to_nat(0u);
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__10() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__9;
x_2 = lean_unsigned_to_nat(0u);
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__11() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__9;
x_2 = l_TexasPoker_Constants_ACTION__RAISE;
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__12() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__8;
x_2 = l_TexasPoker_Constants_ACTION__CALL;
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__13() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__12;
x_2 = lean_unsigned_to_nat(0u);
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_BettingRound_available__actions___closed__14() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l_TexasPoker_BettingRound_available__actions___closed__12;
x_2 = l_TexasPoker_Constants_ACTION__RAISE;
x_3 = lean_nat_lor(x_1, x_2);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_available__actions(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
uint8_t x_4; uint8_t x_5; uint8_t x_6; 
x_4 = l_TexasPoker_BettingRound_can__check(x_1, x_2);
x_5 = l_TexasPoker_BettingRound_can__call(x_1, x_2, x_3);
x_6 = l_TexasPoker_BettingRound_can__raise(x_1, x_2, x_3);
if (x_4 == 0)
{
if (x_5 == 0)
{
if (x_6 == 0)
{
lean_object* x_7; 
x_7 = l_TexasPoker_BettingRound_available__actions___closed__3;
return x_7;
}
else
{
lean_object* x_8; 
x_8 = l_TexasPoker_BettingRound_available__actions___closed__4;
return x_8;
}
}
else
{
if (x_6 == 0)
{
lean_object* x_9; 
x_9 = l_TexasPoker_BettingRound_available__actions___closed__6;
return x_9;
}
else
{
lean_object* x_10; 
x_10 = l_TexasPoker_BettingRound_available__actions___closed__7;
return x_10;
}
}
}
else
{
if (x_5 == 0)
{
if (x_6 == 0)
{
lean_object* x_11; 
x_11 = l_TexasPoker_BettingRound_available__actions___closed__10;
return x_11;
}
else
{
lean_object* x_12; 
x_12 = l_TexasPoker_BettingRound_available__actions___closed__11;
return x_12;
}
}
else
{
if (x_6 == 0)
{
lean_object* x_13; 
x_13 = l_TexasPoker_BettingRound_available__actions___closed__13;
return x_13;
}
else
{
lean_object* x_14; 
x_14 = l_TexasPoker_BettingRound_available__actions___closed__14;
return x_14;
}
}
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_available__actions___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_BettingRound_available__actions(x_1, x_2, x_3);
lean_dec(x_3);
lean_dec(x_2);
lean_dec(x_1);
return x_4;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_process__call(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; uint8_t x_5; 
x_4 = l_TexasPoker_BettingRound_chips__to__call(x_1, x_2);
x_5 = lean_nat_dec_le(x_4, x_3);
if (x_5 == 0)
{
lean_dec(x_4);
lean_inc(x_3);
return x_3;
}
else
{
return x_4;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_process__call___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_BettingRound_process__call(x_1, x_2, x_3);
lean_dec(x_3);
lean_dec(x_2);
lean_dec(x_1);
return x_4;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_process__raise(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
uint8_t x_5; 
x_5 = !lean_is_exclusive(x_1);
if (x_5 == 0)
{
lean_object* x_6; lean_object* x_7; uint8_t x_8; 
x_6 = lean_ctor_get(x_1, 0);
x_7 = lean_ctor_get(x_1, 1);
x_8 = lean_nat_dec_lt(x_6, x_2);
if (x_8 == 0)
{
lean_object* x_9; 
lean_free_object(x_1);
lean_dec(x_7);
lean_dec(x_6);
lean_dec(x_2);
x_9 = lean_box(0);
return x_9;
}
else
{
uint8_t x_10; 
x_10 = lean_nat_dec_lt(x_3, x_2);
if (x_10 == 0)
{
lean_object* x_11; 
lean_free_object(x_1);
lean_dec(x_7);
lean_dec(x_6);
lean_dec(x_2);
x_11 = lean_box(0);
return x_11;
}
else
{
lean_object* x_12; uint8_t x_13; 
x_12 = lean_nat_sub(x_2, x_3);
x_13 = lean_nat_dec_lt(x_4, x_12);
if (x_13 == 0)
{
lean_object* x_14; uint8_t x_15; 
x_14 = lean_nat_sub(x_2, x_6);
lean_dec(x_6);
x_15 = lean_nat_dec_le(x_7, x_14);
if (x_15 == 0)
{
uint8_t x_16; 
lean_dec(x_14);
x_16 = lean_nat_dec_eq(x_12, x_4);
if (x_16 == 0)
{
lean_object* x_17; 
lean_dec(x_12);
lean_free_object(x_1);
lean_dec(x_7);
lean_dec(x_2);
x_17 = lean_box(0);
return x_17;
}
else
{
lean_object* x_18; lean_object* x_19; 
lean_ctor_set(x_1, 0, x_2);
x_18 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_18, 0, x_1);
lean_ctor_set(x_18, 1, x_12);
x_19 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_19, 0, x_18);
return x_19;
}
}
else
{
lean_object* x_20; lean_object* x_21; 
lean_dec(x_7);
lean_ctor_set(x_1, 1, x_14);
lean_ctor_set(x_1, 0, x_2);
x_20 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_20, 0, x_1);
lean_ctor_set(x_20, 1, x_12);
x_21 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_21, 0, x_20);
return x_21;
}
}
else
{
lean_object* x_22; 
lean_dec(x_12);
lean_free_object(x_1);
lean_dec(x_7);
lean_dec(x_6);
lean_dec(x_2);
x_22 = lean_box(0);
return x_22;
}
}
}
}
else
{
lean_object* x_23; lean_object* x_24; uint8_t x_25; 
x_23 = lean_ctor_get(x_1, 0);
x_24 = lean_ctor_get(x_1, 1);
lean_inc(x_24);
lean_inc(x_23);
lean_dec(x_1);
x_25 = lean_nat_dec_lt(x_23, x_2);
if (x_25 == 0)
{
lean_object* x_26; 
lean_dec(x_24);
lean_dec(x_23);
lean_dec(x_2);
x_26 = lean_box(0);
return x_26;
}
else
{
uint8_t x_27; 
x_27 = lean_nat_dec_lt(x_3, x_2);
if (x_27 == 0)
{
lean_object* x_28; 
lean_dec(x_24);
lean_dec(x_23);
lean_dec(x_2);
x_28 = lean_box(0);
return x_28;
}
else
{
lean_object* x_29; uint8_t x_30; 
x_29 = lean_nat_sub(x_2, x_3);
x_30 = lean_nat_dec_lt(x_4, x_29);
if (x_30 == 0)
{
lean_object* x_31; uint8_t x_32; 
x_31 = lean_nat_sub(x_2, x_23);
lean_dec(x_23);
x_32 = lean_nat_dec_le(x_24, x_31);
if (x_32 == 0)
{
uint8_t x_33; 
lean_dec(x_31);
x_33 = lean_nat_dec_eq(x_29, x_4);
if (x_33 == 0)
{
lean_object* x_34; 
lean_dec(x_29);
lean_dec(x_24);
lean_dec(x_2);
x_34 = lean_box(0);
return x_34;
}
else
{
lean_object* x_35; lean_object* x_36; lean_object* x_37; 
x_35 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_35, 0, x_2);
lean_ctor_set(x_35, 1, x_24);
x_36 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_36, 0, x_35);
lean_ctor_set(x_36, 1, x_29);
x_37 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_37, 0, x_36);
return x_37;
}
}
else
{
lean_object* x_38; lean_object* x_39; lean_object* x_40; 
lean_dec(x_24);
x_38 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_38, 0, x_2);
lean_ctor_set(x_38, 1, x_31);
x_39 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_39, 0, x_38);
lean_ctor_set(x_39, 1, x_29);
x_40 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_40, 0, x_39);
return x_40;
}
}
else
{
lean_object* x_41; 
lean_dec(x_29);
lean_dec(x_24);
lean_dec(x_23);
lean_dec(x_2);
x_41 = lean_box(0);
return x_41;
}
}
}
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_BettingRound_process__raise___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; 
x_5 = l_TexasPoker_BettingRound_process__raise(x_1, x_2, x_3, x_4);
lean_dec(x_4);
lean_dec(x_3);
return x_5;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_Mathlib(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Constants(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Types(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_State_Betting(uint8_t builtin, lean_object* w) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Mathlib(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_State_Constants(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_State_Types(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l_TexasPoker_BettingRound_available__actions___closed__1 = _init_l_TexasPoker_BettingRound_available__actions___closed__1();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__1);
l_TexasPoker_BettingRound_available__actions___closed__2 = _init_l_TexasPoker_BettingRound_available__actions___closed__2();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__2);
l_TexasPoker_BettingRound_available__actions___closed__3 = _init_l_TexasPoker_BettingRound_available__actions___closed__3();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__3);
l_TexasPoker_BettingRound_available__actions___closed__4 = _init_l_TexasPoker_BettingRound_available__actions___closed__4();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__4);
l_TexasPoker_BettingRound_available__actions___closed__5 = _init_l_TexasPoker_BettingRound_available__actions___closed__5();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__5);
l_TexasPoker_BettingRound_available__actions___closed__6 = _init_l_TexasPoker_BettingRound_available__actions___closed__6();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__6);
l_TexasPoker_BettingRound_available__actions___closed__7 = _init_l_TexasPoker_BettingRound_available__actions___closed__7();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__7);
l_TexasPoker_BettingRound_available__actions___closed__8 = _init_l_TexasPoker_BettingRound_available__actions___closed__8();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__8);
l_TexasPoker_BettingRound_available__actions___closed__9 = _init_l_TexasPoker_BettingRound_available__actions___closed__9();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__9);
l_TexasPoker_BettingRound_available__actions___closed__10 = _init_l_TexasPoker_BettingRound_available__actions___closed__10();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__10);
l_TexasPoker_BettingRound_available__actions___closed__11 = _init_l_TexasPoker_BettingRound_available__actions___closed__11();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__11);
l_TexasPoker_BettingRound_available__actions___closed__12 = _init_l_TexasPoker_BettingRound_available__actions___closed__12();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__12);
l_TexasPoker_BettingRound_available__actions___closed__13 = _init_l_TexasPoker_BettingRound_available__actions___closed__13();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__13);
l_TexasPoker_BettingRound_available__actions___closed__14 = _init_l_TexasPoker_BettingRound_available__actions___closed__14();
lean_mark_persistent(l_TexasPoker_BettingRound_available__actions___closed__14);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
