// Lean compiler output
// Module: PokerLean.State.Transitions
// Imports: Init Mathlib PokerLean.State.Constants PokerLean.State.Types PokerLean.State.Betting
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
LEAN_EXPORT lean_object* l___private_PokerLean_State_Transitions_0__TexasPoker_update__nth_match__1_splitter___rarg(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_update__nth___rarg(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_List_mapTR_loop___at_TexasPoker_total__chips___spec__1(lean_object*, lean_object*);
static lean_object* l_TexasPoker_apply__fold___closed__1;
LEAN_EXPORT lean_object* l_TexasPoker_apply__raise__opt(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__raise(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_seat__chips___boxed(lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__fold(lean_object*, lean_object*);
lean_object* l_List_foldrTR___at_Nat_zeckendorfEquiv___elambda__1___spec__3(lean_object*, lean_object*);
lean_object* l_TexasPoker_BettingRound_process__raise(lean_object*, lean_object*, lean_object*, lean_object*);
lean_object* l_TexasPoker_BettingRound_process__call(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_seat__chips(lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__check___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__fold(lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_update__nth___rarg___boxed(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__raise___lambda__1(lean_object*, lean_object*, lean_object*);
static lean_object* l_TexasPoker_apply__check___closed__1;
LEAN_EXPORT lean_object* l_TexasPoker_total__chips(lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__call(lean_object*, lean_object*);
uint8_t lean_nat_dec_eq(lean_object*, lean_object*);
uint8_t lean_nat_dec_lt(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__fold___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__call___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__raise___boxed(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__call___lambda__1(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_update__nth(lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__check(lean_object*);
lean_object* lean_nat_sub(lean_object*, lean_object*);
lean_object* l_List_reverse___rarg(lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__raise___boxed(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__call___lambda__1___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__check(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_List_mapTR_loop___at_TexasPoker_total__chips___spec__2(lean_object*, lean_object*);
lean_object* lean_nat_add(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__raise(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__call(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l___private_PokerLean_State_Transitions_0__TexasPoker_update__nth_match__1_splitter(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__call___boxed(lean_object*, lean_object*);
lean_object* l_List_get_x3f___rarg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__raise___lambda__1___boxed(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_update__nth___rarg(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
if (lean_obj_tag(x_1) == 0)
{
lean_object* x_4; 
lean_dec(x_3);
x_4 = lean_box(0);
return x_4;
}
else
{
uint8_t x_5; 
x_5 = !lean_is_exclusive(x_1);
if (x_5 == 0)
{
lean_object* x_6; lean_object* x_7; lean_object* x_8; uint8_t x_9; 
x_6 = lean_ctor_get(x_1, 0);
x_7 = lean_ctor_get(x_1, 1);
x_8 = lean_unsigned_to_nat(0u);
x_9 = lean_nat_dec_eq(x_2, x_8);
if (x_9 == 0)
{
lean_object* x_10; lean_object* x_11; lean_object* x_12; 
x_10 = lean_unsigned_to_nat(1u);
x_11 = lean_nat_sub(x_2, x_10);
x_12 = l_TexasPoker_update__nth___rarg(x_7, x_11, x_3);
lean_dec(x_11);
lean_ctor_set(x_1, 1, x_12);
return x_1;
}
else
{
lean_object* x_13; 
x_13 = lean_apply_1(x_3, x_6);
lean_ctor_set(x_1, 0, x_13);
return x_1;
}
}
else
{
lean_object* x_14; lean_object* x_15; lean_object* x_16; uint8_t x_17; 
x_14 = lean_ctor_get(x_1, 0);
x_15 = lean_ctor_get(x_1, 1);
lean_inc(x_15);
lean_inc(x_14);
lean_dec(x_1);
x_16 = lean_unsigned_to_nat(0u);
x_17 = lean_nat_dec_eq(x_2, x_16);
if (x_17 == 0)
{
lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; 
x_18 = lean_unsigned_to_nat(1u);
x_19 = lean_nat_sub(x_2, x_18);
x_20 = l_TexasPoker_update__nth___rarg(x_15, x_19, x_3);
lean_dec(x_19);
x_21 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_21, 0, x_14);
lean_ctor_set(x_21, 1, x_20);
return x_21;
}
else
{
lean_object* x_22; lean_object* x_23; 
x_22 = lean_apply_1(x_3, x_14);
x_23 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_23, 0, x_22);
lean_ctor_set(x_23, 1, x_15);
return x_23;
}
}
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_update__nth(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = lean_alloc_closure((void*)(l_TexasPoker_update__nth___rarg___boxed), 3, 0);
return x_2;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_update__nth___rarg___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_update__nth___rarg(x_1, x_2, x_3);
lean_dec(x_2);
return x_4;
}
}
LEAN_EXPORT lean_object* l___private_PokerLean_State_Transitions_0__TexasPoker_update__nth_match__1_splitter___rarg(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4, lean_object* x_5, lean_object* x_6) {
_start:
{
if (lean_obj_tag(x_1) == 0)
{
lean_object* x_7; 
lean_dec(x_6);
lean_dec(x_5);
x_7 = lean_apply_2(x_4, x_2, x_3);
return x_7;
}
else
{
lean_object* x_8; lean_object* x_9; lean_object* x_10; uint8_t x_11; 
lean_dec(x_4);
x_8 = lean_ctor_get(x_1, 0);
lean_inc(x_8);
x_9 = lean_ctor_get(x_1, 1);
lean_inc(x_9);
lean_dec(x_1);
x_10 = lean_unsigned_to_nat(0u);
x_11 = lean_nat_dec_eq(x_2, x_10);
if (x_11 == 0)
{
lean_object* x_12; lean_object* x_13; lean_object* x_14; 
lean_dec(x_5);
x_12 = lean_unsigned_to_nat(1u);
x_13 = lean_nat_sub(x_2, x_12);
lean_dec(x_2);
x_14 = lean_apply_4(x_6, x_8, x_9, x_13, x_3);
return x_14;
}
else
{
lean_object* x_15; 
lean_dec(x_6);
lean_dec(x_2);
x_15 = lean_apply_3(x_5, x_8, x_9, x_3);
return x_15;
}
}
}
}
LEAN_EXPORT lean_object* l___private_PokerLean_State_Transitions_0__TexasPoker_update__nth_match__1_splitter(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = lean_alloc_closure((void*)(l___private_PokerLean_State_Transitions_0__TexasPoker_update__nth_match__1_splitter___rarg), 6, 0);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_seat__chips(lean_object* x_1) {
_start:
{
lean_object* x_2; lean_object* x_3; lean_object* x_4; 
x_2 = lean_ctor_get(x_1, 1);
x_3 = lean_ctor_get(x_1, 3);
x_4 = lean_nat_add(x_2, x_3);
return x_4;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_seat__chips___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_TexasPoker_seat__chips(x_1);
lean_dec(x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l_List_mapTR_loop___at_TexasPoker_total__chips___spec__1(lean_object* x_1, lean_object* x_2) {
_start:
{
if (lean_obj_tag(x_1) == 0)
{
lean_object* x_3; 
x_3 = l_List_reverse___rarg(x_2);
return x_3;
}
else
{
uint8_t x_4; 
x_4 = !lean_is_exclusive(x_1);
if (x_4 == 0)
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; 
x_5 = lean_ctor_get(x_1, 0);
x_6 = lean_ctor_get(x_1, 1);
x_7 = l_TexasPoker_seat__chips(x_5);
lean_dec(x_5);
lean_ctor_set(x_1, 1, x_2);
lean_ctor_set(x_1, 0, x_7);
{
lean_object* _tmp_0 = x_6;
lean_object* _tmp_1 = x_1;
x_1 = _tmp_0;
x_2 = _tmp_1;
}
goto _start;
}
else
{
lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; 
x_9 = lean_ctor_get(x_1, 0);
x_10 = lean_ctor_get(x_1, 1);
lean_inc(x_10);
lean_inc(x_9);
lean_dec(x_1);
x_11 = l_TexasPoker_seat__chips(x_9);
lean_dec(x_9);
x_12 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_12, 0, x_11);
lean_ctor_set(x_12, 1, x_2);
x_1 = x_10;
x_2 = x_12;
goto _start;
}
}
}
}
LEAN_EXPORT lean_object* l_List_mapTR_loop___at_TexasPoker_total__chips___spec__2(lean_object* x_1, lean_object* x_2) {
_start:
{
if (lean_obj_tag(x_1) == 0)
{
lean_object* x_3; 
x_3 = l_List_reverse___rarg(x_2);
return x_3;
}
else
{
uint8_t x_4; 
x_4 = !lean_is_exclusive(x_1);
if (x_4 == 0)
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; 
x_5 = lean_ctor_get(x_1, 0);
x_6 = lean_ctor_get(x_1, 1);
x_7 = lean_ctor_get(x_5, 6);
lean_inc(x_7);
lean_dec(x_5);
lean_ctor_set(x_1, 1, x_2);
lean_ctor_set(x_1, 0, x_7);
{
lean_object* _tmp_0 = x_6;
lean_object* _tmp_1 = x_1;
x_1 = _tmp_0;
x_2 = _tmp_1;
}
goto _start;
}
else
{
lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; 
x_9 = lean_ctor_get(x_1, 0);
x_10 = lean_ctor_get(x_1, 1);
lean_inc(x_10);
lean_inc(x_9);
lean_dec(x_1);
x_11 = lean_ctor_get(x_9, 6);
lean_inc(x_11);
lean_dec(x_9);
x_12 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_12, 0, x_11);
lean_ctor_set(x_12, 1, x_2);
x_1 = x_10;
x_2 = x_12;
goto _start;
}
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_total__chips(lean_object* x_1) {
_start:
{
lean_object* x_2; lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; 
x_2 = lean_ctor_get(x_1, 6);
lean_inc(x_2);
x_3 = lean_box(0);
lean_inc(x_2);
x_4 = l_List_mapTR_loop___at_TexasPoker_total__chips___spec__1(x_2, x_3);
x_5 = lean_unsigned_to_nat(0u);
x_6 = l_List_foldrTR___at_Nat_zeckendorfEquiv___elambda__1___spec__3(x_5, x_4);
x_7 = lean_ctor_get(x_1, 8);
lean_inc(x_7);
x_8 = lean_nat_add(x_6, x_7);
lean_dec(x_7);
lean_dec(x_6);
x_9 = lean_ctor_get(x_1, 28);
lean_inc(x_9);
lean_dec(x_1);
x_10 = lean_nat_add(x_8, x_9);
lean_dec(x_9);
lean_dec(x_8);
x_11 = l_List_mapTR_loop___at_TexasPoker_total__chips___spec__2(x_2, x_3);
x_12 = l_List_foldrTR___at_Nat_zeckendorfEquiv___elambda__1___spec__3(x_5, x_11);
x_13 = lean_nat_add(x_10, x_12);
lean_dec(x_12);
lean_dec(x_10);
return x_13;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__fold(lean_object* x_1) {
_start:
{
uint8_t x_2; 
x_2 = !lean_is_exclusive(x_1);
if (x_2 == 0)
{
uint8_t x_3; 
x_3 = 1;
lean_ctor_set_uint8(x_1, sizeof(void*)*8, x_3);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_3);
return x_1;
}
else
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; uint8_t x_9; uint8_t x_10; uint8_t x_11; lean_object* x_12; uint8_t x_13; lean_object* x_14; lean_object* x_15; uint8_t x_16; uint8_t x_17; lean_object* x_18; 
x_4 = lean_ctor_get(x_1, 0);
x_5 = lean_ctor_get(x_1, 1);
x_6 = lean_ctor_get(x_1, 2);
x_7 = lean_ctor_get(x_1, 3);
x_8 = lean_ctor_get(x_1, 4);
x_9 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 1);
x_10 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 3);
x_11 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 4);
x_12 = lean_ctor_get(x_1, 5);
x_13 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 5);
x_14 = lean_ctor_get(x_1, 6);
x_15 = lean_ctor_get(x_1, 7);
x_16 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 6);
lean_inc(x_15);
lean_inc(x_14);
lean_inc(x_12);
lean_inc(x_8);
lean_inc(x_7);
lean_inc(x_6);
lean_inc(x_5);
lean_inc(x_4);
lean_dec(x_1);
x_17 = 1;
x_18 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_18, 0, x_4);
lean_ctor_set(x_18, 1, x_5);
lean_ctor_set(x_18, 2, x_6);
lean_ctor_set(x_18, 3, x_7);
lean_ctor_set(x_18, 4, x_8);
lean_ctor_set(x_18, 5, x_12);
lean_ctor_set(x_18, 6, x_14);
lean_ctor_set(x_18, 7, x_15);
lean_ctor_set_uint8(x_18, sizeof(void*)*8, x_17);
lean_ctor_set_uint8(x_18, sizeof(void*)*8 + 1, x_9);
lean_ctor_set_uint8(x_18, sizeof(void*)*8 + 2, x_17);
lean_ctor_set_uint8(x_18, sizeof(void*)*8 + 3, x_10);
lean_ctor_set_uint8(x_18, sizeof(void*)*8 + 4, x_11);
lean_ctor_set_uint8(x_18, sizeof(void*)*8 + 5, x_13);
lean_ctor_set_uint8(x_18, sizeof(void*)*8 + 6, x_16);
return x_18;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__check(lean_object* x_1) {
_start:
{
uint8_t x_2; 
x_2 = !lean_is_exclusive(x_1);
if (x_2 == 0)
{
uint8_t x_3; 
x_3 = 1;
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_3);
return x_1;
}
else
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; uint8_t x_9; uint8_t x_10; uint8_t x_11; uint8_t x_12; lean_object* x_13; uint8_t x_14; lean_object* x_15; lean_object* x_16; uint8_t x_17; uint8_t x_18; lean_object* x_19; 
x_4 = lean_ctor_get(x_1, 0);
x_5 = lean_ctor_get(x_1, 1);
x_6 = lean_ctor_get(x_1, 2);
x_7 = lean_ctor_get(x_1, 3);
x_8 = lean_ctor_get(x_1, 4);
x_9 = lean_ctor_get_uint8(x_1, sizeof(void*)*8);
x_10 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 1);
x_11 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 3);
x_12 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 4);
x_13 = lean_ctor_get(x_1, 5);
x_14 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 5);
x_15 = lean_ctor_get(x_1, 6);
x_16 = lean_ctor_get(x_1, 7);
x_17 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 6);
lean_inc(x_16);
lean_inc(x_15);
lean_inc(x_13);
lean_inc(x_8);
lean_inc(x_7);
lean_inc(x_6);
lean_inc(x_5);
lean_inc(x_4);
lean_dec(x_1);
x_18 = 1;
x_19 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_19, 0, x_4);
lean_ctor_set(x_19, 1, x_5);
lean_ctor_set(x_19, 2, x_6);
lean_ctor_set(x_19, 3, x_7);
lean_ctor_set(x_19, 4, x_8);
lean_ctor_set(x_19, 5, x_13);
lean_ctor_set(x_19, 6, x_15);
lean_ctor_set(x_19, 7, x_16);
lean_ctor_set_uint8(x_19, sizeof(void*)*8, x_9);
lean_ctor_set_uint8(x_19, sizeof(void*)*8 + 1, x_10);
lean_ctor_set_uint8(x_19, sizeof(void*)*8 + 2, x_18);
lean_ctor_set_uint8(x_19, sizeof(void*)*8 + 3, x_11);
lean_ctor_set_uint8(x_19, sizeof(void*)*8 + 4, x_12);
lean_ctor_set_uint8(x_19, sizeof(void*)*8 + 5, x_14);
lean_ctor_set_uint8(x_19, sizeof(void*)*8 + 6, x_17);
return x_19;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__call(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; 
x_3 = !lean_is_exclusive(x_1);
if (x_3 == 0)
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; uint8_t x_12; 
x_4 = lean_ctor_get(x_1, 1);
x_5 = lean_ctor_get(x_1, 3);
x_6 = lean_ctor_get(x_1, 4);
x_7 = l_TexasPoker_BettingRound_process__call(x_2, x_5, x_4);
x_8 = lean_nat_sub(x_4, x_7);
lean_dec(x_4);
x_9 = lean_nat_add(x_5, x_7);
lean_dec(x_5);
x_10 = lean_nat_add(x_6, x_7);
lean_dec(x_6);
x_11 = lean_unsigned_to_nat(0u);
x_12 = lean_nat_dec_eq(x_8, x_11);
if (x_12 == 0)
{
uint8_t x_13; uint8_t x_14; 
lean_dec(x_7);
x_13 = 0;
x_14 = 1;
lean_ctor_set(x_1, 4, x_10);
lean_ctor_set(x_1, 3, x_9);
lean_ctor_set(x_1, 1, x_8);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 1, x_13);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_14);
return x_1;
}
else
{
uint8_t x_15; uint8_t x_16; 
x_15 = lean_nat_dec_lt(x_11, x_7);
lean_dec(x_7);
x_16 = 1;
lean_ctor_set(x_1, 4, x_10);
lean_ctor_set(x_1, 3, x_9);
lean_ctor_set(x_1, 1, x_8);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 1, x_15);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_16);
return x_1;
}
}
else
{
lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; uint8_t x_22; uint8_t x_23; uint8_t x_24; lean_object* x_25; uint8_t x_26; lean_object* x_27; lean_object* x_28; uint8_t x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; uint8_t x_35; 
x_17 = lean_ctor_get(x_1, 0);
x_18 = lean_ctor_get(x_1, 1);
x_19 = lean_ctor_get(x_1, 2);
x_20 = lean_ctor_get(x_1, 3);
x_21 = lean_ctor_get(x_1, 4);
x_22 = lean_ctor_get_uint8(x_1, sizeof(void*)*8);
x_23 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 3);
x_24 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 4);
x_25 = lean_ctor_get(x_1, 5);
x_26 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 5);
x_27 = lean_ctor_get(x_1, 6);
x_28 = lean_ctor_get(x_1, 7);
x_29 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 6);
lean_inc(x_28);
lean_inc(x_27);
lean_inc(x_25);
lean_inc(x_21);
lean_inc(x_20);
lean_inc(x_19);
lean_inc(x_18);
lean_inc(x_17);
lean_dec(x_1);
x_30 = l_TexasPoker_BettingRound_process__call(x_2, x_20, x_18);
x_31 = lean_nat_sub(x_18, x_30);
lean_dec(x_18);
x_32 = lean_nat_add(x_20, x_30);
lean_dec(x_20);
x_33 = lean_nat_add(x_21, x_30);
lean_dec(x_21);
x_34 = lean_unsigned_to_nat(0u);
x_35 = lean_nat_dec_eq(x_31, x_34);
if (x_35 == 0)
{
uint8_t x_36; uint8_t x_37; lean_object* x_38; 
lean_dec(x_30);
x_36 = 0;
x_37 = 1;
x_38 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_38, 0, x_17);
lean_ctor_set(x_38, 1, x_31);
lean_ctor_set(x_38, 2, x_19);
lean_ctor_set(x_38, 3, x_32);
lean_ctor_set(x_38, 4, x_33);
lean_ctor_set(x_38, 5, x_25);
lean_ctor_set(x_38, 6, x_27);
lean_ctor_set(x_38, 7, x_28);
lean_ctor_set_uint8(x_38, sizeof(void*)*8, x_22);
lean_ctor_set_uint8(x_38, sizeof(void*)*8 + 1, x_36);
lean_ctor_set_uint8(x_38, sizeof(void*)*8 + 2, x_37);
lean_ctor_set_uint8(x_38, sizeof(void*)*8 + 3, x_23);
lean_ctor_set_uint8(x_38, sizeof(void*)*8 + 4, x_24);
lean_ctor_set_uint8(x_38, sizeof(void*)*8 + 5, x_26);
lean_ctor_set_uint8(x_38, sizeof(void*)*8 + 6, x_29);
return x_38;
}
else
{
uint8_t x_39; uint8_t x_40; lean_object* x_41; 
x_39 = lean_nat_dec_lt(x_34, x_30);
lean_dec(x_30);
x_40 = 1;
x_41 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_41, 0, x_17);
lean_ctor_set(x_41, 1, x_31);
lean_ctor_set(x_41, 2, x_19);
lean_ctor_set(x_41, 3, x_32);
lean_ctor_set(x_41, 4, x_33);
lean_ctor_set(x_41, 5, x_25);
lean_ctor_set(x_41, 6, x_27);
lean_ctor_set(x_41, 7, x_28);
lean_ctor_set_uint8(x_41, sizeof(void*)*8, x_22);
lean_ctor_set_uint8(x_41, sizeof(void*)*8 + 1, x_39);
lean_ctor_set_uint8(x_41, sizeof(void*)*8 + 2, x_40);
lean_ctor_set_uint8(x_41, sizeof(void*)*8 + 3, x_23);
lean_ctor_set_uint8(x_41, sizeof(void*)*8 + 4, x_24);
lean_ctor_set_uint8(x_41, sizeof(void*)*8 + 5, x_26);
lean_ctor_set_uint8(x_41, sizeof(void*)*8 + 6, x_29);
return x_41;
}
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__call___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_Seat_apply__call(x_1, x_2);
lean_dec(x_2);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__raise(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
uint8_t x_4; 
x_4 = !lean_is_exclusive(x_1);
if (x_4 == 0)
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; uint8_t x_11; uint8_t x_12; 
x_5 = lean_ctor_get(x_1, 1);
x_6 = lean_ctor_get(x_1, 4);
x_7 = lean_ctor_get(x_1, 3);
lean_dec(x_7);
x_8 = lean_nat_sub(x_5, x_3);
lean_dec(x_5);
x_9 = lean_nat_add(x_6, x_3);
lean_dec(x_6);
x_10 = lean_unsigned_to_nat(0u);
x_11 = lean_nat_dec_eq(x_8, x_10);
x_12 = 1;
lean_ctor_set(x_1, 4, x_9);
lean_ctor_set(x_1, 3, x_2);
lean_ctor_set(x_1, 1, x_8);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 1, x_11);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_12);
return x_1;
}
else
{
lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; uint8_t x_17; uint8_t x_18; uint8_t x_19; lean_object* x_20; uint8_t x_21; lean_object* x_22; lean_object* x_23; uint8_t x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; uint8_t x_28; uint8_t x_29; lean_object* x_30; 
x_13 = lean_ctor_get(x_1, 0);
x_14 = lean_ctor_get(x_1, 1);
x_15 = lean_ctor_get(x_1, 2);
x_16 = lean_ctor_get(x_1, 4);
x_17 = lean_ctor_get_uint8(x_1, sizeof(void*)*8);
x_18 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 3);
x_19 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 4);
x_20 = lean_ctor_get(x_1, 5);
x_21 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 5);
x_22 = lean_ctor_get(x_1, 6);
x_23 = lean_ctor_get(x_1, 7);
x_24 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 6);
lean_inc(x_23);
lean_inc(x_22);
lean_inc(x_20);
lean_inc(x_16);
lean_inc(x_15);
lean_inc(x_14);
lean_inc(x_13);
lean_dec(x_1);
x_25 = lean_nat_sub(x_14, x_3);
lean_dec(x_14);
x_26 = lean_nat_add(x_16, x_3);
lean_dec(x_16);
x_27 = lean_unsigned_to_nat(0u);
x_28 = lean_nat_dec_eq(x_25, x_27);
x_29 = 1;
x_30 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_30, 0, x_13);
lean_ctor_set(x_30, 1, x_25);
lean_ctor_set(x_30, 2, x_15);
lean_ctor_set(x_30, 3, x_2);
lean_ctor_set(x_30, 4, x_26);
lean_ctor_set(x_30, 5, x_20);
lean_ctor_set(x_30, 6, x_22);
lean_ctor_set(x_30, 7, x_23);
lean_ctor_set_uint8(x_30, sizeof(void*)*8, x_17);
lean_ctor_set_uint8(x_30, sizeof(void*)*8 + 1, x_28);
lean_ctor_set_uint8(x_30, sizeof(void*)*8 + 2, x_29);
lean_ctor_set_uint8(x_30, sizeof(void*)*8 + 3, x_18);
lean_ctor_set_uint8(x_30, sizeof(void*)*8 + 4, x_19);
lean_ctor_set_uint8(x_30, sizeof(void*)*8 + 5, x_21);
lean_ctor_set_uint8(x_30, sizeof(void*)*8 + 6, x_24);
return x_30;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_Seat_apply__raise___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_Seat_apply__raise(x_1, x_2, x_3);
lean_dec(x_3);
return x_4;
}
}
static lean_object* _init_l_TexasPoker_apply__fold___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_alloc_closure((void*)(l_TexasPoker_Seat_apply__fold), 1, 0);
return x_1;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__fold(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; 
x_3 = !lean_is_exclusive(x_1);
if (x_3 == 0)
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; 
x_4 = lean_ctor_get(x_1, 6);
x_5 = lean_ctor_get(x_1, 31);
x_6 = l_TexasPoker_apply__fold___closed__1;
x_7 = l_TexasPoker_update__nth___rarg(x_4, x_2, x_6);
x_8 = lean_unsigned_to_nat(1u);
x_9 = lean_nat_add(x_5, x_8);
lean_dec(x_5);
lean_ctor_set(x_1, 31, x_9);
lean_ctor_set(x_1, 6, x_7);
return x_1;
}
else
{
lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; 
x_10 = lean_ctor_get(x_1, 0);
x_11 = lean_ctor_get(x_1, 1);
x_12 = lean_ctor_get(x_1, 2);
x_13 = lean_ctor_get(x_1, 3);
x_14 = lean_ctor_get(x_1, 4);
x_15 = lean_ctor_get(x_1, 5);
x_16 = lean_ctor_get(x_1, 6);
x_17 = lean_ctor_get(x_1, 7);
x_18 = lean_ctor_get(x_1, 8);
x_19 = lean_ctor_get(x_1, 9);
x_20 = lean_ctor_get(x_1, 10);
x_21 = lean_ctor_get(x_1, 11);
x_22 = lean_ctor_get(x_1, 12);
x_23 = lean_ctor_get(x_1, 13);
x_24 = lean_ctor_get(x_1, 14);
x_25 = lean_ctor_get(x_1, 15);
x_26 = lean_ctor_get(x_1, 16);
x_27 = lean_ctor_get(x_1, 17);
x_28 = lean_ctor_get(x_1, 18);
x_29 = lean_ctor_get(x_1, 19);
x_30 = lean_ctor_get(x_1, 20);
x_31 = lean_ctor_get(x_1, 21);
x_32 = lean_ctor_get(x_1, 22);
x_33 = lean_ctor_get(x_1, 23);
x_34 = lean_ctor_get(x_1, 24);
x_35 = lean_ctor_get(x_1, 25);
x_36 = lean_ctor_get(x_1, 26);
x_37 = lean_ctor_get(x_1, 27);
x_38 = lean_ctor_get(x_1, 28);
x_39 = lean_ctor_get(x_1, 29);
x_40 = lean_ctor_get(x_1, 30);
x_41 = lean_ctor_get(x_1, 31);
lean_inc(x_41);
lean_inc(x_40);
lean_inc(x_39);
lean_inc(x_38);
lean_inc(x_37);
lean_inc(x_36);
lean_inc(x_35);
lean_inc(x_34);
lean_inc(x_33);
lean_inc(x_32);
lean_inc(x_31);
lean_inc(x_30);
lean_inc(x_29);
lean_inc(x_28);
lean_inc(x_27);
lean_inc(x_26);
lean_inc(x_25);
lean_inc(x_24);
lean_inc(x_23);
lean_inc(x_22);
lean_inc(x_21);
lean_inc(x_20);
lean_inc(x_19);
lean_inc(x_18);
lean_inc(x_17);
lean_inc(x_16);
lean_inc(x_15);
lean_inc(x_14);
lean_inc(x_13);
lean_inc(x_12);
lean_inc(x_11);
lean_inc(x_10);
lean_dec(x_1);
x_42 = l_TexasPoker_apply__fold___closed__1;
x_43 = l_TexasPoker_update__nth___rarg(x_16, x_2, x_42);
x_44 = lean_unsigned_to_nat(1u);
x_45 = lean_nat_add(x_41, x_44);
lean_dec(x_41);
x_46 = lean_alloc_ctor(0, 32, 0);
lean_ctor_set(x_46, 0, x_10);
lean_ctor_set(x_46, 1, x_11);
lean_ctor_set(x_46, 2, x_12);
lean_ctor_set(x_46, 3, x_13);
lean_ctor_set(x_46, 4, x_14);
lean_ctor_set(x_46, 5, x_15);
lean_ctor_set(x_46, 6, x_43);
lean_ctor_set(x_46, 7, x_17);
lean_ctor_set(x_46, 8, x_18);
lean_ctor_set(x_46, 9, x_19);
lean_ctor_set(x_46, 10, x_20);
lean_ctor_set(x_46, 11, x_21);
lean_ctor_set(x_46, 12, x_22);
lean_ctor_set(x_46, 13, x_23);
lean_ctor_set(x_46, 14, x_24);
lean_ctor_set(x_46, 15, x_25);
lean_ctor_set(x_46, 16, x_26);
lean_ctor_set(x_46, 17, x_27);
lean_ctor_set(x_46, 18, x_28);
lean_ctor_set(x_46, 19, x_29);
lean_ctor_set(x_46, 20, x_30);
lean_ctor_set(x_46, 21, x_31);
lean_ctor_set(x_46, 22, x_32);
lean_ctor_set(x_46, 23, x_33);
lean_ctor_set(x_46, 24, x_34);
lean_ctor_set(x_46, 25, x_35);
lean_ctor_set(x_46, 26, x_36);
lean_ctor_set(x_46, 27, x_37);
lean_ctor_set(x_46, 28, x_38);
lean_ctor_set(x_46, 29, x_39);
lean_ctor_set(x_46, 30, x_40);
lean_ctor_set(x_46, 31, x_45);
return x_46;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__fold___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_apply__fold(x_1, x_2);
lean_dec(x_2);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_apply__check___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_alloc_closure((void*)(l_TexasPoker_Seat_apply__check), 1, 0);
return x_1;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__check(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; 
x_3 = !lean_is_exclusive(x_1);
if (x_3 == 0)
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; 
x_4 = lean_ctor_get(x_1, 6);
x_5 = lean_ctor_get(x_1, 31);
x_6 = l_TexasPoker_apply__check___closed__1;
x_7 = l_TexasPoker_update__nth___rarg(x_4, x_2, x_6);
x_8 = lean_unsigned_to_nat(1u);
x_9 = lean_nat_add(x_5, x_8);
lean_dec(x_5);
lean_ctor_set(x_1, 31, x_9);
lean_ctor_set(x_1, 6, x_7);
return x_1;
}
else
{
lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; 
x_10 = lean_ctor_get(x_1, 0);
x_11 = lean_ctor_get(x_1, 1);
x_12 = lean_ctor_get(x_1, 2);
x_13 = lean_ctor_get(x_1, 3);
x_14 = lean_ctor_get(x_1, 4);
x_15 = lean_ctor_get(x_1, 5);
x_16 = lean_ctor_get(x_1, 6);
x_17 = lean_ctor_get(x_1, 7);
x_18 = lean_ctor_get(x_1, 8);
x_19 = lean_ctor_get(x_1, 9);
x_20 = lean_ctor_get(x_1, 10);
x_21 = lean_ctor_get(x_1, 11);
x_22 = lean_ctor_get(x_1, 12);
x_23 = lean_ctor_get(x_1, 13);
x_24 = lean_ctor_get(x_1, 14);
x_25 = lean_ctor_get(x_1, 15);
x_26 = lean_ctor_get(x_1, 16);
x_27 = lean_ctor_get(x_1, 17);
x_28 = lean_ctor_get(x_1, 18);
x_29 = lean_ctor_get(x_1, 19);
x_30 = lean_ctor_get(x_1, 20);
x_31 = lean_ctor_get(x_1, 21);
x_32 = lean_ctor_get(x_1, 22);
x_33 = lean_ctor_get(x_1, 23);
x_34 = lean_ctor_get(x_1, 24);
x_35 = lean_ctor_get(x_1, 25);
x_36 = lean_ctor_get(x_1, 26);
x_37 = lean_ctor_get(x_1, 27);
x_38 = lean_ctor_get(x_1, 28);
x_39 = lean_ctor_get(x_1, 29);
x_40 = lean_ctor_get(x_1, 30);
x_41 = lean_ctor_get(x_1, 31);
lean_inc(x_41);
lean_inc(x_40);
lean_inc(x_39);
lean_inc(x_38);
lean_inc(x_37);
lean_inc(x_36);
lean_inc(x_35);
lean_inc(x_34);
lean_inc(x_33);
lean_inc(x_32);
lean_inc(x_31);
lean_inc(x_30);
lean_inc(x_29);
lean_inc(x_28);
lean_inc(x_27);
lean_inc(x_26);
lean_inc(x_25);
lean_inc(x_24);
lean_inc(x_23);
lean_inc(x_22);
lean_inc(x_21);
lean_inc(x_20);
lean_inc(x_19);
lean_inc(x_18);
lean_inc(x_17);
lean_inc(x_16);
lean_inc(x_15);
lean_inc(x_14);
lean_inc(x_13);
lean_inc(x_12);
lean_inc(x_11);
lean_inc(x_10);
lean_dec(x_1);
x_42 = l_TexasPoker_apply__check___closed__1;
x_43 = l_TexasPoker_update__nth___rarg(x_16, x_2, x_42);
x_44 = lean_unsigned_to_nat(1u);
x_45 = lean_nat_add(x_41, x_44);
lean_dec(x_41);
x_46 = lean_alloc_ctor(0, 32, 0);
lean_ctor_set(x_46, 0, x_10);
lean_ctor_set(x_46, 1, x_11);
lean_ctor_set(x_46, 2, x_12);
lean_ctor_set(x_46, 3, x_13);
lean_ctor_set(x_46, 4, x_14);
lean_ctor_set(x_46, 5, x_15);
lean_ctor_set(x_46, 6, x_43);
lean_ctor_set(x_46, 7, x_17);
lean_ctor_set(x_46, 8, x_18);
lean_ctor_set(x_46, 9, x_19);
lean_ctor_set(x_46, 10, x_20);
lean_ctor_set(x_46, 11, x_21);
lean_ctor_set(x_46, 12, x_22);
lean_ctor_set(x_46, 13, x_23);
lean_ctor_set(x_46, 14, x_24);
lean_ctor_set(x_46, 15, x_25);
lean_ctor_set(x_46, 16, x_26);
lean_ctor_set(x_46, 17, x_27);
lean_ctor_set(x_46, 18, x_28);
lean_ctor_set(x_46, 19, x_29);
lean_ctor_set(x_46, 20, x_30);
lean_ctor_set(x_46, 21, x_31);
lean_ctor_set(x_46, 22, x_32);
lean_ctor_set(x_46, 23, x_33);
lean_ctor_set(x_46, 24, x_34);
lean_ctor_set(x_46, 25, x_35);
lean_ctor_set(x_46, 26, x_36);
lean_ctor_set(x_46, 27, x_37);
lean_ctor_set(x_46, 28, x_38);
lean_ctor_set(x_46, 29, x_39);
lean_ctor_set(x_46, 30, x_40);
lean_ctor_set(x_46, 31, x_45);
return x_46;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__check___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_apply__check(x_1, x_2);
lean_dec(x_2);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__call___lambda__1(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_Seat_apply__call(x_2, x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__call(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = lean_ctor_get(x_1, 12);
lean_inc(x_3);
if (lean_obj_tag(x_3) == 0)
{
return x_1;
}
else
{
uint8_t x_4; 
x_4 = !lean_is_exclusive(x_1);
if (x_4 == 0)
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; 
x_5 = lean_ctor_get(x_1, 6);
x_6 = lean_ctor_get(x_1, 31);
x_7 = lean_ctor_get(x_1, 12);
lean_dec(x_7);
x_8 = lean_ctor_get(x_3, 0);
lean_inc(x_8);
x_9 = lean_alloc_closure((void*)(l_TexasPoker_apply__call___lambda__1___boxed), 2, 1);
lean_closure_set(x_9, 0, x_8);
x_10 = l_TexasPoker_update__nth___rarg(x_5, x_2, x_9);
x_11 = lean_unsigned_to_nat(1u);
x_12 = lean_nat_add(x_6, x_11);
lean_dec(x_6);
lean_ctor_set(x_1, 31, x_12);
lean_ctor_set(x_1, 6, x_10);
return x_1;
}
else
{
lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; lean_object* x_49; 
x_13 = lean_ctor_get(x_1, 0);
x_14 = lean_ctor_get(x_1, 1);
x_15 = lean_ctor_get(x_1, 2);
x_16 = lean_ctor_get(x_1, 3);
x_17 = lean_ctor_get(x_1, 4);
x_18 = lean_ctor_get(x_1, 5);
x_19 = lean_ctor_get(x_1, 6);
x_20 = lean_ctor_get(x_1, 7);
x_21 = lean_ctor_get(x_1, 8);
x_22 = lean_ctor_get(x_1, 9);
x_23 = lean_ctor_get(x_1, 10);
x_24 = lean_ctor_get(x_1, 11);
x_25 = lean_ctor_get(x_1, 13);
x_26 = lean_ctor_get(x_1, 14);
x_27 = lean_ctor_get(x_1, 15);
x_28 = lean_ctor_get(x_1, 16);
x_29 = lean_ctor_get(x_1, 17);
x_30 = lean_ctor_get(x_1, 18);
x_31 = lean_ctor_get(x_1, 19);
x_32 = lean_ctor_get(x_1, 20);
x_33 = lean_ctor_get(x_1, 21);
x_34 = lean_ctor_get(x_1, 22);
x_35 = lean_ctor_get(x_1, 23);
x_36 = lean_ctor_get(x_1, 24);
x_37 = lean_ctor_get(x_1, 25);
x_38 = lean_ctor_get(x_1, 26);
x_39 = lean_ctor_get(x_1, 27);
x_40 = lean_ctor_get(x_1, 28);
x_41 = lean_ctor_get(x_1, 29);
x_42 = lean_ctor_get(x_1, 30);
x_43 = lean_ctor_get(x_1, 31);
lean_inc(x_43);
lean_inc(x_42);
lean_inc(x_41);
lean_inc(x_40);
lean_inc(x_39);
lean_inc(x_38);
lean_inc(x_37);
lean_inc(x_36);
lean_inc(x_35);
lean_inc(x_34);
lean_inc(x_33);
lean_inc(x_32);
lean_inc(x_31);
lean_inc(x_30);
lean_inc(x_29);
lean_inc(x_28);
lean_inc(x_27);
lean_inc(x_26);
lean_inc(x_25);
lean_inc(x_24);
lean_inc(x_23);
lean_inc(x_22);
lean_inc(x_21);
lean_inc(x_20);
lean_inc(x_19);
lean_inc(x_18);
lean_inc(x_17);
lean_inc(x_16);
lean_inc(x_15);
lean_inc(x_14);
lean_inc(x_13);
lean_dec(x_1);
x_44 = lean_ctor_get(x_3, 0);
lean_inc(x_44);
x_45 = lean_alloc_closure((void*)(l_TexasPoker_apply__call___lambda__1___boxed), 2, 1);
lean_closure_set(x_45, 0, x_44);
x_46 = l_TexasPoker_update__nth___rarg(x_19, x_2, x_45);
x_47 = lean_unsigned_to_nat(1u);
x_48 = lean_nat_add(x_43, x_47);
lean_dec(x_43);
x_49 = lean_alloc_ctor(0, 32, 0);
lean_ctor_set(x_49, 0, x_13);
lean_ctor_set(x_49, 1, x_14);
lean_ctor_set(x_49, 2, x_15);
lean_ctor_set(x_49, 3, x_16);
lean_ctor_set(x_49, 4, x_17);
lean_ctor_set(x_49, 5, x_18);
lean_ctor_set(x_49, 6, x_46);
lean_ctor_set(x_49, 7, x_20);
lean_ctor_set(x_49, 8, x_21);
lean_ctor_set(x_49, 9, x_22);
lean_ctor_set(x_49, 10, x_23);
lean_ctor_set(x_49, 11, x_24);
lean_ctor_set(x_49, 12, x_3);
lean_ctor_set(x_49, 13, x_25);
lean_ctor_set(x_49, 14, x_26);
lean_ctor_set(x_49, 15, x_27);
lean_ctor_set(x_49, 16, x_28);
lean_ctor_set(x_49, 17, x_29);
lean_ctor_set(x_49, 18, x_30);
lean_ctor_set(x_49, 19, x_31);
lean_ctor_set(x_49, 20, x_32);
lean_ctor_set(x_49, 21, x_33);
lean_ctor_set(x_49, 22, x_34);
lean_ctor_set(x_49, 23, x_35);
lean_ctor_set(x_49, 24, x_36);
lean_ctor_set(x_49, 25, x_37);
lean_ctor_set(x_49, 26, x_38);
lean_ctor_set(x_49, 27, x_39);
lean_ctor_set(x_49, 28, x_40);
lean_ctor_set(x_49, 29, x_41);
lean_ctor_set(x_49, 30, x_42);
lean_ctor_set(x_49, 31, x_48);
return x_49;
}
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__call___lambda__1___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_apply__call___lambda__1(x_1, x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__call___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_apply__call(x_1, x_2);
lean_dec(x_2);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__raise___lambda__1(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_Seat_apply__raise(x_3, x_1, x_2);
return x_4;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__raise(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4, lean_object* x_5) {
_start:
{
uint8_t x_6; 
x_6 = !lean_is_exclusive(x_1);
if (x_6 == 0)
{
lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; 
x_7 = lean_ctor_get(x_1, 6);
x_8 = lean_ctor_get(x_1, 31);
x_9 = lean_ctor_get(x_1, 12);
lean_dec(x_9);
x_10 = lean_alloc_closure((void*)(l_TexasPoker_apply__raise___lambda__1___boxed), 3, 2);
lean_closure_set(x_10, 0, x_3);
lean_closure_set(x_10, 1, x_5);
x_11 = l_TexasPoker_update__nth___rarg(x_7, x_2, x_10);
x_12 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_12, 0, x_4);
x_13 = lean_unsigned_to_nat(1u);
x_14 = lean_nat_add(x_8, x_13);
lean_dec(x_8);
lean_ctor_set(x_1, 31, x_14);
lean_ctor_set(x_1, 12, x_12);
lean_ctor_set(x_1, 6, x_11);
return x_1;
}
else
{
lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; lean_object* x_49; lean_object* x_50; lean_object* x_51; 
x_15 = lean_ctor_get(x_1, 0);
x_16 = lean_ctor_get(x_1, 1);
x_17 = lean_ctor_get(x_1, 2);
x_18 = lean_ctor_get(x_1, 3);
x_19 = lean_ctor_get(x_1, 4);
x_20 = lean_ctor_get(x_1, 5);
x_21 = lean_ctor_get(x_1, 6);
x_22 = lean_ctor_get(x_1, 7);
x_23 = lean_ctor_get(x_1, 8);
x_24 = lean_ctor_get(x_1, 9);
x_25 = lean_ctor_get(x_1, 10);
x_26 = lean_ctor_get(x_1, 11);
x_27 = lean_ctor_get(x_1, 13);
x_28 = lean_ctor_get(x_1, 14);
x_29 = lean_ctor_get(x_1, 15);
x_30 = lean_ctor_get(x_1, 16);
x_31 = lean_ctor_get(x_1, 17);
x_32 = lean_ctor_get(x_1, 18);
x_33 = lean_ctor_get(x_1, 19);
x_34 = lean_ctor_get(x_1, 20);
x_35 = lean_ctor_get(x_1, 21);
x_36 = lean_ctor_get(x_1, 22);
x_37 = lean_ctor_get(x_1, 23);
x_38 = lean_ctor_get(x_1, 24);
x_39 = lean_ctor_get(x_1, 25);
x_40 = lean_ctor_get(x_1, 26);
x_41 = lean_ctor_get(x_1, 27);
x_42 = lean_ctor_get(x_1, 28);
x_43 = lean_ctor_get(x_1, 29);
x_44 = lean_ctor_get(x_1, 30);
x_45 = lean_ctor_get(x_1, 31);
lean_inc(x_45);
lean_inc(x_44);
lean_inc(x_43);
lean_inc(x_42);
lean_inc(x_41);
lean_inc(x_40);
lean_inc(x_39);
lean_inc(x_38);
lean_inc(x_37);
lean_inc(x_36);
lean_inc(x_35);
lean_inc(x_34);
lean_inc(x_33);
lean_inc(x_32);
lean_inc(x_31);
lean_inc(x_30);
lean_inc(x_29);
lean_inc(x_28);
lean_inc(x_27);
lean_inc(x_26);
lean_inc(x_25);
lean_inc(x_24);
lean_inc(x_23);
lean_inc(x_22);
lean_inc(x_21);
lean_inc(x_20);
lean_inc(x_19);
lean_inc(x_18);
lean_inc(x_17);
lean_inc(x_16);
lean_inc(x_15);
lean_dec(x_1);
x_46 = lean_alloc_closure((void*)(l_TexasPoker_apply__raise___lambda__1___boxed), 3, 2);
lean_closure_set(x_46, 0, x_3);
lean_closure_set(x_46, 1, x_5);
x_47 = l_TexasPoker_update__nth___rarg(x_21, x_2, x_46);
x_48 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_48, 0, x_4);
x_49 = lean_unsigned_to_nat(1u);
x_50 = lean_nat_add(x_45, x_49);
lean_dec(x_45);
x_51 = lean_alloc_ctor(0, 32, 0);
lean_ctor_set(x_51, 0, x_15);
lean_ctor_set(x_51, 1, x_16);
lean_ctor_set(x_51, 2, x_17);
lean_ctor_set(x_51, 3, x_18);
lean_ctor_set(x_51, 4, x_19);
lean_ctor_set(x_51, 5, x_20);
lean_ctor_set(x_51, 6, x_47);
lean_ctor_set(x_51, 7, x_22);
lean_ctor_set(x_51, 8, x_23);
lean_ctor_set(x_51, 9, x_24);
lean_ctor_set(x_51, 10, x_25);
lean_ctor_set(x_51, 11, x_26);
lean_ctor_set(x_51, 12, x_48);
lean_ctor_set(x_51, 13, x_27);
lean_ctor_set(x_51, 14, x_28);
lean_ctor_set(x_51, 15, x_29);
lean_ctor_set(x_51, 16, x_30);
lean_ctor_set(x_51, 17, x_31);
lean_ctor_set(x_51, 18, x_32);
lean_ctor_set(x_51, 19, x_33);
lean_ctor_set(x_51, 20, x_34);
lean_ctor_set(x_51, 21, x_35);
lean_ctor_set(x_51, 22, x_36);
lean_ctor_set(x_51, 23, x_37);
lean_ctor_set(x_51, 24, x_38);
lean_ctor_set(x_51, 25, x_39);
lean_ctor_set(x_51, 26, x_40);
lean_ctor_set(x_51, 27, x_41);
lean_ctor_set(x_51, 28, x_42);
lean_ctor_set(x_51, 29, x_43);
lean_ctor_set(x_51, 30, x_44);
lean_ctor_set(x_51, 31, x_50);
return x_51;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__raise___lambda__1___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_apply__raise___lambda__1(x_1, x_2, x_3);
lean_dec(x_2);
return x_4;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__raise___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4, lean_object* x_5) {
_start:
{
lean_object* x_6; 
x_6 = l_TexasPoker_apply__raise(x_1, x_2, x_3, x_4, x_5);
lean_dec(x_2);
return x_6;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__raise__opt(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = lean_ctor_get(x_1, 12);
lean_inc(x_4);
if (lean_obj_tag(x_4) == 0)
{
lean_object* x_5; 
lean_dec(x_3);
lean_dec(x_2);
lean_dec(x_1);
x_5 = lean_box(0);
return x_5;
}
else
{
lean_object* x_6; lean_object* x_7; lean_object* x_8; 
x_6 = lean_ctor_get(x_4, 0);
lean_inc(x_6);
lean_dec(x_4);
x_7 = lean_ctor_get(x_1, 6);
lean_inc(x_7);
lean_inc(x_2);
x_8 = l_List_get_x3f___rarg(x_7, x_2);
lean_dec(x_7);
if (lean_obj_tag(x_8) == 0)
{
lean_object* x_9; 
lean_dec(x_6);
lean_dec(x_3);
lean_dec(x_2);
lean_dec(x_1);
x_9 = lean_box(0);
return x_9;
}
else
{
lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; 
x_10 = lean_ctor_get(x_8, 0);
lean_inc(x_10);
lean_dec(x_8);
x_11 = lean_ctor_get(x_10, 3);
lean_inc(x_11);
x_12 = lean_ctor_get(x_10, 1);
lean_inc(x_12);
lean_dec(x_10);
lean_inc(x_3);
x_13 = l_TexasPoker_BettingRound_process__raise(x_6, x_3, x_11, x_12);
lean_dec(x_12);
lean_dec(x_11);
if (lean_obj_tag(x_13) == 0)
{
lean_object* x_14; 
lean_dec(x_3);
lean_dec(x_2);
lean_dec(x_1);
x_14 = lean_box(0);
return x_14;
}
else
{
uint8_t x_15; 
x_15 = !lean_is_exclusive(x_13);
if (x_15 == 0)
{
lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; 
x_16 = lean_ctor_get(x_13, 0);
x_17 = lean_ctor_get(x_16, 0);
lean_inc(x_17);
x_18 = lean_ctor_get(x_16, 1);
lean_inc(x_18);
lean_dec(x_16);
x_19 = l_TexasPoker_apply__raise(x_1, x_2, x_3, x_17, x_18);
lean_dec(x_2);
lean_ctor_set(x_13, 0, x_19);
return x_13;
}
else
{
lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; 
x_20 = lean_ctor_get(x_13, 0);
lean_inc(x_20);
lean_dec(x_13);
x_21 = lean_ctor_get(x_20, 0);
lean_inc(x_21);
x_22 = lean_ctor_get(x_20, 1);
lean_inc(x_22);
lean_dec(x_20);
x_23 = l_TexasPoker_apply__raise(x_1, x_2, x_3, x_21, x_22);
lean_dec(x_2);
x_24 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_24, 0, x_23);
return x_24;
}
}
}
}
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_Mathlib(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Constants(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Types(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Betting(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_State_Transitions(uint8_t builtin, lean_object* w) {
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
res = initialize_PokerLean_State_Betting(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l_TexasPoker_apply__fold___closed__1 = _init_l_TexasPoker_apply__fold___closed__1();
lean_mark_persistent(l_TexasPoker_apply__fold___closed__1);
l_TexasPoker_apply__check___closed__1 = _init_l_TexasPoker_apply__check___closed__1();
lean_mark_persistent(l_TexasPoker_apply__check___closed__1);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
