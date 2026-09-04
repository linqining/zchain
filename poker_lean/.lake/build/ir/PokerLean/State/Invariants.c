// Lean compiler output
// Module: PokerLean.State.Invariants
// Imports: Init Mathlib PokerLean.State.Constants PokerLean.State.Types PokerLean.State.Betting PokerLean.State.Transitions
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
LEAN_EXPORT lean_object* l_TexasPoker_apply__addon(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__rebuy___lambda__1(lean_object*, lean_object*);
lean_object* l_TexasPoker_update__nth___rarg(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__rebuy___boxed(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_collect__ante__step___lambda__1___boxed(lean_object*, lean_object*);
lean_object* l_TexasPoker_TexasPokerTable_get__seat(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_collect__ante__step___lambda__1(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_refund__predicate___boxed(lean_object*);
LEAN_EXPORT lean_object* l_List_mapTR_loop___at_TexasPoker_refund__all__bets___spec__1(lean_object*, lean_object*);
static lean_object* l_TexasPoker_U64__MAX___closed__1;
LEAN_EXPORT lean_object* l_TexasPoker_collect__ante__step(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__addon___lambda__1___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__addon___lambda__1(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_collect__rake(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__rebuy___lambda__1___boxed(lean_object*, lean_object*);
uint8_t lean_nat_dec_eq(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__addon___boxed(lean_object*, lean_object*, lean_object*);
uint8_t lean_nat_dec_lt(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_U64__MAX;
LEAN_EXPORT uint8_t l_TexasPoker_refund__predicate(lean_object*);
lean_object* lean_nat_sub(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_refund__seat(lean_object*);
lean_object* l_List_reverse___rarg(lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_collect__rake___boxed(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__rebuy(lean_object*, lean_object*, lean_object*);
uint8_t lean_nat_dec_le(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_refund__all__bets(lean_object*);
lean_object* lean_nat_add(lean_object*, lean_object*);
uint8_t l_TexasPoker_Seat_is__occupied(lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_apply__addon___lambda__1(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; 
x_3 = !lean_is_exclusive(x_2);
if (x_3 == 0)
{
lean_object* x_4; lean_object* x_5; 
x_4 = lean_ctor_get(x_2, 6);
x_5 = lean_nat_add(x_4, x_1);
lean_dec(x_4);
lean_ctor_set(x_2, 6, x_5);
return x_2;
}
else
{
lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; uint8_t x_11; uint8_t x_12; uint8_t x_13; uint8_t x_14; uint8_t x_15; lean_object* x_16; uint8_t x_17; lean_object* x_18; lean_object* x_19; uint8_t x_20; lean_object* x_21; lean_object* x_22; 
x_6 = lean_ctor_get(x_2, 0);
x_7 = lean_ctor_get(x_2, 1);
x_8 = lean_ctor_get(x_2, 2);
x_9 = lean_ctor_get(x_2, 3);
x_10 = lean_ctor_get(x_2, 4);
x_11 = lean_ctor_get_uint8(x_2, sizeof(void*)*8);
x_12 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 1);
x_13 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 2);
x_14 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 3);
x_15 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 4);
x_16 = lean_ctor_get(x_2, 5);
x_17 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 5);
x_18 = lean_ctor_get(x_2, 6);
x_19 = lean_ctor_get(x_2, 7);
x_20 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 6);
lean_inc(x_19);
lean_inc(x_18);
lean_inc(x_16);
lean_inc(x_10);
lean_inc(x_9);
lean_inc(x_8);
lean_inc(x_7);
lean_inc(x_6);
lean_dec(x_2);
x_21 = lean_nat_add(x_18, x_1);
lean_dec(x_18);
x_22 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_22, 0, x_6);
lean_ctor_set(x_22, 1, x_7);
lean_ctor_set(x_22, 2, x_8);
lean_ctor_set(x_22, 3, x_9);
lean_ctor_set(x_22, 4, x_10);
lean_ctor_set(x_22, 5, x_16);
lean_ctor_set(x_22, 6, x_21);
lean_ctor_set(x_22, 7, x_19);
lean_ctor_set_uint8(x_22, sizeof(void*)*8, x_11);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 1, x_12);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 2, x_13);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 3, x_14);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 4, x_15);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 5, x_17);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 6, x_20);
return x_22;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__addon(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
uint8_t x_4; 
x_4 = !lean_is_exclusive(x_1);
if (x_4 == 0)
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; 
x_5 = lean_ctor_get(x_1, 6);
x_6 = lean_ctor_get(x_1, 20);
x_7 = lean_ctor_get(x_1, 21);
x_8 = lean_ctor_get(x_1, 31);
lean_inc(x_3);
x_9 = lean_alloc_closure((void*)(l_TexasPoker_apply__addon___lambda__1___boxed), 2, 1);
lean_closure_set(x_9, 0, x_3);
x_10 = l_TexasPoker_update__nth___rarg(x_5, x_2, x_9);
x_11 = lean_nat_add(x_6, x_3);
lean_dec(x_6);
x_12 = lean_nat_add(x_7, x_3);
lean_dec(x_3);
lean_dec(x_7);
x_13 = lean_unsigned_to_nat(1u);
x_14 = lean_nat_add(x_8, x_13);
lean_dec(x_8);
lean_ctor_set(x_1, 31, x_14);
lean_ctor_set(x_1, 21, x_12);
lean_ctor_set(x_1, 20, x_11);
lean_ctor_set(x_1, 6, x_10);
return x_1;
}
else
{
lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; lean_object* x_49; lean_object* x_50; lean_object* x_51; lean_object* x_52; lean_object* x_53; 
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
x_27 = lean_ctor_get(x_1, 12);
x_28 = lean_ctor_get(x_1, 13);
x_29 = lean_ctor_get(x_1, 14);
x_30 = lean_ctor_get(x_1, 15);
x_31 = lean_ctor_get(x_1, 16);
x_32 = lean_ctor_get(x_1, 17);
x_33 = lean_ctor_get(x_1, 18);
x_34 = lean_ctor_get(x_1, 19);
x_35 = lean_ctor_get(x_1, 20);
x_36 = lean_ctor_get(x_1, 21);
x_37 = lean_ctor_get(x_1, 22);
x_38 = lean_ctor_get(x_1, 23);
x_39 = lean_ctor_get(x_1, 24);
x_40 = lean_ctor_get(x_1, 25);
x_41 = lean_ctor_get(x_1, 26);
x_42 = lean_ctor_get(x_1, 27);
x_43 = lean_ctor_get(x_1, 28);
x_44 = lean_ctor_get(x_1, 29);
x_45 = lean_ctor_get(x_1, 30);
x_46 = lean_ctor_get(x_1, 31);
lean_inc(x_46);
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
lean_inc(x_3);
x_47 = lean_alloc_closure((void*)(l_TexasPoker_apply__addon___lambda__1___boxed), 2, 1);
lean_closure_set(x_47, 0, x_3);
x_48 = l_TexasPoker_update__nth___rarg(x_21, x_2, x_47);
x_49 = lean_nat_add(x_35, x_3);
lean_dec(x_35);
x_50 = lean_nat_add(x_36, x_3);
lean_dec(x_3);
lean_dec(x_36);
x_51 = lean_unsigned_to_nat(1u);
x_52 = lean_nat_add(x_46, x_51);
lean_dec(x_46);
x_53 = lean_alloc_ctor(0, 32, 0);
lean_ctor_set(x_53, 0, x_15);
lean_ctor_set(x_53, 1, x_16);
lean_ctor_set(x_53, 2, x_17);
lean_ctor_set(x_53, 3, x_18);
lean_ctor_set(x_53, 4, x_19);
lean_ctor_set(x_53, 5, x_20);
lean_ctor_set(x_53, 6, x_48);
lean_ctor_set(x_53, 7, x_22);
lean_ctor_set(x_53, 8, x_23);
lean_ctor_set(x_53, 9, x_24);
lean_ctor_set(x_53, 10, x_25);
lean_ctor_set(x_53, 11, x_26);
lean_ctor_set(x_53, 12, x_27);
lean_ctor_set(x_53, 13, x_28);
lean_ctor_set(x_53, 14, x_29);
lean_ctor_set(x_53, 15, x_30);
lean_ctor_set(x_53, 16, x_31);
lean_ctor_set(x_53, 17, x_32);
lean_ctor_set(x_53, 18, x_33);
lean_ctor_set(x_53, 19, x_34);
lean_ctor_set(x_53, 20, x_49);
lean_ctor_set(x_53, 21, x_50);
lean_ctor_set(x_53, 22, x_37);
lean_ctor_set(x_53, 23, x_38);
lean_ctor_set(x_53, 24, x_39);
lean_ctor_set(x_53, 25, x_40);
lean_ctor_set(x_53, 26, x_41);
lean_ctor_set(x_53, 27, x_42);
lean_ctor_set(x_53, 28, x_43);
lean_ctor_set(x_53, 29, x_44);
lean_ctor_set(x_53, 30, x_45);
lean_ctor_set(x_53, 31, x_52);
return x_53;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__addon___lambda__1___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_apply__addon___lambda__1(x_1, x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__addon___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_apply__addon(x_1, x_2, x_3);
lean_dec(x_2);
return x_4;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__rebuy___lambda__1(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; 
x_3 = !lean_is_exclusive(x_2);
if (x_3 == 0)
{
lean_object* x_4; lean_object* x_5; 
x_4 = lean_ctor_get(x_2, 1);
x_5 = lean_nat_add(x_4, x_1);
lean_dec(x_4);
lean_ctor_set(x_2, 1, x_5);
return x_2;
}
else
{
lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; uint8_t x_11; uint8_t x_12; uint8_t x_13; uint8_t x_14; uint8_t x_15; lean_object* x_16; uint8_t x_17; lean_object* x_18; lean_object* x_19; uint8_t x_20; lean_object* x_21; lean_object* x_22; 
x_6 = lean_ctor_get(x_2, 0);
x_7 = lean_ctor_get(x_2, 1);
x_8 = lean_ctor_get(x_2, 2);
x_9 = lean_ctor_get(x_2, 3);
x_10 = lean_ctor_get(x_2, 4);
x_11 = lean_ctor_get_uint8(x_2, sizeof(void*)*8);
x_12 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 1);
x_13 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 2);
x_14 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 3);
x_15 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 4);
x_16 = lean_ctor_get(x_2, 5);
x_17 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 5);
x_18 = lean_ctor_get(x_2, 6);
x_19 = lean_ctor_get(x_2, 7);
x_20 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 6);
lean_inc(x_19);
lean_inc(x_18);
lean_inc(x_16);
lean_inc(x_10);
lean_inc(x_9);
lean_inc(x_8);
lean_inc(x_7);
lean_inc(x_6);
lean_dec(x_2);
x_21 = lean_nat_add(x_7, x_1);
lean_dec(x_7);
x_22 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_22, 0, x_6);
lean_ctor_set(x_22, 1, x_21);
lean_ctor_set(x_22, 2, x_8);
lean_ctor_set(x_22, 3, x_9);
lean_ctor_set(x_22, 4, x_10);
lean_ctor_set(x_22, 5, x_16);
lean_ctor_set(x_22, 6, x_18);
lean_ctor_set(x_22, 7, x_19);
lean_ctor_set_uint8(x_22, sizeof(void*)*8, x_11);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 1, x_12);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 2, x_13);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 3, x_14);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 4, x_15);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 5, x_17);
lean_ctor_set_uint8(x_22, sizeof(void*)*8 + 6, x_20);
return x_22;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__rebuy(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
uint8_t x_4; 
x_4 = !lean_is_exclusive(x_1);
if (x_4 == 0)
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; 
x_5 = lean_ctor_get(x_1, 6);
x_6 = lean_ctor_get(x_1, 20);
x_7 = lean_ctor_get(x_1, 31);
lean_inc(x_3);
x_8 = lean_alloc_closure((void*)(l_TexasPoker_apply__rebuy___lambda__1___boxed), 2, 1);
lean_closure_set(x_8, 0, x_3);
x_9 = l_TexasPoker_update__nth___rarg(x_5, x_2, x_8);
x_10 = lean_nat_add(x_6, x_3);
lean_dec(x_3);
lean_dec(x_6);
x_11 = lean_unsigned_to_nat(1u);
x_12 = lean_nat_add(x_7, x_11);
lean_dec(x_7);
lean_ctor_set(x_1, 31, x_12);
lean_ctor_set(x_1, 20, x_10);
lean_ctor_set(x_1, 6, x_9);
return x_1;
}
else
{
lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; lean_object* x_49; lean_object* x_50; 
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
x_25 = lean_ctor_get(x_1, 12);
x_26 = lean_ctor_get(x_1, 13);
x_27 = lean_ctor_get(x_1, 14);
x_28 = lean_ctor_get(x_1, 15);
x_29 = lean_ctor_get(x_1, 16);
x_30 = lean_ctor_get(x_1, 17);
x_31 = lean_ctor_get(x_1, 18);
x_32 = lean_ctor_get(x_1, 19);
x_33 = lean_ctor_get(x_1, 20);
x_34 = lean_ctor_get(x_1, 21);
x_35 = lean_ctor_get(x_1, 22);
x_36 = lean_ctor_get(x_1, 23);
x_37 = lean_ctor_get(x_1, 24);
x_38 = lean_ctor_get(x_1, 25);
x_39 = lean_ctor_get(x_1, 26);
x_40 = lean_ctor_get(x_1, 27);
x_41 = lean_ctor_get(x_1, 28);
x_42 = lean_ctor_get(x_1, 29);
x_43 = lean_ctor_get(x_1, 30);
x_44 = lean_ctor_get(x_1, 31);
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
lean_inc(x_14);
lean_inc(x_13);
lean_dec(x_1);
lean_inc(x_3);
x_45 = lean_alloc_closure((void*)(l_TexasPoker_apply__rebuy___lambda__1___boxed), 2, 1);
lean_closure_set(x_45, 0, x_3);
x_46 = l_TexasPoker_update__nth___rarg(x_19, x_2, x_45);
x_47 = lean_nat_add(x_33, x_3);
lean_dec(x_3);
lean_dec(x_33);
x_48 = lean_unsigned_to_nat(1u);
x_49 = lean_nat_add(x_44, x_48);
lean_dec(x_44);
x_50 = lean_alloc_ctor(0, 32, 0);
lean_ctor_set(x_50, 0, x_13);
lean_ctor_set(x_50, 1, x_14);
lean_ctor_set(x_50, 2, x_15);
lean_ctor_set(x_50, 3, x_16);
lean_ctor_set(x_50, 4, x_17);
lean_ctor_set(x_50, 5, x_18);
lean_ctor_set(x_50, 6, x_46);
lean_ctor_set(x_50, 7, x_20);
lean_ctor_set(x_50, 8, x_21);
lean_ctor_set(x_50, 9, x_22);
lean_ctor_set(x_50, 10, x_23);
lean_ctor_set(x_50, 11, x_24);
lean_ctor_set(x_50, 12, x_25);
lean_ctor_set(x_50, 13, x_26);
lean_ctor_set(x_50, 14, x_27);
lean_ctor_set(x_50, 15, x_28);
lean_ctor_set(x_50, 16, x_29);
lean_ctor_set(x_50, 17, x_30);
lean_ctor_set(x_50, 18, x_31);
lean_ctor_set(x_50, 19, x_32);
lean_ctor_set(x_50, 20, x_47);
lean_ctor_set(x_50, 21, x_34);
lean_ctor_set(x_50, 22, x_35);
lean_ctor_set(x_50, 23, x_36);
lean_ctor_set(x_50, 24, x_37);
lean_ctor_set(x_50, 25, x_38);
lean_ctor_set(x_50, 26, x_39);
lean_ctor_set(x_50, 27, x_40);
lean_ctor_set(x_50, 28, x_41);
lean_ctor_set(x_50, 29, x_42);
lean_ctor_set(x_50, 30, x_43);
lean_ctor_set(x_50, 31, x_49);
return x_50;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__rebuy___lambda__1___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_apply__rebuy___lambda__1(x_1, x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_apply__rebuy___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_apply__rebuy(x_1, x_2, x_3);
lean_dec(x_2);
return x_4;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_collect__rake(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
uint8_t x_4; 
x_4 = !lean_is_exclusive(x_1);
if (x_4 == 0)
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; 
x_5 = lean_ctor_get(x_1, 8);
x_6 = lean_ctor_get(x_1, 28);
x_7 = lean_ctor_get(x_1, 31);
x_8 = lean_nat_sub(x_5, x_2);
lean_dec(x_5);
x_9 = lean_nat_add(x_6, x_2);
lean_dec(x_6);
x_10 = lean_unsigned_to_nat(1u);
x_11 = lean_nat_add(x_7, x_10);
lean_dec(x_7);
lean_ctor_set(x_1, 31, x_11);
lean_ctor_set(x_1, 28, x_9);
lean_ctor_set(x_1, 8, x_8);
return x_1;
}
else
{
lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; 
x_12 = lean_ctor_get(x_1, 0);
x_13 = lean_ctor_get(x_1, 1);
x_14 = lean_ctor_get(x_1, 2);
x_15 = lean_ctor_get(x_1, 3);
x_16 = lean_ctor_get(x_1, 4);
x_17 = lean_ctor_get(x_1, 5);
x_18 = lean_ctor_get(x_1, 6);
x_19 = lean_ctor_get(x_1, 7);
x_20 = lean_ctor_get(x_1, 8);
x_21 = lean_ctor_get(x_1, 9);
x_22 = lean_ctor_get(x_1, 10);
x_23 = lean_ctor_get(x_1, 11);
x_24 = lean_ctor_get(x_1, 12);
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
lean_inc(x_12);
lean_dec(x_1);
x_44 = lean_nat_sub(x_20, x_2);
lean_dec(x_20);
x_45 = lean_nat_add(x_40, x_2);
lean_dec(x_40);
x_46 = lean_unsigned_to_nat(1u);
x_47 = lean_nat_add(x_43, x_46);
lean_dec(x_43);
x_48 = lean_alloc_ctor(0, 32, 0);
lean_ctor_set(x_48, 0, x_12);
lean_ctor_set(x_48, 1, x_13);
lean_ctor_set(x_48, 2, x_14);
lean_ctor_set(x_48, 3, x_15);
lean_ctor_set(x_48, 4, x_16);
lean_ctor_set(x_48, 5, x_17);
lean_ctor_set(x_48, 6, x_18);
lean_ctor_set(x_48, 7, x_19);
lean_ctor_set(x_48, 8, x_44);
lean_ctor_set(x_48, 9, x_21);
lean_ctor_set(x_48, 10, x_22);
lean_ctor_set(x_48, 11, x_23);
lean_ctor_set(x_48, 12, x_24);
lean_ctor_set(x_48, 13, x_25);
lean_ctor_set(x_48, 14, x_26);
lean_ctor_set(x_48, 15, x_27);
lean_ctor_set(x_48, 16, x_28);
lean_ctor_set(x_48, 17, x_29);
lean_ctor_set(x_48, 18, x_30);
lean_ctor_set(x_48, 19, x_31);
lean_ctor_set(x_48, 20, x_32);
lean_ctor_set(x_48, 21, x_33);
lean_ctor_set(x_48, 22, x_34);
lean_ctor_set(x_48, 23, x_35);
lean_ctor_set(x_48, 24, x_36);
lean_ctor_set(x_48, 25, x_37);
lean_ctor_set(x_48, 26, x_38);
lean_ctor_set(x_48, 27, x_39);
lean_ctor_set(x_48, 28, x_45);
lean_ctor_set(x_48, 29, x_41);
lean_ctor_set(x_48, 30, x_42);
lean_ctor_set(x_48, 31, x_47);
return x_48;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_collect__rake___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_collect__rake(x_1, x_2, x_3);
lean_dec(x_2);
return x_4;
}
}
LEAN_EXPORT uint8_t l_TexasPoker_refund__predicate(lean_object* x_1) {
_start:
{
uint8_t x_2; 
x_2 = l_TexasPoker_Seat_is__occupied(x_1);
if (x_2 == 0)
{
uint8_t x_3; 
x_3 = 0;
return x_3;
}
else
{
uint8_t x_4; 
x_4 = lean_ctor_get_uint8(x_1, sizeof(void*)*8);
if (x_4 == 0)
{
uint8_t x_5; 
x_5 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 4);
if (x_5 == 0)
{
lean_object* x_6; lean_object* x_7; uint8_t x_8; 
x_6 = lean_ctor_get(x_1, 4);
x_7 = lean_unsigned_to_nat(0u);
x_8 = lean_nat_dec_lt(x_7, x_6);
if (x_8 == 0)
{
uint8_t x_9; 
x_9 = 0;
return x_9;
}
else
{
uint8_t x_10; 
x_10 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 5);
if (x_10 == 0)
{
uint8_t x_11; 
x_11 = 1;
return x_11;
}
else
{
uint8_t x_12; 
x_12 = 0;
return x_12;
}
}
}
else
{
uint8_t x_13; 
x_13 = 0;
return x_13;
}
}
else
{
uint8_t x_14; 
x_14 = 0;
return x_14;
}
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_refund__predicate___boxed(lean_object* x_1) {
_start:
{
uint8_t x_2; lean_object* x_3; 
x_2 = l_TexasPoker_refund__predicate(x_1);
lean_dec(x_1);
x_3 = lean_box(x_2);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_refund__seat(lean_object* x_1) {
_start:
{
uint8_t x_2; 
x_2 = l_TexasPoker_refund__predicate(x_1);
if (x_2 == 0)
{
uint8_t x_3; 
x_3 = !lean_is_exclusive(x_1);
if (x_3 == 0)
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; 
x_4 = lean_ctor_get(x_1, 4);
lean_dec(x_4);
x_5 = lean_ctor_get(x_1, 3);
lean_dec(x_5);
x_6 = lean_unsigned_to_nat(0u);
lean_ctor_set(x_1, 4, x_6);
lean_ctor_set(x_1, 3, x_6);
return x_1;
}
else
{
lean_object* x_7; lean_object* x_8; lean_object* x_9; uint8_t x_10; uint8_t x_11; uint8_t x_12; uint8_t x_13; uint8_t x_14; lean_object* x_15; uint8_t x_16; lean_object* x_17; lean_object* x_18; uint8_t x_19; lean_object* x_20; lean_object* x_21; 
x_7 = lean_ctor_get(x_1, 0);
x_8 = lean_ctor_get(x_1, 1);
x_9 = lean_ctor_get(x_1, 2);
x_10 = lean_ctor_get_uint8(x_1, sizeof(void*)*8);
x_11 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 1);
x_12 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 2);
x_13 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 3);
x_14 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 4);
x_15 = lean_ctor_get(x_1, 5);
x_16 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 5);
x_17 = lean_ctor_get(x_1, 6);
x_18 = lean_ctor_get(x_1, 7);
x_19 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 6);
lean_inc(x_18);
lean_inc(x_17);
lean_inc(x_15);
lean_inc(x_9);
lean_inc(x_8);
lean_inc(x_7);
lean_dec(x_1);
x_20 = lean_unsigned_to_nat(0u);
x_21 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_21, 0, x_7);
lean_ctor_set(x_21, 1, x_8);
lean_ctor_set(x_21, 2, x_9);
lean_ctor_set(x_21, 3, x_20);
lean_ctor_set(x_21, 4, x_20);
lean_ctor_set(x_21, 5, x_15);
lean_ctor_set(x_21, 6, x_17);
lean_ctor_set(x_21, 7, x_18);
lean_ctor_set_uint8(x_21, sizeof(void*)*8, x_10);
lean_ctor_set_uint8(x_21, sizeof(void*)*8 + 1, x_11);
lean_ctor_set_uint8(x_21, sizeof(void*)*8 + 2, x_12);
lean_ctor_set_uint8(x_21, sizeof(void*)*8 + 3, x_13);
lean_ctor_set_uint8(x_21, sizeof(void*)*8 + 4, x_14);
lean_ctor_set_uint8(x_21, sizeof(void*)*8 + 5, x_16);
lean_ctor_set_uint8(x_21, sizeof(void*)*8 + 6, x_19);
return x_21;
}
}
else
{
uint8_t x_22; 
x_22 = !lean_is_exclusive(x_1);
if (x_22 == 0)
{
lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; uint8_t x_28; 
x_23 = lean_ctor_get(x_1, 1);
x_24 = lean_ctor_get(x_1, 4);
x_25 = lean_ctor_get(x_1, 3);
lean_dec(x_25);
x_26 = lean_nat_add(x_23, x_24);
lean_dec(x_24);
lean_dec(x_23);
x_27 = lean_unsigned_to_nat(0u);
x_28 = 1;
lean_ctor_set(x_1, 4, x_27);
lean_ctor_set(x_1, 3, x_27);
lean_ctor_set(x_1, 1, x_26);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 5, x_28);
return x_1;
}
else
{
lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; uint8_t x_33; uint8_t x_34; uint8_t x_35; uint8_t x_36; uint8_t x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; uint8_t x_41; lean_object* x_42; lean_object* x_43; uint8_t x_44; lean_object* x_45; 
x_29 = lean_ctor_get(x_1, 0);
x_30 = lean_ctor_get(x_1, 1);
x_31 = lean_ctor_get(x_1, 2);
x_32 = lean_ctor_get(x_1, 4);
x_33 = lean_ctor_get_uint8(x_1, sizeof(void*)*8);
x_34 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 1);
x_35 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 2);
x_36 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 3);
x_37 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 4);
x_38 = lean_ctor_get(x_1, 5);
x_39 = lean_ctor_get(x_1, 6);
x_40 = lean_ctor_get(x_1, 7);
x_41 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 6);
lean_inc(x_40);
lean_inc(x_39);
lean_inc(x_38);
lean_inc(x_32);
lean_inc(x_31);
lean_inc(x_30);
lean_inc(x_29);
lean_dec(x_1);
x_42 = lean_nat_add(x_30, x_32);
lean_dec(x_32);
lean_dec(x_30);
x_43 = lean_unsigned_to_nat(0u);
x_44 = 1;
x_45 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_45, 0, x_29);
lean_ctor_set(x_45, 1, x_42);
lean_ctor_set(x_45, 2, x_31);
lean_ctor_set(x_45, 3, x_43);
lean_ctor_set(x_45, 4, x_43);
lean_ctor_set(x_45, 5, x_38);
lean_ctor_set(x_45, 6, x_39);
lean_ctor_set(x_45, 7, x_40);
lean_ctor_set_uint8(x_45, sizeof(void*)*8, x_33);
lean_ctor_set_uint8(x_45, sizeof(void*)*8 + 1, x_34);
lean_ctor_set_uint8(x_45, sizeof(void*)*8 + 2, x_35);
lean_ctor_set_uint8(x_45, sizeof(void*)*8 + 3, x_36);
lean_ctor_set_uint8(x_45, sizeof(void*)*8 + 4, x_37);
lean_ctor_set_uint8(x_45, sizeof(void*)*8 + 5, x_44);
lean_ctor_set_uint8(x_45, sizeof(void*)*8 + 6, x_41);
return x_45;
}
}
}
}
LEAN_EXPORT lean_object* l_List_mapTR_loop___at_TexasPoker_refund__all__bets___spec__1(lean_object* x_1, lean_object* x_2) {
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
x_7 = l_TexasPoker_refund__seat(x_5);
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
x_11 = l_TexasPoker_refund__seat(x_9);
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
LEAN_EXPORT lean_object* l_TexasPoker_refund__all__bets(lean_object* x_1) {
_start:
{
uint8_t x_2; 
x_2 = !lean_is_exclusive(x_1);
if (x_2 == 0)
{
lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; 
x_3 = lean_ctor_get(x_1, 6);
x_4 = lean_ctor_get(x_1, 31);
x_5 = lean_ctor_get(x_1, 8);
lean_dec(x_5);
x_6 = lean_box(0);
x_7 = l_List_mapTR_loop___at_TexasPoker_refund__all__bets___spec__1(x_3, x_6);
x_8 = lean_unsigned_to_nat(1u);
x_9 = lean_nat_add(x_4, x_8);
lean_dec(x_4);
x_10 = lean_unsigned_to_nat(0u);
lean_ctor_set(x_1, 31, x_9);
lean_ctor_set(x_1, 8, x_10);
lean_ctor_set(x_1, 6, x_7);
return x_1;
}
else
{
lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; 
x_11 = lean_ctor_get(x_1, 0);
x_12 = lean_ctor_get(x_1, 1);
x_13 = lean_ctor_get(x_1, 2);
x_14 = lean_ctor_get(x_1, 3);
x_15 = lean_ctor_get(x_1, 4);
x_16 = lean_ctor_get(x_1, 5);
x_17 = lean_ctor_get(x_1, 6);
x_18 = lean_ctor_get(x_1, 7);
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
lean_dec(x_1);
x_42 = lean_box(0);
x_43 = l_List_mapTR_loop___at_TexasPoker_refund__all__bets___spec__1(x_17, x_42);
x_44 = lean_unsigned_to_nat(1u);
x_45 = lean_nat_add(x_41, x_44);
lean_dec(x_41);
x_46 = lean_unsigned_to_nat(0u);
x_47 = lean_alloc_ctor(0, 32, 0);
lean_ctor_set(x_47, 0, x_11);
lean_ctor_set(x_47, 1, x_12);
lean_ctor_set(x_47, 2, x_13);
lean_ctor_set(x_47, 3, x_14);
lean_ctor_set(x_47, 4, x_15);
lean_ctor_set(x_47, 5, x_16);
lean_ctor_set(x_47, 6, x_43);
lean_ctor_set(x_47, 7, x_18);
lean_ctor_set(x_47, 8, x_46);
lean_ctor_set(x_47, 9, x_19);
lean_ctor_set(x_47, 10, x_20);
lean_ctor_set(x_47, 11, x_21);
lean_ctor_set(x_47, 12, x_22);
lean_ctor_set(x_47, 13, x_23);
lean_ctor_set(x_47, 14, x_24);
lean_ctor_set(x_47, 15, x_25);
lean_ctor_set(x_47, 16, x_26);
lean_ctor_set(x_47, 17, x_27);
lean_ctor_set(x_47, 18, x_28);
lean_ctor_set(x_47, 19, x_29);
lean_ctor_set(x_47, 20, x_30);
lean_ctor_set(x_47, 21, x_31);
lean_ctor_set(x_47, 22, x_32);
lean_ctor_set(x_47, 23, x_33);
lean_ctor_set(x_47, 24, x_34);
lean_ctor_set(x_47, 25, x_35);
lean_ctor_set(x_47, 26, x_36);
lean_ctor_set(x_47, 27, x_37);
lean_ctor_set(x_47, 28, x_38);
lean_ctor_set(x_47, 29, x_39);
lean_ctor_set(x_47, 30, x_40);
lean_ctor_set(x_47, 31, x_45);
return x_47;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_collect__ante__step___lambda__1(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; 
x_3 = !lean_is_exclusive(x_2);
if (x_3 == 0)
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; uint8_t x_11; 
x_4 = lean_ctor_get(x_2, 1);
x_5 = lean_ctor_get(x_2, 3);
x_6 = lean_ctor_get(x_2, 4);
x_7 = lean_nat_sub(x_4, x_1);
lean_dec(x_4);
x_8 = lean_nat_add(x_5, x_1);
lean_dec(x_5);
x_9 = lean_nat_add(x_6, x_1);
lean_dec(x_6);
x_10 = lean_unsigned_to_nat(0u);
x_11 = lean_nat_dec_eq(x_7, x_10);
if (x_11 == 0)
{
lean_ctor_set(x_2, 4, x_9);
lean_ctor_set(x_2, 3, x_8);
lean_ctor_set(x_2, 1, x_7);
return x_2;
}
else
{
uint8_t x_12; 
x_12 = 1;
lean_ctor_set(x_2, 4, x_9);
lean_ctor_set(x_2, 3, x_8);
lean_ctor_set(x_2, 1, x_7);
lean_ctor_set_uint8(x_2, sizeof(void*)*8 + 1, x_12);
return x_2;
}
}
else
{
lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; uint8_t x_18; uint8_t x_19; uint8_t x_20; uint8_t x_21; uint8_t x_22; lean_object* x_23; uint8_t x_24; lean_object* x_25; lean_object* x_26; uint8_t x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; uint8_t x_32; 
x_13 = lean_ctor_get(x_2, 0);
x_14 = lean_ctor_get(x_2, 1);
x_15 = lean_ctor_get(x_2, 2);
x_16 = lean_ctor_get(x_2, 3);
x_17 = lean_ctor_get(x_2, 4);
x_18 = lean_ctor_get_uint8(x_2, sizeof(void*)*8);
x_19 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 1);
x_20 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 2);
x_21 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 3);
x_22 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 4);
x_23 = lean_ctor_get(x_2, 5);
x_24 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 5);
x_25 = lean_ctor_get(x_2, 6);
x_26 = lean_ctor_get(x_2, 7);
x_27 = lean_ctor_get_uint8(x_2, sizeof(void*)*8 + 6);
lean_inc(x_26);
lean_inc(x_25);
lean_inc(x_23);
lean_inc(x_17);
lean_inc(x_16);
lean_inc(x_15);
lean_inc(x_14);
lean_inc(x_13);
lean_dec(x_2);
x_28 = lean_nat_sub(x_14, x_1);
lean_dec(x_14);
x_29 = lean_nat_add(x_16, x_1);
lean_dec(x_16);
x_30 = lean_nat_add(x_17, x_1);
lean_dec(x_17);
x_31 = lean_unsigned_to_nat(0u);
x_32 = lean_nat_dec_eq(x_28, x_31);
if (x_32 == 0)
{
lean_object* x_33; 
x_33 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_33, 0, x_13);
lean_ctor_set(x_33, 1, x_28);
lean_ctor_set(x_33, 2, x_15);
lean_ctor_set(x_33, 3, x_29);
lean_ctor_set(x_33, 4, x_30);
lean_ctor_set(x_33, 5, x_23);
lean_ctor_set(x_33, 6, x_25);
lean_ctor_set(x_33, 7, x_26);
lean_ctor_set_uint8(x_33, sizeof(void*)*8, x_18);
lean_ctor_set_uint8(x_33, sizeof(void*)*8 + 1, x_19);
lean_ctor_set_uint8(x_33, sizeof(void*)*8 + 2, x_20);
lean_ctor_set_uint8(x_33, sizeof(void*)*8 + 3, x_21);
lean_ctor_set_uint8(x_33, sizeof(void*)*8 + 4, x_22);
lean_ctor_set_uint8(x_33, sizeof(void*)*8 + 5, x_24);
lean_ctor_set_uint8(x_33, sizeof(void*)*8 + 6, x_27);
return x_33;
}
else
{
uint8_t x_34; lean_object* x_35; 
x_34 = 1;
x_35 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_35, 0, x_13);
lean_ctor_set(x_35, 1, x_28);
lean_ctor_set(x_35, 2, x_15);
lean_ctor_set(x_35, 3, x_29);
lean_ctor_set(x_35, 4, x_30);
lean_ctor_set(x_35, 5, x_23);
lean_ctor_set(x_35, 6, x_25);
lean_ctor_set(x_35, 7, x_26);
lean_ctor_set_uint8(x_35, sizeof(void*)*8, x_18);
lean_ctor_set_uint8(x_35, sizeof(void*)*8 + 1, x_34);
lean_ctor_set_uint8(x_35, sizeof(void*)*8 + 2, x_20);
lean_ctor_set_uint8(x_35, sizeof(void*)*8 + 3, x_21);
lean_ctor_set_uint8(x_35, sizeof(void*)*8 + 4, x_22);
lean_ctor_set_uint8(x_35, sizeof(void*)*8 + 5, x_24);
lean_ctor_set_uint8(x_35, sizeof(void*)*8 + 6, x_27);
return x_35;
}
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_collect__ante__step(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; lean_object* x_5; uint8_t x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; 
lean_inc(x_2);
x_4 = l_TexasPoker_TexasPokerTable_get__seat(x_1, x_2);
x_5 = lean_ctor_get(x_4, 1);
lean_inc(x_5);
lean_dec(x_4);
x_6 = lean_nat_dec_le(x_3, x_5);
x_7 = lean_ctor_get(x_1, 0);
lean_inc(x_7);
x_8 = lean_ctor_get(x_1, 1);
lean_inc(x_8);
x_9 = lean_ctor_get(x_1, 2);
lean_inc(x_9);
x_10 = lean_ctor_get(x_1, 3);
lean_inc(x_10);
x_11 = lean_ctor_get(x_1, 4);
lean_inc(x_11);
x_12 = lean_ctor_get(x_1, 5);
lean_inc(x_12);
x_13 = lean_ctor_get(x_1, 6);
lean_inc(x_13);
x_14 = lean_ctor_get(x_1, 7);
lean_inc(x_14);
x_15 = lean_ctor_get(x_1, 8);
lean_inc(x_15);
x_16 = lean_ctor_get(x_1, 9);
lean_inc(x_16);
x_17 = lean_ctor_get(x_1, 10);
lean_inc(x_17);
x_18 = lean_ctor_get(x_1, 11);
lean_inc(x_18);
x_19 = lean_ctor_get(x_1, 12);
lean_inc(x_19);
x_20 = lean_ctor_get(x_1, 13);
lean_inc(x_20);
x_21 = lean_ctor_get(x_1, 14);
lean_inc(x_21);
x_22 = lean_ctor_get(x_1, 15);
lean_inc(x_22);
x_23 = lean_ctor_get(x_1, 16);
lean_inc(x_23);
x_24 = lean_ctor_get(x_1, 17);
lean_inc(x_24);
x_25 = lean_ctor_get(x_1, 18);
lean_inc(x_25);
x_26 = lean_ctor_get(x_1, 19);
lean_inc(x_26);
x_27 = lean_ctor_get(x_1, 20);
lean_inc(x_27);
x_28 = lean_ctor_get(x_1, 21);
lean_inc(x_28);
x_29 = lean_ctor_get(x_1, 22);
lean_inc(x_29);
x_30 = lean_ctor_get(x_1, 23);
lean_inc(x_30);
x_31 = lean_ctor_get(x_1, 24);
lean_inc(x_31);
x_32 = lean_ctor_get(x_1, 25);
lean_inc(x_32);
x_33 = lean_ctor_get(x_1, 26);
lean_inc(x_33);
x_34 = lean_ctor_get(x_1, 27);
lean_inc(x_34);
x_35 = lean_ctor_get(x_1, 28);
lean_inc(x_35);
x_36 = lean_ctor_get(x_1, 29);
lean_inc(x_36);
x_37 = lean_ctor_get(x_1, 30);
lean_inc(x_37);
x_38 = lean_ctor_get(x_1, 31);
lean_inc(x_38);
if (lean_is_exclusive(x_1)) {
 lean_ctor_release(x_1, 0);
 lean_ctor_release(x_1, 1);
 lean_ctor_release(x_1, 2);
 lean_ctor_release(x_1, 3);
 lean_ctor_release(x_1, 4);
 lean_ctor_release(x_1, 5);
 lean_ctor_release(x_1, 6);
 lean_ctor_release(x_1, 7);
 lean_ctor_release(x_1, 8);
 lean_ctor_release(x_1, 9);
 lean_ctor_release(x_1, 10);
 lean_ctor_release(x_1, 11);
 lean_ctor_release(x_1, 12);
 lean_ctor_release(x_1, 13);
 lean_ctor_release(x_1, 14);
 lean_ctor_release(x_1, 15);
 lean_ctor_release(x_1, 16);
 lean_ctor_release(x_1, 17);
 lean_ctor_release(x_1, 18);
 lean_ctor_release(x_1, 19);
 lean_ctor_release(x_1, 20);
 lean_ctor_release(x_1, 21);
 lean_ctor_release(x_1, 22);
 lean_ctor_release(x_1, 23);
 lean_ctor_release(x_1, 24);
 lean_ctor_release(x_1, 25);
 lean_ctor_release(x_1, 26);
 lean_ctor_release(x_1, 27);
 lean_ctor_release(x_1, 28);
 lean_ctor_release(x_1, 29);
 lean_ctor_release(x_1, 30);
 lean_ctor_release(x_1, 31);
 x_39 = x_1;
} else {
 lean_dec_ref(x_1);
 x_39 = lean_box(0);
}
x_40 = lean_unsigned_to_nat(1u);
x_41 = lean_nat_add(x_38, x_40);
lean_dec(x_38);
if (x_6 == 0)
{
lean_dec(x_3);
x_42 = x_5;
goto block_48;
}
else
{
lean_dec(x_5);
x_42 = x_3;
goto block_48;
}
block_48:
{
lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; 
lean_inc(x_42);
x_43 = lean_alloc_closure((void*)(l_TexasPoker_collect__ante__step___lambda__1___boxed), 2, 1);
lean_closure_set(x_43, 0, x_42);
x_44 = l_TexasPoker_update__nth___rarg(x_13, x_2, x_43);
lean_dec(x_2);
x_45 = lean_nat_add(x_15, x_42);
lean_dec(x_15);
x_46 = lean_nat_add(x_31, x_42);
lean_dec(x_42);
lean_dec(x_31);
if (lean_is_scalar(x_39)) {
 x_47 = lean_alloc_ctor(0, 32, 0);
} else {
 x_47 = x_39;
}
lean_ctor_set(x_47, 0, x_7);
lean_ctor_set(x_47, 1, x_8);
lean_ctor_set(x_47, 2, x_9);
lean_ctor_set(x_47, 3, x_10);
lean_ctor_set(x_47, 4, x_11);
lean_ctor_set(x_47, 5, x_12);
lean_ctor_set(x_47, 6, x_44);
lean_ctor_set(x_47, 7, x_14);
lean_ctor_set(x_47, 8, x_45);
lean_ctor_set(x_47, 9, x_16);
lean_ctor_set(x_47, 10, x_17);
lean_ctor_set(x_47, 11, x_18);
lean_ctor_set(x_47, 12, x_19);
lean_ctor_set(x_47, 13, x_20);
lean_ctor_set(x_47, 14, x_21);
lean_ctor_set(x_47, 15, x_22);
lean_ctor_set(x_47, 16, x_23);
lean_ctor_set(x_47, 17, x_24);
lean_ctor_set(x_47, 18, x_25);
lean_ctor_set(x_47, 19, x_26);
lean_ctor_set(x_47, 20, x_27);
lean_ctor_set(x_47, 21, x_28);
lean_ctor_set(x_47, 22, x_29);
lean_ctor_set(x_47, 23, x_30);
lean_ctor_set(x_47, 24, x_46);
lean_ctor_set(x_47, 25, x_32);
lean_ctor_set(x_47, 26, x_33);
lean_ctor_set(x_47, 27, x_34);
lean_ctor_set(x_47, 28, x_35);
lean_ctor_set(x_47, 29, x_36);
lean_ctor_set(x_47, 30, x_37);
lean_ctor_set(x_47, 31, x_41);
return x_47;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_collect__ante__step___lambda__1___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_collect__ante__step___lambda__1(x_1, x_2);
lean_dec(x_1);
return x_3;
}
}
static lean_object* _init_l_TexasPoker_U64__MAX___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_cstr_to_nat("18446744073709551615");
return x_1;
}
}
static lean_object* _init_l_TexasPoker_U64__MAX() {
_start:
{
lean_object* x_1; 
x_1 = l_TexasPoker_U64__MAX___closed__1;
return x_1;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_Mathlib(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Constants(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Types(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Betting(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Transitions(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_State_Invariants(uint8_t builtin, lean_object* w) {
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
res = initialize_PokerLean_State_Transitions(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l_TexasPoker_U64__MAX___closed__1 = _init_l_TexasPoker_U64__MAX___closed__1();
lean_mark_persistent(l_TexasPoker_U64__MAX___closed__1);
l_TexasPoker_U64__MAX = _init_l_TexasPoker_U64__MAX();
lean_mark_persistent(l_TexasPoker_U64__MAX);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
