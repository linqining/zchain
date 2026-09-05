// Lean compiler output
// Module: PokerLean.State.Theorems
// Imports: Init Mathlib PokerLean.State.Constants PokerLean.State.Types PokerLean.State.Transitions PokerLean.State.Invariants PokerLean.State.RoundMachine PokerLean.State.SidePot PokerLean.State.SubPhases
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
extern lean_object* l_TexasPoker_ReconstructState_default;
lean_object* l_TexasPoker_update__nth___rarg(lean_object*, lean_object*, lean_object*);
extern lean_object* l_TexasPoker_ShuffleState_default;
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown__pre___boxed(lean_object*, lean_object*, lean_object*);
extern lean_object* l_TexasPoker_RevealTokenState_default;
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown__pre(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown__pre___lambda__1(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_reset__for__next__hand(lean_object*);
extern lean_object* l_TexasPoker_Constants_ROUND__WAITING;
lean_object* lean_nat_sub(lean_object*, lean_object*);
lean_object* l_List_reverse___rarg(lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown__pre___lambda__1___boxed(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown___boxed(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_List_mapTR_loop___at_TexasPoker_reset__for__next__hand___spec__1(lean_object*, lean_object*);
lean_object* lean_nat_add(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_reset__seat(lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_reset__seat(lean_object* x_1) {
_start:
{
uint8_t x_2; 
x_2 = !lean_is_exclusive(x_1);
if (x_2 == 0)
{
lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; uint8_t x_9; 
x_3 = lean_ctor_get(x_1, 1);
x_4 = lean_ctor_get(x_1, 6);
x_5 = lean_ctor_get(x_1, 4);
lean_dec(x_5);
x_6 = lean_ctor_get(x_1, 3);
lean_dec(x_6);
x_7 = lean_nat_add(x_3, x_4);
lean_dec(x_4);
lean_dec(x_3);
x_8 = lean_unsigned_to_nat(0u);
x_9 = 0;
lean_ctor_set(x_1, 6, x_8);
lean_ctor_set(x_1, 4, x_8);
lean_ctor_set(x_1, 3, x_8);
lean_ctor_set(x_1, 1, x_7);
lean_ctor_set_uint8(x_1, sizeof(void*)*8, x_9);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 1, x_9);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_9);
return x_1;
}
else
{
lean_object* x_10; lean_object* x_11; lean_object* x_12; uint8_t x_13; uint8_t x_14; lean_object* x_15; uint8_t x_16; lean_object* x_17; lean_object* x_18; uint8_t x_19; lean_object* x_20; lean_object* x_21; uint8_t x_22; lean_object* x_23; 
x_10 = lean_ctor_get(x_1, 0);
x_11 = lean_ctor_get(x_1, 1);
x_12 = lean_ctor_get(x_1, 2);
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
lean_inc(x_12);
lean_inc(x_11);
lean_inc(x_10);
lean_dec(x_1);
x_20 = lean_nat_add(x_11, x_17);
lean_dec(x_17);
lean_dec(x_11);
x_21 = lean_unsigned_to_nat(0u);
x_22 = 0;
x_23 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_23, 0, x_10);
lean_ctor_set(x_23, 1, x_20);
lean_ctor_set(x_23, 2, x_12);
lean_ctor_set(x_23, 3, x_21);
lean_ctor_set(x_23, 4, x_21);
lean_ctor_set(x_23, 5, x_15);
lean_ctor_set(x_23, 6, x_21);
lean_ctor_set(x_23, 7, x_18);
lean_ctor_set_uint8(x_23, sizeof(void*)*8, x_22);
lean_ctor_set_uint8(x_23, sizeof(void*)*8 + 1, x_22);
lean_ctor_set_uint8(x_23, sizeof(void*)*8 + 2, x_22);
lean_ctor_set_uint8(x_23, sizeof(void*)*8 + 3, x_13);
lean_ctor_set_uint8(x_23, sizeof(void*)*8 + 4, x_14);
lean_ctor_set_uint8(x_23, sizeof(void*)*8 + 5, x_16);
lean_ctor_set_uint8(x_23, sizeof(void*)*8 + 6, x_19);
return x_23;
}
}
}
LEAN_EXPORT lean_object* l_List_mapTR_loop___at_TexasPoker_reset__for__next__hand___spec__1(lean_object* x_1, lean_object* x_2) {
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
x_7 = l_TexasPoker_reset__seat(x_5);
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
x_11 = l_TexasPoker_reset__seat(x_9);
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
LEAN_EXPORT lean_object* l_TexasPoker_reset__for__next__hand(lean_object* x_1) {
_start:
{
uint8_t x_2; 
x_2 = !lean_is_exclusive(x_1);
if (x_2 == 0)
{
lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; 
x_3 = lean_ctor_get(x_1, 6);
x_4 = lean_ctor_get(x_1, 31);
x_5 = lean_ctor_get(x_1, 17);
lean_dec(x_5);
x_6 = lean_ctor_get(x_1, 16);
lean_dec(x_6);
x_7 = lean_ctor_get(x_1, 15);
lean_dec(x_7);
x_8 = lean_ctor_get(x_1, 13);
lean_dec(x_8);
x_9 = lean_ctor_get(x_1, 12);
lean_dec(x_9);
x_10 = lean_ctor_get(x_1, 11);
lean_dec(x_10);
x_11 = lean_ctor_get(x_1, 10);
lean_dec(x_11);
x_12 = lean_ctor_get(x_1, 9);
lean_dec(x_12);
x_13 = lean_ctor_get(x_1, 8);
lean_dec(x_13);
x_14 = lean_box(0);
x_15 = l_List_mapTR_loop___at_TexasPoker_reset__for__next__hand___spec__1(x_3, x_14);
x_16 = lean_box(0);
x_17 = lean_unsigned_to_nat(1u);
x_18 = lean_nat_add(x_4, x_17);
lean_dec(x_4);
x_19 = lean_unsigned_to_nat(0u);
x_20 = l_TexasPoker_Constants_ROUND__WAITING;
x_21 = l_TexasPoker_ShuffleState_default;
x_22 = l_TexasPoker_RevealTokenState_default;
x_23 = l_TexasPoker_ReconstructState_default;
lean_ctor_set(x_1, 31, x_18);
lean_ctor_set(x_1, 17, x_23);
lean_ctor_set(x_1, 16, x_22);
lean_ctor_set(x_1, 15, x_21);
lean_ctor_set(x_1, 13, x_16);
lean_ctor_set(x_1, 12, x_16);
lean_ctor_set(x_1, 11, x_20);
lean_ctor_set(x_1, 10, x_14);
lean_ctor_set(x_1, 9, x_14);
lean_ctor_set(x_1, 8, x_19);
lean_ctor_set(x_1, 6, x_15);
return x_1;
}
else
{
lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; lean_object* x_49; lean_object* x_50; lean_object* x_51; lean_object* x_52; lean_object* x_53; lean_object* x_54; lean_object* x_55; lean_object* x_56; lean_object* x_57; 
x_24 = lean_ctor_get(x_1, 0);
x_25 = lean_ctor_get(x_1, 1);
x_26 = lean_ctor_get(x_1, 2);
x_27 = lean_ctor_get(x_1, 3);
x_28 = lean_ctor_get(x_1, 4);
x_29 = lean_ctor_get(x_1, 5);
x_30 = lean_ctor_get(x_1, 6);
x_31 = lean_ctor_get(x_1, 7);
x_32 = lean_ctor_get(x_1, 14);
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
lean_dec(x_1);
x_47 = lean_box(0);
x_48 = l_List_mapTR_loop___at_TexasPoker_reset__for__next__hand___spec__1(x_30, x_47);
x_49 = lean_box(0);
x_50 = lean_unsigned_to_nat(1u);
x_51 = lean_nat_add(x_46, x_50);
lean_dec(x_46);
x_52 = lean_unsigned_to_nat(0u);
x_53 = l_TexasPoker_Constants_ROUND__WAITING;
x_54 = l_TexasPoker_ShuffleState_default;
x_55 = l_TexasPoker_RevealTokenState_default;
x_56 = l_TexasPoker_ReconstructState_default;
x_57 = lean_alloc_ctor(0, 32, 0);
lean_ctor_set(x_57, 0, x_24);
lean_ctor_set(x_57, 1, x_25);
lean_ctor_set(x_57, 2, x_26);
lean_ctor_set(x_57, 3, x_27);
lean_ctor_set(x_57, 4, x_28);
lean_ctor_set(x_57, 5, x_29);
lean_ctor_set(x_57, 6, x_48);
lean_ctor_set(x_57, 7, x_31);
lean_ctor_set(x_57, 8, x_52);
lean_ctor_set(x_57, 9, x_47);
lean_ctor_set(x_57, 10, x_47);
lean_ctor_set(x_57, 11, x_53);
lean_ctor_set(x_57, 12, x_49);
lean_ctor_set(x_57, 13, x_49);
lean_ctor_set(x_57, 14, x_32);
lean_ctor_set(x_57, 15, x_54);
lean_ctor_set(x_57, 16, x_55);
lean_ctor_set(x_57, 17, x_56);
lean_ctor_set(x_57, 18, x_33);
lean_ctor_set(x_57, 19, x_34);
lean_ctor_set(x_57, 20, x_35);
lean_ctor_set(x_57, 21, x_36);
lean_ctor_set(x_57, 22, x_37);
lean_ctor_set(x_57, 23, x_38);
lean_ctor_set(x_57, 24, x_39);
lean_ctor_set(x_57, 25, x_40);
lean_ctor_set(x_57, 26, x_41);
lean_ctor_set(x_57, 27, x_42);
lean_ctor_set(x_57, 28, x_43);
lean_ctor_set(x_57, 29, x_44);
lean_ctor_set(x_57, 30, x_45);
lean_ctor_set(x_57, 31, x_51);
return x_57;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown__pre___lambda__1(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
uint8_t x_4; 
x_4 = !lean_is_exclusive(x_3);
if (x_4 == 0)
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; 
x_5 = lean_ctor_get(x_3, 1);
x_6 = lean_ctor_get(x_1, 8);
x_7 = lean_nat_sub(x_6, x_2);
x_8 = lean_nat_add(x_5, x_7);
lean_dec(x_7);
lean_dec(x_5);
lean_ctor_set(x_3, 1, x_8);
return x_3;
}
else
{
lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; uint8_t x_14; uint8_t x_15; uint8_t x_16; uint8_t x_17; uint8_t x_18; lean_object* x_19; uint8_t x_20; lean_object* x_21; lean_object* x_22; uint8_t x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; 
x_9 = lean_ctor_get(x_3, 0);
x_10 = lean_ctor_get(x_3, 1);
x_11 = lean_ctor_get(x_3, 2);
x_12 = lean_ctor_get(x_3, 3);
x_13 = lean_ctor_get(x_3, 4);
x_14 = lean_ctor_get_uint8(x_3, sizeof(void*)*8);
x_15 = lean_ctor_get_uint8(x_3, sizeof(void*)*8 + 1);
x_16 = lean_ctor_get_uint8(x_3, sizeof(void*)*8 + 2);
x_17 = lean_ctor_get_uint8(x_3, sizeof(void*)*8 + 3);
x_18 = lean_ctor_get_uint8(x_3, sizeof(void*)*8 + 4);
x_19 = lean_ctor_get(x_3, 5);
x_20 = lean_ctor_get_uint8(x_3, sizeof(void*)*8 + 5);
x_21 = lean_ctor_get(x_3, 6);
x_22 = lean_ctor_get(x_3, 7);
x_23 = lean_ctor_get_uint8(x_3, sizeof(void*)*8 + 6);
lean_inc(x_22);
lean_inc(x_21);
lean_inc(x_19);
lean_inc(x_13);
lean_inc(x_12);
lean_inc(x_11);
lean_inc(x_10);
lean_inc(x_9);
lean_dec(x_3);
x_24 = lean_ctor_get(x_1, 8);
x_25 = lean_nat_sub(x_24, x_2);
x_26 = lean_nat_add(x_10, x_25);
lean_dec(x_25);
lean_dec(x_10);
x_27 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_27, 0, x_9);
lean_ctor_set(x_27, 1, x_26);
lean_ctor_set(x_27, 2, x_11);
lean_ctor_set(x_27, 3, x_12);
lean_ctor_set(x_27, 4, x_13);
lean_ctor_set(x_27, 5, x_19);
lean_ctor_set(x_27, 6, x_21);
lean_ctor_set(x_27, 7, x_22);
lean_ctor_set_uint8(x_27, sizeof(void*)*8, x_14);
lean_ctor_set_uint8(x_27, sizeof(void*)*8 + 1, x_15);
lean_ctor_set_uint8(x_27, sizeof(void*)*8 + 2, x_16);
lean_ctor_set_uint8(x_27, sizeof(void*)*8 + 3, x_17);
lean_ctor_set_uint8(x_27, sizeof(void*)*8 + 4, x_18);
lean_ctor_set_uint8(x_27, sizeof(void*)*8 + 5, x_20);
lean_ctor_set_uint8(x_27, sizeof(void*)*8 + 6, x_23);
return x_27;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown__pre(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; uint8_t x_36; 
x_4 = lean_ctor_get(x_1, 0);
lean_inc(x_4);
x_5 = lean_ctor_get(x_1, 1);
lean_inc(x_5);
x_6 = lean_ctor_get(x_1, 2);
lean_inc(x_6);
x_7 = lean_ctor_get(x_1, 3);
lean_inc(x_7);
x_8 = lean_ctor_get(x_1, 4);
lean_inc(x_8);
x_9 = lean_ctor_get(x_1, 5);
lean_inc(x_9);
x_10 = lean_ctor_get(x_1, 6);
lean_inc(x_10);
x_11 = lean_ctor_get(x_1, 7);
lean_inc(x_11);
x_12 = lean_ctor_get(x_1, 9);
lean_inc(x_12);
x_13 = lean_ctor_get(x_1, 10);
lean_inc(x_13);
x_14 = lean_ctor_get(x_1, 11);
lean_inc(x_14);
x_15 = lean_ctor_get(x_1, 12);
lean_inc(x_15);
x_16 = lean_ctor_get(x_1, 13);
lean_inc(x_16);
x_17 = lean_ctor_get(x_1, 14);
lean_inc(x_17);
x_18 = lean_ctor_get(x_1, 15);
lean_inc(x_18);
x_19 = lean_ctor_get(x_1, 16);
lean_inc(x_19);
x_20 = lean_ctor_get(x_1, 17);
lean_inc(x_20);
x_21 = lean_ctor_get(x_1, 18);
lean_inc(x_21);
x_22 = lean_ctor_get(x_1, 19);
lean_inc(x_22);
x_23 = lean_ctor_get(x_1, 20);
lean_inc(x_23);
x_24 = lean_ctor_get(x_1, 21);
lean_inc(x_24);
x_25 = lean_ctor_get(x_1, 22);
lean_inc(x_25);
x_26 = lean_ctor_get(x_1, 23);
lean_inc(x_26);
x_27 = lean_ctor_get(x_1, 24);
lean_inc(x_27);
x_28 = lean_ctor_get(x_1, 25);
lean_inc(x_28);
x_29 = lean_ctor_get(x_1, 26);
lean_inc(x_29);
x_30 = lean_ctor_get(x_1, 27);
lean_inc(x_30);
x_31 = lean_ctor_get(x_1, 28);
lean_inc(x_31);
x_32 = lean_ctor_get(x_1, 29);
lean_inc(x_32);
x_33 = lean_ctor_get(x_1, 30);
lean_inc(x_33);
x_34 = lean_ctor_get(x_1, 31);
lean_inc(x_34);
lean_inc(x_3);
lean_inc(x_1);
x_35 = lean_alloc_closure((void*)(l_TexasPoker_end__without__showdown__pre___lambda__1___boxed), 3, 2);
lean_closure_set(x_35, 0, x_1);
lean_closure_set(x_35, 1, x_3);
x_36 = !lean_is_exclusive(x_1);
if (x_36 == 0)
{
lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; lean_object* x_49; lean_object* x_50; lean_object* x_51; lean_object* x_52; lean_object* x_53; lean_object* x_54; lean_object* x_55; lean_object* x_56; lean_object* x_57; lean_object* x_58; lean_object* x_59; lean_object* x_60; lean_object* x_61; lean_object* x_62; lean_object* x_63; lean_object* x_64; lean_object* x_65; lean_object* x_66; lean_object* x_67; lean_object* x_68; lean_object* x_69; lean_object* x_70; lean_object* x_71; lean_object* x_72; lean_object* x_73; 
x_37 = lean_ctor_get(x_1, 31);
lean_dec(x_37);
x_38 = lean_ctor_get(x_1, 30);
lean_dec(x_38);
x_39 = lean_ctor_get(x_1, 29);
lean_dec(x_39);
x_40 = lean_ctor_get(x_1, 28);
lean_dec(x_40);
x_41 = lean_ctor_get(x_1, 27);
lean_dec(x_41);
x_42 = lean_ctor_get(x_1, 26);
lean_dec(x_42);
x_43 = lean_ctor_get(x_1, 25);
lean_dec(x_43);
x_44 = lean_ctor_get(x_1, 24);
lean_dec(x_44);
x_45 = lean_ctor_get(x_1, 23);
lean_dec(x_45);
x_46 = lean_ctor_get(x_1, 22);
lean_dec(x_46);
x_47 = lean_ctor_get(x_1, 21);
lean_dec(x_47);
x_48 = lean_ctor_get(x_1, 20);
lean_dec(x_48);
x_49 = lean_ctor_get(x_1, 19);
lean_dec(x_49);
x_50 = lean_ctor_get(x_1, 18);
lean_dec(x_50);
x_51 = lean_ctor_get(x_1, 17);
lean_dec(x_51);
x_52 = lean_ctor_get(x_1, 16);
lean_dec(x_52);
x_53 = lean_ctor_get(x_1, 15);
lean_dec(x_53);
x_54 = lean_ctor_get(x_1, 14);
lean_dec(x_54);
x_55 = lean_ctor_get(x_1, 13);
lean_dec(x_55);
x_56 = lean_ctor_get(x_1, 12);
lean_dec(x_56);
x_57 = lean_ctor_get(x_1, 11);
lean_dec(x_57);
x_58 = lean_ctor_get(x_1, 10);
lean_dec(x_58);
x_59 = lean_ctor_get(x_1, 9);
lean_dec(x_59);
x_60 = lean_ctor_get(x_1, 8);
lean_dec(x_60);
x_61 = lean_ctor_get(x_1, 7);
lean_dec(x_61);
x_62 = lean_ctor_get(x_1, 6);
lean_dec(x_62);
x_63 = lean_ctor_get(x_1, 5);
lean_dec(x_63);
x_64 = lean_ctor_get(x_1, 4);
lean_dec(x_64);
x_65 = lean_ctor_get(x_1, 3);
lean_dec(x_65);
x_66 = lean_ctor_get(x_1, 2);
lean_dec(x_66);
x_67 = lean_ctor_get(x_1, 1);
lean_dec(x_67);
x_68 = lean_ctor_get(x_1, 0);
lean_dec(x_68);
x_69 = l_TexasPoker_update__nth___rarg(x_10, x_2, x_35);
x_70 = lean_nat_add(x_31, x_3);
lean_dec(x_3);
lean_dec(x_31);
x_71 = lean_unsigned_to_nat(2u);
x_72 = lean_nat_add(x_34, x_71);
lean_dec(x_34);
x_73 = lean_unsigned_to_nat(0u);
lean_ctor_set(x_1, 31, x_72);
lean_ctor_set(x_1, 28, x_70);
lean_ctor_set(x_1, 8, x_73);
lean_ctor_set(x_1, 6, x_69);
return x_1;
}
else
{
lean_object* x_74; lean_object* x_75; lean_object* x_76; lean_object* x_77; lean_object* x_78; lean_object* x_79; 
lean_dec(x_1);
x_74 = l_TexasPoker_update__nth___rarg(x_10, x_2, x_35);
x_75 = lean_nat_add(x_31, x_3);
lean_dec(x_3);
lean_dec(x_31);
x_76 = lean_unsigned_to_nat(2u);
x_77 = lean_nat_add(x_34, x_76);
lean_dec(x_34);
x_78 = lean_unsigned_to_nat(0u);
x_79 = lean_alloc_ctor(0, 32, 0);
lean_ctor_set(x_79, 0, x_4);
lean_ctor_set(x_79, 1, x_5);
lean_ctor_set(x_79, 2, x_6);
lean_ctor_set(x_79, 3, x_7);
lean_ctor_set(x_79, 4, x_8);
lean_ctor_set(x_79, 5, x_9);
lean_ctor_set(x_79, 6, x_74);
lean_ctor_set(x_79, 7, x_11);
lean_ctor_set(x_79, 8, x_78);
lean_ctor_set(x_79, 9, x_12);
lean_ctor_set(x_79, 10, x_13);
lean_ctor_set(x_79, 11, x_14);
lean_ctor_set(x_79, 12, x_15);
lean_ctor_set(x_79, 13, x_16);
lean_ctor_set(x_79, 14, x_17);
lean_ctor_set(x_79, 15, x_18);
lean_ctor_set(x_79, 16, x_19);
lean_ctor_set(x_79, 17, x_20);
lean_ctor_set(x_79, 18, x_21);
lean_ctor_set(x_79, 19, x_22);
lean_ctor_set(x_79, 20, x_23);
lean_ctor_set(x_79, 21, x_24);
lean_ctor_set(x_79, 22, x_25);
lean_ctor_set(x_79, 23, x_26);
lean_ctor_set(x_79, 24, x_27);
lean_ctor_set(x_79, 25, x_28);
lean_ctor_set(x_79, 26, x_29);
lean_ctor_set(x_79, 27, x_30);
lean_ctor_set(x_79, 28, x_75);
lean_ctor_set(x_79, 29, x_32);
lean_ctor_set(x_79, 30, x_33);
lean_ctor_set(x_79, 31, x_77);
return x_79;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown__pre___lambda__1___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_end__without__showdown__pre___lambda__1(x_1, x_2, x_3);
lean_dec(x_2);
lean_dec(x_1);
return x_4;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown__pre___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_end__without__showdown__pre(x_1, x_2, x_3);
lean_dec(x_2);
return x_4;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; lean_object* x_6; 
x_5 = l_TexasPoker_end__without__showdown__pre(x_1, x_2, x_3);
x_6 = l_TexasPoker_reset__for__next__hand(x_5);
return x_6;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_end__without__showdown___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; 
x_5 = l_TexasPoker_end__without__showdown(x_1, x_2, x_3, x_4);
lean_dec(x_2);
return x_5;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_Mathlib(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Constants(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Types(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Transitions(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Invariants(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_RoundMachine(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_SidePot(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_SubPhases(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_State_Theorems(uint8_t builtin, lean_object* w) {
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
res = initialize_PokerLean_State_Transitions(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_State_Invariants(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_State_RoundMachine(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_State_SidePot(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_State_SubPhases(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
