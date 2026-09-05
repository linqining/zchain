// Lean compiler output
// Module: PokerLean.State.Refinement
// Imports: Init Mathlib PokerLean.State.Constants PokerLean.State.Types PokerLean.State.Betting PokerLean.State.Transitions PokerLean.State.Invariants PokerLean.State.RoundMachine PokerLean.State.SidePot PokerLean.State.SubPhases PokerLean.State.Theorems
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
LEAN_EXPORT lean_object* l_TexasPoker_rust__apply__raise(lean_object*, lean_object*, lean_object*);
lean_object* l_TexasPoker_BettingRound_process__call(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_rust__checked__add___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_rust__apply__raise___boxed(lean_object*, lean_object*, lean_object*);
uint8_t lean_nat_dec_eq(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_rust__apply__call(lean_object*, lean_object*);
uint8_t lean_nat_dec_lt(lean_object*, lean_object*);
extern lean_object* l_TexasPoker_U64__MAX;
LEAN_EXPORT lean_object* l_TexasPoker_rust__checked__sub(lean_object*, lean_object*);
lean_object* lean_nat_sub(lean_object*, lean_object*);
uint8_t lean_nat_dec_le(lean_object*, lean_object*);
lean_object* lean_nat_add(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_rust__apply__call___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_rust__checked__sub___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_rust__checked__add(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_TexasPoker_rust__checked__add(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; lean_object* x_4; uint8_t x_5; 
x_3 = lean_nat_add(x_1, x_2);
x_4 = l_TexasPoker_U64__MAX;
x_5 = lean_nat_dec_le(x_3, x_4);
if (x_5 == 0)
{
lean_object* x_6; 
lean_dec(x_3);
x_6 = lean_box(0);
return x_6;
}
else
{
lean_object* x_7; 
x_7 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_7, 0, x_3);
return x_7;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_rust__checked__add___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_rust__checked__add(x_1, x_2);
lean_dec(x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_rust__checked__sub(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; 
x_3 = lean_nat_dec_le(x_2, x_1);
if (x_3 == 0)
{
lean_object* x_4; 
x_4 = lean_box(0);
return x_4;
}
else
{
lean_object* x_5; lean_object* x_6; 
x_5 = lean_nat_sub(x_1, x_2);
x_6 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_6, 0, x_5);
return x_6;
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_rust__checked__sub___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_rust__checked__sub(x_1, x_2);
lean_dec(x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_rust__apply__call(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; 
x_3 = !lean_is_exclusive(x_1);
if (x_3 == 0)
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; 
x_4 = lean_ctor_get(x_1, 0);
x_5 = lean_ctor_get(x_1, 1);
x_6 = lean_ctor_get(x_1, 2);
x_7 = lean_ctor_get(x_1, 3);
x_8 = lean_ctor_get(x_1, 4);
x_9 = lean_ctor_get(x_1, 5);
x_10 = lean_ctor_get(x_1, 6);
x_11 = lean_ctor_get(x_1, 7);
x_12 = l_TexasPoker_BettingRound_process__call(x_2, x_7, x_5);
x_13 = l_TexasPoker_rust__checked__sub(x_5, x_12);
lean_dec(x_5);
if (lean_obj_tag(x_13) == 0)
{
lean_object* x_14; 
lean_dec(x_12);
lean_free_object(x_1);
lean_dec(x_11);
lean_dec(x_10);
lean_dec(x_9);
lean_dec(x_8);
lean_dec(x_7);
lean_dec(x_6);
lean_dec(x_4);
x_14 = lean_box(0);
return x_14;
}
else
{
lean_object* x_15; lean_object* x_16; 
x_15 = lean_ctor_get(x_13, 0);
lean_inc(x_15);
lean_dec(x_13);
x_16 = l_TexasPoker_rust__checked__add(x_7, x_12);
if (lean_obj_tag(x_16) == 0)
{
lean_object* x_17; 
lean_dec(x_15);
lean_dec(x_12);
lean_free_object(x_1);
lean_dec(x_11);
lean_dec(x_10);
lean_dec(x_9);
lean_dec(x_8);
lean_dec(x_7);
lean_dec(x_6);
lean_dec(x_4);
x_17 = lean_box(0);
return x_17;
}
else
{
lean_object* x_18; 
lean_dec(x_16);
x_18 = l_TexasPoker_rust__checked__add(x_8, x_12);
if (lean_obj_tag(x_18) == 0)
{
lean_object* x_19; 
lean_dec(x_15);
lean_dec(x_12);
lean_free_object(x_1);
lean_dec(x_11);
lean_dec(x_10);
lean_dec(x_9);
lean_dec(x_8);
lean_dec(x_7);
lean_dec(x_6);
lean_dec(x_4);
x_19 = lean_box(0);
return x_19;
}
else
{
uint8_t x_20; 
x_20 = !lean_is_exclusive(x_18);
if (x_20 == 0)
{
lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; uint8_t x_25; 
x_21 = lean_ctor_get(x_18, 0);
lean_dec(x_21);
x_22 = lean_nat_add(x_7, x_12);
lean_dec(x_7);
x_23 = lean_nat_add(x_8, x_12);
lean_dec(x_8);
x_24 = lean_unsigned_to_nat(0u);
x_25 = lean_nat_dec_eq(x_15, x_24);
if (x_25 == 0)
{
uint8_t x_26; uint8_t x_27; 
lean_dec(x_12);
x_26 = 0;
x_27 = 1;
lean_ctor_set(x_1, 4, x_23);
lean_ctor_set(x_1, 3, x_22);
lean_ctor_set(x_1, 1, x_15);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 1, x_26);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_27);
lean_ctor_set(x_18, 0, x_1);
return x_18;
}
else
{
uint8_t x_28; uint8_t x_29; 
x_28 = lean_nat_dec_lt(x_24, x_12);
lean_dec(x_12);
x_29 = 1;
lean_ctor_set(x_1, 4, x_23);
lean_ctor_set(x_1, 3, x_22);
lean_ctor_set(x_1, 1, x_15);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 1, x_28);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_29);
lean_ctor_set(x_18, 0, x_1);
return x_18;
}
}
else
{
lean_object* x_30; lean_object* x_31; lean_object* x_32; uint8_t x_33; 
lean_dec(x_18);
x_30 = lean_nat_add(x_7, x_12);
lean_dec(x_7);
x_31 = lean_nat_add(x_8, x_12);
lean_dec(x_8);
x_32 = lean_unsigned_to_nat(0u);
x_33 = lean_nat_dec_eq(x_15, x_32);
if (x_33 == 0)
{
uint8_t x_34; uint8_t x_35; lean_object* x_36; 
lean_dec(x_12);
x_34 = 0;
x_35 = 1;
lean_ctor_set(x_1, 4, x_31);
lean_ctor_set(x_1, 3, x_30);
lean_ctor_set(x_1, 1, x_15);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 1, x_34);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_35);
x_36 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_36, 0, x_1);
return x_36;
}
else
{
uint8_t x_37; uint8_t x_38; lean_object* x_39; 
x_37 = lean_nat_dec_lt(x_32, x_12);
lean_dec(x_12);
x_38 = 1;
lean_ctor_set(x_1, 4, x_31);
lean_ctor_set(x_1, 3, x_30);
lean_ctor_set(x_1, 1, x_15);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 1, x_37);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_38);
x_39 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_39, 0, x_1);
return x_39;
}
}
}
}
}
}
else
{
lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; uint8_t x_45; uint8_t x_46; uint8_t x_47; lean_object* x_48; uint8_t x_49; lean_object* x_50; lean_object* x_51; uint8_t x_52; lean_object* x_53; lean_object* x_54; 
x_40 = lean_ctor_get(x_1, 0);
x_41 = lean_ctor_get(x_1, 1);
x_42 = lean_ctor_get(x_1, 2);
x_43 = lean_ctor_get(x_1, 3);
x_44 = lean_ctor_get(x_1, 4);
x_45 = lean_ctor_get_uint8(x_1, sizeof(void*)*8);
x_46 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 3);
x_47 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 4);
x_48 = lean_ctor_get(x_1, 5);
x_49 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 5);
x_50 = lean_ctor_get(x_1, 6);
x_51 = lean_ctor_get(x_1, 7);
x_52 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 6);
lean_inc(x_51);
lean_inc(x_50);
lean_inc(x_48);
lean_inc(x_44);
lean_inc(x_43);
lean_inc(x_42);
lean_inc(x_41);
lean_inc(x_40);
lean_dec(x_1);
x_53 = l_TexasPoker_BettingRound_process__call(x_2, x_43, x_41);
x_54 = l_TexasPoker_rust__checked__sub(x_41, x_53);
lean_dec(x_41);
if (lean_obj_tag(x_54) == 0)
{
lean_object* x_55; 
lean_dec(x_53);
lean_dec(x_51);
lean_dec(x_50);
lean_dec(x_48);
lean_dec(x_44);
lean_dec(x_43);
lean_dec(x_42);
lean_dec(x_40);
x_55 = lean_box(0);
return x_55;
}
else
{
lean_object* x_56; lean_object* x_57; 
x_56 = lean_ctor_get(x_54, 0);
lean_inc(x_56);
lean_dec(x_54);
x_57 = l_TexasPoker_rust__checked__add(x_43, x_53);
if (lean_obj_tag(x_57) == 0)
{
lean_object* x_58; 
lean_dec(x_56);
lean_dec(x_53);
lean_dec(x_51);
lean_dec(x_50);
lean_dec(x_48);
lean_dec(x_44);
lean_dec(x_43);
lean_dec(x_42);
lean_dec(x_40);
x_58 = lean_box(0);
return x_58;
}
else
{
lean_object* x_59; 
lean_dec(x_57);
x_59 = l_TexasPoker_rust__checked__add(x_44, x_53);
if (lean_obj_tag(x_59) == 0)
{
lean_object* x_60; 
lean_dec(x_56);
lean_dec(x_53);
lean_dec(x_51);
lean_dec(x_50);
lean_dec(x_48);
lean_dec(x_44);
lean_dec(x_43);
lean_dec(x_42);
lean_dec(x_40);
x_60 = lean_box(0);
return x_60;
}
else
{
lean_object* x_61; lean_object* x_62; lean_object* x_63; lean_object* x_64; uint8_t x_65; 
if (lean_is_exclusive(x_59)) {
 lean_ctor_release(x_59, 0);
 x_61 = x_59;
} else {
 lean_dec_ref(x_59);
 x_61 = lean_box(0);
}
x_62 = lean_nat_add(x_43, x_53);
lean_dec(x_43);
x_63 = lean_nat_add(x_44, x_53);
lean_dec(x_44);
x_64 = lean_unsigned_to_nat(0u);
x_65 = lean_nat_dec_eq(x_56, x_64);
if (x_65 == 0)
{
uint8_t x_66; uint8_t x_67; lean_object* x_68; lean_object* x_69; 
lean_dec(x_53);
x_66 = 0;
x_67 = 1;
x_68 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_68, 0, x_40);
lean_ctor_set(x_68, 1, x_56);
lean_ctor_set(x_68, 2, x_42);
lean_ctor_set(x_68, 3, x_62);
lean_ctor_set(x_68, 4, x_63);
lean_ctor_set(x_68, 5, x_48);
lean_ctor_set(x_68, 6, x_50);
lean_ctor_set(x_68, 7, x_51);
lean_ctor_set_uint8(x_68, sizeof(void*)*8, x_45);
lean_ctor_set_uint8(x_68, sizeof(void*)*8 + 1, x_66);
lean_ctor_set_uint8(x_68, sizeof(void*)*8 + 2, x_67);
lean_ctor_set_uint8(x_68, sizeof(void*)*8 + 3, x_46);
lean_ctor_set_uint8(x_68, sizeof(void*)*8 + 4, x_47);
lean_ctor_set_uint8(x_68, sizeof(void*)*8 + 5, x_49);
lean_ctor_set_uint8(x_68, sizeof(void*)*8 + 6, x_52);
if (lean_is_scalar(x_61)) {
 x_69 = lean_alloc_ctor(1, 1, 0);
} else {
 x_69 = x_61;
}
lean_ctor_set(x_69, 0, x_68);
return x_69;
}
else
{
uint8_t x_70; uint8_t x_71; lean_object* x_72; lean_object* x_73; 
x_70 = lean_nat_dec_lt(x_64, x_53);
lean_dec(x_53);
x_71 = 1;
x_72 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_72, 0, x_40);
lean_ctor_set(x_72, 1, x_56);
lean_ctor_set(x_72, 2, x_42);
lean_ctor_set(x_72, 3, x_62);
lean_ctor_set(x_72, 4, x_63);
lean_ctor_set(x_72, 5, x_48);
lean_ctor_set(x_72, 6, x_50);
lean_ctor_set(x_72, 7, x_51);
lean_ctor_set_uint8(x_72, sizeof(void*)*8, x_45);
lean_ctor_set_uint8(x_72, sizeof(void*)*8 + 1, x_70);
lean_ctor_set_uint8(x_72, sizeof(void*)*8 + 2, x_71);
lean_ctor_set_uint8(x_72, sizeof(void*)*8 + 3, x_46);
lean_ctor_set_uint8(x_72, sizeof(void*)*8 + 4, x_47);
lean_ctor_set_uint8(x_72, sizeof(void*)*8 + 5, x_49);
lean_ctor_set_uint8(x_72, sizeof(void*)*8 + 6, x_52);
if (lean_is_scalar(x_61)) {
 x_73 = lean_alloc_ctor(1, 1, 0);
} else {
 x_73 = x_61;
}
lean_ctor_set(x_73, 0, x_72);
return x_73;
}
}
}
}
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_rust__apply__call___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_TexasPoker_rust__apply__call(x_1, x_2);
lean_dec(x_2);
return x_3;
}
}
LEAN_EXPORT lean_object* l_TexasPoker_rust__apply__raise(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
uint8_t x_4; 
x_4 = !lean_is_exclusive(x_1);
if (x_4 == 0)
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; 
x_5 = lean_ctor_get(x_1, 0);
x_6 = lean_ctor_get(x_1, 1);
x_7 = lean_ctor_get(x_1, 2);
x_8 = lean_ctor_get(x_1, 4);
x_9 = lean_ctor_get(x_1, 5);
x_10 = lean_ctor_get(x_1, 6);
x_11 = lean_ctor_get(x_1, 7);
x_12 = lean_ctor_get(x_1, 3);
lean_dec(x_12);
x_13 = l_TexasPoker_rust__checked__sub(x_6, x_3);
lean_dec(x_6);
if (lean_obj_tag(x_13) == 0)
{
lean_object* x_14; 
lean_free_object(x_1);
lean_dec(x_11);
lean_dec(x_10);
lean_dec(x_9);
lean_dec(x_8);
lean_dec(x_7);
lean_dec(x_5);
lean_dec(x_2);
x_14 = lean_box(0);
return x_14;
}
else
{
lean_object* x_15; lean_object* x_16; 
x_15 = lean_ctor_get(x_13, 0);
lean_inc(x_15);
lean_dec(x_13);
x_16 = l_TexasPoker_rust__checked__add(x_8, x_3);
if (lean_obj_tag(x_16) == 0)
{
lean_object* x_17; 
lean_dec(x_15);
lean_free_object(x_1);
lean_dec(x_11);
lean_dec(x_10);
lean_dec(x_9);
lean_dec(x_8);
lean_dec(x_7);
lean_dec(x_5);
lean_dec(x_2);
x_17 = lean_box(0);
return x_17;
}
else
{
uint8_t x_18; 
x_18 = !lean_is_exclusive(x_16);
if (x_18 == 0)
{
lean_object* x_19; lean_object* x_20; lean_object* x_21; uint8_t x_22; uint8_t x_23; 
x_19 = lean_ctor_get(x_16, 0);
lean_dec(x_19);
x_20 = lean_nat_add(x_8, x_3);
lean_dec(x_8);
x_21 = lean_unsigned_to_nat(0u);
x_22 = lean_nat_dec_eq(x_15, x_21);
x_23 = 1;
lean_ctor_set(x_1, 4, x_20);
lean_ctor_set(x_1, 3, x_2);
lean_ctor_set(x_1, 1, x_15);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 1, x_22);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_23);
lean_ctor_set(x_16, 0, x_1);
return x_16;
}
else
{
lean_object* x_24; lean_object* x_25; uint8_t x_26; uint8_t x_27; lean_object* x_28; 
lean_dec(x_16);
x_24 = lean_nat_add(x_8, x_3);
lean_dec(x_8);
x_25 = lean_unsigned_to_nat(0u);
x_26 = lean_nat_dec_eq(x_15, x_25);
x_27 = 1;
lean_ctor_set(x_1, 4, x_24);
lean_ctor_set(x_1, 3, x_2);
lean_ctor_set(x_1, 1, x_15);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 1, x_26);
lean_ctor_set_uint8(x_1, sizeof(void*)*8 + 2, x_27);
x_28 = lean_alloc_ctor(1, 1, 0);
lean_ctor_set(x_28, 0, x_1);
return x_28;
}
}
}
}
else
{
lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; uint8_t x_33; uint8_t x_34; uint8_t x_35; lean_object* x_36; uint8_t x_37; lean_object* x_38; lean_object* x_39; uint8_t x_40; lean_object* x_41; 
x_29 = lean_ctor_get(x_1, 0);
x_30 = lean_ctor_get(x_1, 1);
x_31 = lean_ctor_get(x_1, 2);
x_32 = lean_ctor_get(x_1, 4);
x_33 = lean_ctor_get_uint8(x_1, sizeof(void*)*8);
x_34 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 3);
x_35 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 4);
x_36 = lean_ctor_get(x_1, 5);
x_37 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 5);
x_38 = lean_ctor_get(x_1, 6);
x_39 = lean_ctor_get(x_1, 7);
x_40 = lean_ctor_get_uint8(x_1, sizeof(void*)*8 + 6);
lean_inc(x_39);
lean_inc(x_38);
lean_inc(x_36);
lean_inc(x_32);
lean_inc(x_31);
lean_inc(x_30);
lean_inc(x_29);
lean_dec(x_1);
x_41 = l_TexasPoker_rust__checked__sub(x_30, x_3);
lean_dec(x_30);
if (lean_obj_tag(x_41) == 0)
{
lean_object* x_42; 
lean_dec(x_39);
lean_dec(x_38);
lean_dec(x_36);
lean_dec(x_32);
lean_dec(x_31);
lean_dec(x_29);
lean_dec(x_2);
x_42 = lean_box(0);
return x_42;
}
else
{
lean_object* x_43; lean_object* x_44; 
x_43 = lean_ctor_get(x_41, 0);
lean_inc(x_43);
lean_dec(x_41);
x_44 = l_TexasPoker_rust__checked__add(x_32, x_3);
if (lean_obj_tag(x_44) == 0)
{
lean_object* x_45; 
lean_dec(x_43);
lean_dec(x_39);
lean_dec(x_38);
lean_dec(x_36);
lean_dec(x_32);
lean_dec(x_31);
lean_dec(x_29);
lean_dec(x_2);
x_45 = lean_box(0);
return x_45;
}
else
{
lean_object* x_46; lean_object* x_47; lean_object* x_48; uint8_t x_49; uint8_t x_50; lean_object* x_51; lean_object* x_52; 
if (lean_is_exclusive(x_44)) {
 lean_ctor_release(x_44, 0);
 x_46 = x_44;
} else {
 lean_dec_ref(x_44);
 x_46 = lean_box(0);
}
x_47 = lean_nat_add(x_32, x_3);
lean_dec(x_32);
x_48 = lean_unsigned_to_nat(0u);
x_49 = lean_nat_dec_eq(x_43, x_48);
x_50 = 1;
x_51 = lean_alloc_ctor(0, 8, 7);
lean_ctor_set(x_51, 0, x_29);
lean_ctor_set(x_51, 1, x_43);
lean_ctor_set(x_51, 2, x_31);
lean_ctor_set(x_51, 3, x_2);
lean_ctor_set(x_51, 4, x_47);
lean_ctor_set(x_51, 5, x_36);
lean_ctor_set(x_51, 6, x_38);
lean_ctor_set(x_51, 7, x_39);
lean_ctor_set_uint8(x_51, sizeof(void*)*8, x_33);
lean_ctor_set_uint8(x_51, sizeof(void*)*8 + 1, x_49);
lean_ctor_set_uint8(x_51, sizeof(void*)*8 + 2, x_50);
lean_ctor_set_uint8(x_51, sizeof(void*)*8 + 3, x_34);
lean_ctor_set_uint8(x_51, sizeof(void*)*8 + 4, x_35);
lean_ctor_set_uint8(x_51, sizeof(void*)*8 + 5, x_37);
lean_ctor_set_uint8(x_51, sizeof(void*)*8 + 6, x_40);
if (lean_is_scalar(x_46)) {
 x_52 = lean_alloc_ctor(1, 1, 0);
} else {
 x_52 = x_46;
}
lean_ctor_set(x_52, 0, x_51);
return x_52;
}
}
}
}
}
LEAN_EXPORT lean_object* l_TexasPoker_rust__apply__raise___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_TexasPoker_rust__apply__raise(x_1, x_2, x_3);
lean_dec(x_3);
return x_4;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_Mathlib(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Constants(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Types(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Betting(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Transitions(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Invariants(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_RoundMachine(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_SidePot(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_SubPhases(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_State_Theorems(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_State_Refinement(uint8_t builtin, lean_object* w) {
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
res = initialize_PokerLean_State_Theorems(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
