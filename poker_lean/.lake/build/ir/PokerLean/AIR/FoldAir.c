// Lean compiler output
// Module: PokerLean.AIR.FoldAir
// Imports: Init PokerLean.Common.M31 PokerLean.Common.U64Encoding PokerLean.Common.CommonColumns PokerLean.Contract.Types PokerLean.Contract.Fold PokerLean.AIR.AirBase
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
static lean_object* l_PokerLean_extractPostTableFromFoldAir___closed__1;
lean_object* l_PokerLean_decodeU64(lean_object*, lean_object*, lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__6;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__17;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__12;
lean_object* l_PokerLean_TexasPokerTable_update__seat(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____boxed(lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__8;
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____boxed(lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__3;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__13;
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromFoldAir(lean_object*, lean_object*, lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__2;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__7;
static lean_object* l_PokerLean_instReprFoldRow___closed__1;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__7;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__24;
extern lean_object* l_PokerLean_Seat_empty;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__1;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__16;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__3;
LEAN_EXPORT lean_object* l_PokerLean_extractPreTableFromFoldAir(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_extractFoldParamsFromAir___boxed(lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__5;
lean_object* lean_nat_to_int(lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__11;
LEAN_EXPORT lean_object* l_PokerLean_extractPreTableFromFoldAir___boxed(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_instReprFoldMethodColumns;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__10;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__18;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__19;
lean_object* l_List_replicateTR___rarg(lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__21;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__15;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__20;
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39_(lean_object*, lean_object*);
uint8_t l_PokerLean_RoundState_fromNat(lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__1;
LEAN_EXPORT lean_object* l_PokerLean_instReprFoldRow;
static lean_object* l_PokerLean_extractPreTableFromFoldAir___closed__3;
static lean_object* l_PokerLean_extractPreTableFromFoldAir___closed__2;
lean_object* lean_string_length(lean_object*);
lean_object* l_PokerLean_Seat_mark__folded(lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__6;
static lean_object* l_PokerLean_instReprFoldMethodColumns___closed__1;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__14;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__4;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__22;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__9;
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__5;
LEAN_EXPORT lean_object* l_PokerLean_extractFoldParamsFromAir(lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__4;
static lean_object* l_PokerLean_extractPreTableFromFoldAir___closed__1;
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157_(lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__2;
lean_object* l___private_Init_Data_Repr_0__Nat_reprFast(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_extractPreTableFromFoldAir___lambda__1(lean_object*);
lean_object* l___private_PokerLean_Common_CommonColumns_0__PokerLean_reprCommonRow____x40_PokerLean_Common_CommonColumns___hyg_1741_(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromFoldAir___boxed(lean_object*, lean_object*, lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__23;
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_seat_index", 16, 16);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__2() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__1;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__3() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = lean_box(0);
x_2 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__2;
x_3 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_3, 0, x_1);
lean_ctor_set(x_3, 1, x_2);
return x_3;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__4() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(" := ", 4, 4);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__5() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__4;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__6() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__3;
x_2 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__5;
x_3 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_3, 0, x_1);
lean_ctor_set(x_3, 1, x_2);
return x_3;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__7() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(20u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__8() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(",", 1, 1);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__9() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__8;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__10() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_current_turn", 18, 18);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__11() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__10;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__12() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(22u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__13() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_seat_occupied", 19, 19);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__14() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__13;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__15() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(23u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__16() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("output_folded", 13, 13);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__17() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__16;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__18() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(17u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__19() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("{ ", 2, 2);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__20() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__19;
x_2 = lean_string_length(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__21() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__20;
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__22() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__19;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__23() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(" }", 2, 2);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__24() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__23;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39_(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; uint8_t x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; lean_object* x_49; lean_object* x_50; lean_object* x_51; lean_object* x_52; lean_object* x_53; lean_object* x_54; lean_object* x_55; lean_object* x_56; lean_object* x_57; 
x_3 = lean_ctor_get(x_1, 0);
lean_inc(x_3);
x_4 = l___private_Init_Data_Repr_0__Nat_reprFast(x_3);
x_5 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_5, 0, x_4);
x_6 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__7;
x_7 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_7, 0, x_6);
lean_ctor_set(x_7, 1, x_5);
x_8 = 0;
x_9 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_9, 0, x_7);
lean_ctor_set_uint8(x_9, sizeof(void*)*1, x_8);
x_10 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__6;
x_11 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_11, 0, x_10);
lean_ctor_set(x_11, 1, x_9);
x_12 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__9;
x_13 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_13, 0, x_11);
lean_ctor_set(x_13, 1, x_12);
x_14 = lean_box(1);
x_15 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_15, 0, x_13);
lean_ctor_set(x_15, 1, x_14);
x_16 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__11;
x_17 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_17, 0, x_15);
lean_ctor_set(x_17, 1, x_16);
x_18 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__5;
x_19 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_19, 0, x_17);
lean_ctor_set(x_19, 1, x_18);
x_20 = lean_ctor_get(x_1, 1);
lean_inc(x_20);
x_21 = l___private_Init_Data_Repr_0__Nat_reprFast(x_20);
x_22 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_22, 0, x_21);
x_23 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__12;
x_24 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_24, 0, x_23);
lean_ctor_set(x_24, 1, x_22);
x_25 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_25, 0, x_24);
lean_ctor_set_uint8(x_25, sizeof(void*)*1, x_8);
x_26 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_26, 0, x_19);
lean_ctor_set(x_26, 1, x_25);
x_27 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_27, 0, x_26);
lean_ctor_set(x_27, 1, x_12);
x_28 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_28, 0, x_27);
lean_ctor_set(x_28, 1, x_14);
x_29 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__14;
x_30 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_30, 0, x_28);
lean_ctor_set(x_30, 1, x_29);
x_31 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_31, 0, x_30);
lean_ctor_set(x_31, 1, x_18);
x_32 = lean_ctor_get(x_1, 2);
lean_inc(x_32);
x_33 = l___private_Init_Data_Repr_0__Nat_reprFast(x_32);
x_34 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_34, 0, x_33);
x_35 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__15;
x_36 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_36, 0, x_35);
lean_ctor_set(x_36, 1, x_34);
x_37 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_37, 0, x_36);
lean_ctor_set_uint8(x_37, sizeof(void*)*1, x_8);
x_38 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_38, 0, x_31);
lean_ctor_set(x_38, 1, x_37);
x_39 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_39, 0, x_38);
lean_ctor_set(x_39, 1, x_12);
x_40 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_40, 0, x_39);
lean_ctor_set(x_40, 1, x_14);
x_41 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__17;
x_42 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_42, 0, x_40);
lean_ctor_set(x_42, 1, x_41);
x_43 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_43, 0, x_42);
lean_ctor_set(x_43, 1, x_18);
x_44 = lean_ctor_get(x_1, 3);
lean_inc(x_44);
lean_dec(x_1);
x_45 = l___private_Init_Data_Repr_0__Nat_reprFast(x_44);
x_46 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_46, 0, x_45);
x_47 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__18;
x_48 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_48, 0, x_47);
lean_ctor_set(x_48, 1, x_46);
x_49 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_49, 0, x_48);
lean_ctor_set_uint8(x_49, sizeof(void*)*1, x_8);
x_50 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_50, 0, x_43);
lean_ctor_set(x_50, 1, x_49);
x_51 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__22;
x_52 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_52, 0, x_51);
lean_ctor_set(x_52, 1, x_50);
x_53 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__24;
x_54 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_54, 0, x_52);
lean_ctor_set(x_54, 1, x_53);
x_55 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__21;
x_56 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_56, 0, x_55);
lean_ctor_set(x_56, 1, x_54);
x_57 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_57, 0, x_56);
lean_ctor_set_uint8(x_57, sizeof(void*)*1, x_8);
return x_57;
}
}
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39_(x_1, x_2);
lean_dec(x_2);
return x_3;
}
}
static lean_object* _init_l_PokerLean_instReprFoldMethodColumns___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_alloc_closure((void*)(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____boxed), 2, 0);
return x_1;
}
}
static lean_object* _init_l_PokerLean_instReprFoldMethodColumns() {
_start:
{
lean_object* x_1; 
x_1 = l_PokerLean_instReprFoldMethodColumns___closed__1;
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("common", 6, 6);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__2() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__1;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__3() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = lean_box(0);
x_2 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__2;
x_3 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_3, 0, x_1);
lean_ctor_set(x_3, 1, x_2);
return x_3;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__4() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__3;
x_2 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__5;
x_3 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_3, 0, x_1);
lean_ctor_set(x_3, 1, x_2);
return x_3;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__5() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(10u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__6() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("method", 6, 6);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__7() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__6;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157_(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; uint8_t x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; 
x_3 = lean_ctor_get(x_1, 0);
lean_inc(x_3);
x_4 = lean_unsigned_to_nat(0u);
x_5 = l___private_PokerLean_Common_CommonColumns_0__PokerLean_reprCommonRow____x40_PokerLean_Common_CommonColumns___hyg_1741_(x_3, x_4);
x_6 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__5;
x_7 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_7, 0, x_6);
lean_ctor_set(x_7, 1, x_5);
x_8 = 0;
x_9 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_9, 0, x_7);
lean_ctor_set_uint8(x_9, sizeof(void*)*1, x_8);
x_10 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__4;
x_11 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_11, 0, x_10);
lean_ctor_set(x_11, 1, x_9);
x_12 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__9;
x_13 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_13, 0, x_11);
lean_ctor_set(x_13, 1, x_12);
x_14 = lean_box(1);
x_15 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_15, 0, x_13);
lean_ctor_set(x_15, 1, x_14);
x_16 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__7;
x_17 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_17, 0, x_15);
lean_ctor_set(x_17, 1, x_16);
x_18 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__5;
x_19 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_19, 0, x_17);
lean_ctor_set(x_19, 1, x_18);
x_20 = lean_ctor_get(x_1, 1);
lean_inc(x_20);
lean_dec(x_1);
x_21 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39_(x_20, x_4);
x_22 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_22, 0, x_6);
lean_ctor_set(x_22, 1, x_21);
x_23 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_23, 0, x_22);
lean_ctor_set_uint8(x_23, sizeof(void*)*1, x_8);
x_24 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_24, 0, x_19);
lean_ctor_set(x_24, 1, x_23);
x_25 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__22;
x_26 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_26, 0, x_25);
lean_ctor_set(x_26, 1, x_24);
x_27 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__24;
x_28 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_28, 0, x_26);
lean_ctor_set(x_28, 1, x_27);
x_29 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__21;
x_30 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_30, 0, x_29);
lean_ctor_set(x_30, 1, x_28);
x_31 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_31, 0, x_30);
lean_ctor_set_uint8(x_31, sizeof(void*)*1, x_8);
return x_31;
}
}
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157_(x_1, x_2);
lean_dec(x_2);
return x_3;
}
}
static lean_object* _init_l_PokerLean_instReprFoldRow___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_alloc_closure((void*)(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____boxed), 2, 0);
return x_1;
}
}
static lean_object* _init_l_PokerLean_instReprFoldRow() {
_start:
{
lean_object* x_1; 
x_1 = l_PokerLean_instReprFoldRow___closed__1;
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractPreTableFromFoldAir___lambda__1(lean_object* x_1) {
_start:
{
uint8_t x_2; 
x_2 = !lean_is_exclusive(x_1);
if (x_2 == 0)
{
lean_object* x_3; lean_object* x_4; 
x_3 = lean_ctor_get(x_1, 0);
lean_dec(x_3);
x_4 = lean_unsigned_to_nat(1u);
lean_ctor_set(x_1, 0, x_4);
return x_1;
}
else
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; uint8_t x_8; uint8_t x_9; uint8_t x_10; uint8_t x_11; uint8_t x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; 
x_5 = lean_ctor_get(x_1, 1);
x_6 = lean_ctor_get(x_1, 2);
x_7 = lean_ctor_get(x_1, 3);
x_8 = lean_ctor_get_uint8(x_1, sizeof(void*)*6);
x_9 = lean_ctor_get_uint8(x_1, sizeof(void*)*6 + 1);
x_10 = lean_ctor_get_uint8(x_1, sizeof(void*)*6 + 2);
x_11 = lean_ctor_get_uint8(x_1, sizeof(void*)*6 + 3);
x_12 = lean_ctor_get_uint8(x_1, sizeof(void*)*6 + 4);
x_13 = lean_ctor_get(x_1, 4);
x_14 = lean_ctor_get(x_1, 5);
lean_inc(x_14);
lean_inc(x_13);
lean_inc(x_7);
lean_inc(x_6);
lean_inc(x_5);
lean_dec(x_1);
x_15 = lean_unsigned_to_nat(1u);
x_16 = lean_alloc_ctor(0, 6, 5);
lean_ctor_set(x_16, 0, x_15);
lean_ctor_set(x_16, 1, x_5);
lean_ctor_set(x_16, 2, x_6);
lean_ctor_set(x_16, 3, x_7);
lean_ctor_set(x_16, 4, x_13);
lean_ctor_set(x_16, 5, x_14);
lean_ctor_set_uint8(x_16, sizeof(void*)*6, x_8);
lean_ctor_set_uint8(x_16, sizeof(void*)*6 + 1, x_9);
lean_ctor_set_uint8(x_16, sizeof(void*)*6 + 2, x_10);
lean_ctor_set_uint8(x_16, sizeof(void*)*6 + 3, x_11);
lean_ctor_set_uint8(x_16, sizeof(void*)*6 + 4, x_12);
return x_16;
}
}
}
static lean_object* _init_l_PokerLean_extractPreTableFromFoldAir___closed__1() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; lean_object* x_4; 
x_1 = lean_box(0);
x_2 = lean_box(0);
x_3 = lean_unsigned_to_nat(0u);
x_4 = lean_alloc_ctor(0, 4, 0);
lean_ctor_set(x_4, 0, x_3);
lean_ctor_set(x_4, 1, x_2);
lean_ctor_set(x_4, 2, x_1);
lean_ctor_set(x_4, 3, x_1);
return x_4;
}
}
static lean_object* _init_l_PokerLean_extractPreTableFromFoldAir___closed__2() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(0u);
x_2 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_2, 0, x_1);
lean_ctor_set(x_2, 1, x_1);
return x_2;
}
}
static lean_object* _init_l_PokerLean_extractPreTableFromFoldAir___closed__3() {
_start:
{
lean_object* x_1; 
x_1 = lean_alloc_closure((void*)(l_PokerLean_extractPreTableFromFoldAir___lambda__1), 1, 0);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractPreTableFromFoldAir(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; uint8_t x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; uint8_t x_34; uint8_t x_35; uint8_t x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; 
x_4 = l_PokerLean_Seat_empty;
lean_inc(x_3);
x_5 = l_List_replicateTR___rarg(x_3, x_4);
x_6 = lean_ctor_get(x_1, 7);
x_7 = lean_ctor_get(x_6, 0);
x_8 = lean_ctor_get(x_6, 1);
x_9 = lean_ctor_get(x_8, 0);
x_10 = lean_ctor_get(x_8, 1);
x_11 = lean_ctor_get(x_10, 0);
x_12 = lean_ctor_get(x_10, 1);
x_13 = l_PokerLean_decodeU64(x_7, x_9, x_11, x_12);
x_14 = lean_ctor_get(x_1, 9);
x_15 = l_PokerLean_RoundState_fromNat(x_14);
x_16 = lean_ctor_get(x_2, 0);
lean_inc(x_16);
x_17 = lean_ctor_get(x_2, 1);
lean_inc(x_17);
lean_dec(x_2);
x_18 = lean_ctor_get(x_1, 13);
x_19 = lean_ctor_get(x_1, 11);
x_20 = lean_ctor_get(x_19, 0);
x_21 = lean_ctor_get(x_19, 1);
x_22 = lean_ctor_get(x_21, 0);
x_23 = lean_ctor_get(x_21, 1);
x_24 = lean_ctor_get(x_23, 0);
x_25 = lean_ctor_get(x_23, 1);
x_26 = l_PokerLean_decodeU64(x_20, x_22, x_24, x_25);
x_27 = lean_box(0);
x_28 = lean_unsigned_to_nat(0u);
lean_inc(x_18);
x_29 = lean_alloc_ctor(0, 8, 0);
lean_ctor_set(x_29, 0, x_28);
lean_ctor_set(x_29, 1, x_17);
lean_ctor_set(x_29, 2, x_18);
lean_ctor_set(x_29, 3, x_26);
lean_ctor_set(x_29, 4, x_27);
lean_ctor_set(x_29, 5, x_28);
lean_ctor_set(x_29, 6, x_28);
lean_ctor_set(x_29, 7, x_28);
x_30 = lean_ctor_get(x_1, 5);
x_31 = lean_ctor_get(x_1, 6);
x_32 = l_PokerLean_extractPreTableFromFoldAir___closed__1;
x_33 = l_PokerLean_extractPreTableFromFoldAir___closed__2;
x_34 = 0;
x_35 = 0;
x_36 = 0;
lean_inc(x_31);
lean_inc(x_30);
x_37 = lean_alloc_ctor(0, 22, 4);
lean_ctor_set(x_37, 0, x_28);
lean_ctor_set(x_37, 1, x_28);
lean_ctor_set(x_37, 2, x_5);
lean_ctor_set(x_37, 3, x_3);
lean_ctor_set(x_37, 4, x_28);
lean_ctor_set(x_37, 5, x_28);
lean_ctor_set(x_37, 6, x_28);
lean_ctor_set(x_37, 7, x_13);
lean_ctor_set(x_37, 8, x_29);
lean_ctor_set(x_37, 9, x_32);
lean_ctor_set(x_37, 10, x_33);
lean_ctor_set(x_37, 11, x_30);
lean_ctor_set(x_37, 12, x_31);
lean_ctor_set(x_37, 13, x_28);
lean_ctor_set(x_37, 14, x_28);
lean_ctor_set(x_37, 15, x_28);
lean_ctor_set(x_37, 16, x_28);
lean_ctor_set(x_37, 17, x_28);
lean_ctor_set(x_37, 18, x_28);
lean_ctor_set(x_37, 19, x_28);
lean_ctor_set(x_37, 20, x_28);
lean_ctor_set(x_37, 21, x_28);
lean_ctor_set_uint8(x_37, sizeof(void*)*22, x_15);
lean_ctor_set_uint8(x_37, sizeof(void*)*22 + 1, x_34);
lean_ctor_set_uint8(x_37, sizeof(void*)*22 + 2, x_35);
lean_ctor_set_uint8(x_37, sizeof(void*)*22 + 3, x_36);
x_38 = l_PokerLean_extractPreTableFromFoldAir___closed__3;
x_39 = l_PokerLean_TexasPokerTable_update__seat(x_37, x_16, x_38);
return x_39;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractPreTableFromFoldAir___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_PokerLean_extractPreTableFromFoldAir(x_1, x_2, x_3);
lean_dec(x_1);
return x_4;
}
}
static lean_object* _init_l_PokerLean_extractPostTableFromFoldAir___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_alloc_closure((void*)(l_PokerLean_Seat_mark__folded), 1, 0);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromFoldAir(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; uint8_t x_6; 
x_5 = l_PokerLean_extractPreTableFromFoldAir(x_1, x_2, x_3);
x_6 = !lean_is_exclusive(x_5);
if (x_6 == 0)
{
lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; uint8_t x_18; uint8_t x_19; 
x_7 = lean_ctor_get(x_5, 8);
x_8 = lean_ctor_get(x_5, 7);
lean_dec(x_8);
x_9 = lean_ctor_get(x_1, 8);
x_10 = lean_ctor_get(x_9, 0);
x_11 = lean_ctor_get(x_9, 1);
x_12 = lean_ctor_get(x_11, 0);
x_13 = lean_ctor_get(x_11, 1);
x_14 = lean_ctor_get(x_13, 0);
x_15 = lean_ctor_get(x_13, 1);
x_16 = l_PokerLean_decodeU64(x_10, x_12, x_14, x_15);
x_17 = lean_ctor_get(x_1, 10);
x_18 = l_PokerLean_RoundState_fromNat(x_17);
x_19 = !lean_is_exclusive(x_7);
if (x_19 == 0)
{
lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; 
x_20 = lean_ctor_get(x_7, 3);
lean_dec(x_20);
x_21 = lean_ctor_get(x_7, 2);
lean_dec(x_21);
x_22 = lean_ctor_get(x_1, 14);
x_23 = lean_ctor_get(x_1, 12);
x_24 = lean_ctor_get(x_23, 0);
x_25 = lean_ctor_get(x_23, 1);
x_26 = lean_ctor_get(x_25, 0);
x_27 = lean_ctor_get(x_25, 1);
x_28 = lean_ctor_get(x_27, 0);
x_29 = lean_ctor_get(x_27, 1);
x_30 = l_PokerLean_decodeU64(x_24, x_26, x_28, x_29);
lean_inc(x_22);
lean_ctor_set(x_7, 3, x_30);
lean_ctor_set(x_7, 2, x_22);
lean_ctor_set(x_5, 7, x_16);
lean_ctor_set_uint8(x_5, sizeof(void*)*22, x_18);
x_31 = l_PokerLean_extractPostTableFromFoldAir___closed__1;
x_32 = l_PokerLean_TexasPokerTable_update__seat(x_5, x_4, x_31);
return x_32;
}
else
{
lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; lean_object* x_49; lean_object* x_50; 
x_33 = lean_ctor_get(x_7, 0);
x_34 = lean_ctor_get(x_7, 1);
x_35 = lean_ctor_get(x_7, 4);
x_36 = lean_ctor_get(x_7, 5);
x_37 = lean_ctor_get(x_7, 6);
x_38 = lean_ctor_get(x_7, 7);
lean_inc(x_38);
lean_inc(x_37);
lean_inc(x_36);
lean_inc(x_35);
lean_inc(x_34);
lean_inc(x_33);
lean_dec(x_7);
x_39 = lean_ctor_get(x_1, 14);
x_40 = lean_ctor_get(x_1, 12);
x_41 = lean_ctor_get(x_40, 0);
x_42 = lean_ctor_get(x_40, 1);
x_43 = lean_ctor_get(x_42, 0);
x_44 = lean_ctor_get(x_42, 1);
x_45 = lean_ctor_get(x_44, 0);
x_46 = lean_ctor_get(x_44, 1);
x_47 = l_PokerLean_decodeU64(x_41, x_43, x_45, x_46);
lean_inc(x_39);
x_48 = lean_alloc_ctor(0, 8, 0);
lean_ctor_set(x_48, 0, x_33);
lean_ctor_set(x_48, 1, x_34);
lean_ctor_set(x_48, 2, x_39);
lean_ctor_set(x_48, 3, x_47);
lean_ctor_set(x_48, 4, x_35);
lean_ctor_set(x_48, 5, x_36);
lean_ctor_set(x_48, 6, x_37);
lean_ctor_set(x_48, 7, x_38);
lean_ctor_set(x_5, 8, x_48);
lean_ctor_set(x_5, 7, x_16);
lean_ctor_set_uint8(x_5, sizeof(void*)*22, x_18);
x_49 = l_PokerLean_extractPostTableFromFoldAir___closed__1;
x_50 = l_PokerLean_TexasPokerTable_update__seat(x_5, x_4, x_49);
return x_50;
}
}
else
{
lean_object* x_51; lean_object* x_52; lean_object* x_53; lean_object* x_54; lean_object* x_55; lean_object* x_56; lean_object* x_57; lean_object* x_58; lean_object* x_59; lean_object* x_60; uint8_t x_61; uint8_t x_62; lean_object* x_63; lean_object* x_64; lean_object* x_65; lean_object* x_66; lean_object* x_67; lean_object* x_68; lean_object* x_69; lean_object* x_70; uint8_t x_71; lean_object* x_72; lean_object* x_73; lean_object* x_74; lean_object* x_75; lean_object* x_76; lean_object* x_77; lean_object* x_78; lean_object* x_79; lean_object* x_80; lean_object* x_81; lean_object* x_82; lean_object* x_83; uint8_t x_84; lean_object* x_85; lean_object* x_86; lean_object* x_87; lean_object* x_88; lean_object* x_89; lean_object* x_90; lean_object* x_91; lean_object* x_92; lean_object* x_93; lean_object* x_94; lean_object* x_95; lean_object* x_96; lean_object* x_97; lean_object* x_98; lean_object* x_99; lean_object* x_100; lean_object* x_101; lean_object* x_102; lean_object* x_103; lean_object* x_104; 
x_51 = lean_ctor_get(x_5, 0);
x_52 = lean_ctor_get(x_5, 1);
x_53 = lean_ctor_get(x_5, 2);
x_54 = lean_ctor_get(x_5, 3);
x_55 = lean_ctor_get(x_5, 4);
x_56 = lean_ctor_get(x_5, 5);
x_57 = lean_ctor_get(x_5, 6);
x_58 = lean_ctor_get(x_5, 8);
x_59 = lean_ctor_get(x_5, 9);
x_60 = lean_ctor_get(x_5, 10);
x_61 = lean_ctor_get_uint8(x_5, sizeof(void*)*22 + 1);
x_62 = lean_ctor_get_uint8(x_5, sizeof(void*)*22 + 2);
x_63 = lean_ctor_get(x_5, 11);
x_64 = lean_ctor_get(x_5, 12);
x_65 = lean_ctor_get(x_5, 13);
x_66 = lean_ctor_get(x_5, 14);
x_67 = lean_ctor_get(x_5, 15);
x_68 = lean_ctor_get(x_5, 16);
x_69 = lean_ctor_get(x_5, 17);
x_70 = lean_ctor_get(x_5, 18);
x_71 = lean_ctor_get_uint8(x_5, sizeof(void*)*22 + 3);
x_72 = lean_ctor_get(x_5, 19);
x_73 = lean_ctor_get(x_5, 20);
x_74 = lean_ctor_get(x_5, 21);
lean_inc(x_74);
lean_inc(x_73);
lean_inc(x_72);
lean_inc(x_70);
lean_inc(x_69);
lean_inc(x_68);
lean_inc(x_67);
lean_inc(x_66);
lean_inc(x_65);
lean_inc(x_64);
lean_inc(x_63);
lean_inc(x_60);
lean_inc(x_59);
lean_inc(x_58);
lean_inc(x_57);
lean_inc(x_56);
lean_inc(x_55);
lean_inc(x_54);
lean_inc(x_53);
lean_inc(x_52);
lean_inc(x_51);
lean_dec(x_5);
x_75 = lean_ctor_get(x_1, 8);
x_76 = lean_ctor_get(x_75, 0);
x_77 = lean_ctor_get(x_75, 1);
x_78 = lean_ctor_get(x_77, 0);
x_79 = lean_ctor_get(x_77, 1);
x_80 = lean_ctor_get(x_79, 0);
x_81 = lean_ctor_get(x_79, 1);
x_82 = l_PokerLean_decodeU64(x_76, x_78, x_80, x_81);
x_83 = lean_ctor_get(x_1, 10);
x_84 = l_PokerLean_RoundState_fromNat(x_83);
x_85 = lean_ctor_get(x_58, 0);
lean_inc(x_85);
x_86 = lean_ctor_get(x_58, 1);
lean_inc(x_86);
x_87 = lean_ctor_get(x_58, 4);
lean_inc(x_87);
x_88 = lean_ctor_get(x_58, 5);
lean_inc(x_88);
x_89 = lean_ctor_get(x_58, 6);
lean_inc(x_89);
x_90 = lean_ctor_get(x_58, 7);
lean_inc(x_90);
if (lean_is_exclusive(x_58)) {
 lean_ctor_release(x_58, 0);
 lean_ctor_release(x_58, 1);
 lean_ctor_release(x_58, 2);
 lean_ctor_release(x_58, 3);
 lean_ctor_release(x_58, 4);
 lean_ctor_release(x_58, 5);
 lean_ctor_release(x_58, 6);
 lean_ctor_release(x_58, 7);
 x_91 = x_58;
} else {
 lean_dec_ref(x_58);
 x_91 = lean_box(0);
}
x_92 = lean_ctor_get(x_1, 14);
x_93 = lean_ctor_get(x_1, 12);
x_94 = lean_ctor_get(x_93, 0);
x_95 = lean_ctor_get(x_93, 1);
x_96 = lean_ctor_get(x_95, 0);
x_97 = lean_ctor_get(x_95, 1);
x_98 = lean_ctor_get(x_97, 0);
x_99 = lean_ctor_get(x_97, 1);
x_100 = l_PokerLean_decodeU64(x_94, x_96, x_98, x_99);
lean_inc(x_92);
if (lean_is_scalar(x_91)) {
 x_101 = lean_alloc_ctor(0, 8, 0);
} else {
 x_101 = x_91;
}
lean_ctor_set(x_101, 0, x_85);
lean_ctor_set(x_101, 1, x_86);
lean_ctor_set(x_101, 2, x_92);
lean_ctor_set(x_101, 3, x_100);
lean_ctor_set(x_101, 4, x_87);
lean_ctor_set(x_101, 5, x_88);
lean_ctor_set(x_101, 6, x_89);
lean_ctor_set(x_101, 7, x_90);
x_102 = lean_alloc_ctor(0, 22, 4);
lean_ctor_set(x_102, 0, x_51);
lean_ctor_set(x_102, 1, x_52);
lean_ctor_set(x_102, 2, x_53);
lean_ctor_set(x_102, 3, x_54);
lean_ctor_set(x_102, 4, x_55);
lean_ctor_set(x_102, 5, x_56);
lean_ctor_set(x_102, 6, x_57);
lean_ctor_set(x_102, 7, x_82);
lean_ctor_set(x_102, 8, x_101);
lean_ctor_set(x_102, 9, x_59);
lean_ctor_set(x_102, 10, x_60);
lean_ctor_set(x_102, 11, x_63);
lean_ctor_set(x_102, 12, x_64);
lean_ctor_set(x_102, 13, x_65);
lean_ctor_set(x_102, 14, x_66);
lean_ctor_set(x_102, 15, x_67);
lean_ctor_set(x_102, 16, x_68);
lean_ctor_set(x_102, 17, x_69);
lean_ctor_set(x_102, 18, x_70);
lean_ctor_set(x_102, 19, x_72);
lean_ctor_set(x_102, 20, x_73);
lean_ctor_set(x_102, 21, x_74);
lean_ctor_set_uint8(x_102, sizeof(void*)*22, x_84);
lean_ctor_set_uint8(x_102, sizeof(void*)*22 + 1, x_61);
lean_ctor_set_uint8(x_102, sizeof(void*)*22 + 2, x_62);
lean_ctor_set_uint8(x_102, sizeof(void*)*22 + 3, x_71);
x_103 = l_PokerLean_extractPostTableFromFoldAir___closed__1;
x_104 = l_PokerLean_TexasPokerTable_update__seat(x_102, x_4, x_103);
return x_104;
}
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromFoldAir___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; 
x_5 = l_PokerLean_extractPostTableFromFoldAir(x_1, x_2, x_3, x_4);
lean_dec(x_1);
return x_5;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractFoldParamsFromAir(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = lean_ctor_get(x_1, 0);
lean_inc(x_2);
return x_2;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractFoldParamsFromAir___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_PokerLean_extractFoldParamsFromAir(x_1);
lean_dec(x_1);
return x_2;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_M31(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_U64Encoding(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_CommonColumns(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Contract_Types(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Contract_Fold(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_AIR_AirBase(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_AIR_FoldAir(uint8_t builtin, lean_object* w) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Common_M31(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Common_U64Encoding(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Common_CommonColumns(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Contract_Types(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Contract_Fold(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_AIR_AirBase(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__1 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__1();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__1);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__2 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__2();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__2);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__3 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__3();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__3);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__4 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__4();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__4);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__5 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__5();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__5);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__6 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__6();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__6);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__7 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__7();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__7);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__8 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__8();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__8);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__9 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__9();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__9);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__10 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__10();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__10);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__11 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__11();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__11);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__12 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__12();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__12);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__13 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__13();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__13);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__14 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__14();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__14);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__15 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__15();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__15);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__16 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__16();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__16);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__17 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__17();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__17);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__18 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__18();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__18);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__19 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__19();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__19);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__20 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__20();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__20);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__21 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__21();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__21);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__22 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__22();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__22);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__23 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__23();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__23);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__24 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__24();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldMethodColumns____x40_PokerLean_AIR_FoldAir___hyg_39____closed__24);
l_PokerLean_instReprFoldMethodColumns___closed__1 = _init_l_PokerLean_instReprFoldMethodColumns___closed__1();
lean_mark_persistent(l_PokerLean_instReprFoldMethodColumns___closed__1);
l_PokerLean_instReprFoldMethodColumns = _init_l_PokerLean_instReprFoldMethodColumns();
lean_mark_persistent(l_PokerLean_instReprFoldMethodColumns);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__1 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__1();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__1);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__2 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__2();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__2);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__3 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__3();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__3);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__4 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__4();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__4);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__5 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__5();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__5);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__6 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__6();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__6);
l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__7 = _init_l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__7();
lean_mark_persistent(l___private_PokerLean_AIR_FoldAir_0__PokerLean_reprFoldRow____x40_PokerLean_AIR_FoldAir___hyg_157____closed__7);
l_PokerLean_instReprFoldRow___closed__1 = _init_l_PokerLean_instReprFoldRow___closed__1();
lean_mark_persistent(l_PokerLean_instReprFoldRow___closed__1);
l_PokerLean_instReprFoldRow = _init_l_PokerLean_instReprFoldRow();
lean_mark_persistent(l_PokerLean_instReprFoldRow);
l_PokerLean_extractPreTableFromFoldAir___closed__1 = _init_l_PokerLean_extractPreTableFromFoldAir___closed__1();
lean_mark_persistent(l_PokerLean_extractPreTableFromFoldAir___closed__1);
l_PokerLean_extractPreTableFromFoldAir___closed__2 = _init_l_PokerLean_extractPreTableFromFoldAir___closed__2();
lean_mark_persistent(l_PokerLean_extractPreTableFromFoldAir___closed__2);
l_PokerLean_extractPreTableFromFoldAir___closed__3 = _init_l_PokerLean_extractPreTableFromFoldAir___closed__3();
lean_mark_persistent(l_PokerLean_extractPreTableFromFoldAir___closed__3);
l_PokerLean_extractPostTableFromFoldAir___closed__1 = _init_l_PokerLean_extractPostTableFromFoldAir___closed__1();
lean_mark_persistent(l_PokerLean_extractPostTableFromFoldAir___closed__1);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
