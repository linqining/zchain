// Lean compiler output
// Module: PokerLean.AIR.JoinTableAir
// Imports: Init PokerLean.Common.M31 PokerLean.Common.U64Encoding PokerLean.Common.CommonColumns PokerLean.Contract.Types PokerLean.Contract.JoinTable PokerLean.AIR.AirBase PokerLean.AIR.FundsAir
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
static lean_object* l_PokerLean_extractPreTableFromJoinTableAir___closed__2;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__29;
lean_object* l_PokerLean_decodeU64(lean_object*, lean_object*, lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__20;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__39;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__25;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__5;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__15;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__38;
lean_object* l_PokerLean_TexasPokerTable_update__seat(lean_object*, lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__37;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__4;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__2;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__6;
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromJoinTableAir___lambda__1(lean_object*, lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__1;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__16;
extern lean_object* l_PokerLean_Seat_empty;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__43;
LEAN_EXPORT lean_object* l_PokerLean_extractJoinTableParamsFromAir_x27(lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__44;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__23;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__10;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__21;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__19;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__34;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__27;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__8;
static lean_object* l_PokerLean_extractPreTableFromJoinTableAir___closed__1;
lean_object* lean_nat_to_int(lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__9;
LEAN_EXPORT lean_object* l_PokerLean_extractJoinTableParamsFromAir_x27___boxed(lean_object*);
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232_(lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__46;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__14;
LEAN_EXPORT lean_object* l_PokerLean_extractPreTableFromJoinTableAir___boxed(lean_object*, lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__40;
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromJoinTableAir(lean_object*, lean_object*, lean_object*, lean_object*);
lean_object* l_Prod_repr___at___private_PokerLean_Common_CommonColumns_0__PokerLean_reprCommonRow____x40_PokerLean_Common_CommonColumns___hyg_1741____spec__1(lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__12;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__13;
lean_object* l_List_replicateTR___rarg(lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__32;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__41;
LEAN_EXPORT lean_object* l_PokerLean_instReprJoinTableMethodColumns;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__11;
LEAN_EXPORT lean_object* l_PokerLean_extractJoinTableParamsFromAir___boxed(lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__24;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__36;
uint8_t l_PokerLean_RoundState_fromNat(lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__42;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__45;
lean_object* lean_string_length(lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__28;
lean_object* l_Prod_repr___at___private_PokerLean_AIR_FundsAir_0__PokerLean_reprAddonMethodColumns____x40_PokerLean_AIR_FundsAir___hyg_387____spec__1(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_extractPreTableFromJoinTableAir(lean_object*, lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__33;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__3;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__22;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__31;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__7;
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromJoinTableAir___boxed(lean_object*, lean_object*, lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__35;
static lean_object* l_PokerLean_instReprJoinTableMethodColumns___closed__1;
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromJoinTableAir___lambda__1___boxed(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____boxed(lean_object*, lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__17;
LEAN_EXPORT lean_object* l_PokerLean_extractJoinTableParamsFromAir(lean_object*, lean_object*);
lean_object* l___private_Init_Data_Repr_0__Nat_reprFast(lean_object*);
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__26;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__30;
static lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__18;
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_seat_index", 16, 16);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__2() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__1;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__3() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = lean_box(0);
x_2 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__2;
x_3 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_3, 0, x_1);
lean_ctor_set(x_3, 1, x_2);
return x_3;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__4() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(" := ", 4, 4);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__5() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__4;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__6() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__3;
x_2 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__5;
x_3 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_3, 0, x_1);
lean_ctor_set(x_3, 1, x_2);
return x_3;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__7() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(20u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__8() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(",", 1, 1);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__9() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__8;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__10() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_buy_in", 12, 12);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__11() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__10;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__12() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(16u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__13() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_player_addr", 17, 17);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__14() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__13;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__15() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(21u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__16() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_seat_is_occupied", 22, 22);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__17() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__16;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__18() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(26u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__19() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_big_blind", 15, 15);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__20() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__19;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__21() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(19u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__22() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_pre_chip_pool", 19, 19);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__23() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__22;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__24() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(23u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__25() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("output_post_chip_pool", 21, 21);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__26() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__25;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__27() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(25u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__28() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("output_seat_stack", 17, 17);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__29() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__28;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__30() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_pre_addon_pool", 20, 20);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__31() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__30;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__32() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(24u);
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__33() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_bound_diff", 16, 16);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__34() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__33;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__35() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_bound_carry_lo", 20, 20);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__36() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__35;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__37() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("input_bound_carry_hi", 20, 20);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__38() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__37;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__39() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("chip_pool_add_carry", 19, 19);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__40() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__39;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__41() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked("{ ", 2, 2);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__42() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__41;
x_2 = lean_string_length(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__43() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__42;
x_2 = lean_nat_to_int(x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__44() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__41;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__45() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_unchecked(" }", 2, 2);
return x_1;
}
}
static lean_object* _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__46() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__45;
x_2 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232_(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; uint8_t x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; lean_object* x_49; lean_object* x_50; lean_object* x_51; lean_object* x_52; lean_object* x_53; lean_object* x_54; lean_object* x_55; lean_object* x_56; lean_object* x_57; lean_object* x_58; lean_object* x_59; lean_object* x_60; lean_object* x_61; lean_object* x_62; lean_object* x_63; lean_object* x_64; lean_object* x_65; lean_object* x_66; lean_object* x_67; lean_object* x_68; lean_object* x_69; lean_object* x_70; lean_object* x_71; lean_object* x_72; lean_object* x_73; lean_object* x_74; lean_object* x_75; lean_object* x_76; lean_object* x_77; lean_object* x_78; lean_object* x_79; lean_object* x_80; lean_object* x_81; lean_object* x_82; lean_object* x_83; lean_object* x_84; lean_object* x_85; lean_object* x_86; lean_object* x_87; lean_object* x_88; lean_object* x_89; lean_object* x_90; lean_object* x_91; lean_object* x_92; lean_object* x_93; lean_object* x_94; lean_object* x_95; lean_object* x_96; lean_object* x_97; lean_object* x_98; lean_object* x_99; lean_object* x_100; lean_object* x_101; lean_object* x_102; lean_object* x_103; lean_object* x_104; lean_object* x_105; lean_object* x_106; lean_object* x_107; lean_object* x_108; lean_object* x_109; lean_object* x_110; lean_object* x_111; lean_object* x_112; lean_object* x_113; lean_object* x_114; lean_object* x_115; lean_object* x_116; lean_object* x_117; lean_object* x_118; lean_object* x_119; lean_object* x_120; lean_object* x_121; lean_object* x_122; lean_object* x_123; lean_object* x_124; lean_object* x_125; lean_object* x_126; lean_object* x_127; lean_object* x_128; lean_object* x_129; lean_object* x_130; lean_object* x_131; lean_object* x_132; lean_object* x_133; lean_object* x_134; lean_object* x_135; lean_object* x_136; lean_object* x_137; lean_object* x_138; lean_object* x_139; lean_object* x_140; lean_object* x_141; lean_object* x_142; lean_object* x_143; lean_object* x_144; lean_object* x_145; lean_object* x_146; lean_object* x_147; lean_object* x_148; lean_object* x_149; lean_object* x_150; 
x_3 = lean_ctor_get(x_1, 0);
lean_inc(x_3);
x_4 = l___private_Init_Data_Repr_0__Nat_reprFast(x_3);
x_5 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_5, 0, x_4);
x_6 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__7;
x_7 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_7, 0, x_6);
lean_ctor_set(x_7, 1, x_5);
x_8 = 0;
x_9 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_9, 0, x_7);
lean_ctor_set_uint8(x_9, sizeof(void*)*1, x_8);
x_10 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__6;
x_11 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_11, 0, x_10);
lean_ctor_set(x_11, 1, x_9);
x_12 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__9;
x_13 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_13, 0, x_11);
lean_ctor_set(x_13, 1, x_12);
x_14 = lean_box(1);
x_15 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_15, 0, x_13);
lean_ctor_set(x_15, 1, x_14);
x_16 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__11;
x_17 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_17, 0, x_15);
lean_ctor_set(x_17, 1, x_16);
x_18 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__5;
x_19 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_19, 0, x_17);
lean_ctor_set(x_19, 1, x_18);
x_20 = lean_ctor_get(x_1, 1);
lean_inc(x_20);
x_21 = lean_unsigned_to_nat(0u);
x_22 = l_Prod_repr___at___private_PokerLean_Common_CommonColumns_0__PokerLean_reprCommonRow____x40_PokerLean_Common_CommonColumns___hyg_1741____spec__1(x_20, x_21);
x_23 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__12;
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
x_29 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__14;
x_30 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_30, 0, x_28);
lean_ctor_set(x_30, 1, x_29);
x_31 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_31, 0, x_30);
lean_ctor_set(x_31, 1, x_18);
x_32 = lean_ctor_get(x_1, 2);
lean_inc(x_32);
x_33 = l_Prod_repr___at___private_PokerLean_Common_CommonColumns_0__PokerLean_reprCommonRow____x40_PokerLean_Common_CommonColumns___hyg_1741____spec__1(x_32, x_21);
x_34 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__15;
x_35 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_35, 0, x_34);
lean_ctor_set(x_35, 1, x_33);
x_36 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_36, 0, x_35);
lean_ctor_set_uint8(x_36, sizeof(void*)*1, x_8);
x_37 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_37, 0, x_31);
lean_ctor_set(x_37, 1, x_36);
x_38 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_38, 0, x_37);
lean_ctor_set(x_38, 1, x_12);
x_39 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_39, 0, x_38);
lean_ctor_set(x_39, 1, x_14);
x_40 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__17;
x_41 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_41, 0, x_39);
lean_ctor_set(x_41, 1, x_40);
x_42 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_42, 0, x_41);
lean_ctor_set(x_42, 1, x_18);
x_43 = lean_ctor_get(x_1, 3);
lean_inc(x_43);
x_44 = l___private_Init_Data_Repr_0__Nat_reprFast(x_43);
x_45 = lean_alloc_ctor(3, 1, 0);
lean_ctor_set(x_45, 0, x_44);
x_46 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__18;
x_47 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_47, 0, x_46);
lean_ctor_set(x_47, 1, x_45);
x_48 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_48, 0, x_47);
lean_ctor_set_uint8(x_48, sizeof(void*)*1, x_8);
x_49 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_49, 0, x_42);
lean_ctor_set(x_49, 1, x_48);
x_50 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_50, 0, x_49);
lean_ctor_set(x_50, 1, x_12);
x_51 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_51, 0, x_50);
lean_ctor_set(x_51, 1, x_14);
x_52 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__20;
x_53 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_53, 0, x_51);
lean_ctor_set(x_53, 1, x_52);
x_54 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_54, 0, x_53);
lean_ctor_set(x_54, 1, x_18);
x_55 = lean_ctor_get(x_1, 4);
lean_inc(x_55);
x_56 = l_Prod_repr___at___private_PokerLean_Common_CommonColumns_0__PokerLean_reprCommonRow____x40_PokerLean_Common_CommonColumns___hyg_1741____spec__1(x_55, x_21);
x_57 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__21;
x_58 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_58, 0, x_57);
lean_ctor_set(x_58, 1, x_56);
x_59 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_59, 0, x_58);
lean_ctor_set_uint8(x_59, sizeof(void*)*1, x_8);
x_60 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_60, 0, x_54);
lean_ctor_set(x_60, 1, x_59);
x_61 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_61, 0, x_60);
lean_ctor_set(x_61, 1, x_12);
x_62 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_62, 0, x_61);
lean_ctor_set(x_62, 1, x_14);
x_63 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__23;
x_64 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_64, 0, x_62);
lean_ctor_set(x_64, 1, x_63);
x_65 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_65, 0, x_64);
lean_ctor_set(x_65, 1, x_18);
x_66 = lean_ctor_get(x_1, 5);
lean_inc(x_66);
x_67 = l_Prod_repr___at___private_PokerLean_Common_CommonColumns_0__PokerLean_reprCommonRow____x40_PokerLean_Common_CommonColumns___hyg_1741____spec__1(x_66, x_21);
x_68 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__24;
x_69 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_69, 0, x_68);
lean_ctor_set(x_69, 1, x_67);
x_70 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_70, 0, x_69);
lean_ctor_set_uint8(x_70, sizeof(void*)*1, x_8);
x_71 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_71, 0, x_65);
lean_ctor_set(x_71, 1, x_70);
x_72 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_72, 0, x_71);
lean_ctor_set(x_72, 1, x_12);
x_73 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_73, 0, x_72);
lean_ctor_set(x_73, 1, x_14);
x_74 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__26;
x_75 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_75, 0, x_73);
lean_ctor_set(x_75, 1, x_74);
x_76 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_76, 0, x_75);
lean_ctor_set(x_76, 1, x_18);
x_77 = lean_ctor_get(x_1, 6);
lean_inc(x_77);
x_78 = l_Prod_repr___at___private_PokerLean_Common_CommonColumns_0__PokerLean_reprCommonRow____x40_PokerLean_Common_CommonColumns___hyg_1741____spec__1(x_77, x_21);
x_79 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__27;
x_80 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_80, 0, x_79);
lean_ctor_set(x_80, 1, x_78);
x_81 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_81, 0, x_80);
lean_ctor_set_uint8(x_81, sizeof(void*)*1, x_8);
x_82 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_82, 0, x_76);
lean_ctor_set(x_82, 1, x_81);
x_83 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_83, 0, x_82);
lean_ctor_set(x_83, 1, x_12);
x_84 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_84, 0, x_83);
lean_ctor_set(x_84, 1, x_14);
x_85 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__29;
x_86 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_86, 0, x_84);
lean_ctor_set(x_86, 1, x_85);
x_87 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_87, 0, x_86);
lean_ctor_set(x_87, 1, x_18);
x_88 = lean_ctor_get(x_1, 7);
lean_inc(x_88);
x_89 = l_Prod_repr___at___private_PokerLean_Common_CommonColumns_0__PokerLean_reprCommonRow____x40_PokerLean_Common_CommonColumns___hyg_1741____spec__1(x_88, x_21);
x_90 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_90, 0, x_34);
lean_ctor_set(x_90, 1, x_89);
x_91 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_91, 0, x_90);
lean_ctor_set_uint8(x_91, sizeof(void*)*1, x_8);
x_92 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_92, 0, x_87);
lean_ctor_set(x_92, 1, x_91);
x_93 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_93, 0, x_92);
lean_ctor_set(x_93, 1, x_12);
x_94 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_94, 0, x_93);
lean_ctor_set(x_94, 1, x_14);
x_95 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__31;
x_96 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_96, 0, x_94);
lean_ctor_set(x_96, 1, x_95);
x_97 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_97, 0, x_96);
lean_ctor_set(x_97, 1, x_18);
x_98 = lean_ctor_get(x_1, 8);
lean_inc(x_98);
x_99 = l_Prod_repr___at___private_PokerLean_Common_CommonColumns_0__PokerLean_reprCommonRow____x40_PokerLean_Common_CommonColumns___hyg_1741____spec__1(x_98, x_21);
x_100 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__32;
x_101 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_101, 0, x_100);
lean_ctor_set(x_101, 1, x_99);
x_102 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_102, 0, x_101);
lean_ctor_set_uint8(x_102, sizeof(void*)*1, x_8);
x_103 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_103, 0, x_97);
lean_ctor_set(x_103, 1, x_102);
x_104 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_104, 0, x_103);
lean_ctor_set(x_104, 1, x_12);
x_105 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_105, 0, x_104);
lean_ctor_set(x_105, 1, x_14);
x_106 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__34;
x_107 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_107, 0, x_105);
lean_ctor_set(x_107, 1, x_106);
x_108 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_108, 0, x_107);
lean_ctor_set(x_108, 1, x_18);
x_109 = lean_ctor_get(x_1, 9);
lean_inc(x_109);
x_110 = l_Prod_repr___at___private_PokerLean_Common_CommonColumns_0__PokerLean_reprCommonRow____x40_PokerLean_Common_CommonColumns___hyg_1741____spec__1(x_109, x_21);
x_111 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_111, 0, x_6);
lean_ctor_set(x_111, 1, x_110);
x_112 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_112, 0, x_111);
lean_ctor_set_uint8(x_112, sizeof(void*)*1, x_8);
x_113 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_113, 0, x_108);
lean_ctor_set(x_113, 1, x_112);
x_114 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_114, 0, x_113);
lean_ctor_set(x_114, 1, x_12);
x_115 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_115, 0, x_114);
lean_ctor_set(x_115, 1, x_14);
x_116 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__36;
x_117 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_117, 0, x_115);
lean_ctor_set(x_117, 1, x_116);
x_118 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_118, 0, x_117);
lean_ctor_set(x_118, 1, x_18);
x_119 = lean_ctor_get(x_1, 10);
lean_inc(x_119);
x_120 = l_Prod_repr___at___private_PokerLean_AIR_FundsAir_0__PokerLean_reprAddonMethodColumns____x40_PokerLean_AIR_FundsAir___hyg_387____spec__1(x_119, x_21);
x_121 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_121, 0, x_100);
lean_ctor_set(x_121, 1, x_120);
x_122 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_122, 0, x_121);
lean_ctor_set_uint8(x_122, sizeof(void*)*1, x_8);
x_123 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_123, 0, x_118);
lean_ctor_set(x_123, 1, x_122);
x_124 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_124, 0, x_123);
lean_ctor_set(x_124, 1, x_12);
x_125 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_125, 0, x_124);
lean_ctor_set(x_125, 1, x_14);
x_126 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__38;
x_127 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_127, 0, x_125);
lean_ctor_set(x_127, 1, x_126);
x_128 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_128, 0, x_127);
lean_ctor_set(x_128, 1, x_18);
x_129 = lean_ctor_get(x_1, 11);
lean_inc(x_129);
x_130 = l_Prod_repr___at___private_PokerLean_AIR_FundsAir_0__PokerLean_reprAddonMethodColumns____x40_PokerLean_AIR_FundsAir___hyg_387____spec__1(x_129, x_21);
x_131 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_131, 0, x_100);
lean_ctor_set(x_131, 1, x_130);
x_132 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_132, 0, x_131);
lean_ctor_set_uint8(x_132, sizeof(void*)*1, x_8);
x_133 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_133, 0, x_128);
lean_ctor_set(x_133, 1, x_132);
x_134 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_134, 0, x_133);
lean_ctor_set(x_134, 1, x_12);
x_135 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_135, 0, x_134);
lean_ctor_set(x_135, 1, x_14);
x_136 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__40;
x_137 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_137, 0, x_135);
lean_ctor_set(x_137, 1, x_136);
x_138 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_138, 0, x_137);
lean_ctor_set(x_138, 1, x_18);
x_139 = lean_ctor_get(x_1, 12);
lean_inc(x_139);
lean_dec(x_1);
x_140 = l_Prod_repr___at___private_PokerLean_AIR_FundsAir_0__PokerLean_reprAddonMethodColumns____x40_PokerLean_AIR_FundsAir___hyg_387____spec__1(x_139, x_21);
x_141 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_141, 0, x_68);
lean_ctor_set(x_141, 1, x_140);
x_142 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_142, 0, x_141);
lean_ctor_set_uint8(x_142, sizeof(void*)*1, x_8);
x_143 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_143, 0, x_138);
lean_ctor_set(x_143, 1, x_142);
x_144 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__44;
x_145 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_145, 0, x_144);
lean_ctor_set(x_145, 1, x_143);
x_146 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__46;
x_147 = lean_alloc_ctor(5, 2, 0);
lean_ctor_set(x_147, 0, x_145);
lean_ctor_set(x_147, 1, x_146);
x_148 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__43;
x_149 = lean_alloc_ctor(4, 2, 0);
lean_ctor_set(x_149, 0, x_148);
lean_ctor_set(x_149, 1, x_147);
x_150 = lean_alloc_ctor(6, 1, 1);
lean_ctor_set(x_150, 0, x_149);
lean_ctor_set_uint8(x_150, sizeof(void*)*1, x_8);
return x_150;
}
}
LEAN_EXPORT lean_object* l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232_(x_1, x_2);
lean_dec(x_2);
return x_3;
}
}
static lean_object* _init_l_PokerLean_instReprJoinTableMethodColumns___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_alloc_closure((void*)(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____boxed), 2, 0);
return x_1;
}
}
static lean_object* _init_l_PokerLean_instReprJoinTableMethodColumns() {
_start:
{
lean_object* x_1; 
x_1 = l_PokerLean_instReprJoinTableMethodColumns___closed__1;
return x_1;
}
}
static lean_object* _init_l_PokerLean_extractPreTableFromJoinTableAir___closed__1() {
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
static lean_object* _init_l_PokerLean_extractPreTableFromJoinTableAir___closed__2() {
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
LEAN_EXPORT lean_object* l_PokerLean_extractPreTableFromJoinTableAir(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; uint8_t x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; lean_object* x_32; lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; lean_object* x_49; lean_object* x_50; lean_object* x_51; lean_object* x_52; lean_object* x_53; lean_object* x_54; lean_object* x_55; uint8_t x_56; uint8_t x_57; uint8_t x_58; lean_object* x_59; 
x_4 = l_PokerLean_Seat_empty;
lean_inc(x_3);
x_5 = l_List_replicateTR___rarg(x_3, x_4);
x_6 = lean_ctor_get(x_2, 4);
x_7 = lean_ctor_get(x_6, 0);
x_8 = lean_ctor_get(x_6, 1);
x_9 = lean_ctor_get(x_8, 0);
x_10 = lean_ctor_get(x_8, 1);
x_11 = lean_ctor_get(x_10, 0);
x_12 = lean_ctor_get(x_10, 1);
x_13 = l_PokerLean_decodeU64(x_7, x_9, x_11, x_12);
x_14 = lean_ctor_get(x_1, 7);
x_15 = lean_ctor_get(x_14, 0);
x_16 = lean_ctor_get(x_14, 1);
x_17 = lean_ctor_get(x_16, 0);
x_18 = lean_ctor_get(x_16, 1);
x_19 = lean_ctor_get(x_18, 0);
x_20 = lean_ctor_get(x_18, 1);
x_21 = l_PokerLean_decodeU64(x_15, x_17, x_19, x_20);
x_22 = lean_ctor_get(x_1, 9);
x_23 = l_PokerLean_RoundState_fromNat(x_22);
x_24 = lean_ctor_get(x_1, 13);
x_25 = lean_ctor_get(x_1, 11);
x_26 = lean_ctor_get(x_25, 0);
x_27 = lean_ctor_get(x_25, 1);
x_28 = lean_ctor_get(x_27, 0);
x_29 = lean_ctor_get(x_27, 1);
x_30 = lean_ctor_get(x_29, 0);
x_31 = lean_ctor_get(x_29, 1);
x_32 = l_PokerLean_decodeU64(x_26, x_28, x_30, x_31);
x_33 = lean_box(0);
x_34 = lean_unsigned_to_nat(0u);
lean_inc(x_24);
x_35 = lean_alloc_ctor(0, 8, 0);
lean_ctor_set(x_35, 0, x_34);
lean_ctor_set(x_35, 1, x_34);
lean_ctor_set(x_35, 2, x_24);
lean_ctor_set(x_35, 3, x_32);
lean_ctor_set(x_35, 4, x_33);
lean_ctor_set(x_35, 5, x_34);
lean_ctor_set(x_35, 6, x_34);
lean_ctor_set(x_35, 7, x_34);
x_36 = lean_ctor_get(x_1, 5);
x_37 = lean_ctor_get(x_1, 6);
x_38 = lean_ctor_get(x_2, 5);
x_39 = lean_ctor_get(x_38, 0);
x_40 = lean_ctor_get(x_38, 1);
x_41 = lean_ctor_get(x_40, 0);
x_42 = lean_ctor_get(x_40, 1);
x_43 = lean_ctor_get(x_42, 0);
x_44 = lean_ctor_get(x_42, 1);
x_45 = l_PokerLean_decodeU64(x_39, x_41, x_43, x_44);
x_46 = lean_ctor_get(x_2, 8);
x_47 = lean_ctor_get(x_46, 0);
x_48 = lean_ctor_get(x_46, 1);
x_49 = lean_ctor_get(x_48, 0);
x_50 = lean_ctor_get(x_48, 1);
x_51 = lean_ctor_get(x_50, 0);
x_52 = lean_ctor_get(x_50, 1);
x_53 = l_PokerLean_decodeU64(x_47, x_49, x_51, x_52);
x_54 = l_PokerLean_extractPreTableFromJoinTableAir___closed__1;
x_55 = l_PokerLean_extractPreTableFromJoinTableAir___closed__2;
x_56 = 0;
x_57 = 0;
x_58 = 0;
lean_inc(x_37);
lean_inc(x_36);
x_59 = lean_alloc_ctor(0, 22, 4);
lean_ctor_set(x_59, 0, x_34);
lean_ctor_set(x_59, 1, x_34);
lean_ctor_set(x_59, 2, x_5);
lean_ctor_set(x_59, 3, x_3);
lean_ctor_set(x_59, 4, x_34);
lean_ctor_set(x_59, 5, x_13);
lean_ctor_set(x_59, 6, x_34);
lean_ctor_set(x_59, 7, x_21);
lean_ctor_set(x_59, 8, x_35);
lean_ctor_set(x_59, 9, x_54);
lean_ctor_set(x_59, 10, x_55);
lean_ctor_set(x_59, 11, x_36);
lean_ctor_set(x_59, 12, x_37);
lean_ctor_set(x_59, 13, x_45);
lean_ctor_set(x_59, 14, x_53);
lean_ctor_set(x_59, 15, x_34);
lean_ctor_set(x_59, 16, x_34);
lean_ctor_set(x_59, 17, x_34);
lean_ctor_set(x_59, 18, x_34);
lean_ctor_set(x_59, 19, x_34);
lean_ctor_set(x_59, 20, x_34);
lean_ctor_set(x_59, 21, x_34);
lean_ctor_set_uint8(x_59, sizeof(void*)*22, x_23);
lean_ctor_set_uint8(x_59, sizeof(void*)*22 + 1, x_56);
lean_ctor_set_uint8(x_59, sizeof(void*)*22 + 2, x_57);
lean_ctor_set_uint8(x_59, sizeof(void*)*22 + 3, x_58);
return x_59;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractPreTableFromJoinTableAir___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_PokerLean_extractPreTableFromJoinTableAir(x_1, x_2, x_3);
lean_dec(x_2);
lean_dec(x_1);
return x_4;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromJoinTableAir___lambda__1(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; uint8_t x_5; lean_object* x_6; 
x_4 = lean_unsigned_to_nat(0u);
x_5 = 0;
x_6 = lean_alloc_ctor(0, 6, 5);
lean_ctor_set(x_6, 0, x_1);
lean_ctor_set(x_6, 1, x_2);
lean_ctor_set(x_6, 2, x_4);
lean_ctor_set(x_6, 3, x_4);
lean_ctor_set(x_6, 4, x_4);
lean_ctor_set(x_6, 5, x_4);
lean_ctor_set_uint8(x_6, sizeof(void*)*6, x_5);
lean_ctor_set_uint8(x_6, sizeof(void*)*6 + 1, x_5);
lean_ctor_set_uint8(x_6, sizeof(void*)*6 + 2, x_5);
lean_ctor_set_uint8(x_6, sizeof(void*)*6 + 3, x_5);
lean_ctor_set_uint8(x_6, sizeof(void*)*6 + 4, x_5);
return x_6;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromJoinTableAir(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; lean_object* x_20; lean_object* x_21; lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; lean_object* x_28; lean_object* x_29; lean_object* x_30; lean_object* x_31; uint8_t x_32; 
lean_inc(x_3);
x_5 = l_PokerLean_extractPreTableFromJoinTableAir(x_1, x_2, x_3);
x_6 = lean_ctor_get(x_2, 1);
x_7 = lean_ctor_get(x_6, 0);
x_8 = lean_ctor_get(x_6, 1);
x_9 = lean_ctor_get(x_8, 0);
x_10 = lean_ctor_get(x_8, 1);
x_11 = lean_ctor_get(x_10, 0);
x_12 = lean_ctor_get(x_10, 1);
x_13 = l_PokerLean_decodeU64(x_7, x_9, x_11, x_12);
x_14 = lean_ctor_get(x_2, 6);
x_15 = lean_ctor_get(x_14, 0);
x_16 = lean_ctor_get(x_14, 1);
x_17 = lean_ctor_get(x_16, 0);
x_18 = lean_ctor_get(x_16, 1);
x_19 = lean_ctor_get(x_18, 0);
x_20 = lean_ctor_get(x_18, 1);
x_21 = l_PokerLean_decodeU64(x_15, x_17, x_19, x_20);
x_22 = lean_ctor_get(x_2, 2);
x_23 = lean_ctor_get(x_22, 0);
x_24 = lean_ctor_get(x_22, 1);
x_25 = lean_ctor_get(x_24, 0);
x_26 = lean_ctor_get(x_24, 1);
x_27 = lean_ctor_get(x_26, 0);
x_28 = lean_ctor_get(x_26, 1);
x_29 = l_PokerLean_decodeU64(x_23, x_25, x_27, x_28);
x_30 = l_PokerLean_Seat_empty;
lean_inc(x_3);
x_31 = l_List_replicateTR___rarg(x_3, x_30);
x_32 = !lean_is_exclusive(x_5);
if (x_32 == 0)
{
lean_object* x_33; lean_object* x_34; lean_object* x_35; lean_object* x_36; lean_object* x_37; lean_object* x_38; lean_object* x_39; lean_object* x_40; lean_object* x_41; lean_object* x_42; lean_object* x_43; lean_object* x_44; lean_object* x_45; lean_object* x_46; lean_object* x_47; lean_object* x_48; lean_object* x_49; lean_object* x_50; lean_object* x_51; lean_object* x_52; lean_object* x_53; lean_object* x_54; lean_object* x_55; lean_object* x_56; lean_object* x_57; uint8_t x_58; lean_object* x_59; lean_object* x_60; uint8_t x_61; uint8_t x_62; uint8_t x_63; lean_object* x_64; lean_object* x_65; 
x_33 = lean_ctor_get(x_5, 21);
lean_dec(x_33);
x_34 = lean_ctor_get(x_5, 20);
lean_dec(x_34);
x_35 = lean_ctor_get(x_5, 19);
lean_dec(x_35);
x_36 = lean_ctor_get(x_5, 18);
lean_dec(x_36);
x_37 = lean_ctor_get(x_5, 17);
lean_dec(x_37);
x_38 = lean_ctor_get(x_5, 16);
lean_dec(x_38);
x_39 = lean_ctor_get(x_5, 15);
lean_dec(x_39);
x_40 = lean_ctor_get(x_5, 13);
lean_dec(x_40);
x_41 = lean_ctor_get(x_5, 10);
lean_dec(x_41);
x_42 = lean_ctor_get(x_5, 7);
lean_dec(x_42);
x_43 = lean_ctor_get(x_5, 6);
lean_dec(x_43);
x_44 = lean_ctor_get(x_5, 4);
lean_dec(x_44);
x_45 = lean_ctor_get(x_5, 3);
lean_dec(x_45);
x_46 = lean_ctor_get(x_5, 2);
lean_dec(x_46);
x_47 = lean_ctor_get(x_5, 1);
lean_dec(x_47);
x_48 = lean_ctor_get(x_5, 0);
lean_dec(x_48);
x_49 = lean_ctor_get(x_1, 8);
x_50 = lean_ctor_get(x_49, 0);
x_51 = lean_ctor_get(x_49, 1);
x_52 = lean_ctor_get(x_51, 0);
x_53 = lean_ctor_get(x_51, 1);
x_54 = lean_ctor_get(x_53, 0);
x_55 = lean_ctor_get(x_53, 1);
x_56 = l_PokerLean_decodeU64(x_50, x_52, x_54, x_55);
x_57 = lean_ctor_get(x_1, 10);
x_58 = l_PokerLean_RoundState_fromNat(x_57);
x_59 = lean_unsigned_to_nat(0u);
x_60 = l_PokerLean_extractPreTableFromJoinTableAir___closed__2;
x_61 = 0;
x_62 = 0;
x_63 = 0;
lean_ctor_set(x_5, 21, x_59);
lean_ctor_set(x_5, 20, x_59);
lean_ctor_set(x_5, 19, x_59);
lean_ctor_set(x_5, 18, x_59);
lean_ctor_set(x_5, 17, x_59);
lean_ctor_set(x_5, 16, x_59);
lean_ctor_set(x_5, 15, x_59);
lean_ctor_set(x_5, 13, x_21);
lean_ctor_set(x_5, 10, x_60);
lean_ctor_set(x_5, 7, x_56);
lean_ctor_set(x_5, 6, x_59);
lean_ctor_set(x_5, 4, x_59);
lean_ctor_set(x_5, 3, x_3);
lean_ctor_set(x_5, 2, x_31);
lean_ctor_set(x_5, 1, x_59);
lean_ctor_set(x_5, 0, x_59);
lean_ctor_set_uint8(x_5, sizeof(void*)*22, x_58);
lean_ctor_set_uint8(x_5, sizeof(void*)*22 + 1, x_61);
lean_ctor_set_uint8(x_5, sizeof(void*)*22 + 2, x_62);
lean_ctor_set_uint8(x_5, sizeof(void*)*22 + 3, x_63);
x_64 = lean_alloc_closure((void*)(l_PokerLean_extractPostTableFromJoinTableAir___lambda__1___boxed), 3, 2);
lean_closure_set(x_64, 0, x_29);
lean_closure_set(x_64, 1, x_13);
x_65 = l_PokerLean_TexasPokerTable_update__seat(x_5, x_4, x_64);
return x_65;
}
else
{
lean_object* x_66; lean_object* x_67; lean_object* x_68; lean_object* x_69; lean_object* x_70; lean_object* x_71; lean_object* x_72; lean_object* x_73; lean_object* x_74; lean_object* x_75; lean_object* x_76; lean_object* x_77; lean_object* x_78; lean_object* x_79; lean_object* x_80; uint8_t x_81; lean_object* x_82; lean_object* x_83; uint8_t x_84; uint8_t x_85; uint8_t x_86; lean_object* x_87; lean_object* x_88; lean_object* x_89; 
x_66 = lean_ctor_get(x_5, 5);
x_67 = lean_ctor_get(x_5, 8);
x_68 = lean_ctor_get(x_5, 9);
x_69 = lean_ctor_get(x_5, 11);
x_70 = lean_ctor_get(x_5, 12);
x_71 = lean_ctor_get(x_5, 14);
lean_inc(x_71);
lean_inc(x_70);
lean_inc(x_69);
lean_inc(x_68);
lean_inc(x_67);
lean_inc(x_66);
lean_dec(x_5);
x_72 = lean_ctor_get(x_1, 8);
x_73 = lean_ctor_get(x_72, 0);
x_74 = lean_ctor_get(x_72, 1);
x_75 = lean_ctor_get(x_74, 0);
x_76 = lean_ctor_get(x_74, 1);
x_77 = lean_ctor_get(x_76, 0);
x_78 = lean_ctor_get(x_76, 1);
x_79 = l_PokerLean_decodeU64(x_73, x_75, x_77, x_78);
x_80 = lean_ctor_get(x_1, 10);
x_81 = l_PokerLean_RoundState_fromNat(x_80);
x_82 = lean_unsigned_to_nat(0u);
x_83 = l_PokerLean_extractPreTableFromJoinTableAir___closed__2;
x_84 = 0;
x_85 = 0;
x_86 = 0;
x_87 = lean_alloc_ctor(0, 22, 4);
lean_ctor_set(x_87, 0, x_82);
lean_ctor_set(x_87, 1, x_82);
lean_ctor_set(x_87, 2, x_31);
lean_ctor_set(x_87, 3, x_3);
lean_ctor_set(x_87, 4, x_82);
lean_ctor_set(x_87, 5, x_66);
lean_ctor_set(x_87, 6, x_82);
lean_ctor_set(x_87, 7, x_79);
lean_ctor_set(x_87, 8, x_67);
lean_ctor_set(x_87, 9, x_68);
lean_ctor_set(x_87, 10, x_83);
lean_ctor_set(x_87, 11, x_69);
lean_ctor_set(x_87, 12, x_70);
lean_ctor_set(x_87, 13, x_21);
lean_ctor_set(x_87, 14, x_71);
lean_ctor_set(x_87, 15, x_82);
lean_ctor_set(x_87, 16, x_82);
lean_ctor_set(x_87, 17, x_82);
lean_ctor_set(x_87, 18, x_82);
lean_ctor_set(x_87, 19, x_82);
lean_ctor_set(x_87, 20, x_82);
lean_ctor_set(x_87, 21, x_82);
lean_ctor_set_uint8(x_87, sizeof(void*)*22, x_81);
lean_ctor_set_uint8(x_87, sizeof(void*)*22 + 1, x_84);
lean_ctor_set_uint8(x_87, sizeof(void*)*22 + 2, x_85);
lean_ctor_set_uint8(x_87, sizeof(void*)*22 + 3, x_86);
x_88 = lean_alloc_closure((void*)(l_PokerLean_extractPostTableFromJoinTableAir___lambda__1___boxed), 3, 2);
lean_closure_set(x_88, 0, x_29);
lean_closure_set(x_88, 1, x_13);
x_89 = l_PokerLean_TexasPokerTable_update__seat(x_87, x_4, x_88);
return x_89;
}
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromJoinTableAir___lambda__1___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3) {
_start:
{
lean_object* x_4; 
x_4 = l_PokerLean_extractPostTableFromJoinTableAir___lambda__1(x_1, x_2, x_3);
lean_dec(x_3);
return x_4;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractPostTableFromJoinTableAir___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; 
x_5 = l_PokerLean_extractPostTableFromJoinTableAir(x_1, x_2, x_3, x_4);
lean_dec(x_2);
lean_dec(x_1);
return x_5;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractJoinTableParamsFromAir(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; 
x_3 = lean_ctor_get(x_1, 0);
x_4 = lean_ctor_get(x_1, 1);
x_5 = lean_ctor_get(x_4, 0);
x_6 = lean_ctor_get(x_4, 1);
x_7 = lean_ctor_get(x_6, 0);
x_8 = lean_ctor_get(x_6, 1);
x_9 = lean_ctor_get(x_8, 0);
x_10 = lean_ctor_get(x_8, 1);
x_11 = l_PokerLean_decodeU64(x_5, x_7, x_9, x_10);
lean_inc(x_3);
x_12 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_12, 0, x_3);
lean_ctor_set(x_12, 1, x_11);
lean_ctor_set(x_12, 2, x_2);
return x_12;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractJoinTableParamsFromAir___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_PokerLean_extractJoinTableParamsFromAir(x_1, x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractJoinTableParamsFromAir_x27(lean_object* x_1) {
_start:
{
lean_object* x_2; lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; lean_object* x_7; lean_object* x_8; lean_object* x_9; lean_object* x_10; lean_object* x_11; lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; 
x_2 = lean_ctor_get(x_1, 0);
x_3 = lean_ctor_get(x_1, 1);
x_4 = lean_ctor_get(x_1, 2);
x_5 = lean_ctor_get(x_3, 0);
x_6 = lean_ctor_get(x_3, 1);
x_7 = lean_ctor_get(x_6, 0);
x_8 = lean_ctor_get(x_6, 1);
x_9 = lean_ctor_get(x_8, 0);
x_10 = lean_ctor_get(x_8, 1);
x_11 = l_PokerLean_decodeU64(x_5, x_7, x_9, x_10);
x_12 = lean_ctor_get(x_4, 0);
x_13 = lean_ctor_get(x_4, 1);
x_14 = lean_ctor_get(x_13, 0);
x_15 = lean_ctor_get(x_13, 1);
x_16 = lean_ctor_get(x_15, 0);
x_17 = lean_ctor_get(x_15, 1);
x_18 = l_PokerLean_decodeU64(x_12, x_14, x_16, x_17);
lean_inc(x_2);
x_19 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_19, 0, x_2);
lean_ctor_set(x_19, 1, x_11);
lean_ctor_set(x_19, 2, x_18);
return x_19;
}
}
LEAN_EXPORT lean_object* l_PokerLean_extractJoinTableParamsFromAir_x27___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_PokerLean_extractJoinTableParamsFromAir_x27(x_1);
lean_dec(x_1);
return x_2;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_M31(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_U64Encoding(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_CommonColumns(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Contract_Types(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Contract_JoinTable(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_AIR_AirBase(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_AIR_FundsAir(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_AIR_JoinTableAir(uint8_t builtin, lean_object* w) {
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
res = initialize_PokerLean_Contract_JoinTable(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_AIR_AirBase(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_AIR_FundsAir(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__1 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__1();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__1);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__2 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__2();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__2);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__3 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__3();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__3);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__4 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__4();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__4);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__5 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__5();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__5);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__6 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__6();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__6);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__7 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__7();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__7);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__8 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__8();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__8);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__9 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__9();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__9);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__10 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__10();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__10);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__11 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__11();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__11);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__12 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__12();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__12);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__13 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__13();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__13);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__14 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__14();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__14);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__15 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__15();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__15);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__16 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__16();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__16);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__17 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__17();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__17);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__18 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__18();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__18);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__19 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__19();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__19);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__20 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__20();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__20);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__21 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__21();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__21);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__22 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__22();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__22);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__23 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__23();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__23);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__24 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__24();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__24);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__25 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__25();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__25);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__26 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__26();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__26);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__27 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__27();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__27);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__28 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__28();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__28);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__29 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__29();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__29);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__30 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__30();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__30);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__31 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__31();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__31);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__32 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__32();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__32);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__33 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__33();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__33);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__34 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__34();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__34);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__35 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__35();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__35);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__36 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__36();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__36);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__37 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__37();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__37);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__38 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__38();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__38);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__39 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__39();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__39);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__40 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__40();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__40);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__41 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__41();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__41);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__42 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__42();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__42);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__43 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__43();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__43);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__44 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__44();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__44);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__45 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__45();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__45);
l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__46 = _init_l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__46();
lean_mark_persistent(l___private_PokerLean_AIR_JoinTableAir_0__PokerLean_reprJoinTableMethodColumns____x40_PokerLean_AIR_JoinTableAir___hyg_232____closed__46);
l_PokerLean_instReprJoinTableMethodColumns___closed__1 = _init_l_PokerLean_instReprJoinTableMethodColumns___closed__1();
lean_mark_persistent(l_PokerLean_instReprJoinTableMethodColumns___closed__1);
l_PokerLean_instReprJoinTableMethodColumns = _init_l_PokerLean_instReprJoinTableMethodColumns();
lean_mark_persistent(l_PokerLean_instReprJoinTableMethodColumns);
l_PokerLean_extractPreTableFromJoinTableAir___closed__1 = _init_l_PokerLean_extractPreTableFromJoinTableAir___closed__1();
lean_mark_persistent(l_PokerLean_extractPreTableFromJoinTableAir___closed__1);
l_PokerLean_extractPreTableFromJoinTableAir___closed__2 = _init_l_PokerLean_extractPreTableFromJoinTableAir___closed__2();
lean_mark_persistent(l_PokerLean_extractPreTableFromJoinTableAir___closed__2);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
