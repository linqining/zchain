// Lean compiler output
// Module: PokerLean.Proofs.CreateTableSoundness
// Imports: Init PokerLean.Common.M31 PokerLean.Common.U64Encoding PokerLean.Common.CommonColumns PokerLean.Contract.Types PokerLean.Contract.CreateTable PokerLean.AIR.AirBase PokerLean.AIR.CreateTableAir
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
LEAN_EXPORT lean_object* l___private_PokerLean_Proofs_CreateTableSoundness_0__List_any_match__1_splitter(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l___private_PokerLean_Proofs_CreateTableSoundness_0__PokerLean_decodeLimb___boxed(lean_object*);
LEAN_EXPORT lean_object* l___private_PokerLean_Proofs_CreateTableSoundness_0__List_any_match__1_splitter___rarg(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l___private_PokerLean_Proofs_CreateTableSoundness_0__PokerLean_decodeLimb(lean_object*);
LEAN_EXPORT lean_object* l___private_PokerLean_Proofs_CreateTableSoundness_0__PokerLean_decodeLimb(lean_object* x_1) {
_start:
{
lean_inc(x_1);
return x_1;
}
}
LEAN_EXPORT lean_object* l___private_PokerLean_Proofs_CreateTableSoundness_0__PokerLean_decodeLimb___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l___private_PokerLean_Proofs_CreateTableSoundness_0__PokerLean_decodeLimb(x_1);
lean_dec(x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l___private_PokerLean_Proofs_CreateTableSoundness_0__List_any_match__1_splitter___rarg(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
if (lean_obj_tag(x_1) == 0)
{
lean_object* x_5; 
lean_dec(x_4);
x_5 = lean_apply_1(x_3, x_2);
return x_5;
}
else
{
lean_object* x_6; lean_object* x_7; lean_object* x_8; 
lean_dec(x_3);
x_6 = lean_ctor_get(x_1, 0);
lean_inc(x_6);
x_7 = lean_ctor_get(x_1, 1);
lean_inc(x_7);
lean_dec(x_1);
x_8 = lean_apply_3(x_4, x_6, x_7, x_2);
return x_8;
}
}
}
LEAN_EXPORT lean_object* l___private_PokerLean_Proofs_CreateTableSoundness_0__List_any_match__1_splitter(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = lean_alloc_closure((void*)(l___private_PokerLean_Proofs_CreateTableSoundness_0__List_any_match__1_splitter___rarg), 4, 0);
return x_3;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_M31(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_U64Encoding(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_CommonColumns(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Contract_Types(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Contract_CreateTable(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_AIR_AirBase(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_AIR_CreateTableAir(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_Proofs_CreateTableSoundness(uint8_t builtin, lean_object* w) {
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
res = initialize_PokerLean_Contract_CreateTable(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_AIR_AirBase(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_AIR_CreateTableAir(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
