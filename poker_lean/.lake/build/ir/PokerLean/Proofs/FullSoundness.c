// Lean compiler output
// Module: PokerLean.Proofs.FullSoundness
// Imports: Init PokerLean.Common.M31 PokerLean.Common.U64Encoding PokerLean.Common.CommonColumns PokerLean.Contract.Types PokerLean.Contract.CreateTable PokerLean.Contract.Fold PokerLean.AIR.AirBase PokerLean.AIR.CreateTableAir PokerLean.AIR.FoldAir PokerLean.Proofs.CreateTableSoundness
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
LEAN_EXPORT lean_object* l_PokerLean_decodeU64_x27___boxed(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_decodeU64_x27(lean_object*, lean_object*, lean_object*, lean_object*);
lean_object* lean_nat_mul(lean_object*, lean_object*);
lean_object* lean_nat_add(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_decodeU64_x27(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
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
LEAN_EXPORT lean_object* l_PokerLean_decodeU64_x27___boxed(lean_object* x_1, lean_object* x_2, lean_object* x_3, lean_object* x_4) {
_start:
{
lean_object* x_5; 
x_5 = l_PokerLean_decodeU64_x27(x_1, x_2, x_3, x_4);
lean_dec(x_4);
lean_dec(x_3);
lean_dec(x_2);
lean_dec(x_1);
return x_5;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_M31(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_U64Encoding(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_CommonColumns(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Contract_Types(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Contract_CreateTable(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Contract_Fold(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_AIR_AirBase(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_AIR_CreateTableAir(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_AIR_FoldAir(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Proofs_CreateTableSoundness(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_Proofs_FullSoundness(uint8_t builtin, lean_object* w) {
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
res = initialize_PokerLean_Contract_Fold(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_AIR_AirBase(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_AIR_CreateTableAir(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_AIR_FoldAir(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Proofs_CreateTableSoundness(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
