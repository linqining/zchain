// Lean compiler output
// Module: PokerLean.Proofs.CheckSoundness
// Imports: Init Mathlib PokerLean.Common.M31 PokerLean.Common.U64Encoding PokerLean.Common.PoseidonHash PokerLean.Common.CommonColumns PokerLean.Contract.Types PokerLean.Contract.Check PokerLean.AIR.AirBase PokerLean.AIR.CheckAir
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
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_Mathlib(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_M31(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_U64Encoding(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_PoseidonHash(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Common_CommonColumns(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Contract_Types(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_Contract_Check(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_AIR_AirBase(uint8_t builtin, lean_object*);
lean_object* initialize_PokerLean_AIR_CheckAir(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_Proofs_CheckSoundness(uint8_t builtin, lean_object* w) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Mathlib(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Common_M31(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Common_U64Encoding(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Common_PoseidonHash(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Common_CommonColumns(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Contract_Types(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_Contract_Check(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_AIR_AirBase(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_PokerLean_AIR_CheckAir(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
