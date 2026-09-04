// Lean compiler output
// Module: PokerLean.Contract.Constants
// Imports: Init
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
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRaiseIncrement(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_Constants_BUYIN__MULTIPLIER;
LEAN_EXPORT lean_object* l_PokerLean_Constants_RAKE__NUMERATOR;
LEAN_EXPORT lean_object* l_PokerLean_Constants_minBuyIn___boxed(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_Constants_MIN__PLAYERS;
LEAN_EXPORT lean_object* l_PokerLean_Constants_MAX__PLAYERS;
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRake___boxed(lean_object*);
lean_object* lean_nat_div(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRake(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_Constants_RAKE__DENOMINATOR;
LEAN_EXPORT lean_object* l_PokerLean_Constants_minBuyIn(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_Constants_MAUNTAIN__RATIO;
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRaise___boxed(lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_Constants_EXTRA__TIME__PER__HAND;
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRaiseIncrement___boxed(lean_object*);
lean_object* lean_nat_mul(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRaise(lean_object*);
static lean_object* _init_l_PokerLean_Constants_MAX__PLAYERS() {
_start:
{
lean_object* x_1; 
x_1 = lean_unsigned_to_nat(9u);
return x_1;
}
}
static lean_object* _init_l_PokerLean_Constants_MIN__PLAYERS() {
_start:
{
lean_object* x_1; 
x_1 = lean_unsigned_to_nat(2u);
return x_1;
}
}
static lean_object* _init_l_PokerLean_Constants_BUYIN__MULTIPLIER() {
_start:
{
lean_object* x_1; 
x_1 = lean_unsigned_to_nat(10u);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_Constants_minBuyIn(lean_object* x_1) {
_start:
{
lean_object* x_2; lean_object* x_3; 
x_2 = l_PokerLean_Constants_BUYIN__MULTIPLIER;
x_3 = lean_nat_mul(x_2, x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* l_PokerLean_Constants_minBuyIn___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_PokerLean_Constants_minBuyIn(x_1);
lean_dec(x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRaise(lean_object* x_1) {
_start:
{
lean_inc(x_1);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRaise___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_PokerLean_Constants_minRaise(x_1);
lean_dec(x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRaiseIncrement(lean_object* x_1) {
_start:
{
lean_inc(x_1);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRaiseIncrement___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_PokerLean_Constants_minRaiseIncrement(x_1);
lean_dec(x_1);
return x_2;
}
}
static lean_object* _init_l_PokerLean_Constants_RAKE__NUMERATOR() {
_start:
{
lean_object* x_1; 
x_1 = lean_unsigned_to_nat(5u);
return x_1;
}
}
static lean_object* _init_l_PokerLean_Constants_RAKE__DENOMINATOR() {
_start:
{
lean_object* x_1; 
x_1 = lean_unsigned_to_nat(100u);
return x_1;
}
}
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRake(lean_object* x_1) {
_start:
{
lean_object* x_2; lean_object* x_3; 
x_2 = lean_unsigned_to_nat(2u);
x_3 = lean_nat_div(x_1, x_2);
return x_3;
}
}
LEAN_EXPORT lean_object* l_PokerLean_Constants_minRake___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_PokerLean_Constants_minRake(x_1);
lean_dec(x_1);
return x_2;
}
}
static lean_object* _init_l_PokerLean_Constants_MAUNTAIN__RATIO() {
_start:
{
lean_object* x_1; 
x_1 = lean_unsigned_to_nat(995u);
return x_1;
}
}
static lean_object* _init_l_PokerLean_Constants_EXTRA__TIME__PER__HAND() {
_start:
{
lean_object* x_1; 
x_1 = lean_unsigned_to_nat(180u);
return x_1;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_PokerLean_Contract_Constants(uint8_t builtin, lean_object* w) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l_PokerLean_Constants_MAX__PLAYERS = _init_l_PokerLean_Constants_MAX__PLAYERS();
lean_mark_persistent(l_PokerLean_Constants_MAX__PLAYERS);
l_PokerLean_Constants_MIN__PLAYERS = _init_l_PokerLean_Constants_MIN__PLAYERS();
lean_mark_persistent(l_PokerLean_Constants_MIN__PLAYERS);
l_PokerLean_Constants_BUYIN__MULTIPLIER = _init_l_PokerLean_Constants_BUYIN__MULTIPLIER();
lean_mark_persistent(l_PokerLean_Constants_BUYIN__MULTIPLIER);
l_PokerLean_Constants_RAKE__NUMERATOR = _init_l_PokerLean_Constants_RAKE__NUMERATOR();
lean_mark_persistent(l_PokerLean_Constants_RAKE__NUMERATOR);
l_PokerLean_Constants_RAKE__DENOMINATOR = _init_l_PokerLean_Constants_RAKE__DENOMINATOR();
lean_mark_persistent(l_PokerLean_Constants_RAKE__DENOMINATOR);
l_PokerLean_Constants_MAUNTAIN__RATIO = _init_l_PokerLean_Constants_MAUNTAIN__RATIO();
lean_mark_persistent(l_PokerLean_Constants_MAUNTAIN__RATIO);
l_PokerLean_Constants_EXTRA__TIME__PER__HAND = _init_l_PokerLean_Constants_EXTRA__TIME__PER__HAND();
lean_mark_persistent(l_PokerLean_Constants_EXTRA__TIME__PER__HAND);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
