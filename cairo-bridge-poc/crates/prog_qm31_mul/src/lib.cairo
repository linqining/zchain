#[executable]
fn main() -> felt252 {
    base::benches::bench_qm31_mul(0x1234, 100)
}
