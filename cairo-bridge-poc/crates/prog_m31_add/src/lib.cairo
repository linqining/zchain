#[executable]
fn main() -> felt252 {
    base::benches::bench_m31_add(0x1234, 100)
}
