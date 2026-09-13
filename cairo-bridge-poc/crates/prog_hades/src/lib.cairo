#[executable]
fn main() -> felt252 {
    base::benches::bench_hades(0x1234, 100)
}
