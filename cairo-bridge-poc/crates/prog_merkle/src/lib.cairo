#[executable]
fn main() -> felt252 {
    base::benches::bench_merkle(0x1234, 100)
}
