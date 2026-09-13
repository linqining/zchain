#[executable]
fn main() -> felt252 {
    base::benches::bench_empty(0x1234, 100)
}
