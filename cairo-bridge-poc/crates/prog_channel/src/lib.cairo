#[executable]
fn main() -> felt252 {
    base::benches::bench_channel(0x1234, 100)
}
