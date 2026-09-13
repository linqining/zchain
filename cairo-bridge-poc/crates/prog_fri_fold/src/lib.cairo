#[executable]
fn main() -> felt252 {
    base::benches::bench_fri_fold(0x1234, 100)
}
