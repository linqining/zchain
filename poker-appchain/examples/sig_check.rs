use poker_appchain::keys::SequencerKey;
use poker_appchain::soft_confirm::SignedFrame;
fn main() {
    let key = SequencerKey::from_seed(&[0x5eu8; 32]);
    let path = std::env::args().nth(1).unwrap();
    let off: u64 = std::env::args().nth(2).unwrap().parse().unwrap();
    let mut f = std::fs::File::open(&path).unwrap();
    use std::io::{Read, Seek, SeekFrom};
    f.seek(SeekFrom::Start(off)).unwrap();
    let mut r = std::io::BufReader::new(f);
    let mut lb = [0u8; 4];
    r.read_exact(&mut lb).unwrap();
    let len = u32::from_le_bytes(lb) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).unwrap();
    let frame: SignedFrame = borsh::from_slice(&buf).unwrap();
    println!("index={} ts={}", frame.frame.index, frame.frame.ts_ms);
    println!("op variant: {}", match &frame.frame.op {
        poker_appchain::ops::Operation::Deposit { .. } => "Deposit",
        poker_appchain::ops::Operation::BuyIn { .. } => "BuyIn",
        poker_appchain::ops::Operation::Transfer { .. } => "Transfer",
        _ => "other",
    });
    let h = frame.hash().unwrap();
    let fresh = SequencerKey::sign(&key, &h);
    println!("disk sig: {}", hex::encode(&frame.sig[..16]));
    println!("fresh sig: {}", hex::encode(&fresh[..16]));
    println!("match: {}", fresh == frame.sig);
}
