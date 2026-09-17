use poker_appchain::keys::SequencerKey;
use poker_appchain::soft_confirm::{genesis_prev_hash, SignedFrame};
use std::io::Read;
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let pub_hex = std::env::args().nth(2).unwrap();
    let mut pubb = [0u8; 32];
    pubb.copy_from_slice(&hex::decode(pub_hex).unwrap());
    let mut f = std::fs::File::open(&path).unwrap();
    let mut r = std::io::BufReader::new(&f);
    let mut prev = genesis_prev_hash();
    let mut prev_index: Option<u64> = None;
    let mut off = 0u64;
    let mut n = 0u64;
    loop {
        let mut lb = [0u8; 4];
        match r.read_exact(&mut lb) {
            Ok(_) => {}
            Err(e) => { println!("END at off={off} frames={n}: {e}"); break; }
        }
        let len = u32::from_le_bytes(lb) as usize;
        let mut buf = vec![0u8; len];
        if let Err(e) = r.read_exact(&mut buf) {
            println!("TRUNC at off={off} frames={n}: {e}"); break;
        }
        let frame: SignedFrame = match borsh::from_slice(&buf) {
            Ok(x) => x,
            Err(e) => { println!("BADCODEC at off={off} frames={n}: {e}"); break; }
        };
        let sigok = match prev_index {
            None => {
                frame.frame.index == 0
                    && frame.frame.prev_hash == genesis_prev_hash()
                    && frame.hash().map(|h| SequencerKey::verify(&pubb, &h, &frame.sig)).unwrap_or(false)
            }
            Some(pi) => frame.verify_against(&prev, pi, &pubb).is_ok(),
        };
        if !sigok {
            println!("BADSIG at off={off} frames={n} index={} prev_ok={}", frame.frame.index, frame.frame.prev_hash == prev);
            break;
        }
        prev = frame.hash().unwrap();
        prev_index = Some(frame.frame.index);
        off += 4 + len as u64;
        n += 1;
    }
}
