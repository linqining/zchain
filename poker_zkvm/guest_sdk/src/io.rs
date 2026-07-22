//! 便捷 IO API。

use alloc::vec::Vec;
use crate::syscalls;

/// 读取全部输入。输入格式：[4B LE 长度][数据]。
///
/// 返回实际数据部分（不含长度前缀）。
pub fn read_all_input() -> Vec<u8> {
    use crate::prelude::*;
    let mut buf = vec![0u8; 64 * 1024];
    syscalls::read_input_raw(&mut buf);
    if buf.len() < 4 {
        return Vec::new();
    }
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let n = n.min(buf.len() - 4);
    buf[..n].to_vec()
}

/// 写出结果并终止。
pub fn commit(output: &[u8]) -> ! {
    syscalls::commit_output(output)
}
