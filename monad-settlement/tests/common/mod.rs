//! 测试共用件：内存态 mock L1 JSON-RPC 服务器（std TcpListener，HTTP/1.1
//! 单请求单响应）。覆盖 daemon/submitter/watcher 所需的方法面：
//! `eth_chainId / eth_blockNumber / eth_getBlockByNumber(finalized) /
//! eth_getTransactionCount / eth_gasPrice / eth_sendRawTransaction /
//! eth_getTransactionReceipt / eth_getLogs`。

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// mock 链状态。
#[derive(Default)]
pub struct MockState {
    pub chain_id: u64,
    pub block: u64,
    pub finalized: u64,
    pub nonce: u64,
    pub gas_price: u64,
    /// tx hash (0x-hex) → (成功, 打包高度)。
    pub txs: BTreeMap<String, (bool, u64)>,
    /// eth_getLogs 仓（原始 eth log 对象；within [from,to] 全量返回）。
    pub logs: Vec<(u64, serde_json::Value)>,
}

impl MockState {
    pub fn new(chain_id: u64) -> Self {
        Self { chain_id, block: 100, finalized: 90, nonce: 0, gas_price: 52_000_000_000, ..Default::default() }
    }
}

/// 运行中的 mock 服务器。
pub struct MockL1 {
    pub url: String,
    pub state: Arc<Mutex<MockState>>,
    port: AtomicU64,
}

impl MockL1 {
    /// 启动（后台 accept 线程；请求串行处理——测试面足够）。
    pub fn spawn(state: Arc<Mutex<MockState>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let inner = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                handle_connection(stream, &inner);
            }
        });
        Self {
            url: format!("http://127.0.0.1:{port}"),
            state,
            port: AtomicU64::new(u64::from(port)),
        }
    }

    /// 端口（诊断）。
    pub fn port(&self) -> u64 {
        self.port.load(Ordering::Relaxed)
    }
}

fn handle_connection(mut stream: TcpStream, state: &Arc<Mutex<MockState>>) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let response = dispatch(&body, state);
    let payload = serde_json::to_vec(&response).expect("serializable");
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&payload);
}

fn dispatch(body: &[u8], state: &Arc<Mutex<MockState>>) -> serde_json::Value {
    let req: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return error_value(null_id(), &format!("parse: {e}")),
    };
    let id = req.get("id").cloned().unwrap_or_else(null_id);
    let method = req.get("method").and_then(serde_json::Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or_else(|| serde_json::json!([]));
    let mut st = state.lock().expect("mock state lock");
    let result: Result<serde_json::Value, String> = match method {
        "eth_chainId" => Ok(serde_json::json!(hex_qty(st.chain_id))),
        "eth_blockNumber" => Ok(serde_json::json!(hex_qty(st.block))),
        "eth_gasPrice" => Ok(serde_json::json!(hex_qty(st.gas_price))),
        "eth_getBlockByNumber" => {
            let tag = params.get(0).and_then(serde_json::Value::as_str).unwrap_or("latest");
            match tag {
                "finalized" => Ok(serde_json::json!({"number": hex_qty(st.finalized)})),
                _ => Ok(serde_json::json!({"number": hex_qty(st.block)})),
            }
        }
        "eth_getTransactionCount" => Ok(serde_json::json!(hex_qty(st.nonce))),
        "eth_sendRawTransaction" => {
            let raw_hex = params
                .get(0)
                .and_then(serde_json::Value::as_str)
                .unwrap_or("0x")
                .trim_start_matches("0x");
            let raw = hex::decode(raw_hex).unwrap_or_default();
            // mock tx hash = keccak(raw)（无解析；哈希唯一性足够）。
            let hash = monad_settlement::keccak::keccak256(&raw);
            let block = st.block;
            st.nonce += 1; // 模拟账户 nonce 消费。
            st.txs.entry(format!("0x{}", hex::encode(hash))).or_insert((true, block));
            Ok(serde_json::json!(format!("0x{}", hex::encode(hash))))
        }
        "eth_getTransactionReceipt" => {
            let hash = params.get(0).and_then(serde_json::Value::as_str).unwrap_or("");
            match st.txs.get(hash) {
                Some((success, block)) => Ok(serde_json::json!({
                    "status": if *success { "0x1" } else { "0x0" },
                    "blockNumber": hex_qty(*block),
                    "logs": [],
                })),
                None => Ok(serde_json::Value::Null),
            }
        }
        "eth_getLogs" => {
            let from = qty_of(params.get(0).and_then(|f| f.get("fromBlock")), 0);
            let to = qty_of(params.get(0).and_then(|f| f.get("toBlock")), u64::MAX);
            let logs: Vec<serde_json::Value> = st
                .logs
                .iter()
                .filter(|(h, _)| *h >= from && *h <= to)
                .map(|(_, v)| v.clone())
                .collect();
            Ok(serde_json::Value::Array(logs))
        }
        other => Err(format!("method not mocked: {other}")),
    };
    match result {
        Ok(v) => serde_json::json!({"jsonrpc": "2.0", "id": id, "result": v}),
        Err(e) => serde_json::json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": e}}),
    }
}

fn null_id() -> serde_json::Value {
    serde_json::Value::Null
}

fn error_value(id: serde_json::Value, message: &str) -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32700, "message": message}})
}

fn hex_qty(v: u64) -> String {
    format!("0x{v:x}")
}

fn qty_of(v: Option<&serde_json::Value>, default: u64) -> u64 {
    v.and_then(serde_json::Value::as_str)
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(default)
}
