//! Monad JSON-RPC 客户端（reqwest blocking；EVM 标准方法面 + finalized 标签）。
//!
//! 最终性判定核心：`eth_getBlockByNumber("finalized")` —— Monad 的 MonadBFT
//! 提供单槽终结，节点在终结后把 "finalized" 指针推进；上锚交易所在高度
//! ≤ finalized 高度即视为不可逆（daemon 纪律，见 anchor::AnchorSubmitter）。

use std::time::Duration;

use serde_json::{json, Value};

use crate::error::SettlementError;

/// 交易回执（我们关心的子集）。
#[derive(Debug, Clone)]
pub struct Receipt {
    /// status == 0x1。
    pub success: bool,
    /// 打包高度。
    pub block_number: u64,
    /// 合约创建回执的新地址（非创建交易 = None）。
    pub contract_address: Option<[u8; 20]>,
    /// 原始 log（address + topics + data）。
    pub logs: Vec<RawLog>,
}

/// 原始日志条目。
#[derive(Debug, Clone)]
pub struct RawLog {
    /// 事件发布合约。
    pub address: [u8; 20],
    /// topics（含 topic0）。
    pub topics: Vec<[u8; 32]>,
    /// data 段。
    pub data: Vec<u8>,
}

/// Monad L1 JSON-RPC 客户端。
pub struct L1Rpc {
    url: String,
    http: reqwest::blocking::Client,
}

impl L1Rpc {
    /// 构造（10s 超时；https/http 均可——主网 RPC 为 https）。
    ///
    /// # Errors
    /// URL 不可解析 → [`SettlementError::InvalidArgument`]。
    pub fn new(url: impl Into<String>) -> Result<Self, SettlementError> {
        let url = url.into();
        validate_url(&url)?;
        Ok(Self {
            url,
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| SettlementError::transport("client", e.to_string()))?,
        })
    }

    /// 裸 JSON-RPC 调用（单请求；错误对象 → [`SettlementError::Rpc`]）。
    ///
    /// # Errors
    /// 传输失败 / HTTP 非 2xx / JSON 解析失败 / RPC error 对象。
    pub fn rpc(&self, method: &str, params: Value) -> Result<Value, SettlementError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .map_err(|e| SettlementError::transport(method, e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .map_err(|e| SettlementError::transport(method, e.to_string()))?;
        if !status.is_success() {
            return Err(SettlementError::transport(
                method,
                format!("http {status}: {text}"),
            ));
        }
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| SettlementError::transport(method, format!("json: {e}: {text}")))?;
        if let Some(err) = v.get("error") {
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            return Err(SettlementError::Rpc { method: method.to_string(), message });
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| SettlementError::shape(method, "missing result"))
    }

    /// 目标 RPC URL（诊断 / 二次构造客户端用）。
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// chainId（防错链闸门）。
    ///
    /// # Errors
    /// RPC 失败 / 形状不符。
    pub fn chain_id(&self) -> Result<u64, SettlementError> {
        let v = self.rpc("eth_chainId", json!([]))?;
        hex_qty(&v, "eth_chainId")
    }

    /// 当前高度（latest）。
    ///
    /// # Errors
    /// RPC 失败 / 形状不符。
    pub fn block_number(&self) -> Result<u64, SettlementError> {
        let v = self.rpc("eth_blockNumber", json!([]))?;
        hex_qty(&v, "eth_blockNumber")
    }

    /// 已终结高度（MonadBFT finalized 指针）。
    ///
    /// # Errors
    /// RPC 失败 / 形状不符。
    pub fn finalized_block(&self) -> Result<u64, SettlementError> {
        let v = self.rpc("eth_getBlockByNumber", json!(["finalized", false]))?;
        if v.is_null() {
            // 个别节点对 finalized 标签未支持——fail-closed，不允许当 0 用。
            return Err(SettlementError::shape(
                "eth_getBlockByNumber",
                "finalized block not available",
            ));
        }
        let number = v
            .get("number")
            .ok_or_else(|| SettlementError::shape("eth_getBlockByNumber", "missing number"))?;
        hex_qty(number, "eth_getBlockByNumber.number")
    }

    /// 账户 nonce（latest）。
    ///
    /// # Errors
    /// RPC 失败 / 形状不符。
    pub fn transaction_count(&self, address: &[u8; 20]) -> Result<u64, SettlementError> {
        let v = self.rpc(
            "eth_getTransactionCount",
            json!([hex_addr(address), "latest"]),
        )?;
        hex_qty(&v, "eth_getTransactionCount")
    }

    /// gas 价格（wei）。
    ///
    /// # Errors
    /// RPC 失败 / 形状不符。
    pub fn gas_price(&self) -> Result<u128, SettlementError> {
        let v = self.rpc("eth_gasPrice", json!([]))?;
        let n = hex_qty(&v, "eth_gasPrice")?;
        Ok(u128::from(n))
    }

    /// 广播签名交易 → tx hash。
    ///
    /// # Errors
    /// RPC 失败 / 形状不符。
    pub fn send_raw_transaction(&self, raw: &[u8]) -> Result<[u8; 32], SettlementError> {
        let v = self.rpc(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(raw))]),
        )?;
        let s = v
            .as_str()
            .ok_or_else(|| SettlementError::shape("eth_sendRawTransaction", "result not string"))?;
        hex_to_32(s)
    }

    /// 查回执（未打包 → None）。
    ///
    /// # Errors
    /// RPC 失败 / 形状不符。
    pub fn transaction_receipt(&self, tx_hash: &[u8; 32]) -> Result<Option<Receipt>, SettlementError> {
        let v = self.rpc(
            "eth_getTransactionReceipt",
            json!([format!("0x{}", hex::encode(tx_hash))]),
        )?;
        if v.is_null() {
            return Ok(None);
        }
        let status = v
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::shape("receipt", "missing status"))?;
        let block = v
            .get("blockNumber")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::shape("receipt", "missing blockNumber"))?;
        let block_number = u64::from_str_radix(block.trim_start_matches("0x"), 16)
            .map_err(|e| SettlementError::shape("receipt", format!("blockNumber: {e}")))?;
        let contract_address = match v.get("contractAddress").and_then(Value::as_str) {
            Some(s) if s.len() >= 42 => Some(hex_to_20(s)?),
            _ => None,
        };
        let mut logs = Vec::new();
        if let Some(items) = v.get("logs").and_then(Value::as_array) {
            for item in items {
                let address = item
                    .get("address")
                    .and_then(Value::as_str)
                    .ok_or_else(|| SettlementError::shape("receipt.log", "missing address"))?;
                let address = hex_to_20(address)?;
                let mut topics = Vec::new();
                if let Some(list) = item.get("topics").and_then(Value::as_array) {
                    for t in list {
                        let s = t
                            .as_str()
                            .ok_or_else(|| SettlementError::shape("receipt.log", "topic not string"))?;
                        topics.push(hex_to_32(s)?);
                    }
                }
                let data_hex = item
                    .get("data")
                    .and_then(Value::as_str)
                    .unwrap_or("0x")
                    .trim_start_matches("0x");
                let data = hex::decode(data_hex)
                    .map_err(|e| SettlementError::shape("receipt.log", format!("data: {e}")))?;
                logs.push(RawLog { address, topics, data });
            }
        }
        Ok(Some(Receipt {
            success: status == "0x1",
            block_number,
            contract_address,
            logs,
        }))
    }

    /// 账户原生余额（wei，latest）。
    ///
    /// # Errors
    /// RPC 失败 / 形状不符。
    pub fn get_balance(&self, address: &[u8; 20]) -> Result<u128, SettlementError> {
        let v = self.rpc("eth_getBalance", json!([hex_addr(address), "latest"]))?;
        let s = v
            .as_str()
            .ok_or_else(|| SettlementError::shape("eth_getBalance", "result not hex string"))?;
        let full = u128::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| SettlementError::shape("eth_getBalance", format!("{s}: {e}")))?;
        Ok(full)
    }

    /// 账户代码（无代码 → 空；EOA 也是空）。
    ///
    /// # Errors
    /// RPC 失败 / 形状不符。
    pub fn get_code(&self, address: &[u8; 20]) -> Result<Vec<u8>, SettlementError> {
        let v = self.rpc("eth_getCode", json!([hex_addr(address), "latest"]))?;
        let s = v
            .as_str()
            .ok_or_else(|| SettlementError::shape("eth_getCode", "result not hex string"))?;
        hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| SettlementError::shape("eth_getCode", e.to_string()))
    }

    /// 只读合约调用（latest；返回原始 return data）。
    ///
    /// # Errors
    /// RPC 失败 / 形状不符。
    pub fn call(&self, to: &[u8; 20], data: &[u8]) -> Result<Vec<u8>, SettlementError> {
        let v = self.rpc(
            "eth_call",
            json!([{
                "to": hex_addr(to),
                "data": format!("0x{}", hex::encode(data)),
            }, "latest"]),
        )?;
        let s = v
            .as_str()
            .ok_or_else(|| SettlementError::shape("eth_call", "result not hex string"))?;
        hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| SettlementError::shape("eth_call", e.to_string()))
    }

    /// 等待交易回执（有界轮询；超时 → Shape 错误）。
    ///
    /// # Errors
    /// RPC 失败 / 超时未打包。
    pub fn wait_receipt(
        &self,
        tx_hash: &[u8; 32],
        poll_ms: u64,
        max_attempts: u32,
    ) -> Result<Receipt, SettlementError> {
        for _ in 0..max_attempts {
            if let Some(receipt) = self.transaction_receipt(tx_hash)? {
                return Ok(receipt);
            }
            std::thread::sleep(Duration::from_millis(poll_ms));
        }
        Err(SettlementError::shape(
            "wait_receipt",
            format!("tx 0x{} not mined in {max_attempts} polls", hex::encode(tx_hash)),
        ))
    }

    /// 拉取 `fromBlock..=toBlock` 内指定合约 + topic0 的日志（分页不做——
    /// daemon 轮询窗口小；主网公共 RPC 有限流，窗口超限由调用方缩小）。
    ///
    /// # Errors
    /// RPC 失败 / 形状不符。
    pub fn get_logs(
        &self,
        from_block: u64,
        to_block: u64,
        addresses: &[[u8; 20]],
        topic0: Option<[u8; 32]>,
    ) -> Result<Vec<RawLog>, SettlementError> {
        let address_list: Vec<String> = addresses.iter().map(|a| hex_addr(a)).collect();
        let mut filter = json!({
            "fromBlock": format!("0x{from_block:x}"),
            "toBlock": format!("0x{to_block:x}"),
            "address": address_list,
        });
        if let Some(t0) = topic0 {
            filter["topics"] = json!([[format!("0x{}", hex::encode(t0))]]);
        }
        let v = self.rpc("eth_getLogs", json!([filter]))?;
        let items = v
            .as_array()
            .ok_or_else(|| SettlementError::shape("eth_getLogs", "result not array"))?;
        let mut logs = Vec::with_capacity(items.len());
        for item in items {
            let address = item
                .get("address")
                .and_then(Value::as_str)
                .ok_or_else(|| SettlementError::shape("eth_getLogs", "missing address"))?;
            let address = hex_to_20(address)?;
            let mut topics = Vec::new();
            if let Some(list) = item.get("topics").and_then(Value::as_array) {
                for t in list {
                    let s = t
                        .as_str()
                        .ok_or_else(|| SettlementError::shape("eth_getLogs", "topic not string"))?;
                    topics.push(hex_to_32(s)?);
                }
            }
            let data_hex = item
                .get("data")
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .trim_start_matches("0x");
            let data = hex::decode(data_hex)
                .map_err(|e| SettlementError::shape("eth_getLogs", format!("data: {e}")))?;
            logs.push(RawLog { address, topics, data });
        }
        Ok(logs)
    }
}

/// 地址 hex（0x + 40）。
#[must_use]
pub fn hex_addr(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

fn hex_qty(v: &Value, method: &str) -> Result<u64, SettlementError> {
    let s = v
        .as_str()
        .ok_or_else(|| SettlementError::shape(method, "result not hex string"))?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|e| SettlementError::shape(method, format!("hex qty: {e}")))
}

fn hex_to_32(s: &str) -> Result<[u8; 32], SettlementError> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; 32];
    hex::decode_to_slice(trimmed, &mut out)
        .map_err(|e| SettlementError::shape("hex32", format!("{s}: {e}")))?;
    Ok(out)
}

fn hex_to_20(s: &str) -> Result<[u8; 20], SettlementError> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; 20];
    hex::decode_to_slice(trimmed, &mut out)
        .map_err(|e| SettlementError::shape("hex20", format!("{s}: {e}")))?;
    Ok(out)
}

/// 极简 URL 合法性检查（scheme http/https + authority 非空）。
fn validate_url(url: &str) -> Result<(), SettlementError> {
    let lower = url.to_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .ok_or_else(|| {
            SettlementError::InvalidArgument(format!(
                "l1 rpc url must be http(s): {url}"
            ))
        })?;
    if rest.split('/').next().unwrap_or("").is_empty() {
        return Err(SettlementError::InvalidArgument(format!(
            "l1 rpc url missing host: {url}"
        )));
    }
    Ok(())
}
