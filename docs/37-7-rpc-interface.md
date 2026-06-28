# 37-7 RPC 接口文档

> **文档版本**：v1.0
> **对应代码**：[poker_l1/src/rpc/mod.rs](../poker_l1/src/rpc/mod.rs)、[poker_l1/src/node/mod.rs](../poker_l1/src/node/mod.rs)
> **协议规范**：[JSON-RPC 2.0](https://www.jsonrpc.org/specification)
> **spec 依据**：spec.md Task 31 — SubTask 31.1 / 31.2 / 31.3（FROZEN 2026-06-27）

---

## 目录

1. [概述](#1-概述)
2. [传输层](#2-传输层)
3. [基础类型](#3-基础类型)
4. [JSON-RPC 协议结构](#4-json-rpc-协议结构)
5. [错误码定义](#5-错误码定义)
6. [JSON-RPC 方法](#6-json-rpc-方法)
   - 6.1 [`get_block`](#61-get_block)
   - 6.2 [`get_object`](#62-get_object)
   - 6.3 [`get_tx`](#63-get_tx)
   - 6.4 [`submit_tx`](#64-submit_tx)
   - 6.5 [`get_account`](#65-get_account)
   - 6.6 [`get_dag_vertex`](#66-get_dag_vertex)
   - 6.7 [`secp256k1_aggregate_verify`](#67-secp256k1_aggregate_verify)
   - 6.8 [`bls_verify`](#68-bls_verify)
   - 6.9 [`zk_verify`](#69-zk_verify)
7. [WebSocket 订阅协议](#7-websocket-订阅协议)
8. [CLI 工具](#8-cli-工具)
9. [完整调用示例](#9-完整调用示例)
10. [参考实现](#10-参考实现)

---

## 1. 概述

Poker L1 节点对外暴露 JSON-RPC 2.0 接口，供钱包、浏览器、其他节点与 CLI 工具访问链上数据、提交交易与验证密码学证明。

### 1.1 RPC 方法总览

| # | 方法名 | 分类 | 说明 |
|---|--------|------|------|
| 1 | `get_block` | 链数据查询 | 按 hash 或 height 查询 block |
| 2 | `get_object` | 链数据查询 | 按对象 ID 查询 Object |
| 3 | `get_tx` | 链数据查询 | 按 tx hash 查询 Transaction |
| 4 | `submit_tx` | 交易提交 | 提交 BCS 编码的 tx 字节 |
| 5 | `get_account` | 账户查询 | 按 address 或 tagged_pubkey 查询账户 |
| 6 | `get_dag_vertex` | DAG 查询 | 按 vertex hash 查询 DAG vertex |
| 7 | `secp256k1_aggregate_verify` | 密码学验证 | 批量 secp256k1 签名聚合验证 |
| 8 | `bls_verify` | 密码学验证 | BLS12-381 签名验证 |
| 9 | `zk_verify` | 密码学验证 | ZK 证明验证（Hypernova / Groth16 / IPA） |

### 1.2 角色权限矩阵

| 方法 | Validator | Full | Archive | Light |
|------|:---------:|:----:|:-------:|:-----:|
| `get_block` | ✓ | ✓ | ✓ | ✓（仅 header） |
| `get_object` | ✓ | ✓ | ✓ | ✗ |
| `get_tx` | ✓（缓存） | ✓（缓存） | ✓（遍历 block） | ✗ |
| `submit_tx` | ✓（缓冲装入 vertex） | ✓（仅缓存） | ✓（仅缓存） | ✗ |
| `get_account` | ✓ | ✓ | ✓ | ✗ |
| `get_dag_vertex` | ✓ | ✓ | ✓ | ✗ |
| `secp256k1_aggregate_verify` | ✓ | ✓ | ✓ | ✓ |
| `bls_verify` | ✓ | ✓ | ✓ | ✓ |
| `zk_verify` | ✓ | ✓ | ✓ | ✓ |

> **说明**：crypto verify 三方法（7/8/9）为纯计算 RPC，不依赖节点状态，所有角色均可调用。

---

## 2. 传输层

### 2.1 当前实现：newline-delimited TCP

`zchain` 二进制默认通过 **TCP + 换行符分隔** 传输 JSON-RPC 报文：

- 每条请求为一行 JSON 文本，以 `\n` 结尾
- 每条响应为一行 JSON 文本，以 `\n` 结尾
- 一条 TCP 连接可连续发送多条请求（keep-alive）
- 服务端为每个连接派生独立线程处理

**默认监听地址**：`127.0.0.1:8545`（可通过 `--rpc-listen` 修改）

### 2.2 启动节点

```bash
# 启动 full node，监听默认端口
cargo run --bin zchain -- node --role full --data-dir ./data

# 启动 validator
cargo run --bin zchain -- node --role validator \
  --data-dir ./data \
  --validator-key <32B_hex_secret_key>

# 启动 archive node（提供历史数据 RPC）
cargo run --bin zchain -- node --role archive --data-dir ./archive-data

# 自定义端口
cargo run --bin zchain -- node --role full \
  --rpc-listen 0.0.0.0:8545 \
  --p2p-listen 0.0.0.0:9000 \
  --data-dir ./data
```

### 2.3 客户端连接示例（Python）

```python
import socket, json

def rpc_call(method, params, rpc_id=1, host="127.0.0.1", port=8545):
    req = json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": rpc_id,
    }) + "\n"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))
    s.sendall(req.encode())
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk or b"\n" in chunk:
            data += chunk
            break
        data += chunk
    s.close()
    return json.loads(data.decode().strip())

# 示例：查询 height=10 的 block
print(rpc_call("get_block", {"height": 10}))
```

### 2.4 后续扩展：HTTP / WebSocket

当前库代码（[rpc/mod.rs](../poker_l1/src/rpc/mod.rs)）已设计为传输层无关：

- `RpcHandler::handle(&self, req: &JsonRpcRequest) -> JsonRpcResponse` 为纯函数式派发器
- `RpcBackend` trait 抽象存储访问，不绑定 IO 模型
- 后续可在上层二进制集成 `axum` + `tokio-tungstenite`，将同一 handler 暴露为 HTTP POST 与 WebSocket，无需修改 RPC 库

---

## 3. 基础类型

### 3.1 类型对照表

| 类型 | Rust 类型 | JSON 编码 | 说明 |
|------|-----------|-----------|------|
| `Hash` | `[u8; 32]` | 32 元素数字数组 | blake2b_256 输出 |
| `Address` | `[u8; 20]` | 20 元素数字数组 | `blake2b_256(tagged_pubkey)[0..20]` |
| `BlockHeight` | `u64` | 数字 | 区块高度 |
| `ChainId` | `u64` | 数字 | 网络 ID（默认 `0x706F6B31` = "pok1"） |
| `ObjectID` | `(Address, u64)` | `{"creator": [...20B], "creation_nonce": N}` | 全局唯一对象 ID |
| `TaggedPubkey` | struct | `{"tag": N, "raw": [...]}` | 1B tag + raw pubkey |
| `Vec<u8>` | bytes | 数字数组 | 字节序列 |

### 3.2 TaggedPubkey 编码

```
tag (1B): (scheme_id: 4 bits || version_id: 4 bits)
  - 0x01 = secp256k1 v1（raw = 33B compressed pubkey）
  - 0x11 = ed25519   v1（raw = 32B verifying key）
raw  (变长): 公钥原始字节
```

示例（secp256k1）：
```json
{
  "tag": 1,
  "raw": [2, 123, 179, 179, 134, 150, 201, 167, 100, 179, 4, 28, 201, 188, 144, 147, 222, 11, 153, 200, 52, 245, 23, 180, 110, 100, 140, 97, 230, 23, 210, 66, 41]
}
```

---

## 4. JSON-RPC 协议结构

### 4.1 请求

```json
{
  "jsonrpc": "2.0",
  "method": "<method_name>",
  "params": { ... },
  "id": <number | string | null>
}
```

- `jsonrpc`：固定为 `"2.0"`
- `method`：方法名（见第 6 节）
- `params`：参数对象（命名参数风格，非位置参数数组）
- `id`：客户端提供，原样回传（用于匹配请求/响应）

### 4.2 成功响应

```json
{
  "jsonrpc": "2.0",
  "result": <value | null>,
  "id": <client_id>
}
```

- `result`：成功结果（查询未命中时为 `null`）
- `error`：省略

### 4.3 错误响应

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32601,
    "message": "method not found: foo",
    "data": <optional>
  },
  "id": <client_id>
}
```

- `result`：省略
- `error.code`：见第 5 节
- `error.message`：人类可读错误描述
- `error.data`：可选附加数据

---

## 5. 错误码定义

### 5.1 标准 JSON-RPC 错误码（-32xxx）

| code | 常量 | 含义 | 触发场景 |
|------|------|------|----------|
| `-32700` | `PARSE_ERROR` | 解析错误 | JSON 文本无法解析为 `JsonRpcRequest` |
| `-32600` | `INVALID_REQUEST` | 无效请求 | 请求结构不符合 JSON-RPC 2.0 |
| `-32601` | `METHOD_NOT_FOUND` | 方法未找到 | `method` 不在 9 个支持的方法中 |
| `-32602` | `INVALID_PARAMS` | 无效参数 | 参数反序列化失败 / 业务校验失败 |
| `-32603` | `INTERNAL_ERROR` | 内部错误 | 后端存储异常 |

### 5.2 业务错误（INVALID_PARAMS 子类）

下列业务错误通过 `INVALID_PARAMS (-32602)` 返回，`message` 字段携带具体原因：

| 场景 | message 示例 |
|------|--------------|
| `submit_tx` 超过 128KB | `tx too large: actual=131073, limit=131072` |
| `submit_tx` BCS 解码失败 | `BCS decode failed: ...` |
| `secp256k1_aggregate_verify` 长度不匹配 | `pubkeys / msg_hashes / sigs length mismatch` |
| `bls_verify` pubkey 长度错误 | `invalid pubkey_g2 length: ...` |
| `zk_verify` 无 registry | `zk verifier registry not available` |
| `zk_verify` public_io 反序列化失败 | `public_io 反序列化失败：长度不足或格式错误` |

---

## 6. JSON-RPC 方法

### 6.1 `get_block`

按 block hash 或 height 查询区块。

**参数**（`GetBlockParams`，untagged enum）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `hash` | `Hash` | 二选一 | 32 字节 block hash |
| `height` | `BlockHeight` | 二选一 | 区块高度 |

**请求示例（按 height）**：
```json
{
  "jsonrpc": "2.0",
  "method": "get_block",
  "params": {"height": 10},
  "id": 1
}
```

**请求示例（按 hash）**：
```json
{
  "jsonrpc": "2.0",
  "method": "get_block",
  "params": {"hash": [11, 22, ..., 99]},
  "id": 2
}
```

**成功响应**（返回完整 `Block`）：
```json
{
  "jsonrpc": "2.0",
  "result": {
    "header": {
      "height": 10,
      "timestamp_ms": 1700000000000,
      "prev_hash": [10, 20, ...],
      "state_root": [0xAB, ...],
      "public_tx_root": [...],
      "gameturn_tx_root": [...],
      "dag_commit_certificate": { ... }
    },
    "public_txs": [],
    "gameturn_txs": []
  },
  "id": 1
}
```

**未命中**：`"result": null`

**Block 字段说明**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `header.height` | `u64` | 区块高度 |
| `header.timestamp_ms` | `u64` | 出块时间戳（毫秒） |
| `header.prev_hash` | `Hash` | 前一区块 hash |
| `header.state_root` | `Hash` | Sparse Merkle Root（所有 live 对象） |
| `header.public_tx_root` | `Hash` | public txs 的 Merkle root |
| `header.gameturn_tx_root` | `Hash` | gameturn txs 的 Merkle root |
| `header.dag_commit_certificate` | `DagCommitCertificate` | Bullshark commit 证书 |
| `public_txs` | `Vec<Transaction>` | Public 通道交易列表 |
| `gameturn_txs` | `Vec<Transaction>` | GameTurn 通道交易列表（免 gas） |

---

### 6.2 `get_object`

按 ObjectID 查询对象。

**参数**（`GetObjectParams`）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `id` | `ObjectID` | ✓ | 对象 ID |

**ObjectID 结构**：
```json
{
  "creator": [20 字节 address],
  "creation_nonce": 0
}
```

**请求示例**：
```json
{
  "jsonrpc": "2.0",
  "method": "get_object",
  "params": {
    "id": {
      "creator": [170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170],
      "creation_nonce": 0
    }
  },
  "id": 1
}
```

**成功响应**（返回完整 `Object`）：
```json
{
  "jsonrpc": "2.0",
  "result": {
    "id": { "creator": [...], "creation_nonce": 0 },
    "version": 1,
    "owner": "Shared",
    "type": "GameType",
    "data": [...],
    "assigned_validator": null,
    "content_hash": [...]
  },
  "id": 1
}
```

**Object 字段说明**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | `ObjectID` | 对象唯一 ID |
| `version` | `u64` | 版本号（每次更新 +1） |
| `owner` | `Ownership` enum | `AddressOwned` / `Shared` / `Immutable` / `ChannelOwner` |
| `type` | `String` | 类型标签 |
| `data` | `Vec<u8>` | 对象数据（BCS） |
| `assigned_validator` | `Option<TaggedPubkey>` | Game 对象的 assigned validator |
| `content_hash` | `Hash` | 内容哈希（防篡改） |

---

### 6.3 `get_tx`

按 tx hash 查询交易。

> **注意**：Full / Validator 节点仅返回缓存中的 tx；Archive 节点可遍历 block 查找历史 tx。

**参数**（`GetTxParams`）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `tx_hash` | `Hash` | ✓ | 32 字节 tx hash |

**请求示例**：
```json
{
  "jsonrpc": "2.0",
  "method": "get_tx",
  "params": {"tx_hash": [0, 1, 2, ..., 31]},
  "id": 1
}
```

**成功响应**（返回完整 `Transaction`）：
```json
{
  "jsonrpc": "2.0",
  "result": {
    "inputs": [ {"creator": [...], "creation_nonce": 1} ],
    "outputs": [ { ... } ],
    "contract_call": null,
    "tagged_pubkey": {"tag": 1, "raw": [...]},
    "signature": [65 字节 secp256k1 签名],
    "gas": {"compute_limit": 1000, "price_per_unit": 1},
    "lane_hint": "Public",
    "route_hint": "AnyValidator",
    "chain_id": 1887000561,
    "nonce": 1,
    "gameturn_nonce": null,
    "is_fallback": false
  },
  "id": 1
}
```

**Transaction 字段说明**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `inputs` | `Vec<ObjectID>` | 输入对象 ID 列表 |
| `outputs` | `Vec<Object>` | 输出对象列表 |
| `contract_call` | `Option<ContractCall>` | 合约调用（None = 普通转账） |
| `tagged_pubkey` | `TaggedPubkey` | 签名者公钥 |
| `signature` | `Vec<u8>` | 签名字节（secp256k1 = 65B = r‖s‖v） |
| `gas` | `Gas` | gas 限制与单价（GameTurn tx = zero） |
| `lane_hint` | `TxLane` enum | `Public` / `GameTurn` / `CheckpointAnchor` / `ForceSync` |
| `route_hint` | `RouteHint` | 路由提示 |
| `chain_id` | `ChainId` | 网络 ID（重放保护） |
| `nonce` | `u64` | 账户 nonce（Public tx 用） |
| `gameturn_nonce` | `Option<u64>` | per-game per-player nonce（GameTurn tx 用） |
| `is_fallback` | `bool` | 是否为 fallback tx（SEC-H7） |

---

### 6.4 `submit_tx`

提交交易到节点。节点会校验后放入待装 vertex 缓冲（Validator）或仅缓存（其他角色）。

**参数**（`SubmitTxParams`）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `tx_bytes` | `Vec<u8>` | ✓ | BCS 编码的 Transaction 字节 |

**大小限制**：`tx_bytes.len() <= 128 * 1024`（128KB），超出返回 `INVALID_PARAMS` 错误 `tx too large`。

**请求示例**：
```json
{
  "jsonrpc": "2.0",
  "method": "submit_tx",
  "params": {
    "tx_bytes": [BCS 编码字节...]
  },
  "id": 1
}
```

**成功响应**（返回 `SubmitTxResult`）：
```json
{
  "jsonrpc": "2.0",
  "result": {
    "tx_hash": [32 字节 tx hash]
  },
  "id": 1
}
```

**错误场景**：

| 错误 | message |
|------|---------|
| 超过 128KB | `tx too large: actual=<N>, limit=131072` |
| BCS 解码失败 | `BCS decode failed: <原因>` |
| 内部存储错误 | `<PokerL1Error 描述>` |

**说明**：
- `tx_hash` = `blake2b_256(canonical_bcs(Transaction))`
- Validator 角色会将 tx 装入下一个 DAG vertex（默认 100ms 内必出 vertex）
- 非 Validator 角色仅缓存用于本地查询，不会传播到网络

---

### 6.5 `get_account`

按 address 或 tagged_pubkey 查询账户。

**参数**（`GetAccountParams`，untagged enum）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `address` | `Address` | 二选一 | 20 字节账户地址 |
| `tagged_pubkey` | `TaggedPubkey` | 二选一 | 账户绑定的公钥（库内部派生 address） |

**请求示例（按 address）**：
```json
{
  "jsonrpc": "2.0",
  "method": "get_account",
  "params": {
    "address": [154, 163, 56, 97, 161, 115, 236, 87, 251, 222, 211, 33, 36, 178, 7, 110, 248, 236, 86, 158]
  },
  "id": 1
}
```

**请求示例（按 tagged_pubkey）**：
```json
{
  "jsonrpc": "2.0",
  "method": "get_account",
  "params": {
    "tagged_pubkey": {"tag": 1, "raw": [33 字节 secp256k1 compressed pubkey]}
  },
  "id": 2
}
```

**成功响应**（返回 `Account`）：
```json
{
  "jsonrpc": "2.0",
  "result": {
    "address": [...20 字节...],
    "tagged_pubkey": {"tag": 1, "raw": [...]},
    "nonce": 5,
    "balance": 1000000000
  },
  "id": 1
}
```

**Account 字段说明**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `address` | `Address` | 20 字节地址 |
| `tagged_pubkey` | `TaggedPubkey` | 绑定的公钥 |
| `nonce` | `u64` | 账户 nonce（Public tx 重放保护） |
| `balance` | `u64` | 账户余额（用于 gas 扣费） |

**未命中**：`"result": null`

---

### 6.6 `get_dag_vertex`

按 vertex hash 查询 DAG vertex。

**参数**（`GetDagVertexParams`）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `vertex_hash` | `Hash` | ✓ | 32 字节 vertex hash |

**请求示例**：
```json
{
  "jsonrpc": "2.0",
  "method": "get_dag_vertex",
  "params": {"vertex_hash": [0, 1, 2, ..., 31]},
  "id": 1
}
```

**成功响应**（返回 `DagVertex`）：
```json
{
  "jsonrpc": "2.0",
  "result": {
    "epoch": 1,
    "round": 5,
    "author_pubkey": {"tag": 1, "raw": [...]},
    "tx_list": [ { ... tx ... } ],
    "parent_hashes": [ [...32B...], [...32B...] ],
    "author_sig": [65 字节 secp256k1 签名]
  },
  "id": 1
}
```

**DagVertex 字段说明**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `epoch` | `u64` | epoch 编号 |
| `round` | `u64` | DAG round 编号 |
| `author_pubkey` | `TaggedPubkey` | vertex 作者公钥 |
| `tx_list` | `Vec<Transaction>` | 包含的 tx 列表 |
| `parent_hashes` | `Vec<Hash>` | 引用的 parent vertex hash（需 ≥2/3 validator） |
| `author_sig` | `Vec<u8>` | 作者签名（签名对象 = `hash(chain_id‖epoch‖round‖author_pubkey‖vertex_hash‖parent_hashes)`，R4-H7 修正） |

**未命中**：`"result": null`

---

### 6.7 `secp256k1_aggregate_verify`

批量验证 N 个 secp256k1 签名。所有签名验证通过返回 `verified: true`，任一失败返回 `false`。

**参数**（`Secp256k1AggregateVerifyParams`）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `pubkeys` | `Vec<TaggedPubkey>` | ✓ | N 个公钥 |
| `msg_hashes` | `Vec<Hash>` | ✓ | N 个消息哈希（每个 32 字节） |
| `sigs` | `Vec<Vec<u8>>` | ✓ | N 个签名字节（每个 65B = r‖s‖v） |

**约束**：三个数组长度必须相等，否则返回 `INVALID_PARAMS` 错误 `pubkeys / msg_hashes / sigs length mismatch`。

**请求示例**：
```json
{
  "jsonrpc": "2.0",
  "method": "secp256k1_aggregate_verify",
  "params": {
    "pubkeys": [
      {"tag": 1, "raw": [33B pubkey A]},
      {"tag": 1, "raw": [33B pubkey B]}
    ],
    "msg_hashes": [
      [32B hash A],
      [32B hash B]
    ],
    "sigs": [
      [65B sig A],
      [65B sig B]
    ]
  },
  "id": 1
}
```

**成功响应**（返回 `Secp256k1AggregateVerifyResult`）：
```json
{
  "jsonrpc": "2.0",
  "result": {"verified": true},
  "id": 1
}
```

**安全说明**：
- 强制 low-s（BIP-62）：`s > n/2` 返回 `verified: false`（NEW-L1 修复）
- 全程常数时间（IMPL-SEC-1 修复）
- 适用于 tx / vertex / receipt / operator_ack / ACK 签名验证

---

### 6.8 `bls_verify`

验证 BLS12-381 签名（用于 consensus commit certificate、aggregated validator signature）。

**参数**（`BlsVerifyParams`）：

| 字段 | 类型 | 必填 | 长度 | 说明 |
|------|------|:----:|:-----:|------|
| `pubkey_g2` | `Vec<u8>` | ✓ | 96B | 签名者公钥（G2 compressed） |
| `signature_g1` | `Vec<u8>` | ✓ | 48B | 签名（G1 compressed） |
| `msg` | `Vec<u8>` | ✓ | 任意 | 被签名的消息 |

**请求示例**：
```json
{
  "jsonrpc": "2.0",
  "method": "bls_verify",
  "params": {
    "pubkey_g2": [96 字节 G2 compressed pubkey],
    "signature_g1": [48 字节 G1 compressed signature],
    "msg": [72 字节消息内容]
  },
  "id": 1
}
```

**成功响应**（返回 `BlsVerifyResult`）：
```json
{
  "jsonrpc": "2.0",
  "result": {"verified": true},
  "id": 1
}
```

**安全说明**：
- 使用 `blstrs` crate（真实实现，非 stub）
- 包含 G1 / G2 子群检查（防 rogue key 攻击）
- 长度不符返回 `INVALID_PARAMS` 错误

---

### 6.9 `zk_verify`

验证 ZK 证明（用于 offline proof 验证、bridge 状态转移证明、Game shuffle 证明）。

**参数**（`ZkVerifyParams`）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `scheme_id` | `u32` | ✓ | 1 = Hypernova / 2 = Groth16 / 3 = IPA |
| `proof` | `Vec<u8>` | ✓ | 证明字节 |
| `public_io_bytes` | `Vec<u8>` | ✓ | public_io 的 BCS 序列化字节 |
| `max_skip_segments` | `u32` | ✓ | skip_segments 上限 |
| `max_ack_chain_length` | `u32` | ✓ | ack_chain_length 上限 |

**scheme_id 对照**：

| scheme_id | 名称 | 状态 | 用途 |
|:---------:|------|:----:|------|
| 1 | Hypernova | Stub | 递归 fold 证明（CCS） |
| 2 | Groth16 | Stub | 单次证明 |
| 3 | IPA | Stub | 内积论证（无 trusted setup） |

**请求示例**：
```json
{
  "jsonrpc": "2.0",
  "method": "zk_verify",
  "params": {
    "scheme_id": 2,
    "proof": [Groth16 证明字节...],
    "public_io_bytes": [BCS 编码的 ZkPublicIo...],
    "max_skip_segments": 3,
    "max_ack_chain_length": 1000
  },
  "id": 1
}
```

**成功响应**（返回 `ZkVerifyRpcResult`）：
```json
{
  "jsonrpc": "2.0",
  "result": {
    "verified": true,
    "verifier_status": "Stub",
    "scheme_id": 2
  },
  "id": 1
}
```

**返回字段说明**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `verified` | `bool` | 验证结果 |
| `verifier_status` | `String` | `"Stub"` = 占位实现 / `"Production"` = 生产实现 |
| `scheme_id` | `u32` | 回显的 scheme_id |

**错误场景**：

| 错误 | message |
|------|---------|
| 节点未配置 ZK registry | `zk verifier registry not available` |
| `public_io_bytes` 反序列化失败 | `public_io 反序列化失败：长度不足或格式错误` |
| 未知 `scheme_id` | 由 ZkVerifierRegistry 内部返回 |

**说明**：
- 当前所有 scheme 均为 `Stub` 状态（生产部署前需替换为 Production verifier）
- `ZkPublicIo` 的固定布局由 [offline/zk_verifier.rs](../poker_l1/src/offline/zk_verifier.rs) 定义
- `max_skip_segments` / `max_ack_chain_length` 用于限制递归证明深度，防 DoS

---

## 7. WebSocket 订阅协议

> **状态**：库代码已定义类型（[rpc/mod.rs](../poker_l1/src/rpc/mod.rs) 第 258-301 行），当前 `zchain` 二进制暂未启用 WebSocket server；后续集成 `tokio-tungstenite` 后可启用。

### 7.1 事件类型（EventType）

| 枚举值 | 说明 | payload 内容 |
|--------|------|--------------|
| `Block` | 新 block 事件 | BCS 编码的 `Block` |
| `Vertex` | 新 DAG vertex 事件 | BCS 编码的 `DagVertex` |
| `Transaction` | 新 tx 事件 | BCS 编码的 `Transaction` |

### 7.2 订阅请求（SubscribeRequest）

```json
{
  "jsonrpc": "2.0",
  "method": "subscribe",
  "params": {
    "event_types": ["Block", "Transaction"]
  },
  "id": 1
}
```

**响应**（SubscribeResponse）：
```json
{
  "jsonrpc": "2.0",
  "result": {"subscription_id": 42},
  "id": 1
}
```

### 7.3 取消订阅（UnsubscribeRequest）

```json
{
  "jsonrpc": "2.0",
  "method": "unsubscribe",
  "params": {"subscription_id": 42},
  "id": 2
}
```

### 7.4 事件推送（EventMessage）

服务端通过 WebSocket 推送事件消息：

```json
{
  "subscription_id": 42,
  "event_type": "Block",
  "payload": [BCS 编码的字节数组]
}
```

**payload 解码**：客户端按 `event_type` 使用对应类型反序列化：
- `Block` → `Block::from_bcs(&payload)`
- `Vertex` → `DagVertex::from_bcs(&payload)`
- `Transaction` → `Transaction::from_bcs(&payload)`

---

## 8. CLI 工具

`zchain` 二进制内置两个子命令，便于快速生成密钥与启动节点。

### 8.1 `keygen` — 生成密钥对

```bash
# 生成 secp256k1 密钥对（默认）
cargo run --bin zchain -- keygen --scheme secp256k1

# 生成 ed25519 密钥对
cargo run --bin zchain -- keygen --scheme ed25519
```

**输出示例**（JSON 格式）：
```json
{
  "scheme": "secp256k1",
  "secret_key_hex": "2204b4d026237656ceb719afbd55665cac70f9c50af349ee6e6b008f7b143597",
  "tagged_pubkey": {
    "tag": "01",
    "raw_hex": "037ab3b38696c9a764b3041cc9bc9093de0b99c834f517b46e648c61e617d24229"
  },
  "address_hex": "9aa33861a173ec57fbded32124b2076ef8ec569e"
}
```

**字段说明**：

| 字段 | 说明 |
|------|------|
| `secret_key_hex` | 32 字节私钥（hex），妥善保管，**勿提交到版本控制** |
| `tagged_pubkey.tag` | 1 字节 tag（hex），`01` = secp256k1 v1，`11` = ed25519 v1 |
| `tagged_pubkey.raw_hex` | 公钥原始字节（hex），secp256k1 = 33B compressed，ed25519 = 32B |
| `address_hex` | 20 字节账户地址（hex），由 `blake2b_256(tagged_pubkey)[0..20]` 派生 |

### 8.2 `node` — 启动节点

```bash
cargo run --bin zchain -- node [options]
```

**选项**：

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--role <role>` | `full` | 节点角色：`validator` / `full` / `archive` / `light` |
| `--data-dir <path>` | `./data` | 数据目录（RocksDB 路径） |
| `--rpc-listen <addr>` | `127.0.0.1:8545` | JSON-RPC TCP 监听地址 |
| `--p2p-listen <addr>` | `127.0.0.1:9000` | P2P 网络监听地址 |
| `--validator-key <hex>` | 无 | validator 私钥（32B hex，仅 `--role validator` 时必填） |

**角色说明**：

| 角色 | 共识参与 | 裁剪 | 历史数据 RPC | 用途 |
|------|:--------:|:----:|:------------:|------|
| `validator` | ✓（DAG + Bullshark） | Layer 1-3 | ✗ | 出块节点 |
| `full` | ✗ | Layer 1-3 | ✗ | 验证 + RPC 服务 |
| `archive` | ✗ | 不裁剪 | ✓ | 历史数据查询 |
| `light` | ✗ | 仅 header | ✗ | 轻客户端 |

### 8.3 `version` — 查看版本

```bash
cargo run --bin zchain -- version
# 输出：zchain 0.1.0
```

### 8.4 `help` — 查看帮助

```bash
cargo run --bin zchain -- help
cargo run --bin zchain -- --help
cargo run --bin zchain -- -h
```

---

## 9. 完整调用示例

### 9.1 启动 full node

```bash
# 终端 1
cargo run --bin zchain -- node --role full --data-dir ./data
```

### 9.2 查询区块（Python 客户端）

```python
import socket, json

def rpc(method, params, port=8545):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    s.sendall((json.dumps({"jsonrpc":"2.0","method":method,"params":params,"id":1}) + "\n").encode())
    data = b""
    while b"\n" not in data:
        data += s.recv(4096)
    s.close()
    return json.loads(data.decode().strip())

# 1. 查询 height=0 的 block（空库时返回 null）
print("get_block(height=0):", rpc("get_block", {"height": 0}))

# 2. 查询未知 tx
print("get_tx:", rpc("get_tx", {"tx_hash": [0]*32}))

# 3. 查询未知 account
print("get_account:", rpc("get_account", {"address": [0]*20}))

# 4. 验证 BLS 签名（错误长度的 pubkey）
print("bls_verify:", rpc("bls_verify", {
    "pubkey_g2": [0]*95,  # 应为 96B
    "signature_g1": [0]*48,
    "msg": [0]*32
}))

# 5. 调用不存在的方法
print("nonexistent:", rpc("nonexistent_method", {}))
```

**预期输出**：
```
get_block(height=0): {'jsonrpc': '2.0', 'result': None, 'id': 1}
get_tx: {'jsonrpc': '2.0', 'result': None, 'id': 1}
get_account: {'jsonrpc': '2.0', 'result': None, 'id': 1}
bls_verify: {'jsonrpc': '2.0', 'error': {'code': -32602, 'message': '...'}, 'id': 1}
nonexistent: {'jsonrpc': '2.0', 'error': {'code': -32601, 'message': 'method not found: nonexistent_method'}, 'id': 1}
```

### 9.3 提交交易（伪代码）

```python
# 1. 客户端构造 Transaction 并 BCS 编码
tx_bytes = bcs_encode(transaction)

# 2. 通过 RPC 提交
resp = rpc("submit_tx", {"tx_bytes": list(tx_bytes)})
tx_hash = resp["result"]["tx_hash"]
print(f"tx submitted, hash = {bytes(tx_hash).hex()}")

# 3. 通过 get_tx 查询
resp = rpc("get_tx", {"tx_hash": tx_hash})
assert resp["result"] is not None
```

---

## 10. 参考实现

### 10.1 源文件

| 文件 | 说明 |
|------|------|
| [poker_l1/src/rpc/mod.rs](../poker_l1/src/rpc/mod.rs) | RPC 库核心：协议类型、RpcBackend trait、RpcHandler 派发器、MemoryBackend（测试用） |
| [poker_l1/src/node/mod.rs](../poker_l1/src/node/mod.rs) | 节点模块：NodeConfig、Node、NodeRpcBackend、CLI keygen/query 工具 |
| [src/main.rs](../src/main.rs) | 二进制入口：CLI 解析 + Node 启动 + TCP JSON-RPC server |
| [poker_l1/src/crypto_precompiles/native_api.rs](../poker_l1/src/crypto_precompiles/native_api.rs) | secp256k1 / BLS12-381 原生 API（被 crypto verify RPC 调用） |
| [poker_l1/src/offline/zk_verifier.rs](../poker_l1/src/offline/zk_verifier.rs) | ZK verifier registry 与 scheme 实现 |

### 10.2 关键类型索引

| 类型 | 定义位置 |
|------|----------|
| `JsonRpcRequest` / `JsonRpcResponse` / `JsonRpcError` | rpc/mod.rs L33-L123 |
| `RpcBackend` trait | rpc/mod.rs L309-L328 |
| `RpcHandler` | rpc/mod.rs L336-L500 |
| `MemoryBackend`（测试用） | rpc/mod.rs L507-L632 |
| `NodeConfig` / `NodeRole` / `Node` | node/mod.rs L33-L384 |
| `NodeRpcBackend` | node/mod.rs L531-L586 |
| `keygen` / `keygen_secp256k1` / `keygen_ed25519` | node/mod.rs L401-L459 |
| `ValidatorKey` | node/mod.rs L172-L200 |
| `query_node_info` / `NodeInfo` | node/mod.rs L495-L523 |

### 10.3 测试覆盖

RPC 库单元测试位于 [poker_l1/src/rpc/mod.rs](../poker_l1/src/rpc/mod.rs) `#[cfg(test)] mod tests`（L634-L1056），覆盖：

- JSON-RPC 响应序列化
- `get_block` 按 height / hash 查询（命中 + 未命中）
- `get_object` 查询
- `submit_tx` 成功 + 超大 tx 拒绝
- `get_account` 按 address / pubkey 查询
- `get_dag_vertex` 查询
- `method not found` 错误
- `secp256k1_aggregate_verify` 长度不匹配
- `bls_verify` 无效 pubkey 长度
- `zk_verify` 无 registry 错误
- WebSocket 事件类型序列化往返
- `get_tx` 未命中 + submit 后命中

### 10.4 相关文档

| 文档 | 说明 |
|------|------|
| [37-1-node-deployment.md](./37-1-node-deployment.md) | 节点部署指南（含 genesis 配置） |
| [37-2-contract-development.md](./37-2-contract-development.md) | 合约开发（含 gas 表） |
| [37-3-offline-proof-development.md](./37-3-offline-proof-development.md) | 离线证明开发（Hypernova / Groth16 / IPA） |
| [37-4-bridge-extension.md](./37-4-bridge-extension.md) | 跨链桥扩展 |
| [37-5-governance-operations.md](./37-5-governance-operations.md) | 治理操作（41 个参数） |
| [37-6-dag-consensus-ops.md](./37-6-dag-consensus-ops.md) | DAG 共识运维 |

---

## 附录 A：JSON-RPC 方法速查表

```
┌───────────────────────────────────┬────────────────────────────────────────────┐
│ 方法                              │ 参数                                       │
├───────────────────────────────────┼────────────────────────────────────────────┤
│ get_block                         │ {"height": N} 或 {"hash": [32B]}           │
│ get_object                        │ {"id": {"creator":[20B], "creation_nonce":N}}│
│ get_tx                            │ {"tx_hash": [32B]}                         │
│ submit_tx                         │ {"tx_bytes": [BCS bytes]}                  │
│ get_account                       │ {"address": [20B]} 或 {"tagged_pubkey":{...}}│
│ get_dag_vertex                    │ {"vertex_hash": [32B]}                     │
│ secp256k1_aggregate_verify        │ {"pubkeys":[...], "msg_hashes":[...], "sigs":[...]}│
│ bls_verify                        │ {"pubkey_g2":[96B], "signature_g1":[48B], "msg":[...]}│
│ zk_verify                         │ {"scheme_id":N, "proof":[...], "public_io_bytes":[...],│
│                                   │  "max_skip_segments":N, "max_ack_chain_length":N}│
└───────────────────────────────────┴────────────────────────────────────────────┘
```

## 附录 B：错误码速查表

```
┌──────────┬──────────────────────┬──────────────────────────────────────────┐
│ code     │ 常量                 │ 含义                                     │
├──────────┼──────────────────────┼──────────────────────────────────────────┤
│ -32700   │ PARSE_ERROR          │ JSON 解析失败                            │
│ -32600   │ INVALID_REQUEST      │ 请求结构无效                             │
│ -32601   │ METHOD_NOT_FOUND     │ 方法未找到                               │
│ -32602   │ INVALID_PARAMS       │ 参数无效（含业务校验失败）               │
│ -32603   │ INTERNAL_ERROR       │ 内部错误                                 │
└──────────┴──────────────────────┴──────────────────────────────────────────┘
```

---

**文档结束**
