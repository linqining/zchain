# run\_node 集成 DAG 产块循环计划

## Context

`src/main.rs` 中已实现所有 DAG 产块循环所需的辅助函数：

* `TcpTransport`（lines 468-556）：实现 `NetworkTransport` trait，4 字节 length-prefix + BCS

* `send_p2p_message` / `recv_p2p_message`（lines 559-595）：帧编解码

* `handle_p2p_connection`（lines 603-653）：接收端消息分发（DagVertex/Transaction/ResponseBlocks）

* `secp256k1_sign_hash`（lines 669-677）：65B recoverable 签名

* `build_block_from_vertex`（lines 684-753）：从单个 vertex 构造 Block + DagCommitCertificate

* `run_validator_loop`（lines 762-928）：validator 后台产块循环

**唯一剩余工作**：修改 `run_node`（lines 151-370）集成上述组件，并更新 `print_usage`。

## 当前 run\_node 结构

```
run_node(args):
  1. 解析 CLI 参数（role/data-dir/rpc-listen/p2p-listen/max-connections/validator-key）
  2. 构建 NodeConfig → Node::open → Arc<Node>
  3. 绑定 RPC TcpListener（non-blocking）
  4. spawn signal handler 线程（SIGINT/SIGTERM → shutdown_flag）
  5. 创建 RpcGuard（限流）
  6. std::thread::scope { RPC accept loop }  ← 当前阻塞在这里
  7. join signal_thread
```

## 改动方案

### 1. 新增 CLI 参数解析（run\_node 内）

在 `--validator-key` 之后、`"--help"` 之前新增两个 match 分支：

```rust
"--block-interval-ms" => {
    i += 1;
    let v = args.get(i).ok_or("--block-interval-ms 缺少参数")?;
    block_interval_ms = v.parse::<u64>()
        .map_err(|e| format!("--block-interval-ms 解析失败：{e}"))?;
    if block_interval_ms == 0 {
        return Err("--block-interval-ms 必须 > 0".to_string());
    }
}
"--peer" => {
    i += 1;
    let addr = args.get(i).ok_or("--peer 缺少参数")?.clone();
    peers.push(addr);
}
```

新增局部变量（在函数开头）：

```rust
let mut block_interval_ms: u64 = DEFAULT_BLOCK_INTERVAL_MS; // 1000
let mut peers: Vec<String> = Vec::new();
```

### 2. 集成 P2P + validator 循环（run\_node 内，RPC scope 之前）

在 "按 Ctrl+C 退出" 日志之后、`std::thread::scope` 之前插入：

```rust
// === P2P 传输层 ===
let transport = Arc::new(TcpTransport::new());

// 绑定 P2P listener
let p2p_listener = TcpListener::bind(&p2p_listen)
    .map_err(|e| format!("P2P 监听绑定 {p2p_listen} 失败：{e}"))?;
p2p_listener.set_nonblocking(true)
    .map_err(|e| format!("P2P set_nonblocking 失败：{e}"))?;
info!("P2P server 监听 {p2p_listen}（length-prefixed BCS）");

// 主动连接 --peer 列表
for peer_addr in &peers {
    if let Err(e) = transport.connect_peer(peer_addr) {
        warn!("初始连接 peer {peer_addr} 失败：{e}（后续可重试）");
    }
}
info!("P2P 已连接 {} 个 peer", transport.peer_count());

// === P2P accept loop 线程 ===
let p2p_node = Arc::clone(&node_arc);
let p2p_transport = Arc::clone(&transport);
let p2p_shutdown = Arc::clone(&shutdown_flag);
let p2p_thread = std::thread::Builder::new()
    .name("p2p-accept".to_string())
    .spawn(move || {
        loop {
            if p2p_shutdown.load(Ordering::SeqCst) {
                break;
            }
            match p2p_listener.accept() {
                Ok((stream, addr)) => {
                    let _ = stream.set_nonblocking(false);
                    info!("P2P 接入连接：{addr}");
                    let node = Arc::clone(&p2p_node);
                    let transport = Arc::clone(&p2p_transport);
                    std::thread::spawn(move || {
                        handle_p2p_connection(stream, node, transport);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
                }
                Err(e) => {
                    warn!("P2P accept 失败：{e}");
                    std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
                }
            }
        }
    })
    .map_err(|e| format!("P2P accept 线程启动失败：{e}"))?;

// === validator 产块循环线程（仅 validator 角色）===
// 注意：config 已 move 进 Node::open，需从 node_arc.config() 获取 validator_key
let validator_thread = if role.is_validator() {
    let vkey = node_arc.config().validator_key.clone()
        .ok_or("validator 角色缺少 validator_key")?;
    let chain_id = node_arc.chain_id();
    let dag = Arc::new(Mutex::new(Dag::new()));
    let v_transport = Arc::clone(&transport);
    let v_shutdown = Arc::clone(&shutdown_flag);
    let v_node = Arc::clone(&node_arc);
    let interval = Duration::from_millis(block_interval_ms);
    Some(std::thread::Builder::new()
        .name("validator-loop".to_string())
        .spawn(move || {
            run_validator_loop(v_node, vkey, chain_id, dag, v_transport, interval, v_shutdown);
        })
        .map_err(|e| format!("validator loop 线程启动失败：{e}"))?)
} else {
    info!("非 validator 角色，跳过产块循环");
    None
};
```

### 3. RPC scope 之后 join 新线程

将现有的：

```rust
let _ = signal_thread.join();
```

改为：

```rust
let _ = signal_thread.join();
let _ = p2p_thread.join();
if let Some(vt) = validator_thread {
    let _ = vt.join();
}
```

### 4. 更新 print\_usage

在 `--validator-key` 行之后新增：

```
--block-interval-ms <ms>                  出块间隔毫秒（默认 1000，仅 validator）
--peer <addr>                             P2P peer 地址（可重复，如 127.0.0.1:9001）
```

## 关键文件

| 文件                                                           | 改动                                                         |
| ------------------------------------------------------------ | ---------------------------------------------------------- |
| [src/main.rs](file:///Users/mac/projects/zchain/src/main.rs) | 修改 `run_node`（lines 151-370）+ `print_usage`（lines 108-146） |

## 验证

1. **编译**：`cargo zigbuild --release --target x86_64-unknown-linux-musl`
2. **本地启动 validator**：

   ```
   zchain keygen --scheme secp256k1  # 获取 secret_key_hex
   ZCHAIN_VALIDATOR_KEY=<hex> zchain node --role validator --data-dir /tmp/val1
   ```
3. **观察日志**：应看到 "validator 产块循环已启动" + 每秒 "vertex 已产出" + 从第 2 轮起 "✅ 出块成功"
4. **RPC 查询**：`submit_tx` 提交交易 → 等待 2 秒 → `get_block` height=1 确认含 tx

## 假设与决策

* **P2P listener non-blocking**：与 RPC listener 相同模式，100ms 轮询 shutdown\_flag

* **validator 线程独立 spawn**（非 scoped thread）：因为它需要在 RPC scope 之外持续运行，由 shutdown\_flag 协调退出

* **full/light/archive 角色不 spawn validator loop**，但仍启动 P2P accept loop（可接收同步数据）

* **不修改任何 poker\_l1 库代码**：所有集成在 main.rs 内完成

