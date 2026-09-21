#!/usr/bin/env python3
"""poker_air_bridge.py — poker_texas_air(appchain) 结算 → zchain L1 提交桥。

数据流（对应 scripts/dev_poker_air.sh 的整体部署）：

    texas 服务器（appchain 出口）→ sequencer.wal
      └─ explorer_gateway --write-index（全量重放 + 验签，fail-closed）
          └─ 本桥解析 archive index 的 Settle 行 → 每笔结算构造并签名
             zchain Public tx（payload = 结算事实 JSON）→ submit_tx
             （newline-delimited JSON-RPC over TCP）→ get_tx 确认入块。

子命令：
  pubkeys  --sequencer-seed-hex H [--attestor-seed-hex H]
           推导 ed25519 公钥（纯 python RFC 8032 实现，供 gateway
           --sequencer-public 与 deploy-record 使用）。
  deploy-record --secret-key-hex K --rpc-port P [--meta JSON]
           向 zchain 提交 poker_texas_air 合约部署/绑定记录 tx。
  bridge   --secret-key-hex K --rpc-port P --wal PATH --sequencer-public HEX
           [--gateway-bin BIN] [--state-file PATH] [--poll-secs N]
           [--target N] [--max-rounds N] [--once]
           常驻：增量发现 appchain 结算并逐笔锚定到 zchain。

状态文件（JSON）记录已锚定的 binding_hex → {tx_hash, height?}，重启续跑。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# ed25519 公钥推导（RFC 8032 参考实现的最小子集；仅推导公钥，不签名）。
# ---------------------------------------------------------------------------

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def _edwards_inv(x: int) -> int:
    return pow(x, P - 2, P)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _edwards_inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


_BY = [None] * 4
_BY[0] = (_x_recover(4 * _edwards_inv(5)) % P, 4 * _edwards_inv(5) % P)


def ed25519_public(seed: bytes) -> bytes:
    """32B 种子 → 32B ed25519 公钥（与 ed25519_dalek 一致）。"""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254

    def point_add(p1, p2):
        x1, y1 = p1
        x2, y2 = p2
        x3 = (x1 * y2 + x2 * y1) * _edwards_inv(1 + D * x1 * x2 * y1 * y2)
        y3 = (y1 * y2 + x1 * x2) * _edwards_inv(1 - D * x1 * x2 * y1 * y2)
        return (x3 % P, y3 % P)

    def scalarmult(p, e):
        if e == 0:
            return (0, 1)
        q = scalarmult(p, e // 2)
        q = point_add(q, q)
        if e & 1:
            q = point_add(q, p)
        return q

    def encode_point(p):
        x, y = p
        return ((y | ((x & 1) << 255))).to_bytes(32, "little")

    if _BY[0][0] is not None and _BY[1] is None:
        _BY[1] = point_add(_BY[0], _BY[0])
        _BY[2] = point_add(_BY[1], _BY[1])
        _BY[3] = point_add(_BY[1], _BY[2])

    a_clamped = a
    pub = scalarmult(_BY[0], a_clamped)
    return encode_point(pub)


# ---------------------------------------------------------------------------
# zchain 节点 TCP JSON-RPC（newline-delimited）。
# ---------------------------------------------------------------------------

class NodeRpc:
    def __init__(self, host: str, port: int, timeout: float = 8.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        # 持久连接：批量提交时每笔新建 TCP 会被节点拒绝/重置（节点
        # max_connections 全局 128 含 P2P，抖动期新连接最易被拒）。
        # 复用单条连接 + 断线自动重连。
        self._sock: socket.socket | None = None
        self._buf = b""

    def _connect(self) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock = s
        self._buf = b""
        return s

    def _ensure(self) -> socket.socket:
        if self._sock is None:
            return self._connect()
        return self._sock

    def _reset(self) -> None:
        try:
            if self._sock is not None:
                self._sock.close()
        except Exception:  # noqa: BLE001
            pass
        self._sock = None
        self._buf = b""

    def call(self, method: str, params) -> dict:
        req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        last_err: Exception | None = None
        for _ in range(2):  # 一次失败重连重试
            try:
                s = self._ensure()
                s.sendall((req + "\n").encode())
                buf = self._buf
                while b"\n" not in buf:
                    chunk = s.recv(65536)
                    if not chunk:
                        raise ConnectionError("connection closed by node")
                    buf += chunk
                line, self._buf = buf.split(b"\n", 1)
                return json.loads(line.decode())
            except (OSError, ConnectionError) as e:
                last_err = e
                self._reset()
        raise last_err if last_err else RuntimeError("rpc call failed")

    def submit_tx(self, tx_bytes: list[int]) -> str:
        resp = self.call("submit_tx", {"tx_bytes": tx_bytes})
        if "error" in resp:
            raise RuntimeError(f"submit_tx error: {resp['error']}")
        return resp["result"]["tx_hash"]

    def get_tx(self, tx_hash: str):
        h = tx_hash.lower()
        if h.startswith("0x"):
            h = h[2:]
        resp = self.call("get_tx", {"tx_hash": list(bytes.fromhex(h))})
        if "error" in resp:
            return None
        return resp["result"]

    def get_block_count(self) -> int:
        resp = self.call("get_block_count", {})
        if "error" in resp:
            return -1
        result = resp["result"]
        if isinstance(result, dict):
            return int(result.get("height") or 0)
        return int(result)

    def get_account_nonce(self, address_hex: str) -> int | None:
        """地址（20B hex）→ 链上 nonce；账户不存在返回 0，查询失败 None。"""
        resp = self.call("get_account", {"address": list(bytes.fromhex(address_hex))})
        if "error" in resp:
            return None
        acct = resp["result"]
        if not acct:
            return 0
        return int(acct.get("nonce", 0))


# ---------------------------------------------------------------------------
# tx 构造（复用 zchain CLI：构造 + secp256k1 可恢复签名 + BCS）。
# ---------------------------------------------------------------------------

def build_tx(zchain_bin: str, secret_hex: str, payload: str, nonce: int) -> tuple[str, list[int]]:
    """返回 (tx_hash_hex, tx_bytes)。payload 必须为 ASCII。"""
    out = subprocess.run(
        [zchain_bin, "tx", "--secret-key-hex", secret_hex,
         "--payload", payload, "--nonce", str(nonce)],
        capture_output=True, text=True, check=True,
    )
    data = json.loads(out.stdout.strip().splitlines()[-1])
    return data["tx_hash_hex"], data["tx_bytes"]


def anchor_payload(record: dict) -> str:
    """结算/部署记录 → tx payload（紧凑 ASCII JSON）。"""
    body = {"v": "poker_air_settlement_v1", "src": "texas-appchain"}
    body.update(record)
    text = json.dumps(body, separators=(",", ":"), sort_keys=True)
    text.encode("ascii")  # fail fast：payload 必须全 ASCII（CLI 参数约束）
    return text


# ---------------------------------------------------------------------------
# archive index 解析。
# ---------------------------------------------------------------------------

def parse_settlements(index_path: Path) -> list[dict]:
    """archive index（首行 header，其后逐行 frame JSON）→ Settle 摘要列表。"""
    rows = []
    with index_path.open() as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if i > 0 and obj.get("kind") == "Settle":
                rows.append(obj)
    return rows


def refresh_index(gateway_bin: str, wal: Path, seq_pub_hex: str, out: Path) -> None:
    res = subprocess.run(
        [gateway_bin, "--write-index", str(out),
         "--appchain-wal", str(wal), "--sequencer-public", seq_pub_hex],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"write-index failed: {res.stderr.strip()[:400]}")


# ---------------------------------------------------------------------------
# 状态文件。
# ---------------------------------------------------------------------------

def load_state(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            pass
    return {"anchored": {}, "nonce": 0}


def save_state(path: Path, state: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# 子命令。
# ---------------------------------------------------------------------------

def cmd_pubkeys(args) -> int:
    if args.sequencer_seed_hex:
        seed = bytes.fromhex(args.sequencer_seed_hex)
        print("sequencer_public:", ed25519_public(seed).hex())
    if args.attestor_seed_hex:
        seed = bytes.fromhex(args.attestor_seed_hex)
        print("attestor_public:", ed25519_public(seed).hex())
    return 0


def submit_and_confirm(rpc: NodeRpc, zchain_bin: str, secret_hex: str,
                       payload: str, nonce: int, address: str | None = None,
                       wait_secs: float = 30.0) -> tuple[str, bool]:
    """提交并以「账户 nonce 推进」确认真正入块执行。

    不能用 get_tx 判定：节点的 get_tx 读的是 submit_tx 时写入的**内存
    tx_cache**（rpc/mod.rs submit 路径先 insert 再返回），提交即命中——
    与是否被打包进块无关。曾因此把 300+ 笔从未入块的 tx 误标 ANCHORED。
    账户 nonce 是执行序号：account_nonce > tx nonce ⟺ 本笔已被执行。
    （桥单线程串行提交，同账户无并发在途 tx，语义精确。）"""
    tx_hash, tx_bytes = build_tx(zchain_bin, secret_hex, payload, nonce)
    rpc.submit_tx(tx_bytes)
    deadline = time.time() + wait_secs
    while time.time() < deadline:
        if address:
            try:
                chain_nonce = rpc.get_account_nonce(address)
            except Exception:  # noqa: BLE001 — 网络抖动，下轮再查
                chain_nonce = None
            if chain_nonce is not None and chain_nonce > nonce:
                return tx_hash, True
        else:
            # 无 address 时退化为旧语义（仅本地演练用，不保证入块）
            tx = rpc.get_tx(tx_hash)
            if tx is not None:
                return tx_hash, True
        # 2s 间隔：远程低配盘上每次 get_account 都是节点 RocksDB 读，
        # 0.5s 轮询会叠加出块执行把云盘读 IOPS 打满（IO wait 锁死全机）。
        time.sleep(2.0)
    return tx_hash, False


def sync_nonce(rpc: NodeRpc, address: str | None, fallback: int) -> int:
    """链上权威 nonce；查询失败退回本地状态（仅作兜底，绝不自行加码——
    此前 max(chain, local+1) 的口径会让失败重试把 nonce 越推越高）。"""
    if not address:
        return fallback
    try:
        chain_nonce = rpc.get_account_nonce(address)
    except Exception:  # noqa: BLE001
        return fallback
    if chain_nonce is None:
        return fallback
    return chain_nonce


def cmd_deploy_record(args) -> int:
    rpc = NodeRpc(args.rpc_host, args.rpc_port)
    meta = json.loads(args.meta) if args.meta else {}
    record = {
        "action": "contract_deploy_record",
        "project": "poker_texas_air",
        "chain": "zchain-devnet-1",
        "ts_ms": int(time.time() * 1000),
        **meta,
    }
    nonce = sync_nonce(rpc, args.address, args.nonce)
    tx_hash, ok = submit_and_confirm(rpc, args.zchain_bin, args.secret_key_hex,
                                     anchor_payload(record), nonce,
                                     address=args.address, wait_secs=args.wait_secs)
    print(json.dumps({"deploy_record_tx": tx_hash, "included": ok, "nonce": nonce}))
    return 0 if ok else 1


def chain_nonce_max(fans, address):
    """跨节点读账户 nonce 取最大值（最新视图）。

    单节点读取会被块应用滞后拖累（实测读到 0 而实际 4），导致 sync_nonce
    回退旧值 → 重提旧 nonce → 拒收 + 90s 空等。取 max 恒为新视图。"""
    best = None
    for fan in fans:
        try:
            n = fan.get_account_nonce(address)
        except Exception:  # noqa: BLE001
            continue
        if n is not None and (best is None or n > best):
            best = n
    return best


def strict_chain_nonce(rpc_fans, rpc, address, attempts: int = 8):
    """严格获取链上账户 nonce（幽灵 anchored 根修，2026-09-21）。

    旧路径：chain_nonce_max 全部读取失败 → sync_nonce 再失败 → 回退调用方
    的陈旧游标。陈旧 nonce 的 submit 被四个节点静默拒绝（异常被吞），而
    确认判据「chain_nonce > nonce」因 nonce 停在旧值**瞬时误判为已确认**
    —— 同一 nonce 被两个 binding 记入 anchored，其中一个从未上链（远程
    重锚 3029 笔实测 10 条幽灵，含启动期读到 nonce 0 的记录）。

    现改为：两路读取轮流重试（退避至多 ~20s），全部失败返回 None，由调用
    方放弃本轮；**绝不用陈旧 nonce 提交**。"""
    delay = 0.5
    for _ in range(attempts):
        n = chain_nonce_max(rpc_fans, address)
        if n is not None:
            return n
        n = sync_nonce(rpc, address, None)
        if n is not None:
            return n
        time.sleep(delay)
        delay = min(delay * 1.5, 5.0)
    return None


def cmd_bridge(args) -> int:
    rpc = NodeRpc(args.rpc_host, args.rpc_port)
    # 全节点广播面：tx 提交到每个节点，消除 gossip 丢失导致的"永不执行"。
    # 端口组从主端口推导（18546→18545-18548；SSH 隧道偏移 28546→28545-28548）。
    fan_base = args.rpc_port - ((args.rpc_port - 5) % 4)
    rpc_fans = [rpc] + [
        NodeRpc(args.rpc_host, p)
        for p in range(fan_base, fan_base + 4)
        if p != args.rpc_port
    ]
    state_path = Path(args.state_file)
    state = load_state(state_path)
    anchored: dict = state.setdefault("anchored", {})
    nonce: int = sync_nonce(rpc, args.address, int(state.get("nonce", 0)))
    state["nonce"] = nonce
    save_state(state_path, state)
    index_path = state_path.parent / "bridge_archive_index.jsonl"
    deadline_rounds = args.max_rounds if args.max_rounds > 0 else 10 ** 9
    settled_target_hit_at = None

    for round_no in range(deadline_rounds):
        try:
            refresh_index(args.gateway_bin, Path(args.wal), args.sequencer_public, index_path)
            rows = parse_settlements(index_path)
        except Exception as e:  # noqa: BLE001 — 常驻桥，单轮失败记录后继续
            print(f"[bridge] round {round_no}: refresh failed: {e}", flush=True)
            rows = []
        newly = 0
        # ---- 批量模式：连续 nonce 预构造 N 笔一次提交，再统一等 nonce 追上。
        # 链按 nonce 序执行，批量入块吞吐 ~N/(1-2 块间隔)，远快于逐笔确认
        # （链重置周期 ~10 分钟，全量重锚必须分钟级完成才能收敛）。
        batch: list[tuple[str, str]] = []  # (binding, payload)
        owned_all = None
        if args.partition_m > 1:
            owned_all = {row["binding_hex"] for i, row in enumerate(rows)
                         if row.get("binding_hex") and i % args.partition_m == args.partition_n}
        for row in rows:
            if args.max_per_round > 0 and len(batch) >= args.max_per_round:
                break  # 余下的留给下一轮（WAL 不丢）
            binding = row.get("binding_hex")
            if not binding or binding in anchored:
                continue
            if owned_all is not None and binding not in owned_all:
                continue
            payload = anchor_payload({
                "action": "settle_hand_anchor",
                "binding": binding,
                "table_id": row.get("table_id"),
                "frame_index": row.get("index"),
                "pot": row.get("pot"),
                "rake_total": row.get("rake_total"),
                "payouts": row.get("payouts"),
                "ts_ms": row.get("ts_ms"),
            })
            batch.append((binding, payload))
        if batch and not args.stream_only:
            # 严格取 nonce（同 stream 模式幽灵根修）：读取失败重试，绝不退回
            # 陈旧游标 —— 全部 submit 会被静默拒绝，而确认判据瞬时误判。
            base_nonce = strict_chain_nonce(rpc_fans, rpc, args.address)
            if base_nonce is None:
                print("[bridge] chain nonce 不可读，本轮跳过批量（下轮重试）", flush=True)
                batch = []
            nonce = base_nonce if base_nonce is not None else nonce
            submitted: list[tuple[str, str, int]] = []  # (binding, tx_hash, nonce)
            ok_submit = bool(batch)
            for offset, (binding, payload) in enumerate(batch):
                n = base_nonce + offset
                try:
                    tx_hash, tx_bytes = build_tx(args.zchain_bin, args.secret_key_hex,
                                                 payload, n)
                    # 广播到全部节点：出块的 validator 可能没收到单点提交的
                    # tx（gossip 丢失）——块里不含它则该 tx 永不执行、堵死
                    # 后续 nonce。同 hash 各节点幂等去重，全网必见。
                    for fan in rpc_fans:
                        try:
                            fan.submit_tx(tx_bytes)
                        except Exception:  # noqa: BLE001 — 单节点失败不阻断
                            pass
                    submitted.append((binding, tx_hash, n))
                    # 密集提交（20ms）：submit_tx 会即时唤醒节点 validator loop
                    # 单独 drain——0.3s 间隔会让每笔独占一个 vertex，每块只
                    # 执行 1 笔。密集提交使整批落入同一次 drain/同一个 vertex。
                    time.sleep(0.02)
                except Exception as e:  # noqa: BLE001
                    msg = str(e)
                    if "nonce" in msg:
                        # 竞态/重置：放弃本批，下轮以链上权威 nonce 重来
                        nonce = sync_nonce(rpc, args.address, nonce)
                        ok_submit = False
                        break
                    print(f"[bridge] anchor {binding[:16]}… failed: {e}", flush=True)
                    break
            if ok_submit and submitted:
                target_nonce = submitted[-1][2]
                deadline = time.time() + max(args.wait_secs, 60.0)
                done_nonce = base_nonce
                while time.time() < deadline:
                    try:
                        chain_nonce = rpc.get_account_nonce(args.address)
                    except Exception:  # noqa: BLE001 — 下轮再查
                        chain_nonce = None
                    if chain_nonce is None:
                        time.sleep(2.0)
                        continue
                    done_nonce = chain_nonce - 1
                    if chain_nonce > target_nonce:
                        done_nonce = target_nonce
                        break
                    time.sleep(2.0)
                for binding, tx_hash, n in submitted:
                    if n <= done_nonce:
                        anchored[binding] = {"tx_hash": tx_hash, "nonce": n}
                        newly += 1
                    else:
                        # 链停在半途：已执行部分入账，未执行部分下轮重来
                        print(f"[bridge] anchor {binding[:16]}… nonce={n} 未入块"
                              f"（链执行到 {done_nonce}），下轮重试", flush=True)
                state["nonce"] = done_nonce + 1
                save_state(state_path, state)
                if newly:
                    last = submitted[-1]
                    print(f"[bridge] ANCHORED batch={newly}/{len(submitted)} "
                          f"last_binding={submitted[newly-1][0][:24]} "
                          f"total={len(anchored)}", flush=True)
        total = len(anchored)
        print(f"[bridge] round {round_no}: settlements={len(rows)} newly_anchored={newly} "
              f"total_anchored={total}", flush=True)
        if args.target > 0 and total >= args.target:
            print(f"[bridge] target reached: {total} >= {args.target}", flush=True)
            return 0
        if args.once:
            return 0

        # ---- 串行流模式（nonce 严格 admission 的配套提交策略）----
        # 节点 submit_tx 校验 tx.nonce == account.nonce（严格相等，无 future
        # nonce 缓冲）——批量预构造连续 nonce 只有首笔能入池，其余全部
        # "nonce too high" 拒收。这里在单轮内串行推进：提交一笔 → 等 nonce
        # 推进（0.5s 步进）→ 立即提交下一笔，免去整轮 refresh/poll 开销。
        # 每笔执行时延 ≈ 1-2 个块间隔，吞吐由链出块率决定。
        stream = [row for row in rows
                  if row.get("binding_hex") and row["binding_hex"] not in anchored]
        # 分片：多账户并行时各桥认领互不重叠的 WAL 行（按全局序取模）
        if args.partition_m > 1:
            all_rows = [row for row in rows if row.get("binding_hex")]
            owned = {row["binding_hex"] for i, row in enumerate(all_rows)
                     if i % args.partition_m == args.partition_n}
            stream = [row for row in stream if row["binding_hex"] in owned]
        for row in stream:
            binding = row["binding_hex"]
            payload = anchor_payload({
                "action": "settle_hand_anchor",
                "binding": binding,
                "table_id": row.get("table_id"),
                "frame_index": row.get("index"),
                "pot": row.get("pot"),
                "rake_total": row.get("rake_total"),
                "payouts": row.get("payouts"),
                "ts_ms": row.get("ts_ms"),
            })
            confirmed = False
            tx_hash = None
            nonce_dead = False
            for attempt in range(3):
                # 严格取 nonce（幽灵 anchored 根修）：读取失败重试，绝不退回
                # 陈旧游标——陈旧 nonce 的 submit 被静默拒绝后，确认判据
                # 「chain_nonce > nonce」瞬时误判（详见 strict_chain_nonce）。
                fresh = strict_chain_nonce(rpc_fans, rpc, args.address)
                if fresh is None:
                    nonce_dead = True
                    break
                nonce = fresh
                try:
                    tx_hash, tx_bytes = build_tx(args.zchain_bin, args.secret_key_hex,
                                                 payload, nonce)
                    for fan in rpc_fans:
                        try:
                            fan.submit_tx(tx_bytes)
                        except Exception:  # noqa: BLE001
                            pass
                except Exception as e:  # noqa: BLE001
                    msg = str(e)
                    if "nonce" in msg:
                        continue  # 竞态：重读链上 nonce 重试
                    print(f"[bridge] anchor {binding[:16]}… failed: {e}", flush=True)
                    break
                deadline = time.time() + 90.0
                last_resubmit = time.time()
                while time.time() < deadline:
                    chain_nonce = chain_nonce_max(rpc_fans, args.address)
                    if chain_nonce is not None and chain_nonce > nonce:
                        confirmed = True
                        break
                    # 30s 未入块：重提（同 hash，已在池节点 RBF 拒之无害，
                    # 已 drain 节点重新入池）+ 生产者 2s 重播兜底
                    if time.time() - last_resubmit > 30:
                        last_resubmit = time.time()
                        try:
                            for fan in rpc_fans:
                                try:
                                    fan.submit_tx(tx_bytes)
                                except Exception:  # noqa: BLE001
                                    pass
                        except Exception:  # noqa: BLE001
                            pass
                    time.sleep(0.5)
                if confirmed:
                    break
                print(f"[bridge] anchor {binding[:16]}… nonce={nonce} 90s 未入块，重试", flush=True)
            if nonce_dead:
                # 链 nonce 持续不可读：整轮放弃（绝不带陈旧 nonce 继续提交）。
                print("[bridge] chain nonce 持续不可读，退出本轮 stream（下轮重试）",
                      flush=True)
                break
            if confirmed and tx_hash:
                anchored[binding] = {"tx_hash": tx_hash, "nonce": nonce}
                newly += 1
                state["nonce"] = nonce + 1
                save_state(state_path, state)
                total += 1
                print(f"[bridge] ANCHORED binding={binding[:32]} tx={tx_hash[:20]} "
                      f"total={total}", flush=True)
                if args.target > 0 and total >= args.target:
                    print(f"[bridge] target reached: {total} >= {args.target}", flush=True)
                    return 0
            else:
                # 链停滞：退出流模式回到轮询（外层会重走 refresh/重试）
                break
        time.sleep(args.poll_secs)
    total = len(anchored)
    if args.target > 0 and total < args.target:
        print(f"[bridge] timeout: anchored {total} < target {args.target}", flush=True)
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pubkeys")
    p.add_argument("--sequencer-seed-hex", default="")
    p.add_argument("--attestor-seed-hex", default="")

    p = sub.add_parser("deploy-record")
    p.add_argument("--secret-key-hex", required=True)
    p.add_argument("--address", default="", help="发送方账户地址（keygen address_hex；用于链上 nonce 同步）")
    p.add_argument("--rpc-port", type=int, required=True)
    p.add_argument("--rpc-host", default="127.0.0.1", help="zchain RPC host（远程 4 节点部署时传公网地址）")
    p.add_argument("--zchain-bin", default="./target/release/zchain")
    p.add_argument("--nonce", type=int, default=0)
    p.add_argument("--meta", default="")
    p.add_argument("--wait-secs", type=float, default=20.0)

    p = sub.add_parser("bridge")
    p.add_argument("--secret-key-hex", required=True)
    p.add_argument("--address", default="", help="发送方账户地址（keygen address_hex；用于链上 nonce 同步）")
    p.add_argument("--rpc-port", type=int, required=True)
    p.add_argument("--rpc-host", default="127.0.0.1", help="zchain RPC host（远程 4 节点部署时传公网地址）")
    p.add_argument("--wal", required=True)
    p.add_argument("--sequencer-public", required=True)
    p.add_argument("--gateway-bin", default="./target/release/explorer_gateway")
    p.add_argument("--zchain-bin", default="./target/release/zchain")
    p.add_argument("--state-file", required=True)
    p.add_argument("--poll-secs", type=float, default=10.0)
    p.add_argument("--target", type=int, default=0)
    p.add_argument("--partition-n", type=int, default=0, help="分片序号（配合 --partition-m）")
    p.add_argument("--stream-only", action="store_true",
                   help="跳过 batch 提交阶段，直接串行流模式（batch 的 60s 确认窗口"
                        "在流模式前空等，实测每笔多耗 60-90s）")
    p.add_argument("--partition-m", type=int, default=1, help="总分片数（多账户并行锚定）")
    p.add_argument("--max-per-round", type=int, default=0,
                   help="每轮最多锚定笔数（0=不限）。爆发提交会诱发节点 DAG 视图"
                        "分叉（mempool 不同步 → vertex parent not found → 全链停"
                        "摆），远程链建议 5-10 笔/轮温和提交。")
    p.add_argument("--max-rounds", type=int, default=0)
    p.add_argument("--wait-secs", type=float, default=25.0)
    p.add_argument("--once", action="store_true")

    args = ap.parse_args()
    if args.cmd == "pubkeys":
        return cmd_pubkeys(args)
    if args.cmd == "deploy-record":
        return cmd_deploy_record(args)
    return cmd_bridge(args)


if __name__ == "__main__":
    sys.exit(main())
