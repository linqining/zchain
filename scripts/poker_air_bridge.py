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

    def call(self, method: str, params) -> dict:
        req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
            s.sendall((req + "\n").encode())
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        line = buf.split(b"\n", 1)[0].decode().strip()
        if not line:
            raise RuntimeError(f"empty RPC response for {method}")
        return json.loads(line)

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
                       payload: str, nonce: int, wait_secs: float) -> tuple[str, bool]:
    tx_hash, tx_bytes = build_tx(zchain_bin, secret_hex, payload, nonce)
    rpc.submit_tx(tx_bytes)
    deadline = time.time() + wait_secs
    while time.time() < deadline:
        tx = rpc.get_tx(tx_hash)
        if tx is not None:
            return tx_hash, True
        time.sleep(0.5)
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
    rpc = NodeRpc("127.0.0.1", args.rpc_port)
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
                                     anchor_payload(record), nonce, args.wait_secs)
    print(json.dumps({"deploy_record_tx": tx_hash, "included": ok, "nonce": nonce}))
    return 0 if ok else 1


def cmd_bridge(args) -> int:
    rpc = NodeRpc("127.0.0.1", args.rpc_port)
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
        for row in rows:
            binding = row.get("binding_hex")
            if not binding or binding in anchored:
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
            # 每次提交前都从链上取权威 nonce（admission 要求 tx.nonce 与
            # 账户 nonce 严格一致；本地计数在失败/竞态下必然漂移）。
            nonce = sync_nonce(rpc, args.address, nonce)
            tx_hash = None
            included = False
            for attempt in range(3):
                try:
                    tx_hash, tx_bytes = build_tx(args.zchain_bin, args.secret_key_hex,
                                                 payload, nonce)
                    rpc.submit_tx(tx_bytes)
                except Exception as e:  # noqa: BLE001
                    msg = str(e)
                    if "nonce" in msg:
                        # nonce 竞态（他处已提交）：读链上最新值原地重试。
                        nonce = sync_nonce(rpc, args.address, nonce)
                        continue
                    print(f"[bridge] anchor {binding[:16]}… failed: {e}", flush=True)
                    break
                # 提交受理：轮询确认入块（节点空闲休眠由新 tx 提交唤醒，
                # 正常 <1s 入块；90s 上限覆盖极端情况）。
                deadline = time.time() + args.wait_secs
                while time.time() < deadline:
                    if rpc.get_tx(tx_hash) is not None:
                        included = True
                        break
                    time.sleep(0.5)
                if included:
                    break
                # 未在窗口内入块：不再用其他 nonce 重发（严格 nonce 口径下
                # 只允许一笔在途），留给下一轮以链上权威 nonce 重试。
                print(f"[bridge] anchor {binding[:16]}… submitted (nonce={nonce}) "
                      f"but not included in {args.wait_secs}s — will retry next round",
                      flush=True)
                break
            if included and tx_hash:
                anchored[binding] = {"tx_hash": tx_hash, "nonce": nonce}
                newly += 1
                state["nonce"] = nonce + 1
                save_state(state_path, state)
                print(f"[bridge] ANCHORED binding={binding} tx={tx_hash} "
                      f"pot={row.get('pot')} total={len(anchored)}", flush=True)
        total = len(anchored)
        print(f"[bridge] round {round_no}: settlements={len(rows)} newly_anchored={newly} "
              f"total_anchored={total}", flush=True)
        if args.target > 0 and total >= args.target:
            print(f"[bridge] target reached: {total} >= {args.target}", flush=True)
            return 0
        if args.once:
            return 0
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
    p.add_argument("--zchain-bin", default="./target/release/zchain")
    p.add_argument("--nonce", type=int, default=0)
    p.add_argument("--meta", default="")
    p.add_argument("--wait-secs", type=float, default=20.0)

    p = sub.add_parser("bridge")
    p.add_argument("--secret-key-hex", required=True)
    p.add_argument("--address", default="", help="发送方账户地址（keygen address_hex；用于链上 nonce 同步）")
    p.add_argument("--rpc-port", type=int, required=True)
    p.add_argument("--wal", required=True)
    p.add_argument("--sequencer-public", required=True)
    p.add_argument("--gateway-bin", default="./target/release/explorer_gateway")
    p.add_argument("--zchain-bin", default="./target/release/zchain")
    p.add_argument("--state-file", required=True)
    p.add_argument("--poll-secs", type=float, default=10.0)
    p.add_argument("--target", type=int, default=0)
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
