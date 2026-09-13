#!/usr/bin/env python3
"""rake 审计外部独立复验工具（M5-ACC-3：独立语言 + 独立代码路径）。

本工具是 `zchain.rake_audit.v1` 审计 JSON 的**第三方复验器**：

- **独立性边界**：纯 Python 标准库（无第三方包），不 import 任何仓库
  Rust 产物（不读 poker-appchain 源码/不调用其校验器与费率模块），公式
  按 `poker-appchain/docs/ABI.md` §3/§4 的规范独立重实现：
    * rake 计费基数（B9 contested-only 口径）= **contested 层 gross 之和**，
      contested 标志按 `eligible_seats >= 2` 独立重导出（不信任导出标志）；
    * `rake = min(floor(rake_base * rate_bps / 10^4), cap)`（cap == 0 = 无
      封顶；mode 0 = ZERO 桌恒 0）；
    * 分账 `treasury = floor(rake * treasury_bps / 10^4)`、零头归 operator；
    * uncontested 层 rake 必须为 0（uncalled 返还层不计费）；
    * 守恒 `Σinputs == Σpayouts + Σrake_outputs`；
    * 汇总一致 `header.rake_total == Σ明细 rake_total`；hand_binding 非零。
- 只读审计 JSON 文件；任何差异或输入问题 → 退出码 1，零差异 → 0。

用法：
    python3 tools_external/rake_audit_verify.py <audit.json>

退出码：0 = 零差异；1 = 差异或输入错误。
"""

import json
import sys

FORMAT_TAG = "zchain.rake_audit.v1"


def fail(diffs, msg):
    diffs.append(msg)


def is_hex32_nonzero(s):
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        bytes.fromhex(s)
    except ValueError:
        return False
    return any(c != "0" for c in s)


def get_int(obj, key, diffs, tag, errors):
    v = obj.get(key) if isinstance(obj, dict) else None
    if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
        return v
    errors.append(f"{tag}: 缺少/非法的非负整数 {key}")
    return None


def verify_record(i, rec, diffs):
    tag = f"records[{i}]"

    errors = []

    # hand_binding 形状 + 非零（32 字节 hex）
    binding = rec.get("hand_binding")
    if not is_hex32_nonzero(binding):
        fail(diffs, f"{tag}: hand_binding 非法或全零（应为 64 位 hex 非零）")

    frame_index = rec.get("frame_index")

    # 逐层：contested 标志独立重导出（eligible_seats >= 2）+ uncontested rake==0
    pots = rec.get("pots")
    if not isinstance(pots, list) or not pots:
        fail(diffs, f"{tag}: pots 缺失或为空（结算至少一层）")
        return
    recomputed_base = 0
    for li, pot in enumerate(pots):
        ptag = f"{tag} pots[{li}]"
        gross = get_int(pot, "gross_amount", diffs, ptag, errors)
        rake = get_int(pot, "rake", diffs, ptag, errors)
        seats = get_int(pot, "eligible_seats", diffs, ptag, errors)
        contested = pot.get("contested")
        if errors:
            diffs.extend(errors)
            return
        if gross is None or rake is None or seats is None:
            fail(diffs, f"{ptag}: 缺 gross_amount/rake/eligible_seats")
            continue
        recomputed_contested = seats >= 2
        if contested is not recomputed_contested:
            fail(
                diffs,
                f"{ptag}: contested 标志 {contested} 与 eligible_seats={seats} "
                f"矛盾（应为 {recomputed_contested}）",
            )
        if not recomputed_contested and rake != 0:
            fail(
                diffs,
                f"{ptag}: uncontested 层 rake={rake} != 0"
                "（B9：uncalled/sole-survivor 层不计费）",
            )
        if recomputed_contested:
            recomputed_base += gross

    # rake_base / 期望 rake 独立重算（floor(base*rate/10^4)，cap 封顶）
    rake_base = get_int(rec, "rake_base", diffs, tag, errors)
    if errors:
        diffs.extend(errors)
        return
    if rake_base != recomputed_base:
        fail(
            diffs,
            f"{tag}: rake_base={rake_base} 与 contested 层 gross 之和"
            f"={recomputed_base} 不符",
        )

    policy = rec.get("policy")
    if not isinstance(policy, dict):
        fail(diffs, f"{tag}: 缺 policy 对象")
        return
    mode = get_int(policy, "mode", diffs, tag, errors)
    rate_bps = get_int(policy, "rate_bps", diffs, tag, errors)
    cap = get_int(policy, "cap", diffs, tag, errors)
    treasury_bps = get_int(policy, "treasury_bps", diffs, tag, errors)
    if errors:
        diffs.extend(errors)
        return

    if mode == 0:
        expected_total = 0  # ZERO 桌：任意基数抽取恒 0
    elif mode == 1:
        if rate_bps > 10000:
            fail(diffs, f"{tag}: rate_bps={rate_bps} 越界（>10000）")
        raw = rake_base * rate_bps // 10**4
        expected_total = raw if cap == 0 else min(raw, cap)
    else:
        fail(diffs, f"{tag}: 未知策略 mode={mode}")
        return

    rake_total = get_int(rec, "rake_total", diffs, tag, errors)
    if errors:
        diffs.extend(errors)
        return
    if rake_total != expected_total:
        fail(
            diffs,
            f"{tag}: rake_total={rake_total} 与独立重算值={expected_total} 不符"
            f"（base={rake_base} rate_bps={rate_bps} cap={cap}）",
        )

    # 分账：treasury = floor(rake*treasury_bps/10^4)，零头归 operator
    expected_treasury = expected_total * treasury_bps // 10**4
    expected_operator = expected_total - expected_treasury

    def check_split(name, expected):
        out = rec.get(name)
        if expected == 0:
            if out is not None:
                fail(diffs, f"{tag} {name} 应为 null（期望分账为 0）")
            return
        if not isinstance(out, dict):
            fail(diffs, f"{tag} 缺 {name}（期望分账 {expected}）")
            return
        amount = out.get("amount")
        owner = out.get("owner")
        if amount != expected:
            fail(
                diffs,
                f"{tag} {name}.amount={amount} 与独立重算值={expected} 不符",
            )
        if not isinstance(owner, str):
            fail(diffs, f"{tag} {name}.owner 非法（应为 hex 字符串）")
            return
        try:
            if len(bytes.fromhex(owner)) != 33:
                fail(diffs, f"{tag} {name}.owner 不是 33 字节压缩公钥 hex")
        except ValueError:
            fail(diffs, f"{tag} {name}.owner 不是合法 hex")

    check_split("treasury_out", expected_treasury)
    check_split("operator_out", expected_operator)

    # 守恒：Σinputs == Σpayouts + Σrake_outputs（全部用导出数值）
    cons = rec.get("conservation")
    if not isinstance(cons, dict):
        fail(diffs, f"{tag}: 缺 conservation 对象")
        return
    inputs = get_int(cons, "inputs_sum", diffs, tag, errors)
    payouts = get_int(cons, "payouts_sum", diffs, tag, errors)
    rake_outs = get_int(cons, "rake_outputs_sum", diffs, tag, errors)
    if errors:
        diffs.extend(errors)
        return
    if inputs != payouts + rake_outs:
        fail(
            diffs,
            f"{tag}: 守恒不符 Σinputs={inputs} != Σpayouts={payouts}"
            f" + Σrake_outputs={rake_outs}",
        )


def main(argv):
    if len(argv) != 2:
        print("用法: rake_audit_verify.py <audit.json>", file=sys.stderr)
        return 1
    path = argv[1]
    try:
        with open(path, "rb") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        print(f"输入错误：无法读取/解析 {path}: {e}", file=sys.stderr)
        return 1

    diffs = []

    if doc.get("format") != FORMAT_TAG:
        fail(diffs, f"format 不支持: {doc.get('format')!r}（期望 {FORMAT_TAG!r}）")
        return finish(diffs)

    header = doc.get("header")
    if not isinstance(header, dict):
        fail(diffs, "缺 header 对象")
        return finish(diffs)
    if "wal_head_hash" not in header:
        fail(diffs, "header 缺 wal_head_hash")
    header_total = header.get("rake_total")
    if not isinstance(header_total, int) or isinstance(header_total, bool) or header_total < 0:
        fail(diffs, "header.rake_total 不是非负整数")
        header_total = None

    records = doc.get("records")
    if not isinstance(records, list):
        fail(diffs, "缺 records 数组")
        return finish(diffs)

    detail_sum = 0
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            fail(diffs, f"records[{i}] 不是对象")
            continue
        verify_record(i, rec, diffs)
        rt = rec.get("rake_total")
        if isinstance(rt, int) and not isinstance(rt, bool):
            detail_sum += rt

    # 汇总一致性：删改明细必然造成明细和 != 头部汇总
    if header_total is not None and detail_sum != header_total:
        fail(
            diffs,
            f"汇总不一致：header.rake_total={header_total} 但明细和={detail_sum}"
            f"（记录数 {len(records)}）",
        )

    return finish(diffs)


def finish(diffs):
    if diffs:
        for d in diffs:
            print(f"DIFF: {d}")
        print(f"共 {len(diffs)} 处差异")
        return 1
    print("OK: 复验零差异")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
