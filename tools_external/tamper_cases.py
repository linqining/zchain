#!/usr/bin/env python3
"""rake 审计篡改负例生成器（M5-ACC-3 外部复验配套）。

读一份合法的 `zchain.rake_audit.v1` 审计 JSON，在**复验器侧**注入 ≥4 类
篡改，各写出一个负例文件（语义上仍像审计文件，数值已被破坏）：

1. rake_total 抬高（抽取与独立重算值不符）；
2. rake_base 改为全额 gross（B9 contested-only 口径破坏：uncalled 层计入
   基数）；
3. treasury_out 分账额改动（split_of 重算不符）；
4. conservation.payouts_sum 改动（守恒破坏）；
5. header.rake_total 改动（汇总与明细和不一致）；
6. uncontested 层 rake 注入（uncalled 返还层计费）。

每个负例都应被 `rake_audit_verify.py` 判为差异（退出码 1）。

用法：
    python3 tools_external/tamper_cases.py <audit.json> <outdir>
"""

import copy
import json
import os
import sys


def deep_get_first_raked(records):
    """找第一条 rake_total > 0 的记录（负例需要非零费手）。"""
    for i, r in enumerate(records):
        if r.get("rake_total", 0) > 0:
            return i, r
    return None, None


def find_uncontested(rec):
    """找第一条 uncontested 层（eligible_seats < 2）的 (记录下标, 层下标)。"""
    for i, r in enumerate(rec):
        for li, pot in enumerate(r.get("pots", [])):
            if pot.get("eligible_seats", 0) < 2:
                return i, li
    return None, None


def main(argv):
    if len(argv) != 3:
        print("用法: tamper_cases.py <audit.json> <outdir>", file=sys.stderr)
        return 1
    with open(argv[1], "rb") as f:
        doc = json.load(f)
    outdir = argv[2]
    os.makedirs(outdir, exist_ok=True)

    records = doc["records"]
    idx, raked = deep_get_first_raked(records)
    if raked is None:
        print("审计文件无非零费记录，无法构造费类负例", file=sys.stderr)
        return 1

    def write(name, d):
        path = os.path.join(outdir, name)
        with open(path, "w") as f:
            json.dump(d, f, indent=2)
        print(path)

    # 1. rake_total 抬高（与独立重算值不符）
    d1 = copy.deepcopy(doc)
    d1["records"][idx]["rake_total"] += 1
    write("01_rake_total_bumped.json", d1)

    # 2. rake_base 改为全额 gross（contested-only 口径破坏：把 uncalled
    #    返还层计入基数——必须作用于含 uncontested 层的手，否则是无操作）
    d2 = copy.deepcopy(doc)
    ui0, uli0 = find_uncontested(records)
    if ui0 is not None:
        rec2 = d2["records"][ui0]
        full_gross = sum(p["gross_amount"] for p in rec2["pots"])
        rec2["rake_base"] = full_gross
        write("02_rake_base_full_gross.json", d2)
    else:
        d2["records"][idx]["rake_base"] += 1
        write("02_rake_base_off_by_one.json", d2)

    # 3. treasury_out 分账额 -1（split_of 重算不符）
    d3 = copy.deepcopy(doc)
    t = d3["records"][idx].get("treasury_out")
    if isinstance(t, dict) and t.get("amount", 0) > 0:
        t["amount"] -= 1
        write("03_treasury_split_off_by_one.json", d3)
    else:
        # 无 treasury 出账的文件退化为：operator_out 注入
        d3["records"][idx]["operator_out"] = {"owner": "00" * 33, "amount": 1}
        write("03_operator_out_injected.json", d3)

    # 4. 守恒破坏：payouts_sum 减 1
    d4 = copy.deepcopy(doc)
    d4["records"][idx]["conservation"]["payouts_sum"] -= 1
    write("04_conservation_broken.json", d4)

    # 5. 汇总不一致：header.rake_total 改动
    d5 = copy.deepcopy(doc)
    d5["header"]["rake_total"] += 100
    write("05_header_total_mismatch.json", d5)

    # 6. uncontested 层 rake 注入（若存在 uncalled 层；否则跳过）
    ui, uli = find_uncontested(records)
    if ui is not None:
        d6 = copy.deepcopy(doc)
        d6["records"][ui]["pots"][uli]["rake"] = 7
        write("06_uncontested_rake_injected.json", d6)
        print("NOTE: case 06 present")
    else:
        print("NOTE: case 06 skipped (no uncontested pot in fixture)")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
