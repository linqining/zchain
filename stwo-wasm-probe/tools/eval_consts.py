import re, json, sys

SRC = "/Users/mac/projects/poker_texas_air/src/texas_canonical_air.rs"
MAX_CANONICAL_SEATS = 9            # texas_canonical.rs:13
MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS = 6  # texas_canonical.rs:17

consts = {
    "MAX_CANONICAL_SEATS": MAX_CANONICAL_SEATS,
    "MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS": MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS,
}
pat = re.compile(r"^const ([A-Z0-9_]+): usize =\s*(.+?);", re.M | re.S)
lines = re.sub(r"//[^\n]*", "", open(SRC).read())  # strip comments
for m in pat.finditer(lines):
    consts[m.group(1)] = m.group(2).replace("usize", "").strip()

def resolve(name, seen=()):
    if name in seen: raise RecursionError(name)
    v = consts[name]
    if isinstance(v, int): return v
    expr = " ".join(v.split()) if isinstance(v, str) else v
    # substitute identifiers
    while True:
        ids = set(re.findall(r"[A-Z_][A-Z0-9_]*", expr))
        if not ids: break
        for i in ids:
            if i not in consts: raise KeyError(f"{i} in {name}")
            expr = re.sub(rf"\b{i}\b", f"({resolve(i, seen+(name,))})", expr)
    val = eval(expr)
    consts[name] = val
    return val

out = {
  "NUM_COLUMNS": resolve("NUM_COLUMNS"),
  "PREPROCESSED_COLUMNS": resolve("PREPROCESSED_COLUMNS"),
  "RANGE_INTERACTION_COLUMNS": resolve("RANGE_INTERACTION_COLUMNS"),
  "KIND_COUNT": resolve("KIND_COUNT"),
  "BASE_NUM_COLUMNS": resolve("BASE_NUM_COLUMNS"),
  "STATE_IMAGE_PROJECTION_LIMBS": resolve("STATE_IMAGE_PROJECTION_LIMBS"),
  "PREPROCESSED_TRACE_IDX_tree0": "log_size x PREPROCESSED_COLUMNS",
  "tree1": "log_size x (NUM_COLUMNS + 1)",
  "tree2": "log_size x (RANGE_INTERACTION_COLUMNS*4 = %d)" % (resolve("RANGE_INTERACTION_COLUMNS")*4),
}
print(json.dumps(out, indent=1))
