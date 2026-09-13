/* ZChain Wallet UI — 无框架、无外部运行时（本地静态资源）。
 *
 * 传输适配层：
 *  - Tauri（路线 A）：window.__TAURI__.core.invoke（withGlobalTauri）
 *  - 非 Tauri（路线 B 本地 server，若启用）：POST /api/<cmd>
 * UI 与业务数据形状在两条路线下完全一致。
 */
"use strict";

const INVOKE_ARGS = (args) => args ?? {};
const api = window.__TAURI__
  ? {
      call: (cmd, args) => window.__TAURI__.core.invoke(cmd, INVOKE_ARGS(args)),
    }
  : {
      call: async (cmd, args) => {
        const res = await fetch("/api/" + cmd, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(args ?? {}),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || "HTTP " + res.status);
        return body;
      },
    };

const $ = (id) => document.getElementById(id);
const els = {};
[
  "topbar", "lock-countdown", "btn-lock", "setup-view", "setup-password", "setup-password2",
  "setup-secret", "btn-create", "setup-error", "lock-view", "lock-password", "btn-unlock",
  "lock-error", "app-view", "acc-network", "acc-chain", "acc-domain", "acc-abi", "acc-owner",
  "acc-datadir", "acc-balances", "acc-real-gate", "notes-play-free", "notes-play-locked",
  "faucet-amount", "btn-faucet", "notes-error", "notes-body", "sign-kind", "sign-amount",
  "sign-recipient", "sign-recipient-label", "sign-table", "sign-table-label", "sign-inputs",
  "btn-preview", "sign-error", "preview-card", "preview-table", "btn-confirm", "btn-cancel-sign",
  "signed-card", "signed-table", "raw-bytes", "btn-raw-sign", "raw-result", "backup-password",
  "btn-backup-export", "backup-export-result", "restore-password", "btn-backup-import",
  "backup-import-result", "autolock-secs", "btn-autolock", "settings-result", "status-text",
].forEach((id) => (els[id] = $(id)));

let lastStatus = null;
let pendingReq = null;

/* ===== 渲染 ===== */

function show(view) {
  els["setup-view"].classList.toggle("hidden", view !== "setup");
  els["lock-view"].classList.toggle("hidden", view !== "lock");
  els["app-view"].classList.toggle("hidden", view !== "app");
}

function renderStatus(s) {
  lastStatus = s;
  els["acc-network"].textContent = s.network_label;
  els["acc-chain"].textContent = s.chain_id;
  els["acc-domain"].textContent = s.domain;
  els["acc-abi"].textContent = "v" + s.abi_version;
  els["acc-owner"].textContent = s.owner_public_hex || "—";
  els["acc-datadir"].textContent = s.data_dir;

  if (!s.initialized) { show("setup"); return; }
  if (s.locked) { show("lock"); return; }
  show("app");

  if (s.balances) {
    const b = s.balances;
    els["acc-balances"].innerHTML = "";
    els["acc-balances"].appendChild(balanceCard("PLAY 自由", b.play_free));
    els["acc-balances"].appendChild(balanceCard("PLAY 桌内锁定", b.play_locked));
    els["acc-balances"].appendChild(balanceCard("REAL 自由（未上线网络）", b.real_free));
    // REAL 展示门：wallet-core display 决定（离线 → 无 claim/提现入口 + 托管提示）。
    const gate = b.real_view;
    els["acc-real-gate"].textContent =
      "REAL 展示门（wallet-core display）：claim/提现入口" + (gate.show_claim ? "可见" : "已隐藏") +
      (gate.claim_disabled_reason ? " — 原因: " + gate.claim_disabled_reason : "") +
      (gate.custody_risk_notice ? " · 托管提示: " + gate.custody_risk_notice : "");
  }
  els["autolock-secs"].value = s.auto_lock_secs;
}

function balanceCard(label, value) {
  const div = document.createElement("div");
  div.className = "balance";
  const l = document.createElement("span");
  l.className = "muted";
  l.textContent = label;
  const v = document.createElement("strong");
  v.textContent = value;
  div.append(l, v);
  return div;
}

async function refreshNotes() {
  const page = await api.call("play_notes");
  els["notes-play-free"].textContent = page.play_free;
  els["notes-play-locked"].textContent = page.play_locked;
  const tbody = els["notes-body"];
  tbody.innerHTML = "";
  for (const n of page.play) {
    const tr = document.createElement("tr");
    const cells = [
      n.commitment_hex,
      n.amount,
      n.table_id == null ? "—" : "#" + n.table_id,
      n.proof,
      n.spent_by_op == null ? "否" : "op#" + n.spent_by_op,
      n.nullifier_hex,
    ];
    for (const c of cells) {
      const td = document.createElement("td");
      if (typeof c === "number") td.className = "num";
      td.textContent = c;
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  if (page.play.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6;
    td.className = "muted";
    td.textContent = "（空）— 用上方按钮本地铸造演示 PLAY note";
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
}

/* ===== 签名预览：逐字段渲染 SigningPreview ===== */

function previewRows(p) {
  const rows = [
    ["操作种类", p.kind],
    ["网络（chain id）", p.chain_id],
    ["域标签", p.domain],
    ["ABI 版本", "v" + p.abi_version],
    ["资产类", p.asset_class],
    ["输入总额", String(p.amount_in)],
    ["输出总额", String(p.amount_out)],
    ["rake", p.rake === 0 ? "0（非结算操作）" : String(p.rake)],
    ["桌 ID", p.table_id == null ? "—（无桌操作）" : "#" + p.table_id],
  ];
  for (const [i, o] of p.outputs.entries()) {
    rows.push(["输出 #" + (i + 1), o.amount + " → " + o.owner]);
  }
  rows.push(["request_id", p.request_id || "—（非提现操作）"]);
  rows.push(["hand_binding", p.hand_binding || "—（非结算操作）"]);
  p.proof_states.forEach((s, i) => rows.push(["输入 proof #" + (i + 1), s]));
  rows.push(["过期时间 (unix)", String(p.expiry)]);
  rows.push(["nonce", String(p.nonce)]);
  rows.push(["确认摘要 (digest)", p.digest]);
  return rows;
}

function fillKvTable(table, rows) {
  table.innerHTML = "";
  for (const [k, v] of rows) {
    const tr = document.createElement("tr");
    const th = document.createElement("th");
    th.textContent = k;
    const td = document.createElement("td");
    td.className = "breakable";
    td.textContent = v;
    tr.append(th, td);
    table.appendChild(tr);
  }
}

function buildRequestDto() {
  const kind = els["sign-kind"].value;
  const amount = Number(els["sign-amount"].value || 0);
  const req = {
    kind,
    asset_class: "PLAY",
    inputs: els["sign-inputs"].value.split(",").map((s) => s.trim()).filter(Boolean),
    outputs: [],
    table_id: null,
    seat_owner: null,
    nonce: null,
    expiry: null,
  };
  const recipient = els["sign-recipient"].value.trim();
  if (kind === "transfer") {
    if (!amount || amount <= 0) throw new Error("金额必须 > 0");
    // 收款留空 = 自己（演示自转账）；多输出属后续里程碑。
    req.outputs = [{ owner: recipient || null, amount }].map((o) => ({
      owner: o.owner || (lastStatus && lastStatus.owner_public_hex) || "",
      amount: o.amount,
    }));
  } else if (kind === "buy_in") {
    req.table_id = Number(els["sign-table"].value || 0) || null;
    if (!req.table_id) throw new Error("buy_in 需要桌 ID");
    if (!amount || amount <= 0) throw new Error("金额必须 > 0");
    // buy_in 金额经单 note sweep 语义：输入留空 = 全部未花费；这里要求恰好等于输入总额。
    req.outputs = [];
    if (recipient) req.seat_owner = recipient;
    req._buyInAmount = amount;
  }
  return req;
}

/* buy_in 的金额在 core DTO 中没有显式字段（seat note = Σinputs），
 * 用输入 note 选择来表达：优先取等于金额的单张 note；否则要求手选承诺。 */
async function prepareBuyIn(req) {
  const page = await api.call("play_notes");
  const exact = page.play.find((n) => n.spent_by_op == null && n.table_id == null && n.amount === req._buyInAmount);
  if (exact) {
    req.inputs = [exact.commitment_hex];
    return req;
  }
  if (req.inputs.length > 0) return req; // 用户手选
  throw new Error(
    "没有恰好等于 " + req._buyInAmount + " 的未花费 note：请先本地铸造该面额，或在“输入 note 承诺”中手选（buy_in 金额 = Σinputs）"
  );
}

/* ===== 事件 ===== */

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", async () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".panel").forEach((p) => p.classList.add("hidden"));
    $("tab-" + btn.dataset.tab).classList.remove("hidden");
    if (btn.dataset.tab === "notes") {
      try { await refreshNotes(); } catch (e) { els["notes-error"].textContent = e.message; }
    }
  });
});

els["btn-create"].addEventListener("click", async () => {
  els["setup-error"].textContent = "";
  const pw = els["setup-password"].value;
  if (pw.length < 8) { els["setup-error"].textContent = "口令至少 8 个字符"; return; }
  if (pw !== els["setup-password2"].value) { els["setup-error"].textContent = "两次口令不一致"; return; }
  const secret = els["setup-secret"].value.trim();
  try {
    renderStatus(await api.call("create_wallet", { password: pw, secretHex: secret || null }));
  } catch (e) { els["setup-error"].textContent = e.message; }
});

els["btn-unlock"].addEventListener("click", async () => {
  els["lock-error"].textContent = "";
  try {
    renderStatus(await api.call("unlock", { password: els["lock-password"].value }));
    els["lock-password"].value = "";
  } catch (e) {
    // 口令错 → wallet-core BadPassword fail-closed（原文透传）。
    els["lock-error"].textContent = e.message;
  }
});

els["lock-password"].addEventListener("keydown", (e) => {
  if (e.key === "Enter") els["btn-unlock"].click();
});

els["btn-lock"].addEventListener("click", async () => {
  renderStatus(await api.call("lock_wallet"));
});

els["btn-faucet"].addEventListener("click", async () => {
  els["notes-error"].textContent = "";
  const amount = Number(els["faucet-amount"].value || 0);
  try {
    await api.call("demo_faucet", { amount });
    await refreshNotes();
  } catch (e) { els["notes-error"].textContent = e.message; }
});

els["sign-kind"].addEventListener("change", () => {
  const isBuyIn = els["sign-kind"].value === "buy_in";
  els["sign-table-label"].classList.toggle("hidden", !isBuyIn);
  els["sign-recipient-label"].textContent = isBuyIn
    ? "seat owner（66 hex；留空 = 自己）"
    : "收款 owner（66 hex；留空 = 自己）";
});

els["btn-preview"].addEventListener("click", async () => {
  els["sign-error"].textContent = "";
  els["preview-card"].classList.add("hidden");
  els["signed-card"].classList.add("hidden");
  try {
    pendingReq = buildRequestDto();
    if (pendingReq.kind === "buy_in") pendingReq = await prepareBuyIn(pendingReq);
    if (pendingReq._buyInAmount) delete pendingReq._buyInAmount;
    const preview = await api.call("preview_sign", { req: pendingReq });
    fillKvTable(els["preview-table"], previewRows(preview));
    els["preview-card"].classList.remove("hidden");
  } catch (e) { els["sign-error"].textContent = e.message; }
});

els["btn-cancel-sign"].addEventListener("click", () => {
  pendingReq = null;
  els["preview-card"].classList.add("hidden");
});

els["btn-confirm"].addEventListener("click", async () => {
  els["sign-error"].textContent = "";
  if (!pendingReq) return;
  try {
    const signed = await api.call("confirm_sign", { req: pendingReq });
    fillKvTable(els["signed-table"], [
      ...previewRows(signed.preview),
      ["操作 (borsh hex)", signed.operation_borsh_hex],
    ]);
    els["preview-card"].classList.add("hidden");
    els["signed-card"].classList.remove("hidden");
    pendingReq = null;
  } catch (e) { els["sign-error"].textContent = e.message; }
});

els["btn-raw-sign"].addEventListener("click", async () => {
  els["raw-result"].className = "mono-result";
  const bytes = Array.from(new TextEncoder().encode(els["raw-bytes"].value));
  try {
    const r = await api.call("sign_raw_bytes", { label: "malicious dapp", bytes });
    els["raw-result"].textContent = r;
  } catch (e) {
    els["raw-result"].className = "mono-result rejected";
    els["raw-result"].textContent = "已拒绝 ✓ — " + e.message;
  }
});

els["btn-backup-export"].addEventListener("click", async () => {
  els["backup-export-result"].textContent = "";
  try {
    const r = await api.call("backup_export", { password: els["backup-password"].value });
    els["backup-export-result"].textContent =
      "备份生成 ✓ v" + r.info.version + " · " + r.bytes_len + " 字节 · REAL " + r.info.notes_real +
      " 张 / PLAY " + r.info.notes_play + " 张 note" +
      (r.saved_to ? "\n已保存: " + r.saved_to : "\n（对话框已取消 — 未写盘）");
  } catch (e) { els["backup-export-result"].textContent = "失败: " + e.message; }
});

els["btn-backup-import"].addEventListener("click", async () => {
  els["backup-import-result"].textContent = "";
  try {
    const s = await api.call("backup_import", { password: els["restore-password"].value });
    els["backup-import-result"].textContent = "导入成功 ✓（索引自检通过）；钱包已回锁定态。";
    renderStatus(s);
  } catch (e) { els["backup-import-result"].textContent = "导入被拒绝（fail-closed）: " + e.message; }
});

els["btn-autolock"].addEventListener("click", async () => {
  els["settings-result"].textContent = "";
  try {
    renderStatus(await api.call("set_auto_lock", { secs: Number(els["autolock-secs"].value || 0) }));
    els["settings-result"].textContent = "已保存：空闲 " + els["autolock-secs"].value + " 秒后自动锁屏";
  } catch (e) { els["settings-result"].textContent = "失败: " + e.message; }
});

/* ===== 轮询（状态 + 自动锁屏倒计时） ===== */

async function poll() {
  try {
    const s = await api.call("status");
    const wasLocked = lastStatus ? lastStatus.locked : true;
    renderStatus(s);
    if (s.initialized && !s.locked) {
      els["lock-countdown"].textContent = "自动锁屏 " + s.lock_remaining_secs + "s";
    } else {
      els["lock-countdown"].textContent = "";
    }
    if (wasLocked && !s.locked) {
      // 刚解锁：刷新余额视图。
      try { await refreshNotes(); } catch (_) {}
    }
    els["status-text"].textContent =
      s.environment_badge + " · " + (s.locked ? "已锁定" : "已解锁 · " + s.chain_id);
  } catch (e) {
    els["status-text"].textContent = "后端不可达: " + e.message;
  }
}

poll();
setInterval(poll, 1000);
