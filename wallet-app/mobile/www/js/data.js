/* ZChain Wallet mobile — 设计稿示例数据(与 design/zchain-wallet-ui-b-ledger.html 同一套示例数据)。
 * 移动客户端 MVP 阶段为静态演示数据;接入 wallet-core 时按桌面端 ui/app.js 的
 * 传输适配层(Tauri invoke / POST /api/<cmd>)替换字段来源。 */
"use strict";

const DEMO = {
  account: {
    name: "牌手一号",
    initial: "A",
    zc: "zc1qpoker…f7x2",
    evm: "0x5919…7527",
    stk: "0x058f…853f",
    evmFull: "0x59195049a3…29f97527",
    stkFull: "0x058ff920c8…8b29853f",
  },
  password: "felt-poker-verifiable-9x2a",
  net: "zchain-devnet-1",
  chains: {
    zc:  { kind: "Ledger · Zchain",   net: "zchain-devnet-1",      addr: "zc1qpoker…f7x2", cnt: 2 },
    evm: { kind: "Ledger · Evm",      net: "Ethereum · chainId 1", addr: "0x5919…7527",    cnt: 1 },
    stk: { kind: "Ledger · Starknet", net: "SN DevNet · ZCDN",     addr: "0x058f…853f",    cnt: 1 },
  },
};

/* 凭证条(pending → soft → proven → finalized)渲染辅助:
 * state = 最弱一环:'soft'(cur) | 'proven'(cur,线推进到 proven) | 'finalized' …
 * 直接用四节点布尔序列描述,与设计稿逐屏一致。 */
function rail(n, capLeft, capRight) {
  // n: {pending:'done'|'cur'|'bad'|'', soft:…, proven:…, finalized:…}
  const keys = ["pending", "soft", "proven", "finalized"];
  let h = '<div class="rail">';
  keys.forEach((k, i) => {
    const st = n[k] || "";
    h += `<div class="rn ${st}"><i></i><span>${k}</span></div>`;
    if (i < 3) h += `<div class="rline ${st === "done" ? "done" : ""}"></div>`;
  });
  h += "</div>";
  if (capLeft || capRight) {
    h += `<div class="rail-cap"><span>${capLeft || ""}</span><span>${capRight || ""}</span></div>`;
  }
  return h;
}

const CHIP = {
  real:  (t) => `<span class="ch ch-real">${t}</span>`,
  play:  (t) => `<span class="ch ch-play">${t}</span>`,
  felt:  (t) => `<span class="ch ch-felt">${t}</span>`,
  bad:   (t) => `<span class="ch ch-bad">${t}</span>`,
  amb:   (t) => `<span class="ch ch-amb">${t}</span>`,
  xs:    (t, cls) => `<span class="ch ${cls || ""} ch-xs">${t}</span>`,
  solid: (t) => `<span class="ch ch-solid">${t}</span>`,
  plain: (t) => `<span class="ch">${t}</span>`,
};

const ICO = (id, cls) => `<svg class="ic ${cls || ""}"><use href="#i-${id}"/></svg>`;
