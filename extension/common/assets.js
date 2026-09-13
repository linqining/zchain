// =============================================================================
// extension/common/assets.js — 资产维度展示/分组（TE-M5；Extension 0.4.0-alpha 追加）
//
// 把 0.4 的 REAL/PLAY 二元分栏升级为 ABI v2 AssetId（domain + token_id）维度：
// - REAL 域（domain=1）：NATIVE/USDT/USDC 三列（封闭枚举；0.4 钱包账本仍是
//   v1（只有 REAL=REAL/NATIVE 一列），USDT/USDC 列如实标注"未接入"，恒为空
//   ——不伪造 0 值语义）；
// - GAME 域（domain=2）：遗留 PLAY + 已注册 GTS 游戏币列表（注册表从网关
//   `status.assets` 按网络动态获取；展示的是**链上供给对账**（outstanding =
//   Σminted − Σburned），不是用户余额——0.4 钱包无 GAME v2 note，不得混淆）；
// - token 名称解析表集中一处：common/networks.js 的 `ASSET_TABLE`（网络配置
//   级），本模块只消费、不再定义第二张表；
// - 结算记录徽章：网关 settlement 明细的 `asset_id` 字段（TE-M5 新增）优先，
//   旧载荷回落 v1 `asset_class` 冻结映射（Real → REAL/NATIVE、Play →
//   GAME/PLAY(legacy)）。
//
// 诚实边界：本模块是纯展示/分组逻辑——余额语义全部来自 wallet-core 账本与
// 网关只读面，这里不推断、不估算、不合并跨域数值（REAL/GAME 物理隔离在
// 展示层同样成立，禁跨币轧差）。
//
// 纯函数 + 零 IO + 零浏览器全局（node --test 直接覆盖）。
// =============================================================================

import { ASSET_TABLE } from './networks.js';

/** 资产域判别值（ABI v2 冻结）。 */
export const DOMAIN = { REAL: 1, GAME: 2 };

/** 域名解析（未知判别值 → null，fail-closed）。 */
export function domainName(domain) {
  if (domain !== DOMAIN.REAL && domain !== DOMAIN.GAME) return null;
  return ASSET_TABLE.domainNames[domain] ?? null;
}

/** REAL 域 token 展示名（封闭枚举；未知 token_id → null，不造名）。 */
export function realTokenName(tokenId) {
  return ASSET_TABLE.realTokens[tokenId] ?? null;
}

/** GAME 域 token 展示名：静态表只有遗留 PLAY；其余（GTS 注册币）返回
 * null——调用方以 `token <id>` 编号呈现或用网关注册表解析。 */
export function gameTokenName(tokenId) {
  return ASSET_TABLE.gameTokens[tokenId] ?? null;
}

/**
 * v1 `asset_class` → AssetId 冻结映射（镜像 poker-appchain `AssetId::of_v1`
 * ——唯一换算，UI 层不做第二种）。
 * @param {string} assetClass 'REAL' | 'PLAY'
 * @returns {{domain:number, token_id:number}|null} 未知 assetClass → null
 */
export function assetIdOfV1(assetClass) {
  if (assetClass === 'REAL') return { domain: DOMAIN.REAL, token_id: 0 };
  if (assetClass === 'PLAY') return { domain: DOMAIN.GAME, token_id: 0 };
  return null;
}

/**
 * AssetId → 徽章/展示结构（余额与结算记录共用的唯一入口）。
 *
 * @param {{domain:number, token_id:number}|null|string} asset
 *        AssetId 对象（网关 `asset_id` 字段）；字符串时按 v1 asset_class
 *        冻结映射（回落路径）。
 * @param {Array<{token_id:number, label?:string}>} [registeredGameTokens]
 *        网关 status.assets 的 GAME 域行（可选；命中时用其 label）。
 * @returns {{ok:true, domain, domainName, tokenId, tokenLabel, asset, badgeClass}}
 *          | {{ok:false, code:'UnknownAsset', reason}}
 */
export function assetBadge(asset, registeredGameTokens = []) {
  let id = asset;
  if (typeof asset === 'string') {
    id = assetIdOfV1(asset);
    if (!id) return { ok: false, code: 'UnknownAsset', reason: `unknown v1 asset_class ${String(asset)}` };
  }
  if (!id || typeof id !== 'object' || typeof id.domain !== 'number' || typeof id.token_id !== 'number') {
    return { ok: false, code: 'UnknownAsset', reason: 'asset_id shape invalid (domain/token_id numeric)' };
  }
  const dName = domainName(id.domain);
  if (!dName) {
    return { ok: false, code: 'UnknownAsset', reason: `unknown asset domain ${id.domain}` };
  }
  let tokenLabel;
  let assetStr;
  if (id.domain === DOMAIN.REAL) {
    tokenLabel = realTokenName(id.token_id);
    if (!tokenLabel) {
      return { ok: false, code: 'UnknownAsset', reason: `REAL domain token ${id.token_id} is not in the closed enum (fail-closed)` };
    }
    assetStr = `real:${tokenLabel.toLowerCase()}`;
  } else {
    const registered = (registeredGameTokens ?? []).find((t) => t?.token_id === id.token_id);
    tokenLabel = registered?.label ?? gameTokenName(id.token_id) ?? `token ${id.token_id}`;
    assetStr = id.token_id === 0 ? 'game:play(legacy)' : `game:${id.token_id}`;
  }
  return {
    ok: true,
    domain: id.domain,
    domainName: dName,
    tokenId: id.token_id,
    tokenLabel,
    asset: assetStr,
    // 徽章配色沿用 popup.css 既有域色：REAL=托管警示色、GAME=休闲色
    badgeClass: id.domain === DOMAIN.REAL ? 'badge-real' : 'badge-play',
  };
}

/**
 * v1 钱包余额 → REAL 域三列 / GAME 域分组（0.4 账本口径的如实投影）。
 *
 * 输入是 wallet-core `wallet_get_all_notes` 的 balances（v1 二元账本：
 * real_free/real_locked/play_free/play_locked）。冻结映射 Real →
 * REAL/NATIVE：v1 REAL 余额**只**出现在 NATIVE 列；USDT/USDC 列
 * `connected:false`（0.4 未接入 v2 入金通道，恒为空——如实占位，不是 0）。
 *
 * @param {{real_free?:number, real_locked?:number, play_free?:number, play_locked?:number}} balances
 */
export function groupBalances(balances = {}) {
  const num = (v) => (Number.isSafeInteger(v) && v >= 0 ? v : 0);
  return {
    real: {
      domainName: 'REAL',
      native: {
        tokenLabel: 'NATIVE',
        connected: true,
        free: num(balances.real_free),
        locked: num(balances.real_locked),
      },
      usdt: { tokenLabel: 'USDT', connected: false, free: null, locked: null },
      usdc: { tokenLabel: 'USDC', connected: false, free: null, locked: null },
    },
    game: {
      domainName: 'GAME',
      play: {
        tokenLabel: 'PLAY(legacy)',
        free: num(balances.play_free),
        locked: num(balances.play_locked),
      },
    },
  };
}

/**
 * 网关 `status.assets` → 已注册游戏币行（fail-closed 形状校验）。
 *
 * GAME 域逐 token：label（注册表无链上名称 → `token <id>`）、模式、锚定
 * 资产（AssetId 规范字符串）、供给对账（**字符串**原样透传——网关侧 u128
 * 十进制字符串，转数字会丢精度）、恒等式核对位。`consistent:false` 的行
 * 必须原样透出（账本 bug 信号，不得美化）。
 *
 * @param {object} statusJson /api/v1/status 响应体
 * @returns {{ok:true, source:string, gameTokens:Array, allConsistent:boolean}}
 *          | {{ok:false, code:'BadShape', reason}}
 */
export function summarizeGatewayAssets(statusJson) {
  const assets = statusJson?.assets;
  if (!assets || typeof assets !== 'object' || typeof assets.source !== 'string') {
    return { ok: false, code: 'BadShape', reason: 'status.assets missing (index mode or old gateway)' };
  }
  const game = assets.game;
  if (!game || !Array.isArray(game.tokens) || typeof game.all_consistent !== 'boolean') {
    return { ok: false, code: 'BadShape', reason: 'status.assets.game shape invalid' };
  }
  const gameTokens = game.tokens
    .filter((t) => t && typeof t.token_id === 'number')
    .map((t) => ({
      tokenId: t.token_id,
      label: gameTokenName(t.token_id) ?? `token ${t.token_id}`,
      registered: t.registered === true,
      mode: typeof t.mode === 'string' ? t.mode : null,
      anchor: typeof t.anchor === 'string' ? t.anchor : null,
      rate: typeof t.rate === 'string' ? t.rate : null,
      maxSupply: typeof t.max_supply === 'string' ? t.max_supply : null,
      outstanding: typeof t.outstanding === 'string' ? t.outstanding : null,
      consistent: t.consistent === true,
      legacy: t.token_id === 0,
    }));
  return {
    ok: true,
    source: assets.source,
    gameTokens,
    allConsistent: game.all_consistent === true,
  };
}
