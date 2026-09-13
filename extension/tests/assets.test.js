// =============================================================================
// extension/tests/assets.test.js — 资产维度展示/分组测试（TE-M5）
//
// 覆盖：ASSET_TABLE 封闭枚举冻结（REAL 域 0/1/2、GAME 域遗留 PLAY）/
// v1 asset_class 冻结映射 / assetBadge（AssetId 对象 + 字符串回落 + GAME
// 注册币列表 + fail-closed 未知资产）/ groupBalances（v1 账本 → REAL 三列
// + GAME 组；USDT/USDC 未接入占位）/ summarizeGatewayAssets（形状校验
// fail-closed + u128 字符串透传 + consistent 告警位）/ fetchAssetSummary
// （注入 fetch；未配置/网络失败/404/形状不符全错误路径）。
// 零网络真实 IO。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ASSET_TABLE } from '../common/networks.js';
import {
  assetBadge,
  assetIdOfV1,
  domainName,
  gameTokenName,
  groupBalances,
  realTokenName,
  summarizeGatewayAssets,
} from '../common/assets.js';
import { fetchAssetSummary } from '../common/portal.js';

const GATEWAY = 'http://127.0.0.1:18900';

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => (typeof body === 'string' ? JSON.parse(body) : body),
    headers: { get: () => null },
  };
}

test('01 ASSET_TABLE：封闭枚举冻结（与 ABI v2 判别值同源）', () => {
  assert.deepEqual(ASSET_TABLE.domainNames, { 1: 'REAL', 2: 'GAME' });
  assert.deepEqual(ASSET_TABLE.realTokens, { 0: 'NATIVE', 1: 'USDT', 2: 'USDC' });
  assert.deepEqual(ASSET_TABLE.gameTokens, { 0: 'PLAY(legacy)' });
  assert.equal(Object.keys(ASSET_TABLE.realTokens).length, 3, 'REAL domain is a closed enum');
});

test('02 名称解析：REAL 封闭枚举外 fail-closed；GAME 静态表只有遗留 PLAY', () => {
  assert.equal(domainName(1), 'REAL');
  assert.equal(domainName(2), 'GAME');
  assert.equal(domainName(0), null);
  assert.equal(domainName(3), null);
  assert.equal(realTokenName(0), 'NATIVE');
  assert.equal(realTokenName(1), 'USDT');
  assert.equal(realTokenName(2), 'USDC');
  assert.equal(realTokenName(3), null, 'unknown REAL token must not get an invented name');
  assert.equal(gameTokenName(0), 'PLAY(legacy)');
  assert.equal(gameTokenName(1), null, 'GTS registered coins have no on-chain name field');
});

test('03 v1 冻结映射：REAL→REAL/NATIVE、PLAY→GAME/PLAY(0)；未知 → null', () => {
  assert.deepEqual(assetIdOfV1('REAL'), { domain: 1, token_id: 0 });
  assert.deepEqual(assetIdOfV1('PLAY'), { domain: 2, token_id: 0 });
  assert.equal(assetIdOfV1('real'), null, 'case-sensitive: no silent coercion');
  assert.equal(assetIdOfV1('USDT'), null, 'v1 ledger has no USDT representation');
  assert.equal(assetIdOfV1(''), null);
  assert.equal(assetIdOfV1(null), null);
});

test('04 assetBadge：AssetId 对象 + 规范字符串', () => {
  const native = assetBadge({ domain: 1, token_id: 0 });
  assert.equal(native.ok, true);
  assert.equal(native.domainName, 'REAL');
  assert.equal(native.tokenLabel, 'NATIVE');
  assert.equal(native.asset, 'real:native');
  assert.equal(native.badgeClass, 'badge-real');

  const play = assetBadge({ domain: 2, token_id: 0 });
  assert.equal(play.ok, true);
  assert.equal(play.tokenLabel, 'PLAY(legacy)');
  assert.equal(play.asset, 'game:play(legacy)');
  assert.equal(play.badgeClass, 'badge-play');

  const fallback = assetBadge('REAL');
  assert.equal(fallback.ok, true);
  assert.equal(fallback.asset, 'real:native', 'string input maps via frozen of_v1');
  const playFallback = assetBadge('PLAY');
  assert.equal(playFallback.asset, 'game:play(legacy)');
});

test('05 assetBadge：GAME 注册币列表命中 label；未注册 token 如实给编号', () => {
  const registry = [{ token_id: 1, label: 'token 1' }, { token_id: 7 }];
  const g1 = assetBadge({ domain: 2, token_id: 1 }, registry);
  assert.equal(g1.ok, true);
  assert.equal(g1.tokenLabel, 'token 1');
  assert.equal(g1.asset, 'game:1');
  const g7 = assetBadge({ domain: 2, token_id: 7 }, registry);
  assert.equal(g7.tokenLabel, 'token 7');
  const g9 = assetBadge({ domain: 2, token_id: 9 }, []);
  assert.equal(g9.ok, true, 'GAME domain tokens are structurally expressible pre-registration');
  assert.equal(g9.tokenLabel, 'token 9', 'unregistered tokens get an honest number, not a name');
});

test('06 assetBadge：fail-closed（未知 REAL token / 坏形状 / 未知字符串）', () => {
  const badToken = assetBadge({ domain: 1, token_id: 9 });
  assert.equal(badToken.ok, false);
  assert.equal(badToken.code, 'UnknownAsset');
  assert.match(badToken.reason, /closed enum/);

  assert.equal(assetBadge({ domain: 5, token_id: 0 }).code, 'UnknownAsset');
  assert.equal(assetBadge({ domain: 'REAL' }).code, 'UnknownAsset');
  assert.equal(assetBadge(null).code, 'UnknownAsset');
  assert.equal(assetBadge(undefined).code, 'UnknownAsset');
  assert.equal(assetBadge(42).code, 'UnknownAsset');
  assert.equal(assetBadge('USDT').code, 'UnknownAsset', 'unknown v1 asset_class never silently maps');
});

test('07 groupBalances：v1 账本 → REAL 三列（USDT/USDC 未接入占位）+ GAME 组', () => {
  const g = groupBalances({ real_free: 1200, real_locked: 300, play_free: 50, play_locked: 10 });
  assert.deepEqual(g.real.native, { tokenLabel: 'NATIVE', connected: true, free: 1200, locked: 300 });
  assert.equal(g.real.usdt.connected, false);
  assert.equal(g.real.usdt.free, null, 'unconnected columns stay null — honest placeholder, not a 0');
  assert.equal(g.real.usdc.connected, false);
  assert.deepEqual(g.game.play, { tokenLabel: 'PLAY(legacy)', free: 50, locked: 10 });
});

test('08 groupBalances：缺省/非法输入归零（不抛错、不产生负数）', () => {
  const g = groupBalances(undefined);
  assert.equal(g.real.native.free, 0);
  assert.equal(g.game.play.free, 0);
  const bad = groupBalances({ real_free: -5, play_free: Number.MAX_SAFE_INTEGER + 1 });
  assert.equal(bad.real.native.free, 0, 'negative balances are rejected to 0');
  assert.equal(bad.game.play.free, 0, 'non-safe-integer is rejected to 0');
});

test('09 summarizeGatewayAssets：正例（u128 字符串透传 + consistent 告警位）', () => {
  const status = {
    data_source: 'replay',
    assets: {
      source: 'appchain_ledger (chain-visible face; ...)',
      real: { tokens: [{ token_id: 0, token: 'native', issued: '1000' }] },
      game: {
        all_consistent: false,
        tokens: [
          { token_id: 1, asset: 'game:1', registered: true, mode: 'paid', anchor: 'real:usdt', rate: '1000000', max_supply: '0', minted_total: '3000000', burned_total: '1000000', outstanding: '2000000', live_note_sum: '1999999', consistent: false },
          { token_id: 0, asset: 'game:play(legacy)', registered: true, mode: null, outstanding: '5', consistent: true },
        ],
      },
    },
  };
  const s = summarizeGatewayAssets(status);
  assert.equal(s.ok, true);
  assert.match(s.source, /chain-visible/);
  assert.equal(s.allConsistent, false);
  assert.equal(s.gameTokens.length, 2);
  const t1 = s.gameTokens[0];
  assert.equal(t1.tokenId, 1);
  assert.equal(t1.label, 'token 1');
  assert.equal(t1.outstanding, '2000000', 'u128 decimal strings pass through verbatim');
  assert.equal(t1.consistent, false, 'identity breach is surfaced, never prettified');
  assert.equal(t1.mode, 'paid');
  assert.equal(t1.anchor, 'real:usdt');
  const legacy = s.gameTokens[1];
  assert.equal(legacy.legacy, true);
  assert.equal(legacy.label, 'PLAY(legacy)', 'static table resolves the legacy slot');
});

test('10 summarizeGatewayAssets：形状 fail-closed（index 模式 null / 旧网关 / 缺 tokens）', () => {
  assert.equal(summarizeGatewayAssets({ assets: null }).code, 'BadShape');
  assert.equal(summarizeGatewayAssets({}).code, 'BadShape');
  assert.equal(summarizeGatewayAssets(null).code, 'BadShape');
  assert.equal(summarizeGatewayAssets({ assets: { source: 'x' } }).code, 'BadShape');
  assert.equal(
    summarizeGatewayAssets({ assets: { source: 'x', game: { tokens: 'nope', all_consistent: true } } }).code,
    'BadShape',
  );
  // 非数字 token_id 行被过滤（不抛错）
  const filtered = summarizeGatewayAssets({
    assets: { source: 'x', game: { all_consistent: true, tokens: [null, { token_id: 'z' }, { token_id: 2 }] } },
  });
  assert.equal(filtered.ok, true);
  assert.deepEqual(filtered.gameTokens.map((t) => t.tokenId), [2]);
});

test('11 fetchAssetSummary 正例：透传 assets（注入 fetch，零真实 IO）', async () => {
  const assets = { source: 's', real: { tokens: [] }, game: { all_consistent: true, tokens: [] } };
  let calledUrl = '';
  const res = await fetchAssetSummary(GATEWAY, async (url) => {
    calledUrl = url;
    return jsonResponse(200, { data_source: 'replay', assets });
  });
  assert.equal(res.ok, true);
  assert.equal(calledUrl, `${GATEWAY}/api/v1/status`);
  assert.equal(res.assets.game.all_consistent, true);
});

test('12 fetchAssetSummary 错误路径：未配置/网络失败/404/形状不符', async () => {
  const notConfigured = await fetchAssetSummary(null, async () => { throw new Error('no fetch'); });
  assert.equal(notConfigured.code, 'GatewayNotConfigured');

  const unreachable = await fetchAssetSummary(GATEWAY, async () => { throw new TypeError('Failed to fetch'); });
  assert.equal(unreachable.code, 'GatewayUnreachable');

  const notFound = await fetchAssetSummary(GATEWAY, async () => jsonResponse(404, { error: 'not found' }));
  assert.equal(notFound.code, 'NotFound', 'non-settlement/proof 404 gets an honest generic code');

  const badShape = await fetchAssetSummary(GATEWAY, async () =>
    jsonResponse(200, { data_source: 'index', assets: null }));
  assert.equal(badShape.code, 'BadShape', 'index mode assets=null is surfaced honestly');
  assert.match(badShape.reason, /index mode|asset summary/);

  const oldGateway = await fetchAssetSummary(GATEWAY, async () => jsonResponse(200, { frame_count: 1 }));
  assert.equal(oldGateway.code, 'BadShape');
});
