// =============================================================================
// extension/content/bridge.js — 页面 ↔ 后台桥（isolated world，Extension 0.1）
//
// plan-appchain §6.12.4："Web page content bridge ↕ origin-bound message"。
//
// 信任模型：
// - 页面（MAIN world）只能通过 window.postMessage 到达本桥；本桥再经
//   chrome.runtime.sendMessage 转后台。后台看到的 sender.origin 由**浏览器**
//   固定为脚本注入页的真实 origin，页面无法伪造；
// - 本桥绝不信任页面消息中的任何身份字段；origin/expiry/nonce/sessionId 的
//   强校验全部在后台（common/validation.js）完成，这里只做形状过滤，
//   阻断明显畸形流量；
// - 会话令牌（sessionId）只在本桥与后台之间传递（chrome.runtime 通道），
//   provider（页面 world）经下面的 postMessage 握手获取——锁定后旧令牌失效。
// =============================================================================

(() => {
  // 防重复注入（同页面多次 content script 注入是 no-op）。
  if (window.__zchainBridgeInstalled) return;
  window.__zchainBridgeInstalled = true;

  const BRIDGE_TIMEOUT_MS = 45_000;

  /** 向后台请求当前会话令牌（锁定时为 null）。 */
  function getSession() {
    try {
      return chrome.runtime.sendMessage({ type: 'bridge:getSession' });
    } catch (e) {
      // 扩展上下文失效（重载/更新中）：让页面侧超时，而不是抛进页面。
      return Promise.resolve({ sessionId: null, unlocked: false });
    }
  }

  function relayRpc(payload) {
    // sender.origin 由浏览器填充，后台以此做伪造 origin 检测。
    return chrome.runtime.sendMessage({
      envelope: payload.envelope,
      method: payload.method,
      params: payload.params,
    });
  }

  window.addEventListener('message', (event) => {
    // 同源过滤：只接受本页面 frame 的消息（postMessage origin 校验）。
    if (event.source !== window || event.origin !== window.location.origin) return;
    const data = event.data;
    if (!data || data.target !== 'zchain:bridge') return;

    // ---- 握手：provider 获取会话令牌（不经过页面可控字段）----
    if (data.payload?.type === 'session') {
      getSession()
        .then((res) => {
          window.postMessage(
            { target: 'zchain:page', requestId: data.requestId, response: { sessionId: res?.sessionId ?? null, unlocked: Boolean(res?.unlocked) } },
            window.location.origin,
          );
        })
        .catch(() => {
          window.postMessage(
            { target: 'zchain:page', requestId: data.requestId, response: { sessionId: null, unlocked: false } },
            window.location.origin,
          );
        });
      return;
    }

    // ---- RPC 转发：形状过滤 + 超时状态（取消/超时是 §6.12.4 必查项）----
    if (data.payload?.type === 'rpc') {
      const { envelope, method, params } = data.payload;
      // 最小形状过滤（完整校验在后台；这里挡掉明显畸形消息）。
      if (
        typeof method !== 'string' ||
        !envelope || typeof envelope !== 'object' ||
        typeof envelope.requestId !== 'string' ||
        typeof envelope.sessionId !== 'string' ||
        !Number.isSafeInteger(envelope.nonce) ||
        !Number.isSafeInteger(envelope.expiry)
      ) {
        window.postMessage(
          { target: 'zchain:page', requestId: data.requestId, response: { error: { code: 'BadEnvelope', reason: 'malformed message' } } },
          window.location.origin,
        );
        return;
      }
      const timer = setTimeout(() => {
        window.postMessage(
          { target: 'zchain:page', requestId: data.requestId, response: { error: { code: 'TimeoutReached', reason: 'background did not answer in time' } } },
          window.location.origin,
        );
      }, BRIDGE_TIMEOUT_MS);
      relayRpc({ envelope, method, params })
        .then((response) => {
          clearTimeout(timer);
          window.postMessage(
            { target: 'zchain:page', requestId: data.requestId, response: response ?? { error: { code: 'InternalError', reason: 'empty response' } } },
            window.location.origin,
          );
        })
        .catch((e) => {
          clearTimeout(timer);
          window.postMessage(
            { target: 'zchain:page', requestId: data.requestId, response: { error: { code: 'BridgeUnavailable', reason: String(e?.message ?? 'extension unreachable') } } },
            window.location.origin,
          );
        });
    }
  });
})();
