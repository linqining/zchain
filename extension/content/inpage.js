// =============================================================================
// extension/content/inpage.js — window.zchain provider（MAIN world，Extension 0.1）
//
// plan-appchain §6.12.4：版本化 `zchain_*` 接口，**不冒充 EIP-1193 / MetaMask**。
//
// EIP-6963 边界（如实说明）：EIP-6963 的 announceProvider 发现机制与
// window.ethereum 命名空间**仅用于外部 EVM 钱包（MetaMask/Rabby/Argent X/
// Braavos 等）共存**。本 provider 刻意：
//   1) 不写入 window.ethereum，不设置 isMetaMask/isRabby 等 EIP-1193 属性；
//   2) 不派发 `eip6963:announceProvider` 事件（那会让 dapp 把我们当成 EVM
//      钱包并发出 eth_* 调用——本 provider 不支持也不应接受 eth_*）；
//   3) 使用独立 namespace（window.zchain）、独立名称与 ZChain 链能力矩阵
//      （zchain_getCapabilities），避免被 dapp 误连。
// 后续（0.3+）WalletConnect Vault adapter 才涉及与外部钱包的互操作。
//
// 信任边界：本脚本运行在页面 world，页面可以重定义 window.zchain 的一切。
// 真正的信任锚是 content bridge（isolated world）与后台的 sender.origin 绑定：
// 页面伪造/篡改只会导致校验失败，不可能越过校验层。
// =============================================================================

(() => {
  if (window.zchain) {
    // 已有 ZChain provider（其他扩展/重复注入）：不覆盖，保持 first-wins，
    // 与 EVM 钱包生态对多 provider 的处理一致。
    return;
  }

  const PROVIDER_VERSION = '0.2.0-alpha';
  const REQUEST_TTL_SEC = 300; // 信封 expiry：now + 300s
  const DEFAULT_TIMEOUT_MS = 45_000;

  // ---- 会话令牌：由 bridge（isolated world）从后台获取；锁定后失效 ----
  let bridgeSessionId = null;
  let nonceCounter = Date.now(); // 单调：以当前时间起跳，页面刷新不回退

  function postToBridge(payload) {
    return new Promise((resolve) => {
      const requestId = `bridge-${crypto.randomUUID()}`;
      const timer = setTimeout(() => resolve({ error: { code: 'TimeoutReached', reason: 'bridge did not answer' } }), DEFAULT_TIMEOUT_MS);
      const onMsg = (event) => {
        if (event.source !== window) return;
        const d = event.data;
        if (!d || d.target !== 'zchain:page' || d.requestId !== requestId) return;
        window.removeEventListener('message', onMsg);
        clearTimeout(timer);
        resolve(d.response);
      };
      window.addEventListener('message', onMsg);
      window.postMessage({ target: 'zchain:bridge', requestId, payload }, window.location.origin);
    });
  }

  async function refreshSession() {
    const res = await postToBridge({ type: 'session' });
    bridgeSessionId = res?.sessionId ?? null;
    return bridgeSessionId;
  }

  /** 构造带信封的内部请求（§6.12.4：nonce/origin/expiry/sessionId 全带上）。 */
  async function call(method, params = {}, { retryOnSession = true } = {}) {
    if (bridgeSessionId == null) await refreshSession();
    const envelope = {
      origin: window.location.origin,
      nonce: ++nonceCounter, // 每 origin 单调递增；后台强制校验
      expiry: Math.floor(Date.now() / 1000) + REQUEST_TTL_SEC,
      sessionId: bridgeSessionId ?? '',
      requestId: `req-${crypto.randomUUID()}`,
    };
    const response = await postToBridge({ type: 'rpc', envelope, method, params });
    // 会话令牌失效（解锁前/重锁后）：读方法可自动刷新一次重试；签名类绝不自动重试。
    if (response?.error?.code === 'SessionInvalid' && retryOnSession) {
      await refreshSession();
      if (bridgeSessionId != null && envelope.sessionId !== bridgeSessionId) {
        return call(method, params, { retryOnSession: false });
      }
    }
    if (response?.error) {
      throw Object.assign(new Error(`${response.error.code}: ${response.error.reason}`), {
        code: response.error.code,
        reason: response.error.reason,
      });
    }
    return response;
  }

  // ---------------------------------------------------------------------------
  // 版本化 zchain_* API（§6.12.4 接口全集；0.1 未交付的如实返回
  // NotSupportedIn01，绝不假装支持）
  // ---------------------------------------------------------------------------

  const provider = {
    isZChain: true, // 唯一命名空间标志；刻意不提供 isMetaMask/isRabby 等
    providerName: 'ZChain Wallet',
    version: PROVIDER_VERSION,

    /** 连接：未授权 origin 触发弹窗显式确认（权限最小化）。
     *  幂等且确认门控——后台会话令牌轮换（SW 休眠重启）时可安全重试。 */
    requestAccounts: () => call('zchain_requestAccounts'),

    /** 当前网络（0.1 恒为 devnet）。 */
    getNetwork: () => call('zchain_getNetwork'),

    /** 能力矩阵（dapp 应据此降级，而不是探测 eth_*）。 */
    getCapabilities: () => call('zchain_getCapabilities'),

    /**
     * 换网（0.2）：networkId ∈ {zchain-devnet-1, zchain-testnet-1}（注册表外
     * 网络——含 mainnet——一律 NetworkUnsupported）。异网切换必须经弹窗二次
     * 确认；批准后 chain_id 绑定该账户（签名摘要域含 chain_id，跨网重放必
     * 换摘要）。同网重复切换为幂等 no-op。
     */
    switchNetwork: (networkId) => call('zchain_switchNetwork', { chainId: networkId }),

    /** 当前账户（公钥；未解锁返回空数组）。 */
    getAccounts: () => call('zchain_getAccounts'),

    /**
     * 签署结构化操作（transfer/buy_in；settle 走 signSettlement）。
     * @param operation 结构化请求（kind/chainId/domain/abiVersion/nonce/expiry/
     *                  assetClass/inputs/outputs|tableId+seatOwner）
     * @param previewHash 期望的确认摘要（必须与钱包重算一致，防展示-签名调包）
     */
    signOperation: (operation, previewHash) =>
      call('zchain_signOperation', { operation, previewHash }, { retryOnSession: false }),

    /**
     * 签署结算（§6.12.4 signSettlement(settlement_digest, preview) 的 0.1 形状：
     * operator 下发 record/policy 的稳定 borsh hex + 预览摘要绑定；逐输入补签
     * 的多人桌路径在 0.2 开放给 dapp）。
     */
    signSettlement: (settlement, previewHash) =>
      call('zchain_signSettlement', { settlement, previewHash }, { retryOnSession: false }),

    /** 会话密钥授权：0.3 交付（SNIP-12 delegated key）。 */
    authorizeSessionKey: (request) => call('zchain_authorizeSessionKey', { request }),

    /** 会话密钥撤销：0.4 交付。 */
    revokeSessionKey: (bindingId) => call('zchain_revokeSessionKey', { bindingId }),

    /** note 列表（已脱敏：无 spend secret / nullifier；filter 仅支持 {spendable}）。 */
    getNotes: (filter) => call('zchain_getNotes', { filter: filter ?? {} }).then((r) => {
      const notes = r.notes ?? [];
      if (filter && typeof filter === 'object' && typeof filter.spendable === 'boolean') {
        return notes.filter((n) => n.spendable === filter.spendable);
      }
      return notes;
    }),

    /** proof 验证：0.2 交付（proof portal）。 */
    verifyProof: (proof) => call('zchain_verifyProof', { proof }),

    /** proof 订阅：0.2 交付。 */
    watchProof: (binding) => call('zchain_watchProof', { binding }),

    /** 立即锁定钱包。 */
    lock: () => call('zchain_lock', {}, { retryOnSession: false }),
  };

  window.zchain = provider;

  // provider 就绪事件（独立命名空间，非 eip6963）。
  window.dispatchEvent(new CustomEvent('zchain:initialized', { detail: { version: PROVIDER_VERSION } }));
})();
