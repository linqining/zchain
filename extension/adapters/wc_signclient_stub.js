// =============================================================================
// extension/adapters/wc_signclient_stub.js — WalletConnect v2 SignClient 内存 stub
//
// 用途（如实声明）：**测试与本地演练用**。用内存对象模拟 relay 的三类往返：
//   propose → approve/reject（会话建立）、request 往返（dapp 请求 → 钱包响应）、
//   过期/断开（session_delete / 会话失效）。
// 零网络、零 npm 依赖、零密码学。
//
// 生产接入路径（adapters/README.md 有完整步骤）：把真实的
// `@walletconnect/sign-client` 实例注入 adapters/walletconnect.js 的同一接口。
// 本 stub 与 SignClient 的接口契约（wallet 侧）：
//   on('session_proposal'|'session_request'|'session_delete', cb) / off(...)
//   approveSession({ id, namespaces }) -> { topic, namespaces, expiry }
//   rejectSession({ id, reason: { code, message } })
//   respondSessionRequest({ topic, response: { id, jsonrpc, result|error } })
//   rejectRequest({ topic, id, error })
//   disconnect({ topic, reason })  → 派发 'session_delete'
//   emitSessionEvent({ topic, event: { name, data }, chainId })
//   getActiveSessions() / session: Map<topic, session>
// （dapp 侧，仅 stub 提供以便端到端演练）：connect() / request() / expireSession()
// =============================================================================

/** 单调递增的 topic 生成器（内存级唯一即可；非密码学）。 */
let stubCounter = 0;
function newTopic() {
  stubCounter += 1;
  return `stub-topic-${stubCounter.toString().padStart(4, '0')}`;
}

function newId() {
  stubCounter += 1;
  return 1_000 + stubCounter;
}

/**
 * 创建内存 SignClient stub。
 *
 * @param {object} [opts]
 * @param {number} [opts.sessionTtlSec=604800] approve 会话默认有效期（秒）
 * @param {() => number} [opts.now=() => Date.now()] 时钟注入（与适配器共用，
 *        过期模拟才与适配器的 now 语义一致）
 */
export function createSignClientStub({ sessionTtlSec = 7 * 24 * 3600, now = () => Date.now() } = {}) {
  /** topic → { topic, namespaces, expiry, } */
  const sessions = new Map();
  const walletListeners = new Map(); // event → Set<cb>
  const dappListeners = new Map(); // event → Set<cb>
  const pendingConnects = new Map(); // proposal id → { resolve, reject }
  const pendingRequests = new Map(); // request id → { resolve, reject }

  function emitTo(map, event, payload) {
    const set = map.get(event);
    if (!set) return;
    for (const cb of [...set]) cb(payload);
  }

  const on = (map) => (event, cb) => {
    if (!map.has(event)) map.set(event, new Set());
    map.get(event).add(cb);
  };
  const off = (map) => (event, cb) => {
    map.get(event)?.delete(cb);
  };

  const signClient = {
    /** SignClient 形状：活动会话表（wallet 视角）。 */
    session: sessions,
    on: on(walletListeners),
    off: off(walletListeners),

    getActiveSessions() {
      return new Map(sessions);
    },

    // ---- 会话建立：dapp connect() → wallet 收到 'session_proposal' ----
    /** dapp 侧（stub 专用）：发起 connect，返回 promise（approve 后 resolve）。 */
    connect({ requiredNamespaces } = {}) {
      const id = newId();
      const proposal = {
        id,
        params: {
          requiredNamespaces: requiredNamespaces ?? {},
          relays: [{ protocol: 'irn (stubbed)' }],
          proposer: { publicKey: `stub-proposer-${id}`, metadata: { name: 'stub-dapp' } },
        },
      };
      return new Promise((resolve, reject) => {
        pendingConnects.set(id, { resolve, reject });
        // 模拟 relay 投递：同步派发（测试确定性）。
        emitTo(walletListeners, 'session_proposal', proposal);
      });
    },

    /** wallet 侧：批准提案（建立会话并回执 dapp）。 */
    approveSession({ id, namespaces } = {}) {
      if (!pendingConnects.has(id)) {
        throw new Error(`stub: unknown proposal ${id}`);
      }
      const topic = newTopic();
      const session = {
        topic,
        namespaces,
        expiry: Math.floor(now() / 1000) + sessionTtlSec,
        peer: { metadata: { name: 'stub-dapp' } },
      };
      sessions.set(topic, session);
      const { resolve } = pendingConnects.get(id);
      pendingConnects.delete(id);
      resolve({ topic, namespaces, expiry: session.expiry });
      return { topic, namespaces, expiry: session.expiry };
    },

    /** wallet 侧：拒绝提案（dapp connect promise 以 CAIP-25 形状 reject）。 */
    rejectSession({ id, reason } = {}) {
      if (!pendingConnects.has(id)) {
        throw new Error(`stub: unknown proposal ${id}`);
      }
      const { reject } = pendingConnects.get(id);
      pendingConnects.delete(id);
      reject({ code: reason?.code ?? 5000, message: reason?.message ?? 'rejected' });
      return { id, reason };
    },

    // ---- 请求往返：dapp request() → wallet 收到 'session_request' ----
    /** dapp 侧（stub 专用）：发送 session request。 */
    request({ topic, chainId, request } = {}) {
      const id = newId();
      return new Promise((resolve, reject) => {
        pendingRequests.set(id, { resolve, reject, topic });
        emitTo(walletListeners, 'session_request', {
          id,
          topic,
          params: { request: { ...request }, chainId: chainId ?? null },
        });
      });
    },

    /** wallet 侧：回执成功/失败。response: { id, jsonrpc, result } 或 { id, jsonrpc, error }。 */
    respondSessionRequest({ topic, response } = {}) {
      const id = response?.id;
      const pending = pendingRequests.get(id);
      if (!pending) throw new Error(`stub: unknown request ${id}`);
      pendingRequests.delete(id);
      if (response.error) {
        pending.reject(response.error);
      } else {
        pending.resolve(response.result);
      }
      return { topic, id, acknowledged: true };
    },

    /** wallet 侧：显式拒绝单个请求。 */
    rejectRequest({ topic, id, error } = {}) {
      const pending = pendingRequests.get(id);
      if (!pending) throw new Error(`stub: unknown request ${id}`);
      pendingRequests.delete(id);
      pending.reject(error ?? { code: 4001, message: 'rejected' });
      return { topic, id };
    },

    // ---- 会话事件：wallet → dapp（chainChanged / accountsChanged） ----
    emitSessionEvent({ topic, event, chainId } = {}) {
      if (!sessions.has(topic)) throw new Error(`stub: unknown session ${topic}`);
      emitTo(dappListeners, 'session_event', { topic, event, chainId });
      return true;
    },

    /** dapp 侧（stub 专用）：订阅会话事件。 */
    onSessionEvent(cb) {
      on(dappListeners)('session_event', cb);
    },
    offSessionEvent(cb) {
      off(dappListeners)('session_event', cb);
    },

    /**
     * 测试钩子：向 wallet 侧直接注入任意 session_request 形状事件
     * （重放/回退 id、畸形请求等负例用——真实 SignClient 不可能产生重复 id，
     * 本钩子正是用来验证适配器对"违反传输层假设"的请求仍然拒绝）。
     */
    emitSessionRequestFromDapp(event) {
      emitTo(walletListeners, 'session_request', event);
    },

    // ---- 断开/过期 ----
    /** wallet 侧：主动断开（触发 session_delete）。 */
    disconnect({ topic, reason } = {}) {
      if (!sessions.has(topic)) throw new Error(`stub: unknown session ${topic}`);
      sessions.delete(topic);
      emitTo(walletListeners, 'session_delete', { topic, reason: reason?.message ?? 'wallet disconnected' });
      emitTo(dappListeners, 'session_delete', { topic, reason: reason?.message ?? 'wallet disconnected' });
      return true;
    },

    /** 测试钩子：模拟 relay 侧会话过期（expiry 拨到注入时钟的过去并通知两侧）。 */
    expireSession(topic) {
      const session = sessions.get(topic);
      if (!session) throw new Error(`stub: unknown session ${topic}`);
      session.expiry = Math.floor(now() / 1000) - 1;
      sessions.set(topic, session);
      return session;
    },
  };

  return signClient;
}
