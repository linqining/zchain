/* ZChain Wallet mobile — 屏幕 + 路由 + 交互(设计稿 19 屏 1:1 移植)。
 *
 * 结构对应 design/zchain-wallet-ui-b-ledger.html:
 *   t-welcome/t-success/t-import/t-lock/t-home/t-acct(×3 链)/t-zc-send/
 *   t-zc-withdraw/t-zc-confirm/t-zc-sessions/t-zc-portal/t-zc-receipts/
 *   t-evm-send/t-evm-history/t-evm-manage/t-proofs/t-settings
 * 文案、示例数据、状态语义(凭证条/fail-closed/诚实性说明)逐屏同源。
 * 差异:返回键统一走导航栈(data-back);供出图的 shot/export 模式见文件尾。
 */
"use strict";

/* =============== 屏幕模板(返回 HTML 字符串) =============== */

const S = {}; // id → 渲染函数

S.welcome = () => `
<section class="scr" aria-label="欢迎">
  <div class="cover">
    <span class="ch ch-solid" style="position:absolute;right:0;top:2px">DevNet</span>
    <svg class="cv-logo" viewBox="0 0 64 64" aria-label="ZChain 单色 logo" style="color:var(--ink)"><use href="#logo-zc"/></svg>
    <div class="cv-n">ZChain Wallet</div>
    <div class="cv-t">桌上飞快,结算可证</div>
    <div class="cv-e">Fast at the table. Verifiable at settlement.</div>
    <div class="cv-meta">
      <div><b>3</b><span>账户层</span></div>
      <div><b>2 套 KDF</b><span>本地加密</span></div>
      <div><b>STARK</b><span>可复验</span></div>
    </div>
    <div class="row" style="gap:6px;margin-top:14px;flex-wrap:wrap">
      <span class="ch ch-felt">${ICO("spade", "ic-xs")}ZChain 隐私层</span>
      <span class="ch">${ICO("ether", "ic-xs")}EVM 多链</span>
      <span class="ch">${ICO("layers", "ic-xs")}Starknet</span>
    </div>
    <div class="cv-acts">
      <button class="btn btn-p btn-lg" data-nav="success">${ICO("plus", "ic-s")}一键创建钱包</button>
      <button class="btn btn-s" data-nav="import">导入或恢复钱包</button>
      <div class="hint-s">一次创建三层账户:ZChain 隐私层 + EVM 多链 + Starknet</div>
    </div>
  </div>
  <div class="cv-foot">移动客户端 0.1.0 · 继续即代表知悉测试网风险<br>Play / DevNet / v1.3</div>
</section>`;

S.success = () => `
<section class="scr" aria-label="创建成功">
  <div class="body pb">
    <div class="center" style="padding:22px 0 16px">
      <span class="seal seal-ok" style="font-size:10px">已创建</span>
      <h1 style="font-size:19px;margin:14px 0 4px">钱包已创建</h1>
      <p style="color:var(--ink-2);font-size:12px">三层账户已就绪,先保存好解锁口令。</p>
    </div>
    <div class="bn bn-bad">${ICO("warn")}<div><b>解锁口令只显示这一次</b><p>钱包不存储口令;丢失后仅能通过加密备份恢复。</p></div></div>
    <div class="pass"><span class="grow">${DEMO.password}</span><button class="ib" data-copy="${DEMO.password}" data-toast="口令已复制到剪贴板">${ICO("copy", "ic-s")}</button></div>
    <div class="cd" style="margin-top:12px">
      <div class="cd-h">三层地址</div>
      <div class="lr"><span class="lr-k">${ICO("spade", "ic-xs")} ZChain</span><span class="lr-v">${DEMO.account.zc} <button class="ib bare" data-copy="${DEMO.account.zc}" data-toast="地址已复制">${ICO("copy", "ic-xs")}</button></span></div>
      <div class="lr"><span class="lr-k">${ICO("ether", "ic-xs")} EVM</span><span class="lr-v">${DEMO.account.evm} <button class="ib bare" data-copy="${DEMO.account.evm}" data-toast="地址已复制">${ICO("copy", "ic-xs")}</button></span></div>
      <div class="lr"><span class="lr-k">${ICO("layers", "ic-xs")} Starknet</span><span class="lr-v">${DEMO.account.stk} <button class="ib bare" data-copy="${DEMO.account.stk}" data-toast="地址已复制">${ICO("copy", "ic-xs")}</button></span></div>
    </div>
    <label class="chk" data-check="[data-gated=start]" style="margin:2px 0 14px"><span class="cb">${ICO("check", "ic-xs")}</span>我已将口令保存在安全的地方(密码管理器 / 纸质备份)</label>
    <button class="btn btn-p btn-lg" data-gated="start" disabled data-nav="home">我已保存,开始使用</button>
  </div>
</section>`;

S.import = () => `
<section class="scr" aria-label="导入恢复">
  <header class="sub"><button class="ib bare" data-back>${ICO("back")}</button><div class="sub-t">导入 / 恢复</div><div class="sub-s"></div></header>
  <div class="body">
    <div class="seg"><button class="on" data-seg="backup">备份恢复</button><button data-seg="key">私钥导入</button><button data-seg="pass">自定义口令</button></div>
    <div data-pane="backup">
      <button class="empty" style="width:100%;padding:24px 14px;cursor:pointer" data-toast="示意:文件选择器">
        ${ICO("ul", "")}
        <b style="display:block;font-size:13px;color:var(--ink);margin:7px 0 3px">选择 .zcbk 备份文件</b>
        <span class="mono" style="font-size:10.5px">由「设置 → 备份导出」生成 · 仅 ZChain 层 note 库</span>
      </button>
      <div class="fld" style="margin-top:13px"><div class="fl">备份口令</div><input type="password" placeholder="≥ 8 位,与钱包解锁口令相互独立"></div>
      <button class="btn btn-p" data-toast="示意:Argon2id 本地解密中">恢复钱包</button>
      <div class="bn bn-info" style="margin-top:12px">${ICO("info")}<div><b>只覆盖 ZChain 层</b><p>ZCBK v1 含 REAL/PLAY 双库与 keystore 信封,不含 EVM / Starknet 账户——那两层请在各自管理页导出私钥。解密全程本地完成,备份口令不离开设备。</p></div></div>
    </div>
    <div data-pane="key" style="display:none">
      <div class="fld"><div class="fl">目标层</div><div class="iw"><input readonly value="EVM · Ethereum compatible" style="cursor:pointer"><span class="in-ic">${ICO("chev-d", "ic-s")}</span></div></div>
      <div class="fld"><div class="fl">私钥(hex)</div><input class="mono" style="font-size:11.5px" placeholder="0x…"></div>
      <div class="fld"><div class="fl">加密口令</div><input type="password" placeholder="用于本地 keystore 加密"></div>
      <button class="btn btn-p">导入到所选层</button>
      <p class="hint-s" style="text-align:left;margin-top:12px">支持各层独立导入:Starknet 走 STARK curve,EVM 走 secp256k1,ZChain note 层<b style="color:var(--bad)">暂不支持私钥导入</b>。</p>
    </div>
    <div data-pane="pass" style="display:none">
      <div class="fld"><div class="fl">自定义解锁口令</div><input type="password" placeholder="至少 10 位,含数字与字母"></div>
      <div class="meter" style="margin-bottom:6px"><i style="width:66%"></i></div>
      <div class="mono" style="font-size:10.5px;color:var(--ink-3);margin-bottom:13px">强度:良好</div>
      <div class="fld"><div class="fl">确认口令</div><input type="password" placeholder="再次输入"></div>
      <button class="btn btn-p" data-nav="home">创建并使用自定义口令</button>
    </div>
  </div>
</section>`;

S.lock = () => `
<section class="scr" aria-label="解锁">
  <div class="cover" style="justify-content:center;align-items:center;text-align:center">
    <span class="av" style="width:52px;height:52px;font-size:19px">${DEMO.account.initial}</span>
    <div style="font-size:16px;font-weight:700;margin-top:12px">${DEMO.account.name}</div>
    <div class="mono" style="font-size:11px;color:var(--ink-3);margin-top:2px">${DEMO.account.zc}</div>
    <div class="row" style="gap:6px;margin-top:12px;justify-content:center"><span class="ch ch-amb">${ICO("lock", "ic-xs")}已锁定</span><span class="ch">15 分钟无操作 / 切后台即锁</span></div>
    <div style="width:100%;max-width:282px;margin-top:22px">
      <div class="iw"><input type="password" id="lock-pw" placeholder="解锁口令"><span class="in-ic"><button class="ib bare" data-eye="#lock-pw">${ICO("eye", "ic-xs")}</button></span></div>
      <button class="btn btn-p" style="margin-top:10px" id="btn-unlock" data-nav="home">解锁三层</button>
      <button class="btn btn-g" style="margin-top:4px" data-nav="import">忘记口令?使用备份恢复</button>
    </div>
  </div>
  <div class="cv-foot">统一解锁三层 · ZChain 层 Argon2id + ChaCha20-Poly1305,EVM / Starknet 层 PBKDF2-SHA256(600k)+ AES-256-GCM</div>
</section>`;

const tabsHtml = (on) => `
<nav class="tabs">
  <button class="tb ${on === "home" ? "on" : ""}" data-tab="home">${ICO("home")}总账</button>
  <button class="tb ${on === "acct" ? "on" : ""}" data-tab="acct">${ICO("book")}账簿</button>
  <button class="tb ${on === "proofs" ? "on" : ""}" data-tab="proofs">${ICO("shield")}证明</button>
</nav>`;

S.home = () => `
<section class="scr" aria-label="三链总账">
  <header class="dh">
    <div class="dh-top"><span class="dh-kind">General Ledger</span><span class="net"><span class="dot"></span>${DEMO.net}</span><span class="dh-r"><button class="ib bare" data-nav="settings">${ICO("gear", "ic-s")}</button></span></div>
    <div class="dh-main"><span class="av">${DEMO.account.initial}</span><div class="grow" style="min-width:0"><div class="acct-n">${DEMO.account.name}${ICO("chev-d", "ic-s")}</div><div class="acct-a">三层统一账户 · 已解锁 2 / 3</div></div><span class="dh-r"><button class="ib" data-nav="lock">${ICO("lock", "ic-s")}</button></span></div>
  </header>
  <div class="body">
    <div class="tot">
      <div class="tot-l">三链总资产 <button class="ib bare" data-toast="示意:隐藏金额">${ICO("eye", "ic-xs")}</button></div>
      <div class="tot-a"><span class="eq">≈</span>$22,288.63</div>
      <div class="tot-s"><span class="ch ch-real">REAL 托管 $10,120.00</span><span>PLAY 为测试筹码,不计价</span></div>
    </div>
    <div class="sec-t">账户层</div>
    <div class="cd tight" style="padding:2px 14px">
      <button class="ar" data-tab="acct" data-acct="zc"><span class="tk tk-felt">${ICO("spade", "ic-s")}</span><div class="ar-m"><div class="ar-n">ZChain 隐私层 <span class="ch ch-felt ch-xs">已解锁</span></div><div class="ar-s">PLAY 12,400.00 · NATIVE 10,000.00</div></div><div class="ar-r"><div class="ar-amt">$10,120.00</div><div class="ar-s mono" style="text-align:right">${DEMO.account.zc}</div></div></button>
      <button class="ar" data-tab="acct" data-acct="evm"><span class="tk">${ICO("ether", "ic-s")}</span><div class="ar-m"><div class="ar-n">EVM 多链 <span class="ch ch-felt ch-xs">已解锁</span></div><div class="ar-s">ETH 2.4183 · Ethereum</div></div><div class="ar-r"><div class="ar-amt">$8,124.69</div><div class="ar-s mono" style="text-align:right">${DEMO.account.evm}</div></div></button>
      <button class="ar" data-tab="acct" data-acct="stk"><span class="tk">${ICO("layers", "ic-s")}</span><div class="ar-m"><div class="ar-n">Starknet <span class="ch ch-amb ch-xs">已锁定</span></div><div class="ar-s">ETH 1.2034 · SN DevNet</div></div><div class="ar-r"><div class="ar-amt">$4,043.42</div><div class="ar-s mono" style="text-align:right">${DEMO.account.stk}</div></div></button>
    </div>
    <div class="cd">
      <div class="cd-h">最弱凭证</div>
      ${rail({ pending: "done", soft: "done", proven: "cur" })}
      <div class="rail-cap"><span>1 张 REAL note 停在 <b style="color:var(--amb)">soft</b></span><button class="btn btn-s btn-sm" data-nav="zc-withdraw">查看</button></div>
    </div>
    <div class="cd">
      <div class="cd-h">待办 <span class="more" data-nav="zc-confirm">1 项</span></div>
      <button class="mi" data-nav="zc-confirm"><span class="mi-ic" style="color:var(--amb);border-color:var(--amb-rl);background:var(--amb-w)">${ICO("pen", "ic-s")}</span><span class="grow"><b>开桌签名请求 · 8♠ 桌</b><span>poker.zchain.devnet · 92s 后过期</span></span>${ICO("chev-r", "ic-s")}</button>
    </div>
    <button class="btn btn-s btn-sm" style="width:100%;height:38px" data-nav="lock">${ICO("lock", "ic-s")}全部锁定</button>
    <div class="foot">ZChain Wallet · 移动客户端 0.1.0 · DevNet<br>Play / DevNet / v1.3</div>
  </div>
  ${tabsHtml("home")}
</section>`;

/* ---- 账簿:单模板 × 三链 ---- */
const paneZc = () => `
  <div data-csp="zc">
    <div class="split">
      <div class="col"><div class="tot-l"><span class="ch ch-play ch-xs">GAME</span>可用筹码</div><div class="tot-a">12,400.00<span class="u">PLAY</span></div></div>
      <div class="col"><div class="tot-l"><span class="ch ch-real ch-xs">REAL</span>托管映射</div><div class="tot-a" style="color:var(--real)">10,000.00<span class="u">NATIVE</span></div></div>
    </div>
    <div class="bn bn-real" style="padding:9px 11px">${ICO("warn")}<div><b>托管映射资产</b><p>REAL 域提现通道未开放;GAME 域筹码不上主网。</p></div></div>
    <div class="acts">
      <button class="play" data-open="ovl-zc-recv">${ICO("qr")}收款</button>
      <button data-nav="zc-send">${ICO("send")}转账</button>
      <button class="real" data-nav="zc-withdraw">${ICO("out")}提现</button>
      <button data-nav="zc-portal">${ICO("shield")}Portal</button>
    </div>
    <div class="cd">
      <div class="cd-h">资产 <span class="more" data-nav="zc-receipts">回执${ICO("chev-r", "ic-xs")}</span></div>
      <div class="ar"><span class="tk tk-play">P</span><div class="ar-m"><div class="ar-n">PLAY <span class="ch ch-play ch-xs">GAME</span></div><div class="ar-s">可用 12,400.00 · 桌上锁定 0.00</div></div><div class="ar-r"><div class="ar-amt">12,400.00</div></div></div>
      <div class="ar"><span class="tk tk-real">N</span><div class="ar-m"><div class="ar-n">NATIVE <span class="ch ch-real ch-xs">REAL</span></div><div class="ar-s">托管映射 · 提现未开放</div></div><div class="ar-r"><div class="ar-amt">10,000.00</div></div></div>
      <div class="ar" style="opacity:.5"><span class="tk">U</span><div class="ar-m"><div class="ar-n">USDT / USDC</div><div class="ar-s">未接入</div></div><div class="ar-r"><div class="ar-amt dim">—</div></div></div>
    </div>
    <div class="cd">
      <div class="cd-h">最新动态 <span class="more" data-nav="zc-receipts">查看全部${ICO("chev-r", "ic-xs")}</span></div>
      <div class="tx"><span class="tic ok">${ICO("check", "ic-s")}</span><div class="ar-m"><div class="ar-n">买入 · 8♠ 桌</div><div class="ar-s">0xc41d…9b · 2 分钟前</div></div><div class="ar-r"><div class="ar-amt neg">-500.00</div><div class="ar-st"><span class="ch ch-felt ch-xs">included</span></div></div></div>
      <div class="tx"><span class="tic blue">${ICO("receipt", "ic-s")}</span><div class="ar-m"><div class="ar-n">结算 · 8♠ 桌 #128</div><div class="ar-s">0x3f9e…aa · 刚刚</div></div><div class="ar-r"><div class="ar-amt pos">+620.50</div><div class="ar-st"><span class="ch ch-xs">seen</span></div></div></div>
    </div>
    <div class="cd">
      <div class="cd-h">会话密钥 · SNIP-12 <span class="more" data-nav="zc-sessions">管理${ICO("chev-r", "ic-xs")}</span></div>
      <div class="lr"><span class="lr-k">poker.zchain.devnet</span><span class="lr-v" style="color:var(--felt)">活跃</span></div>
      <div class="lr"><span class="lr-k">单笔 / 日累计</span><span class="lr-v">≤1,000 · 2,150/5,000</span></div>
      <div class="meter" style="margin-top:8px"><i style="width:43%"></i></div>
    </div>
  </div>`;

const paneEvm = () => `
  <div data-csp="evm" style="display:none">
    <div class="tot">
      <div class="tot-l">总余额 · ETH</div>
      <div class="tot-a">2.4183<span class="u">ETH</span></div>
      <div class="tot-s"><span class="mono">≈ $8,124.69</span><button class="ib bare" data-open="ovl-evm-recv">${ICO("qr", "ic-xs")}</button><button class="ib bare" data-toast="示意:浏览器打开">${ICO("ext", "ic-xs")}</button></div>
    </div>
    <div class="acts">
      <button data-nav="evm-send">${ICO("send")}发送</button>
      <button data-open="ovl-evm-recv">${ICO("qr")}收款</button>
      <button data-nav="evm-history">${ICO("receipt")}历史</button>
      <button data-toast="示意:合约读写面板">${ICO("file")}合约</button>
    </div>
    <div class="cd">
      <div class="cd-h">网络 <span class="more" data-toast="示意:切换网络下拉">切换${ICO("swap", "ic-xs")}</span></div>
      <div class="lr"><span class="lr-k">chainId</span><span class="lr-v">1 <span class="ch ch-felt ch-xs">校验通过</span></span></div>
      <div class="lr"><span class="lr-k">gas</span><span class="lr-v">12 gwei <span class="ch ch-xs">偏低</span></span></div>
      <div class="lr"><span class="lr-k">nonce</span><span class="lr-v">42</span></div>
    </div>
    <div class="cd">
      <div class="cd-h">资产</div>
      <div class="ar"><span class="tk">Ξ</span><div class="ar-m"><div class="ar-n">ETH</div><div class="ar-s">原生币</div></div><div class="ar-r"><div class="ar-amt">2.4183</div></div></div>
      <div class="ar"><span class="tk">U</span><div class="ar-m"><div class="ar-n">USDC <span class="ch ch-xs">只读</span></div><div class="ar-s">erc-20 · eth_call 读取</div></div><div class="ar-r"><div class="ar-amt">320.00</div></div></div>
    </div>
    <div class="cd">
      <div class="cd-h">最新动态 <span class="more" data-nav="evm-history">查看全部${ICO("chev-r", "ic-xs")}</span></div>
      <div class="tx"><span class="tic ok">${ICO("send", "ic-s")}</span><div class="ar-m"><div class="ar-n">发送 · 0.25 ETH</div><div class="ar-s">0x8f3a…c2 · 2 分钟前</div></div><div class="ar-r"><div class="ar-amt neg">-0.2500</div><div class="ar-st"><span class="ch ch-felt ch-xs">成功</span></div></div></div>
      <div class="tx"><span class="tic blue">${ICO("recv", "ic-s")}</span><div class="ar-m"><div class="ar-n">接收 · 1.20 ETH</div><div class="ar-s">0x51b7…c8 · 昨天</div></div><div class="ar-r"><div class="ar-amt pos">+1.2000</div><div class="ar-st"><span class="ch ch-felt ch-xs">成功</span></div></div></div>
    </div>
    <div class="cd">
      <div class="cd-h">账户管理 <span class="more" data-nav="evm-manage">进入${ICO("chev-r", "ic-xs")}</span></div>
      <div class="lr"><span class="lr-k">私钥 · 口令 · RPC</span><span class="lr-v dim">危险区需二次确认</span></div>
    </div>
  </div>`;

const paneStk = () => `
  <div data-csp="stk" style="display:none">
    <div class="tot">
      <div class="tot-l">总余额 · ETH</div>
      <div class="tot-a">1.2034<span class="u">ETH</span></div>
      <div class="tot-s"><span class="mono">≈ $4,043.42</span><button class="ib bare" data-open="ovl-stk-recv">${ICO("qr", "ic-xs")}</button><button class="ib bare" data-toast="示意:starkscan 打开">${ICO("ext", "ic-xs")}</button></div>
    </div>
    <div class="bn bn-amb">${ICO("lock")}<div><b>本层已锁定</b><p>解锁后才能发起 invoke;当前余额为链上只读数据。</p></div></div>
    <div class="acts">
      <button data-toast="示意:解锁后发送(同账簿模板)">${ICO("send")}发送</button>
      <button data-open="ovl-stk-recv">${ICO("qr")}收款</button>
      <button data-toast="示意:水龙头领取 10 ETH">${ICO("flask")}水龙头</button>
      <button data-toast="示意:历史(同账簿模板)">${ICO("receipt")}历史</button>
    </div>
    <div class="cd">
      <div class="cd-h">网络 <span class="more" data-toast="示意:切换网络下拉">切换${ICO("swap", "ic-xs")}</span></div>
      <div class="lr"><span class="lr-k">chainId</span><span class="lr-v">ZCDN <span class="ch ch-felt ch-xs">校验通过</span></span></div>
      <div class="lr"><span class="lr-k">nonce</span><span class="lr-v">7</span></div>
      <div class="lr"><span class="lr-k">UDC 地址</span><span class="lr-v">0x41a7…8e02(公式推导)</span></div>
    </div>
    <div class="cd">
      <div class="cd-h">资产</div>
      <div class="ar"><span class="tk">Ξ</span><div class="ar-m"><div class="ar-n">ETH</div><div class="ar-s">ERC-20 · u256 形状</div></div><div class="ar-r"><div class="ar-amt">1.2034</div></div></div>
    </div>
    <div class="cd">
      <div class="cd-h">最新动态</div>
      <div class="tx"><span class="tic ok">${ICO("send", "ic-s")}</span><div class="ar-m"><div class="ar-n">invoke · transfer</div><div class="ar-s">0x33c1…67 · maxFee 0.00042</div></div><div class="ar-r"><div class="ar-amt neg">-0.5000</div><div class="ar-st"><span class="ch ch-felt ch-xs">成功</span></div></div></div>
      <div class="tx"><span class="tic blue">${ICO("flask", "ic-s")}</span><div class="ar-m"><div class="ar-n">水龙头 · dev_faucet</div><div class="ar-s">0xe8b0…19 · 1 小时前</div></div><div class="ar-r"><div class="ar-amt pos">+10.0000</div><div class="ar-st"><span class="ch ch-play ch-xs">dev</span></div></div></div>
    </div>
  </div>`;

const recvSheet = (id, title, addr, sub) => `
  <div class="ovl" id="${id}">
    <div class="ovl-bg" data-close></div>
    <div class="sheet"><div class="grab"></div>
      <div class="row"><div style="font-weight:600;font-size:13px;flex:1">${title}</div><button class="ib bare" data-close>${ICO("x", "ic-s")}</button></div>
      <div class="mono c" style="font-size:9.5px;color:var(--ink-3);margin:6px 0 0;word-break:break-all">${addr}</div>
      <div class="c" style="font-size:10px;color:var(--ink-3);margin-bottom:12px">${sub}</div>
      <div class="qr"><svg viewBox="0 0 29 29"><use href="#qr-art"/></svg></div>
      <button class="btn btn-s btn-sm" style="margin-top:14px;width:100%" data-close data-copy="${addr}" data-toast="地址已复制">${ICO("copy", "ic-s")}复制地址</button>
    </div>
  </div>`;

S.acct = (seg) => {
  const c = DEMO.chains[seg || "zc"];
  return `
<section class="scr" aria-label="账簿" data-seg-cur="${seg || "zc"}">
  <header class="dh">
    <div class="dh-top"><span class="dh-kind" data-kind>${c.kind}</span><span class="net" data-net><span class="dot"></span>${c.net}</span><span class="dh-r"><button class="ib bare" data-nav="settings">${ICO("gear", "ic-s")}</button></span></div>
    <div class="dh-main"><span class="av">${DEMO.account.initial}</span><div class="grow" style="min-width:0"><div class="acct-n">${DEMO.account.name}${ICO("chev-d", "ic-s")}</div><div class="acct-a" data-addr>${c.addr}</div></div><span class="dh-r"><button class="ib" data-copy="${c.addr}" data-toast="地址已复制">${ICO("copy", "ic-s")}</button><button class="ib" data-nav="lock">${ICO("lock", "ic-s")}</button></span></div>
  </header>
  <div class="body">
    <div class="csw">
      <button class="${seg === "zc" || !seg ? "on" : ""}" data-cs="zc">ZChain<span class="cnt">2</span></button>
      <button class="${seg === "evm" ? "on" : ""}" data-cs="evm">EVM<span class="cnt">1</span></button>
      <button class="${seg === "stk" ? "on" : ""}" data-cs="stk">Starknet<span class="cnt">1</span></button>
    </div>
    ${paneZc()}
    ${paneEvm()}
    ${paneStk()}
  </div>
  ${recvSheet("ovl-zc-recv", "收款 · ZChain 层", "zc1qpoker9xf7x2wwn2h3a5v8…", "完整地址 · 点按下方按钮复制")}
  ${recvSheet("ovl-evm-recv", "收款 · EVM 层", DEMO.account.evmFull, "Ethereum · chainId 1")}
  ${recvSheet("ovl-stk-recv", "收款 · Starknet 层", DEMO.account.stkFull, "SN DevNet · ZCDN")}
  ${tabsHtml("acct")}
</section>`;
};

S["zc-send"] = () => `
<section class="scr" aria-label="ZChain 转账">
  <header class="sub"><button class="ib bare" data-back>${ICO("back")}</button><div class="sub-t">转账</div><div class="sub-s"><span class="ch ch-play ch-xs">GAME</span></div></header>
  <div class="body">
    <div class="fld"><div class="fl">金额 <span class="aux">可用 12,400.00 · <button data-max="#amt-send" data-maxval="12,400.00">MAX</button></span></div>
      <div class="iw"><input class="inp-amt" id="amt-send" value="500.00"><span class="tsel"><span class="tk tk-play" style="width:18px;height:18px;font-size:9px">P</span>PLAY${ICO("chev-d", "ic-xs")}</span></div>
      <div class="fiat">测试筹码 · 不计价</div>
    </div>
    <div class="fld"><div class="fl">收款 owner</div>
      <div class="iw"><input class="mono" style="font-size:11.5px" placeholder="0x… / zc1q…"><span class="in-ic"><button class="ib" data-toast="已粘贴">${ICO("copy", "ic-xs")}</button><button class="ib" data-toast="示意:扫码">${ICO("qr", "ic-xs")}</button></span></div>
    </div>
    <div class="cd">
      <div class="cd-h">贪心选币 · 消耗 2 张 note</div>
      <div class="lr"><span class="lr-k hashline" style="max-width:96px">4f2a…c19d</span><span class="lr-v">300.00 <span class="ch ch-felt ch-xs">proven</span></span></div>
      <div class="lr"><span class="lr-k hashline" style="max-width:96px">91c7…e03a</span><span class="lr-v">200.00 <span class="ch ch-felt ch-xs">proven</span></span></div>
      <div class="lr"><span class="lr-k">找零 note</span><span class="lr-v dim">0.00(本次无找零)</span></div>
    </div>
    <div class="cd">
      <div class="lr"><span class="lr-k">网络费</span><span class="lr-v">网关代付 <span class="ch ch-felt ch-xs">免费</span></span></div>
      <div class="lr"><span class="lr-k">回执路径</span><span class="lr-v dim">signed → seen → included</span></div>
    </div>
    <div class="cd" style="padding:10px 12px">
      ${rail({ pending: "done", soft: "done", proven: "done" })}
      <div class="rail-cap"><span>支出 note 短板 <b>proven</b> · 满足 GAME 域要求</span></div>
    </div>
    <button class="btn btn-p btn-lg" data-toast="已签名并提交 · 回执 0xc41d…9b">确认转账</button>
    <p class="hint-s" style="margin-top:10px">提交后可在「证明 → 回执」跟踪 inclusion 状态</p>
  </div>
</section>`;

S["zc-withdraw"] = () => `
<section class="scr" aria-label="REAL 提现预览">
  <header class="sub"><button class="ib bare" data-back>${ICO("back")}</button><div class="sub-t">提现(预览)</div><div class="sub-s"><span class="ch ch-real ch-xs">REAL</span></div></header>
  <div class="body">
    <div class="bn bn-real">${ICO("warn")}<div><b>托管警示</b><p>REAL 域由运营方托管映射。以下为<b>模拟预览</b>,不会提交任何链上交易。</p></div></div>
    <div class="fld"><div class="fl">提现金额 <span class="aux mono">REAL 可用 10,000.00</span></div>
      <div class="iw"><input class="inp-amt" value="5,000.00"><span class="tsel"><span class="tk tk-real" style="width:18px;height:18px;font-size:9px">N</span>NATIVE${ICO("chev-d", "ic-xs")}</span></div>
    </div>
    <div class="fld"><div class="fl">收款 owner(L1 地址)</div>
      <div class="iw"><input class="mono" style="font-size:11.5px" placeholder="0x…"><span class="in-ic"><button class="ib" data-toast="已粘贴">${ICO("copy", "ic-xs")}</button></span></div>
    </div>
    <div class="cd">
      <div class="cd-h">贪心选币 · 3 张 note</div>
      <div class="lr"><span class="lr-k hashline" style="max-width:88px">77b1…04dd</span><span class="lr-v">1,000.00 <span class="ch ch-felt ch-xs">proven</span></span></div>
      <div class="lr"><span class="lr-k hashline" style="max-width:88px">c93e…5f10</span><span class="lr-v">2,500.00 <span class="ch ch-felt ch-xs">proven</span></span></div>
      <div class="lr"><span class="lr-k hashline" style="max-width:88px">a208…91ce</span><span class="lr-v">1,500.00 <span class="ch ch-amb ch-xs">soft</span></span></div>
      <div class="lr"><span class="lr-k">找零 note</span><span class="lr-v dim">0.00(合计恰好 5,000.00)</span></div>
    </div>
    <div class="cd">
      <div class="cd-h">finality 检查 <span class="more" data-toast="示意:凭证阶梯说明">?</span></div>
      ${rail({ pending: "done", soft: "done", proven: "bad" })}
      <div class="lr" style="margin-top:9px"><span class="lr-k">所需证明</span><span class="lr-v">finalized</span></div>
      <div class="lr"><span class="lr-k">最弱凭证</span><span class="lr-v" style="color:var(--amb)">soft(1 张 note 未达标)</span></div>
    </div>
    <div class="cd">
      <div class="cd-h">暂不可提交 · 原因</div>
      <div class="rsn">${ICO("x", "ic-s")}提现通道未开放(v1 托管模式)</div>
      <div class="rsn">${ICO("x", "ic-s")}1 张 note 的证明未达 finalized</div>
      <div class="rsn real">${ICO("x", "ic-s")}托管方签名服务待接入</div>
    </div>
    <button class="btn btn-p btn-lg" disabled>提交提现</button>
    <p class="hint-s" style="margin-top:10px">fail-closed:原因消除前,提交入口保持禁用(虚线即「不可用」的专用笔触)</p>
  </div>
</section>`;

S["zc-confirm"] = () => `
<section class="scr" aria-label="签名确认">
  <header class="sub"><button class="ib bare" data-back>${ICO("x")}</button><div class="sub-t">签名请求</div><div class="sub-s"><span class="ch ch-amb ch-xs mono">1:52</span></div></header>
  <div class="body">
    <div class="dapp"><span class="dapp-fav">${ICO("spade", "ic-s")}</span><div class="grow" style="min-width:0"><b>poker.zchain.devnet</b><span>请求签名 · 会话密钥路径</span></div><span class="ch ch-felt ch-xs">已授权 origin</span></div>
    <div class="cfm">
      <div class="l">开桌买入</div>
      <div class="v neg">-500.00</div>
      <div class="s">PLAY · 8♠ 桌 · GAME 域 · 不动 REAL 资产</div>
    </div>
    <div class="cd">
      <div class="cd-h">请求内容</div>
      <div class="lr"><span class="lr-k">链</span><span class="lr-v">zchain-devnet-1</span></div>
      <div class="lr"><span class="lr-k">桌 table_id</span><span class="lr-v">#A3F2</span></div>
      <div class="lr"><span class="lr-k">资产</span><span class="lr-v">PLAY <span class="ch ch-play ch-xs">GAME</span></span></div>
      <div class="lr"><span class="lr-k">rake</span><span class="lr-v">2.00%</span></div>
      <div class="lr"><span class="lr-k">过期</span><span class="lr-v">120 秒 <span class="ch ch-amb ch-xs">倒计时中</span></span></div>
    </div>
    <div class="cd">
      <div class="cd-h">授权对象</div>
      <div class="lr"><span class="lr-k">收款 owner</span><span class="lr-v">0x8f3a91c4…d7e2</span></div>
      <div class="lr"><span class="lr-k">hand_binding</span><span class="lr-v">0xc41d8f22…04b79b</span></div>
      <div class="lr"><span class="lr-k">request_id</span><span class="lr-v">3f9e77d0…aa31</span></div>
      <div class="lr"><span class="lr-k">证明</span><span class="lr-v dim">结算后可在 Portal 完整验证</span></div>
    </div>
    <div class="bn bn-ok">${ICO("key")}<div><b>将使用会话密钥签名</b><p>在单笔限额(≤ 1,000 PLAY)内,无需输入口令。</p></div></div>
    <div class="btn-row">
      <button class="btn btn-d" data-back>拒绝</button>
      <button class="btn btn-p" data-toast="已用会话密钥签名 · 回执 0xc41d…9b">批准签名</button>
    </div>
    <details style="margin-top:12px"><summary style="font-size:11px;color:var(--ink-3);cursor:pointer;font-family:var(--mono)">原始摘要(SNIP-12)</summary><div class="raw">0x1a2b3c4d5e6f70819a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d</div></details>
  </div>
</section>`;

S["zc-sessions"] = () => `
<section class="scr" aria-label="会话密钥">
  <header class="sub"><button class="ib bare" data-back>${ICO("back")}</button><div class="sub-t">会话密钥</div><div class="sub-s"><span class="ch ch-xs mono">SNIP-12</span></div></header>
  <div class="body">
    <div class="seg">
      <button class="on" data-seg="list">现有会话</button>
      <button data-seg="new">新建草稿</button>
    </div>
    <div data-pane="list">
      <div class="cd" style="border-color:var(--ink);border-width:1.5px">
        <div class="row" style="gap:9px;margin-bottom:9px">
          <span class="tic ok" style="width:26px;height:26px">${ICO("key", "ic-s")}</span>
          <div class="grow" style="min-width:0"><div class="ar-n" style="font-size:12.5px">poker.zchain.devnet</div><div class="ar-s">delegated 0x7ad9…c1e4</div></div>
          <span class="ch ch-felt ch-xs">活跃</span>
        </div>
        <div class="lr"><span class="lr-k">scope</span><span class="lr-v"><span class="ch ch-xs">开桌</span> <span class="ch ch-xs">买入</span> <span class="ch ch-xs">结算</span></span></div>
        <div class="lr"><span class="lr-k">单笔限额</span><span class="lr-v">≤ 1,000 PLAY</span></div>
        <div class="lr"><span class="lr-k">日累计</span><span class="lr-v">2,150 / 5,000 PLAY</span></div>
        <div class="meter" style="margin:7px 0"><i style="width:43%"></i></div>
        <div class="lr"><span class="lr-k">桌白名单</span><span class="lr-v">8♠ · 9♣(2 桌)</span></div>
        <div class="lr"><span class="lr-k">有效期</span><span class="lr-v">剩 6 天 12 小时</span></div>
        <button class="btn btn-d btn-sm" style="margin-top:11px;width:100%" data-toast="示意:撤销为粘滞操作,需二次确认">撤销授权</button>
        <p class="hint-s" style="margin-top:7px">撤销为粘滞操作:立即生效,本会话永久失效</p>
      </div>
      <div class="cd" style="opacity:.6">
        <div class="row" style="gap:9px;margin-bottom:8px">
          <span class="tic warn" style="width:26px;height:26px">${ICO("key", "ic-s")}</span>
          <div class="grow" style="min-width:0"><div class="ar-n" style="font-size:12.5px">demo.local</div><div class="ar-s">delegated 0x1e40…88a2</div></div>
          <span class="ch ch-amb ch-xs">已耗尽</span>
        </div>
        <div class="lr"><span class="lr-k">日累计</span><span class="lr-v">5,000 / 5,000 PLAY</span></div>
        <button class="btn btn-g btn-sm" style="margin-top:9px" data-toast="示意:已删除">删除记录</button>
      </div>
      <p class="hint-s" style="text-align:left;margin-top:2px">授权簿按 origin 记账;撤销只影响该 origin 的委托密钥,不动主密钥。</p>
    </div>
    <div data-pane="new" style="display:none">
      <div class="cd">
        <div class="cd-h">scope 授权</div>
        <label class="chk" style="margin-bottom:9px" data-check="[data-gated=scope]"><span class="cb on">${ICO("check", "ic-xs")}</span>开桌(OpenTable)</label>
        <label class="chk" style="margin-bottom:9px" data-check="[data-gated=scope]"><span class="cb on">${ICO("check", "ic-xs")}</span>买入(BuyIn)</label>
        <label class="chk" data-check="[data-gated=scope]"><span class="cb">${ICO("check", "ic-xs")}</span>结算(Settlement)</label>
      </div>
      <div class="fld"><div class="fl">单笔限额</div>
        <div class="iw"><input class="mono" value="1,000" style="font-size:15px"><span class="tsel"><span class="tk tk-play" style="width:18px;height:18px;font-size:9px">P</span>PLAY</span></div></div>
      <div class="fld"><div class="fl">日累计限额</div>
        <div class="iw"><input class="mono" value="5,000" style="font-size:15px"><span class="tsel"><span class="tk tk-play" style="width:18px;height:18px;font-size:9px">P</span>PLAY</span></div></div>
      <div class="fld"><div class="fl">桌白名单 <span class="aux">不填 = 不限桌(不推荐)</span></div>
        <div class="iw"><input class="mono" style="font-size:11.5px" placeholder="table_id,逗号分隔"><span class="in-ic"><button class="ib" data-toast="示意:添加桌号">${ICO("plus", "ic-xs")}</button></span></div></div>
      <div class="fld"><div class="fl">有效期</div>
        <button class="selrow" data-toast="示意:有效期下拉"><span>7 天</span>${ICO("chev-d", "ic-s")}</button></div>
      <button class="btn btn-p" data-gated="scope" data-toast="示意:生成摘要并确认登记">生成摘要并确认</button>
      <p class="hint-s" style="text-align:left;margin-top:10px">登记前会展示 SNIP-12 摘要供核对;签名路径不再需要口令,但受上述限额约束。scope 全部取消勾选时,登记入口自动禁用。</p>
    </div>
  </div>
</section>`;

S["zc-portal"] = () => `
<section class="scr" aria-label="Proof Portal">
  <header class="sub"><button class="ib bare" data-back>${ICO("back")}</button><div class="sub-t">Proof Portal</div><div class="sub-s"><span class="ch ch-felt ch-xs">STARK</span></div></header>
  <div class="body">
    <div class="fld"><div class="fl">hand binding</div>
      <div class="iw"><input class="mono" style="font-size:11.5px" value="0xc41d8f22e9a04b79b"><span class="in-ic"><button class="ib" data-toast="已粘贴">${ICO("copy", "ic-xs")}</button></span></div></div>
    <button class="btn btn-p" data-toast="示意:开始验证流程">${ICO("shield", "ic-s")}验证这一手牌</button>
    <div class="cd" style="margin-top:14px">
      <div class="cd-h">验证步骤 <span class="more mono">3/4</span></div>
      <div class="steps">
        <div class="stp done"><i>${ICO("check", "ic-xs")}</i><div><b>拉取结算明细</b><span>网关 127.0.0.1:18900 · 200 OK</span></div></div>
        <div class="stp done"><i>${ICO("check", "ic-xs")}</i><div><b>下载 STARK 证明</b><span>payload 84.2 KB · engine stwo</span></div></div>
        <div class="stp run"><i>${ICO("refresh", "ic-xs")}</i><div><b>本机完整验证</b><span>stwo 引擎运行中…</span></div></div>
        <div class="stp"><i>4</i><div><b>wallet-core 本地复验</b><span>结算关系与 payout_root 比对</span></div></div>
      </div>
    </div>
    <div class="bn bn-info">${ICO("info")}<div><b>性能如实标注</b><p>本机完整验证约 1.7s,超出 500ms 交互预算——进度如实展示,不伪装即时。</p></div></div>
    <div class="cd">
      <div class="cd-h">结算摘要</div>
      <div class="lr"><span class="lr-k">底池</span><span class="lr-v">1,240.00 PLAY</span></div>
      <div class="lr"><span class="lr-k">rake</span><span class="lr-v">24.80 PLAY(2%)</span></div>
      <div class="lr"><span class="lr-k">我方份额</span><span class="lr-v" style="color:var(--felt)">+620.50 PLAY</span></div>
      <div class="lr"><span class="lr-k">payout_root</span><span class="lr-v">0x8c3f…d210</span></div>
    </div>
    <div class="seal seal-ok">已验证</div>
    <div class="bn bn-ok">${ICO("shield")}<div><b>验证通过</b><p>该手牌结算与链上 STARK 证明一致。</p></div></div>
  </div>
</section>`;

S["zc-receipts"] = () => `
<section class="scr" aria-label="交易回执">
  <header class="sub"><button class="ib bare" data-back>${ICO("back")}</button><div class="sub-t">交易回执</div><div class="sub-s"><span class="ch ch-xs mono">signed→seen→included</span></div></header>
  <div class="body">
    <div class="seg">
      <button class="on" data-seg="all">全部</button>
      <button data-seg="pend">签名中</button>
      <button data-seg="done">已上链</button>
    </div>
    <div data-pane="all">
      <div class="cd" style="padding:2px 14px">
        <div class="tx"><span class="tic warn">${ICO("clock", "ic-s")}</span><div class="ar-m"><div class="ar-n">开桌签名 · 8♠ 桌</div><div class="ar-s">0x77d0…31 · 92s 后过期</div></div><div class="ar-r"><div class="ar-amt neg">-500.00</div><div class="ar-st"><span class="ch ch-amb ch-xs">signed</span></div></div></div>
        <div class="tx"><span class="tic blue">${ICO("receipt", "ic-s")}</span><div class="ar-m"><div class="ar-n">结算 · 8♠ 桌 #128</div><div class="ar-s">0x3f9e…aa · 刚刚</div></div><div class="ar-r"><div class="ar-amt pos">+620.50</div><div class="ar-st"><span class="ch ch-play ch-xs">seen</span></div></div></div>
        <div class="tx"><span class="tic ok">${ICO("check", "ic-s")}</span><div class="ar-m"><div class="ar-n">买入 · 8♠ 桌</div><div class="ar-s">0xc41d…9b · 2 分钟前</div></div><div class="ar-r"><div class="ar-amt neg">-500.00</div><div class="ar-st"><span class="ch ch-felt ch-xs">included</span></div></div></div>
        <div class="tx"><span class="tic ok">${ICO("check", "ic-s")}</span><div class="ar-m"><div class="ar-n">转账 · 收款人 0x8f…d7</div><div class="ar-s">0x9a02…ef · 1 小时前</div></div><div class="ar-r"><div class="ar-amt neg">-200.00</div><div class="ar-st"><span class="ch ch-felt ch-xs">included</span></div></div></div>
        <div class="tx"><span class="tic bad">${ICO("warn", "ic-s")}</span><div class="ar-m"><div class="ar-n">结算 · 9♣ 桌 #96</div><div class="ar-s">0x51b7…c8 · 超出 deadline</div></div><div class="ar-r"><div class="ar-amt pos">+88.00</div><div class="ar-st"><button class="btn btn-g btn-sm" disabled>ForceInclude 未开放</button></div></div></div>
      </div>
      <p class="hint-s" style="text-align:left;margin-top:2px">回执状态机 signed → seen → included 单向推进,与凭证阶梯 pending → proven → finalized 是两套独立状态,不得混用同一种笔触。超出 deadline(10s)时提示存在 ForceInclude 协议路径,但当前版本<b style="color:var(--bad)">只展示状态、不实现提交</b>——按钮保持禁用。</p>
    </div>
    <div data-pane="pend" style="display:none">
      <div class="cd" style="padding:2px 14px">
        <div class="tx"><span class="tic warn">${ICO("clock", "ic-s")}</span><div class="ar-m"><div class="ar-n">开桌签名 · 8♠ 桌</div><div class="ar-s">0x77d0…31 · 92s 后过期</div></div><div class="ar-r"><div class="ar-amt neg">-500.00</div><div class="ar-st"><span class="ch ch-amb ch-xs">signed</span></div></div></div>
      </div>
    </div>
    <div data-pane="done" style="display:none">
      <div class="cd" style="padding:2px 14px">
        <div class="tx"><span class="tic ok">${ICO("check", "ic-s")}</span><div class="ar-m"><div class="ar-n">买入 · 8♠ 桌</div><div class="ar-s">0xc41d…9b · 2 分钟前</div></div><div class="ar-r"><div class="ar-amt neg">-500.00</div><div class="ar-st"><span class="ch ch-felt ch-xs">included</span></div></div></div>
        <div class="tx"><span class="tic ok">${ICO("check", "ic-s")}</span><div class="ar-m"><div class="ar-n">转账 · 收款人 0x8f…d7</div><div class="ar-s">0x9a02…ef · 1 小时前</div></div><div class="ar-r"><div class="ar-amt neg">-200.00</div><div class="ar-st"><span class="ch ch-felt ch-xs">included</span></div></div></div>
      </div>
    </div>
  </div>
</section>`;

S["evm-send"] = () => `
<section class="scr" aria-label="EVM 发送">
  <header class="sub"><button class="ib bare" data-back>${ICO("back")}</button><div class="sub-t">发送</div><div class="sub-s"><span class="ch ch-xs">Ethereum</span></div></header>
  <div class="body">
    <div class="fld"><div class="fl">金额 <span class="aux mono">可用 2.4183 · <button data-max="#amt-evm" data-maxval="2.4183">MAX</button></span></div>
      <div class="iw"><input class="inp-amt" id="amt-evm" value="0.25"><span class="tsel"><span class="tk" style="width:18px;height:18px;font-size:10px">Ξ</span>ETH${ICO("chev-d", "ic-xs")}</span></div>
      <div class="fiat">≈ $840.12 · gas price 12 gwei</div>
    </div>
    <div class="fld"><div class="fl">收款地址</div>
      <div class="iw"><input class="mono" style="font-size:11.5px" placeholder="0x…"><span class="in-ic"><button class="ib" data-toast="已粘贴">${ICO("copy", "ic-xs")}</button><button class="ib" data-toast="示意:扫码">${ICO("qr", "ic-xs")}</button></span></div>
    </div>
    <div class="cd">
      <div class="cd-h">交易预览 <span class="more mono">eth_sendTransaction</span></div>
      <div class="lr"><span class="lr-k">from</span><span class="lr-v">0x5919…7527</span></div>
      <div class="lr"><span class="lr-k">to</span><span class="lr-v">0x8f3a…d7e2</span></div>
      <div class="lr"><span class="lr-k">value</span><span class="lr-v">0.25 ETH</span></div>
      <div class="lr"><span class="lr-k">gas limit</span><span class="lr-v">21,000(EIP-155)</span></div>
      <div class="lr"><span class="lr-k">预估手续费</span><span class="lr-v">0.000252 ETH ≈ $0.85</span></div>
      <div class="lr"><span class="lr-k">chainId</span><span class="lr-v">1 <span class="ch ch-felt ch-xs">校验通过</span></span></div>
    </div>
    <div class="bn bn-bad">${ICO("warn")}<div><b>发送后不可撤销</b><p>请核对地址与金额;chainId 不符时交易将被拒绝签名。</p></div></div>
    <button class="btn btn-p btn-lg" data-toast="已签名并广播 · 0x8f3a…c2">确认签名并发送</button>
  </div>
</section>`;

S["evm-history"] = () => `
<section class="scr" aria-label="EVM 交易记录">
  <header class="sub"><button class="ib bare" data-back>${ICO("back")}</button><div class="sub-t">交易记录</div><div class="sub-s"><span class="ch ch-xs">Ethereum</span></div></header>
  <div class="body">
    <div class="row" style="margin-bottom:12px">
      <div class="grow"><b style="font-size:12px;font-weight:600">合并 Explorer 数据</b><div class="ar-s">本地账本 + Etherscan 兼容 txlist</div></div>
      <span class="sw2 on" data-toast="示意:切换数据源"></span>
    </div>
    <div class="seg">
      <button class="on" data-seg="all">全部</button>
      <button data-seg="tx">转账</button>
      <button data-seg="c">合约</button>
    </div>
    <div data-pane="all">
      <div class="cd" style="padding:2px 14px">
        <div class="tx"><span class="tic ok">${ICO("send", "ic-s")}</span><div class="ar-m"><div class="ar-n">发送 · 0.25 ETH</div><div class="ar-s">0x8f3a…c2 · 2 分钟前 · fee $0.85</div></div><div class="ar-r"><div class="ar-amt neg">-0.2500</div><div class="ar-st"><span class="ch ch-felt ch-xs">成功</span></div></div></div>
        <div class="tx"><span class="tic warn">${ICO("clock", "ic-s")}</span><div class="ar-m"><div class="ar-n">发送 · 0.10 ETH</div><div class="ar-s">0x22af…71 · 30 秒前</div></div><div class="ar-r"><div class="ar-amt neg">-0.1000</div><div class="ar-st"><span class="ch ch-amb ch-xs">pending</span></div></div></div>
        <div class="tx"><span class="tic blue">${ICO("recv", "ic-s")}</span><div class="ar-m"><div class="ar-n">接收 · 1.20 ETH</div><div class="ar-s">0x51b7…c8 · 昨天</div></div><div class="ar-r"><div class="ar-amt pos">+1.2000</div><div class="ar-st"><span class="ch ch-felt ch-xs">成功</span></div></div></div>
        <div class="tx"><span class="tic blue">${ICO("file", "ic-s")}</span><div class="ar-m"><div class="ar-n">approve · USDC</div><div class="ar-s">0xd901…34 · 3 天前</div></div><div class="ar-r"><div class="ar-amt dim" style="font-size:11px">合约</div><div class="ar-st"><span class="ch ch-felt ch-xs">成功</span></div></div></div>
        <div class="tx"><span class="tic bad">${ICO("file", "ic-s")}</span><div class="ar-m"><div class="ar-n">swap · 1inch</div><div class="ar-s">0x9a02…ef · 5 天前</div></div><div class="ar-r"><div class="ar-amt" style="color:var(--bad)">Failed</div><div class="ar-st"><span class="ch ch-bad ch-xs">失败</span></div></div></div>
      </div>
      <p class="hint-s" style="text-align:left;margin-top:2px">来源用 chip 区分(本地 / explorer);两者冲突时以链上回执为准,并把差异原样列在详情里,不做静默合并。</p>
    </div>
    <div data-pane="tx" style="display:none">
      <div class="cd" style="padding:2px 14px">
        <div class="tx"><span class="tic ok">${ICO("send", "ic-s")}</span><div class="ar-m"><div class="ar-n">发送 · 0.25 ETH</div><div class="ar-s">0x8f3a…c2 · 2 分钟前</div></div><div class="ar-r"><div class="ar-amt neg">-0.2500</div></div></div>
        <div class="tx"><span class="tic blue">${ICO("recv", "ic-s")}</span><div class="ar-m"><div class="ar-n">接收 · 1.20 ETH</div><div class="ar-s">0x51b7…c8 · 昨天</div></div><div class="ar-r"><div class="ar-amt pos">+1.2000</div></div></div>
      </div>
    </div>
    <div data-pane="c" style="display:none">
      <div class="cd" style="padding:2px 14px">
        <div class="tx"><span class="tic blue">${ICO("file", "ic-s")}</span><div class="ar-m"><div class="ar-n">approve · USDC</div><div class="ar-s">0xd901…34 · 3 天前</div></div><div class="ar-r"><div class="ar-st"><span class="ch ch-felt ch-xs">成功</span></div></div></div>
        <div class="tx"><span class="tic bad">${ICO("file", "ic-s")}</span><div class="ar-m"><div class="ar-n">swap · 1inch</div><div class="ar-s">0x9a02…ef · 5 天前</div></div><div class="ar-r"><div class="ar-st"><span class="ch ch-bad ch-xs">失败</span></div></div></div>
      </div>
    </div>
  </div>
</section>`;

S["evm-manage"] = () => `
<section class="scr" aria-label="EVM 账户管理">
  <header class="sub"><button class="ib bare" data-back>${ICO("back")}</button><div class="sub-t">账户管理</div><div class="sub-s"></div></header>
  <div class="body">
    <div class="cd">
      <div class="row" style="gap:12px"><span class="av" style="width:38px;height:38px;font-size:15px">B</span><div class="grow" style="min-width:0"><div class="ar-n" style="font-size:13px">账户 2 <button class="ib bare" style="width:18px;height:18px" data-toast="示意:重命名">${ICO("pen", "ic-xs")}</button></div><div class="ar-s">0x59195049a3…29f97527</div></div><span class="ch ch-felt ch-xs">已解锁</span></div>
    </div>
    <div class="sec-t">安全</div>
    <div class="cd" style="padding:2px 14px">
      <button class="mi"><span class="mi-ic" style="color:var(--bad);border-color:var(--bad-rl);background:var(--bad-w)">${ICO("eye", "ic-s")}</span><span class="grow"><b>导出私钥</b><span>口令确认后展开 · 30 秒自动收起</span></span>${ICO("chev-r", "ic-s")}</button>
      <button class="mi"><span class="mi-ic">${ICO("key", "ic-s")}</span><span class="grow"><b>修改口令</b><span>三层 keystore 各自重派生(两套 KDF)</span></span>${ICO("chev-r", "ic-s")}</button>
      <button class="mi" data-nav="lock"><span class="mi-ic">${ICO("lock", "ic-s")}</span><span class="grow"><b>锁定</b><span>立即清除内存中的会话</span></span>${ICO("chev-r", "ic-s")}</button>
    </div>
    <div class="sec-t">网络</div>
    <div class="cd" style="padding:2px 14px">
      <button class="mi"><span class="mi-ic">${ICO("swap", "ic-s")}</span><span class="grow"><b>RPC 覆盖</b><span>Ethereum · 自定义 https://…</span></span>${ICO("chev-r", "ic-s")}</button>
      <button class="mi"><span class="mi-ic">${ICO("ext", "ic-s")}</span><span class="grow"><b>Explorer API 覆盖</b><span>Etherscan 兼容 · 已配置</span></span>${ICO("chev-r", "ic-s")}</button>
    </div>
    <div class="sec-t danger">危险区</div>
    <div class="cd" style="padding:2px 14px;border-color:var(--bad-rl)">
      <button class="mi danger" data-open="mdl-del"><span class="mi-ic">${ICO("trash", "ic-s")}</span><span class="grow"><b>删除账户</b><span>需输入口令确认;导出私钥前请先备份</span></span>${ICO("chev-r", "ic-s")}</button>
    </div>
    <div class="foot">本机 keystore(本层):PBKDF2-SHA256 600k + AES-256-GCM · 私钥只在内存会话,落盘仅密文 · 无云端副本</div>
  </div>
  <div class="mdl-bg" id="mdl-del">
    <div class="mdl">
      <h3>删除账户 2?</h3>
      <p>该账户的私钥将从本机 keystore 永久移除。若没有备份,资产无法找回。此操作与其他两层无关。</p>
      <div class="btn-row"><button class="btn btn-g" data-close>取消</button><button class="btn btn-d" data-close data-toast="示意:需口令校验后执行">确认删除</button></div>
    </div>
  </div>
</section>`;

S.proofs = () => `
<section class="scr" aria-label="证明中心">
  <header class="dh">
    <div class="dh-top"><span class="dh-kind">Proofs</span><span class="net"><span class="dot"></span>engine stwo</span><span class="dh-r"><button class="ib bare" data-nav="settings">${ICO("gear", "ic-s")}</button></span></div>
    <div class="dh-main"><span class="seal seal-ok">独立可验</span><div class="grow" style="min-width:0"><div class="acct-n">本机凭证簿</div><div class="acct-a">最近 24 小时 · 5 份结算证明</div></div><span class="dh-r"><button class="ib" data-nav="lock">${ICO("lock", "ic-s")}</button></span></div>
  </header>
  <div class="body">
    <div class="cd">
      <div class="cd-h">凭证分布 <span class="more" data-toast="示意:阶梯说明">阶梯</span></div>
      ${rail({ pending: "done", soft: "done", proven: "done", finalized: "cur" })}
      <div class="lr" style="margin-top:9px"><span class="lr-k">4 份已达 finalized</span><span class="lr-v" style="color:var(--felt)">可提现</span></div>
      <div class="lr"><span class="lr-k">1 份停在 soft</span><span class="lr-v" style="color:var(--amb)">未达 REAL 门槛</span></div>
    </div>
    <div class="sec-t">待复验</div>
    <div class="cd" style="padding:2px 14px">
      <button class="mi" data-nav="zc-portal"><span class="mi-ic" style="color:var(--amb);border-color:var(--amb-rl);background:var(--amb-w)">${ICO("shield", "ic-s")}</span><span class="grow"><b>8♠ 桌 #128 · 结算</b><span>0x3f9e…aa · seen 未 included</span></span>${ICO("chev-r", "ic-s")}</button>
      <button class="mi" data-nav="zc-portal"><span class="mi-ic">${ICO("bolt", "ic-s")}</span><span class="grow"><b>9♣ 桌 #96 · 超期回执</b><span>0x51b7…c8 · 可 ForceInclude</span></span>${ICO("chev-r", "ic-s")}</button>
    </div>
    <div class="sec-t">已复验</div>
    <div class="cd" style="padding:2px 14px">
      <div class="lr"><span class="lr-k">8♠ 桌 #127</span><span class="lr-v"><span class="seal seal-ok" style="font-size:8px;padding:1px 5px">verified</span></span></div>
      <div class="lr"><span class="lr-k">校验耗时</span><span class="lr-v dim">1.72s(本机 stwo)</span></div>
      <div class="lr"><span class="lr-k">payout_root</span><span class="lr-v">0x8c3f…d210</span></div>
    </div>
    <div class="bn bn-info">${ICO("info")}<div><b>验证在本地完成</b><p>证明文件与结算明细由网关拉取,复验在本机 wallet-core 执行;不依赖服务端「已验证」结论。</p></div></div>
    <p class="hint-s" style="text-align:left">阶梯是<b style="color:var(--ink)">凭证</b>状态(锚定在 note 上);回执的 signed → seen → included 是<b style="color:var(--ink)">投递</b>状态。两者在 DS-07 里刻意用了不同笔触。</p>
  </div>
  ${tabsHtml("proofs")}
</section>`;

S.settings = () => `
<section class="scr" aria-label="设置">
  <header class="sub"><button class="ib bare" data-back>${ICO("back")}</button><div class="sub-t">设置</div><div class="sub-s"></div></header>
  <div class="body">
    <div class="sec-t">通用</div>
    <div class="cd" style="padding:2px 14px">
      <button class="mi"><span class="mi-ic">${ICO("clock", "ic-s")}</span><span class="grow"><b>自动锁定</b><span>无操作 15 分钟,或切后台即锁(即 fail-closed)</span></span><span class="ch ch-xs mono">15 min</span></button>
      <div class="mi"><span class="mi-ic">${ICO("eye", "ic-s")}</span><span class="grow"><b>显示测试网</b><span>关闭后隐藏 devnet 资产</span></span><span class="sw2 on" role="switch" aria-checked="true"></span></div>
      <button class="mi"><span class="mi-ic">${ICO("wallet", "ic-s")}</span><span class="grow"><b>货币计价</b><span>USD(仅展示,非托管承诺)</span></span><span class="ch ch-xs mono">USD</span></button>
      <button class="mi" id="mi-ground"><span class="mi-ic">${ICO("book", "ic-s")}</span><span class="grow"><b>外观底面</b><span>纸白账簿 / 夜场账簿</span></span><span class="ch ch-xs mono" id="ground-label">纸白</span></button>
    </div>
    <div class="sec-t">安全与备份</div>
    <div class="cd" style="padding:2px 14px">
      <button class="mi" data-toast="示意:加密导出 .zcbk"><span class="mi-ic">${ICO("dl", "ic-s")}</span><span class="grow"><b>备份导出(.zcbk)</b><span>仅 ZChain 层 REAL/PLAY 双库 · 备份口令独立</span></span>${ICO("chev-r", "ic-s")}</button>
      <button class="mi" data-nav="import"><span class="mi-ic">${ICO("ul", "ic-s")}</span><span class="grow"><b>从备份恢复</b><span>Argon2id 本地解密</span></span>${ICO("chev-r", "ic-s")}</button>
      <button class="mi" data-nav="zc-sessions"><span class="mi-ic">${ICO("key", "ic-s")}</span><span class="grow"><b>授权簿 / 会话密钥</b><span>按 origin 撤销 dapp 授权</span></span>${ICO("chev-r", "ic-s")}</button>
      <button class="mi" data-open="mdl-cap"><span class="mi-ic">${ICO("file", "ic-s")}</span><span class="grow"><b>能力矩阵</b><span>各层能力与红线的如实说明</span></span>${ICO("chev-r", "ic-s")}</button>
    </div>
    <div class="sec-t">关于</div>
    <div class="cd" style="padding:2px 14px">
      <div class="mi"><span class="mi-ic">${ICO("info", "ic-s")}</span><span class="grow"><b>版本</b><span>移动客户端 · DevNet 形态</span></span><span class="ch ch-xs mono">0.1.0</span></div>
      <button class="mi" data-toast="示意:打开文档站"><span class="mi-ic">${ICO("ext", "ic-s")}</span><span class="grow"><b>文档与源码</b><span>docs / website</span></span>${ICO("chev-r", "ic-s")}</button>
    </div>
    <div class="bn bn-bad">${ICO("warn")}<div><b>未通过第三方审计</b><p>「可验证」指密码学与结算证明可被独立复核,不等于已审计;本界面不出现任何审计徽章。</p></div></div>
    <div class="foot">ZChain Wallet · 桌上飞快,结算可证<br>Fast at the table. Verifiable at settlement.<br>Play / DevNet / v1.3</div>
  </div>
  <div class="mdl-bg" id="mdl-cap">
    <div class="mdl">
      <h3>能力矩阵</h3>
      <p style="margin-bottom:6px">逐层能力与红线,按钱包交付面如实列举;不为好看放宽。</p>
      <div class="rsn">${ICO("spade", "ic-s")}<div><b class="mono">ZChain</b> · GAME 域可签可转;REAL 仅展示,提现预览 canSubmit 恒 false</div></div>
      <div class="rsn">${ICO("ether", "ic-s")}<div><b class="mono">EVM</b> · 转账与合约写入可签名广播(EIP-155 + chainId 校验);不签 note spend</div></div>
      <div class="rsn">${ICO("layers", "ic-s")}<div><b class="mono">Starknet</b> · invoke v1 + devnet 水龙头;SNIP-12 授权面已备,链上 admission 未开放</div></div>
      <div class="rsn">${ICO("swap", "ic-s")}<div><b class="mono">网络</b> · mainnet 刻意不注册 → NetworkUnsupported;devnet/testnet 才可选</div></div>
      <div class="rsn">${ICO("key", "ic-s")}<div><b class="mono">边界</b> · 盲签拒绝;私钥 / 助记词 / nullifier 不出边界;网关水位原样展示、不推进</div></div>
      <div class="rsn">${ICO("lock", "ic-s")}<div><b class="mono">会话</b> · 三层共用口令、会话彼此独立;切后台即锁定(fail-closed)</div></div>
      <div class="btn-row" style="margin-top:14px"><button class="btn btn-p" data-close>知道了</button></div>
    </div>
  </div>
</section>`;

/* =============== 屏幕注册表(19 屏) =============== */

const SCREENS = [
  { id: "welcome",     grp: "引导",  name: "欢迎 · 一次创建三层" },
  { id: "success",     grp: "引导",  name: "创建成功 · 解锁口令" },
  { id: "import",      grp: "引导",  name: "导入 / 恢复" },
  { id: "lock",        grp: "引导",  name: "锁定 · 统一解锁" },
  { id: "home",        grp: "账户",  name: "三链总账" },
  { id: "zc-dash",     grp: "账簿",  name: "账簿 · ZChain 层",   acct: "zc" },
  { id: "evm-dash",    grp: "账簿",  name: "账簿 · EVM 层",      acct: "evm" },
  { id: "stk-dash",    grp: "账簿",  name: "账簿 · Starknet 层", acct: "stk" },
  { id: "zc-send",     grp: "ZChain", name: "转账 · 贪心选币" },
  { id: "zc-withdraw", grp: "ZChain", name: "REAL 提现预览 · fail-closed" },
  { id: "zc-confirm",  grp: "ZChain", name: "dapp 签名请求" },
  { id: "zc-sessions", grp: "ZChain", name: "会话密钥 · SNIP-12" },
  { id: "zc-portal",   grp: "ZChain", name: "Proof Portal" },
  { id: "zc-receipts", grp: "ZChain", name: "回执状态机" },
  { id: "evm-send",    grp: "EVM",   name: "发送 · 交易预览" },
  { id: "evm-history", grp: "EVM",   name: "交易记录 · 双边对账" },
  { id: "evm-manage",  grp: "EVM",   name: "账户管理 · 危险区" },
  { id: "proofs",      grp: "证明",  name: "凭证簿 · 新增屏" },
  { id: "settings",    grp: "系统",  name: "设置 · 能力矩阵" },
];
const ACCT_ID = { zc: "zc-dash", evm: "evm-dash", stk: "stk-dash" };

/* =============== 主题(纸白/夜场) =============== */

function setGround(g) {
  document.documentElement.dataset.ground = g;
  try { localStorage.setItem("zc.ground", g); } catch { /* 私密模式忽略 */ }
}

/* =============== 剪贴板 / toast =============== */

async function copyText(t) {
  try {
    if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(t); return true; }
  } catch { /* 落到下面兜底 */ }
  try {
    const ta = document.createElement("textarea");
    ta.value = t; ta.style.cssText = "position:fixed;opacity:0";
    document.body.appendChild(ta); ta.select();
    const ok = document.execCommand("copy"); ta.remove();
    return ok;
  } catch { return false; }
}

function toast(root, msg) {
  if (!root) return;
  let t = root.querySelector(":scope > .tst");
  if (!t) {
    t = document.createElement("div");
    t.className = "tst";
    root.appendChild(t);
  }
  t.innerHTML = `${ICO("check", "ic-s")}<span class="grow"></span>`;
  t.lastChild.textContent = msg;
  t.classList.add("on");
  clearTimeout(t.__h);
  t.__h = setTimeout(() => t.classList.remove("on"), 1900);
}

/* =============== 路由(导航栈 + 屏幕缓存) =============== */

const appEl = document.getElementById("app");
let navStack = [];          // [{id, scrEl, scroll}]
let cur = null;             // 当前屏元素
let lastAcct = "zc-dash";

function mount(id) {
  const meta = SCREENS.find((s) => s.id === id);
  if (!meta) return null;
  const seg = meta.acct || null;
  const fn = S[id] || S.acct; // 账簿三屏(zc/evm/stk-dash)共用一份 S.acct 模板,只换数据面
  const frag = document.createElement("div");
  frag.innerHTML = fn(seg);
  return frag.firstElementChild;
}

function show(id, opts) {
  opts = opts || {};
  const target = id === "acct" ? lastAcct : id;
  if (!SCREENS.find((s) => s.id === target)) return;
  const keep = !opts.fresh;
  if (cur && opts.push !== false) {
    const body = cur.querySelector(".body");
    navStack.push({ id: cur.dataset.sid, el: cur, scroll: body ? body.scrollTop : 0 });
  }
  if (cur) { cur.classList.remove("on"); cur.remove(); }
  let el = keep && show.__cache && show.__cache[target];
  if (!el) { /* 主题走 :root CSS 变量,缓存节点跨底色通用 */
    el = mount(target);
    el.dataset.sid = target;
    (show.__cache = show.__cache || {})[target] = el;
  }
  el.dataset.ground = document.documentElement.dataset.ground;
  appEl.appendChild(el);
  el.classList.add("on");
  cur = el;
  const seg = meta_seg(target);
  if (seg) applyChain(el, seg);
}

function meta_seg(id) {
  const m = SCREENS.find((s) => s.id === id);
  return m && m.acct ? m.acct : null;
}

function back() {
  const prev = navStack.pop();
  if (!prev || !prev.el) return;
  if (cur) { show.__cache[cur.dataset.sid] = cur; cur.classList.remove("on"); cur.remove(); }
  const el = prev.el;
  el.dataset.ground = document.documentElement.dataset.ground;
  appEl.appendChild(el);
  el.classList.add("on");
  cur = el;
  const body = el.querySelector(".body");
  if (body) body.scrollTop = prev.scroll || 0;
}

function switchTab(id) {
  navStack = [];
  if (id === "acct") show(lastAcct, { push: false });
  else show(id, { push: false });
}

function applyChain(el, seg) {
  lastAcct = ACCT_ID[seg];
  el.querySelectorAll(".csw button").forEach((b) => b.classList.toggle("on", b.dataset.cs === seg));
  el.querySelectorAll("[data-csp]").forEach((p) => (p.style.display = p.dataset.csp === seg ? "" : "none"));
  const c = DEMO.chains[seg];
  const k = el.querySelector("[data-kind]"); if (k) k.textContent = c.kind;
  const n = el.querySelector("[data-net]"); if (n) n.innerHTML = `<span class="dot"></span>${c.net}`;
  const a = el.querySelector("[data-addr]"); if (a) a.textContent = c.addr;
}

/* =============== 事件委托 =============== */

document.addEventListener("click", (e) => {
  const t = e.target;

  const eye = t.closest("[data-eye]");
  if (eye) {
    const inp = document.querySelector(eye.dataset.eye);
    if (inp) inp.type = inp.type === "password" ? "text" : "password";
    return;
  }

  const cp = t.closest("[data-copy]");
  if (cp) { copyText(cp.dataset.copy); if (cp.dataset.toast) toast(rootOf(cp), cp.dataset.toast); return; }

  const close = t.closest("[data-close]");
  if (close) {
    const o = close.closest(".ovl"), m = close.closest(".mdl-bg");
    if (o) o.classList.remove("on");
    if (m) m.classList.remove("on");
    return;
  }

  const open = t.closest("[data-open]");
  if (open) {
    const ov = cur && cur.querySelector("#" + CSS.escape(open.dataset.open));
    if (ov) ov.classList.add("on");
    return;
  }

  const mx = t.closest("[data-max]");
  if (mx) {
    const inp = cur && cur.querySelector(mx.dataset.max);
    if (inp) inp.value = mx.dataset.maxval;
    toast(rootOf(mx), "已填入最大可用");
    return;
  }

  const cs = t.closest("[data-cs]");
  if (cs) { applyChain(rootOf(cs), cs.dataset.cs); return; }

  const tab = t.closest("[data-tab]");
  if (tab) {
    if (tab.dataset.acct) lastAcct = ACCT_ID[tab.dataset.acct];
    switchTab(tab.dataset.tab);
    return;
  }

  const nav = t.closest("[data-nav]");
  if (nav) { show(nav.dataset.nav); if (nav.dataset.toast) toast(rootOf(nav), nav.dataset.toast); return; }

  const bk = t.closest("[data-back]");
  if (bk) { back(); return; }

  const segb = t.closest("[data-seg]");
  if (segb) {
    const el = rootOf(segb), bar = segb.parentElement, key = segb.dataset.seg;
    bar.querySelectorAll("[data-seg]").forEach((b) => b.classList.toggle("on", b === segb));
    el.querySelectorAll("[data-pane]").forEach((p) => (p.style.display = p.dataset.pane === key ? "" : "none"));
    return;
  }

  const chk = t.closest("[data-check]");
  if (chk) {
    const el = rootOf(chk), box = chk.querySelector(".cb");
    box.classList.toggle("on", !box.classList.contains("on"));
    const key = chk.getAttribute("data-check");
    const g = key && key !== "-" ? el.querySelector(key) : null;
    if (g) {
      const any = Array.from(el.querySelectorAll(`[data-check="${key}"]`))
        .some((c) => c.querySelector(".cb").classList.contains("on"));
      g.disabled = !any;
    }
    return;
  }

  const sw = t.closest(".sw2");
  if (sw) {
    sw.classList.toggle("on");
    sw.setAttribute("aria-checked", sw.classList.contains("on"));
    if (sw.dataset.toast) toast(rootOf(sw), sw.dataset.toast);
    return;
  }

  const gmi = t.closest("#mi-ground");
  if (gmi) {
    const next = document.documentElement.dataset.ground === "night" ? "paper" : "night";
    setGround(next);
    const label = gmi.querySelector("#ground-label");
    if (label) label.textContent = next === "night" ? "夜场" : "纸白";
    // 重建当前屏(缓存按 ground 失效)
    const sid = cur ? cur.dataset.sid : "home";
    if (show.__cache) delete show.__cache[sid];
    show(sid, { fresh: true });
    return;
  }

  const ts = t.closest("[data-toast]");
  if (ts) toast(rootOf(ts), ts.dataset.toast);
});

function rootOf(el) { return el.closest(".scr"); }

/* =============== 出图模式(供 design/figma 批量渲染) =============== *
 * #shot=<id>&g=paper|night&full=1
 *   - g:设置底色;full=1:把画板撑到内容高度(长屏整屏出图)
 * __exportStandalone():导出独立 HTML(CSS/图标精灵内联,固定尺寸画板)   */

function shotBoot() {
  const q = new URLSearchParams(location.hash.slice(1));
  if (!q.get("shot")) return false;
  const id = q.get("s") || q.get("shot") || "home";
  setGround(q.get("g") === "night" ? "night" : "paper");
  show(id, { fresh: true });
  if (q.get("full")) {
    requestAnimationFrame(() => {
      try {
        const scr = cur, body = scr.querySelector(".body");
        if (!body) { scr.dataset.fullH = String(scr.offsetHeight || 852); return; } // 封面屏:内容自然撑满 dvh
        const h = scr.offsetHeight - body.clientHeight + body.scrollHeight;
        scr.style.height = h + "px";
        scr.style.flex = "none";
        appEl.style.height = "auto";
        document.body.style.height = "auto";
        body.style.overflow = "hidden";
        scr.dataset.fullH = String(h);
      } catch (e) { console.error("full-mode measure failed", e); }
    });
  }
  return true;
}

window.__exportStandalone = function () {
  if (!cur) return "";
  const ground = document.documentElement.dataset.ground;
  const fullH = cur.dataset.fullH ? `height:${cur.dataset.fullH}px;` : "";
  const css = Array.from(document.querySelectorAll("style")).map((s) => s.textContent).join("\n");
  const sprite = document.querySelector("svg[aria-hidden='true']")?.outerHTML || "";
  return `<!DOCTYPE html>
<html lang="zh-CN" data-ground="${ground}">
<head><meta charset="UTF-8"><title>ZChain Wallet · ${cur.dataset.sid}</title>
<style>
html,body{margin:0;padding:0;background:var(--pg)}
#board{width:393px;${fullH}position:relative;overflow:hidden;margin:0}
${css}
</style></head>
<body>
${sprite}
<div id="board">${cur.outerHTML}</div>
</body></html>`;
};

/* =============== 启动 =============== */

(function boot() {
  try { setGround(localStorage.getItem("zc.ground") || "paper"); } catch { setGround("paper"); }
  if (shotBoot()) return;
  show("welcome", { fresh: true });
})();
