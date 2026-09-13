// ZChain dapp demo（页面 world；验证 window.zchain provider 的 0.2 行为）。
// 0.2：switchNetwork(devnet↔testnet) 走弹窗二次确认（批准后生效）；
// previewHash 仍允许为空（dapp 侧摘要绑定属 dapp SDK，未随 0.2 交付——弹窗
// 结构化预览是唯一确认面）。
// 本文件由 localhost 静态服务直接提供，不属于扩展本身。

const $out = document.getElementById('out');
function show(tag, value, isErr = false) {
  const line = document.createElement('div');
  if (isErr) line.className = 'bad';
  line.textContent = `[${tag}] ${typeof value === 'string' ? value : JSON.stringify(value, null, 2)}`;
  $out.appendChild(line);
}

async function run(tag, fn) {
  try {
    show(tag, await fn());
  } catch (e) {
    show(tag, `${e.code ?? ''} ${e.message}`, true);
  }
}

function makeTransferOperation(notes) {
  const spendable = notes.filter((n) => n.spendable);
  if (spendable.length === 0) throw new Error('钱包没有可用 PLAY note（先在弹窗用水龙头铸造）');
  return {
    kind: 'transfer',
    assetClass: 'PLAY',
    chainId: 'zchain-devnet-1',
    domain: 'zchain',
    abiVersion: 1,
    nonce: Date.now(), // 页面侧单调 nonce（后台强校验单调性）
    expiry: Math.floor(Date.now() / 1000) + 300,
    inputs: spendable.map((n) => n.commitment),
    outputs: [], // 调用点填入当前账户
  };
}

document.getElementById('connect').onclick = () => run('requestAccounts', () => window.zchain.requestAccounts());
document.getElementById('net').onclick = () => run('getNetwork', () => window.zchain.getNetwork());
document.getElementById('caps').onclick = () => run('getCapabilities', () => window.zchain.getCapabilities());
document.getElementById('accounts').onclick = () => run('getAccounts', () => window.zchain.getAccounts());
document.getElementById('notes').onclick = () => run('getNotes', () => window.zchain.getNotes());
document.getElementById('switch').onclick = () => run('switchNetwork', () => window.zchain.switchNetwork('zchain-testnet-1'));
document.getElementById('session').onclick = () => run('authorizeSessionKey', () => window.zchain.authorizeSessionKey({}));

document.getElementById('sign').onclick = () =>
  run('signOperation', async () => {
    const notes = await window.zchain.getNotes();
    const accounts = await window.zchain.getAccounts();
    const op = makeTransferOperation(notes);
    op.outputs = [{ owner: accounts.accounts[0], amount: '1' }];
    // previewHash 允许为空（dapp 侧摘要绑定属 dapp SDK，未交付）；
    // 弹窗预览是唯一确认面。
    const res = await window.zchain.signOperation(op, '');
    return { digest: res.digest, preview: res.preview, operationBorshLen: res.operationBorsh.length / 2 };
  });

document.getElementById('signWrong').onclick = () =>
  run('signOperation(坏 previewHash)', async () => {
    const notes = await window.zchain.getNotes();
    const accounts = await window.zchain.getAccounts();
    const op = makeTransferOperation(notes);
    op.outputs = [{ owner: accounts.accounts[0], amount: '1' }];
    return window.zchain.signOperation(op, 'ff'.repeat(32)); // 必然与钱包重算不符
  });
