const $ = (id) => document.getElementById(id);

const urlInput = $('urlInput');
const resultList = $('resultList');
const proxyTableBody = $('proxyTableBody');
const chainDialog = $('chainDialog');

let controller = null;
let directIp = '';
/** @type {Set<string>} */
let vaultSelection = new Set();
let chainEditId = null;
/** @type {string[]} */
let chainPickOrder = [];

function linesOf(text) {
  return text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && line.charAt(0) !== '#');
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch (err) {
    return value;
  }
}

function parseToForm(line) {
  const text = String(line || '').trim();
  if (!text) return null;
  let matched = /^(socks5|socks4|https?):\/\/([^:/\s]+):(\d+):([^:]*):(.*)$/i.exec(text);
  if (matched) {
    return {
      protocol: matched[1].toLowerCase(),
      host: matched[2],
      port: matched[3],
      username: matched[4],
      password: matched[5],
    };
  }
  matched = /^(socks5|socks4|https?):\/\/(?:([^:@\s]*):([^@\s]*)@)?([^:/\s]+):(\d+)$/i.exec(text);
  if (matched) {
    return {
      protocol: matched[1].toLowerCase(),
      host: matched[4],
      port: matched[5],
      username: safeDecode(matched[2] || ''),
      password: safeDecode(matched[3] || ''),
    };
  }
  matched = /^([^:/\s]+):(\d+)(?::([^:]*):(.*))?$/.exec(text);
  if (matched) {
    return {
      protocol: 'socks5',
      host: matched[1],
      port: matched[2],
      username: matched[3] || '',
      password: matched[4] || '',
    };
  }
  return null;
}

function maskProxy(proxy) {
  if (proxy.username || proxy.password) {
    return proxy.protocol + '://' + proxy.host + ':' + proxy.port + ':' + proxy.username + ':***';
  }
  return proxy.protocol + '://' + proxy.host + ':' + proxy.port;
}

function maskLine(line) {
  const parsed = parseToForm(line);
  if (!parsed) return line.length > 80 ? line.slice(0, 80) + '…' : line;
  return maskProxy(parsed);
}

function readForm() {
  const protocol = $('protocol').value;
  const host = $('host').value.trim();
  const port = Number($('port').value.trim());
  const username = $('username').value;
  const password = $('password').value;
  if (!host) return { error: '请填写主机' };
  if (/[\r\n]/.test(username) || /[\r\n]/.test(password)) return { error: '账号和密码不能包含换行' };
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { error: '端口应为 1 到 65535' };
  return { proxy: { protocol, host, port, username, password } };
}

function formToLine(proxy) {
  if (proxy.username || proxy.password) {
    return proxy.protocol + '://' + proxy.host + ':' + proxy.port + ':' + proxy.username + ':' + proxy.password;
  }
  return proxy.protocol + '://' + proxy.host + ':' + proxy.port;
}

function setMessage(text) {
  $('message').textContent = text || '';
}

function setBusy(busy) {
  $('checkUrls').disabled = busy;
  $('checkForm').disabled = busy;
  $('vaultCheckSelected').disabled = busy;
  $('vaultCheckAll').disabled = busy;
  $('stopBtn').disabled = !busy;
}

function updateCount() {
  const count = linesOf(urlInput.value).length;
  $('count').textContent = count ? '已识别 ' + count + ' 条' : '每行一个代理';
}

function locationText(data) {
  const country = data.country
    ? (data.countryCode ? data.country + ' (' + data.countryCode + ')' : data.country)
    : '';
  const place = [country, data.region, data.city].filter(Boolean).join(' / ');
  if (data.zip && place) return place + ' ' + data.zip;
  return place;
}

function updateSummary() {
  const nodes = Array.from(resultList.querySelectorAll('.result'));
  if (!nodes.length) {
    $('summary').textContent = '还没有检测';
    return;
  }
  const count = (name) => nodes.filter((node) => node.classList.contains(name)).length;
  $('summary').textContent = '可用 ' + count('ok') + ' · 异常 ' + count('warn') + ' · 失败 ' + count('fail') + ' · 进行中 ' + count('pending');
}

function addFact(dl, label, value) {
  if (!value) return;
  const wrap = document.createElement('div');
  const dt = document.createElement('dt');
  const dd = document.createElement('dd');
  dt.textContent = label;
  if (typeof value === 'string') dd.textContent = value;
  else dd.append(value);
  wrap.append(dt, dd);
  dl.append(wrap);
}

function ipNode(data) {
  const span = document.createElement('span');
  span.textContent = data.ip || '';
  if (directIp && data.ip === directIp) {
    const mark = document.createElement('em');
    mark.textContent = '与本机相同';
    span.append(mark);
  }
  return span;
}

function renderResult(node, data) {
  node._data = data;
  const status = data.status || 'fail';
  node.className = 'result ' + status;
  node.replaceChildren();

  const head = document.createElement('div');
  head.className = 'result-head';
  const badge = document.createElement('span');
  badge.className = 'badge';
  badge.textContent = status === 'ok' ? '可用' : status === 'warn' ? '异常' : status === 'pending' ? '检测中' : '失败';
  const title = document.createElement('strong');
  title.textContent = data.display || '代理';
  head.append(badge, title);
  if (data.totalMs != null && status !== 'pending') {
    const time = document.createElement('span');
    time.className = 'time';
    const connect = data.connectMs != null ? '连接 ' + data.connectMs + ' ms · ' : '';
    time.textContent = connect + '总计 ' + data.totalMs + ' ms';
    head.append(time);
  }
  node.append(head);

  if (status === 'pending') return;
  if (data.error) {
    const error = document.createElement('p');
    error.className = 'error';
    error.textContent = data.error;
    node.append(error);
  }
  if (!data.ip && !data.country && !data.isp) return;

  const dl = document.createElement('dl');
  addFact(dl, '出口 IP', data.ip ? ipNode(data) : '');
  addFact(dl, '位置', locationText(data));
  addFact(dl, '运营商', data.isp || '');
  if (data.org && data.org !== data.isp) addFact(dl, '组织', data.org);
  addFact(dl, 'ASN', data.as || '');
  addFact(dl, '时区', data.timezone || '');
  if (typeof data.lat === 'number' && typeof data.lon === 'number') {
    addFact(dl, '坐标', data.lat.toFixed(4) + ', ' + data.lon.toFixed(4));
  }
  addFact(dl, '查询来源', data.querySource || '');
  node.append(dl);
}

function clearResults() {
  resultList.replaceChildren();
  const empty = document.createElement('p');
  empty.className = 'empty';
  empty.id = 'empty';
  empty.textContent = '开始检测后，结果会显示在此处。';
  resultList.append(empty);
  updateSummary();
}

async function postCheck(payload, signal) {
  const res = await fetch('/api/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    throw new Error('服务器返回了无法解析的结果');
  }
  if (!res.ok && (!data || !data.error)) throw new Error('请求失败');
  return data;
}

async function displayForChain(chain) {
  if (chain.length <= 1) return maskProxy(chain[0]);
  return chain.map(maskProxy).join(' → ');
}

async function buildCheckItemFromEntry(row) {
  const chain = await ProxyStore.resolveChainForEntry(row);
  return {
    display: await displayForChain(chain),
    payload: { chain },
    entryId: row.id,
  };
}

async function upsertParsed(parsed) {
  if (!parsed) return null;
  return ProxyStore.upsertProxy({
    protocol: parsed.protocol,
    host: parsed.host,
    port: Number(parsed.port),
    username: parsed.username,
    password: parsed.password,
  });
}

async function upsertFromLine(line) {
  return upsertParsed(parseToForm(line));
}

async function runChecks(items) {
  if (controller) controller.abort();
  controller = new AbortController();
  const signal = controller.signal;
  setBusy(true);
  setMessage('');
  resultList.replaceChildren();

  const nodes = items.map((item) => {
    const node = document.createElement('article');
    renderResult(node, { status: 'pending', display: item.display });
    resultList.append(node);
    return node;
  });
  updateSummary();

  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      if (signal.aborted) return;
      const index = cursor;
      cursor += 1;
      const item = items[index];
      const node = nodes[index];
      if (signal.aborted) {
        renderResult(node, { status: 'fail', display: item.display, error: '已停止' });
        updateSummary();
        return;
      }
      try {
        const data = await postCheck(item.payload, signal);
        if (!data.display) data.display = item.display;
        renderResult(node, data);
      } catch (err) {
        const stopped = err.name === 'AbortError' || signal.aborted;
        renderResult(node, {
          status: 'fail',
          display: item.display,
          error: stopped ? '已停止' : (err.message || '请求失败'),
        });
      }
      updateSummary();
    }
  }

  const workers = Math.min(4, items.length);
  await Promise.all(Array.from({ length: workers }, () => worker()));
  if (signal.aborted) {
    nodes.forEach((node, index) => {
      if (node.classList.contains('pending')) {
        renderResult(node, { status: 'fail', display: items[index].display, error: '已停止' });
      }
    });
    updateSummary();
  }
  if (controller && controller.signal === signal) {
    controller = null;
    setBusy(false);
  }
}

function currentLine() {
  const value = urlInput.value;
  const start = urlInput.selectionStart || 0;
  const end = urlInput.selectionEnd || 0;
  if (end > start) return value.slice(start, end).split(/\r?\n/)[0];
  const lineStart = value.lastIndexOf('\n', start - 1) + 1;
  const nextBreak = value.indexOf('\n', start);
  return value.slice(lineStart, nextBreak === -1 ? value.length : nextBreak);
}

async function loadDirect() {
  const node = $('direct');
  node.textContent = '正在查询本机出口…';
  try {
    const res = await fetch('/api/direct');
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || '查询失败');
    directIp = data.ip || '';
    const place = locationText(data);
    node.textContent = '本机出口 ' + data.ip + (place ? ' · ' + place : '') + (data.isp ? ' · ' + data.isp : '');
    resultList.querySelectorAll('.result').forEach((item) => {
      if (item._data && item._data.status !== 'pending') renderResult(item, item._data);
    });
  } catch (err) {
    node.textContent = '本机出口查询失败：' + (err.message || '网络错误');
  }
}

function updateVaultSelectionUi() {
  const n = vaultSelection.size;
  $('vaultSelected').textContent = n ? '已选 ' + n + ' 条' : '未选择';
  const rows = ProxyStore.listEntries();
  const head = $('vaultHeadCheck');
  if (!rows.length) {
    head.checked = false;
    head.indeterminate = false;
    return;
  }
  head.checked = n === rows.length;
  head.indeterminate = n > 0 && n < rows.length;
}

function renderProxyTable() {
  const rows = ProxyStore.listEntries();
  const byId = ProxyStore.mapById();
  $('vaultCount').textContent = rows.length ? rows.length + ' 条' : '0 条';
  proxyTableBody.replaceChildren();
  if (!rows.length) {
    const tr = document.createElement('tr');
    tr.className = 'empty-row';
    const td = document.createElement('td');
    td.colSpan = 6;
    td.textContent = '还没有保存的代理。检测或追加后会自动加入列表。';
    tr.append(td);
    proxyTableBody.append(tr);
    vaultSelection.clear();
    updateVaultSelectionUi();
    return;
  }
  const validIds = new Set(rows.map((r) => r.id));
  vaultSelection = new Set([...vaultSelection].filter((id) => validIds.has(id)));

  rows.forEach((row) => {
    const tr = document.createElement('tr');
    tr.dataset.id = row.id;

    const tdCheck = document.createElement('td');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = vaultSelection.has(row.id);
    cb.addEventListener('change', () => {
      if (cb.checked) vaultSelection.add(row.id);
      else vaultSelection.delete(row.id);
      updateVaultSelectionUi();
    });
    tdCheck.append(cb);

    const tdProto = document.createElement('td');
    tdProto.textContent = row.protocol;

    const tdHost = document.createElement('td');
    tdHost.className = 'mono';
    tdHost.textContent = row.host + ':' + row.port;

    const tdUser = document.createElement('td');
    tdUser.textContent = row.username || '—';

    const tdChain = document.createElement('td');
    tdChain.className = 'chain-cell';
    tdChain.textContent = ProxyStore.chainSummary(row, byId);
    tdChain.title = tdChain.textContent;

    const tdAct = document.createElement('td');
    tdAct.className = 'col-actions';
    const actions = document.createElement('div');
    actions.className = 'row-actions';

    const btnCheck = document.createElement('button');
    btnCheck.type = 'button';
    btnCheck.className = 'primary';
    btnCheck.textContent = '检测';
    btnCheck.addEventListener('click', () => checkVaultEntries([row.id]));

    const btnChain = document.createElement('button');
    btnChain.type = 'button';
    btnChain.textContent = '链式';
    btnChain.addEventListener('click', () => openChainDialog(row.id));

    const btnFill = document.createElement('button');
    btnFill.type = 'button';
    btnFill.textContent = '填入表单';
    btnFill.addEventListener('click', () => fillFormFromEntry(row.id));

    const btnDel = document.createElement('button');
    btnDel.type = 'button';
    btnDel.textContent = '删除';
    btnDel.addEventListener('click', () => {
      ProxyStore.removeByIds([row.id]);
      vaultSelection.delete(row.id);
      renderProxyTable();
    });

    actions.append(btnCheck, btnChain, btnFill, btnDel);
    tdAct.append(actions);
    tr.append(tdCheck, tdProto, tdHost, tdUser, tdChain, tdAct);
    proxyTableBody.append(tr);
  });
  updateVaultSelectionUi();
}

async function fillFormFromEntry(id) {
  const row = ProxyStore.entryById(id);
  if (!row) return;
  const proxy = await ProxyStore.entryToProxy(row);
  $('protocol').value = proxy.protocol;
  $('host').value = proxy.host;
  $('port').value = String(proxy.port);
  $('username').value = proxy.username;
  $('password').value = proxy.password;
  setMessage('已从列表填入表单');
}

function openChainDialog(id) {
  const row = ProxyStore.entryById(id);
  if (!row) return;
  chainEditId = id;
  chainPickOrder = (row.chainIds || []).slice();
  $('chainTarget').textContent = maskProxy({
    protocol: row.protocol,
    host: row.host,
    port: row.port,
    username: row.username,
    password: '',
  }) + '（当前出口）';
  renderChainOptions();
  chainDialog.showModal();
}

function renderChainOptions() {
  const box = $('chainOptions');
  box.replaceChildren();
  const selfId = chainEditId;
  const rows = ProxyStore.listEntries().filter((r) => r.id !== selfId);
  if (!rows.length) {
    const p = document.createElement('p');
    p.className = 'hint';
    p.textContent = '没有其他代理可选，请先保存更多代理。';
    box.append(p);
    return;
  }
  rows.forEach((row) => {
    const label = document.createElement('label');
    label.className = 'chain-option';
    const order = document.createElement('span');
    order.className = 'order';
    const idx = chainPickOrder.indexOf(row.id);
    order.textContent = idx >= 0 ? String(idx + 1) : '';
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = idx >= 0;
    input.addEventListener('change', () => {
      if (input.checked) {
        if (!chainPickOrder.includes(row.id)) chainPickOrder.push(row.id);
      } else {
        chainPickOrder = chainPickOrder.filter((cid) => cid !== row.id);
      }
      renderChainOptions();
    });
    const text = document.createElement('span');
    text.textContent = row.protocol + ' ' + row.host + ':' + row.port + (row.username ? ' · ' + row.username : '');
    label.append(order, input, text);
    box.append(label);
  });
}

async function checkVaultEntries(ids) {
  const idList = ids || ProxyStore.listEntries().map((r) => r.id);
  if (!idList.length) {
    setMessage('请先选择或保存代理');
    return;
  }
  if (idList.length > 100) {
    setMessage('一次最多检测 100 条');
    return;
  }
  const items = [];
  for (const id of idList) {
    const row = ProxyStore.entryById(id);
    if (row) items.push(await buildCheckItemFromEntry(row));
  }
  if (!items.length) return;
  runChecks(items);
}

urlInput.addEventListener('input', updateCount);

urlInput.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
    event.preventDefault();
    $('checkUrls').click();
  }
});

$('checkUrls').addEventListener('click', async () => {
  updateCount();
  const lines = linesOf(urlInput.value);
  if (!lines.length) {
    setMessage('请先粘贴至少一条代理');
    return;
  }
  if (lines.length > 100) {
    setMessage('一次最多检测 100 条');
    return;
  }
  const items = [];
  for (const line of lines) {
    const parsed = parseToForm(line);
    if (parsed) await upsertParsed(parsed);
    items.push({
      display: maskLine(line),
      payload: { url: line },
    });
  }
  renderProxyTable();
  runChecks(items);
});

$('fillForm').addEventListener('click', () => {
  const line = currentLine().trim();
  const parsed = parseToForm(line);
  if (!parsed) {
    setMessage('这一行无法识别，格式应为 socks5://主机:端口:账号:密码');
    return;
  }
  $('protocol').value = parsed.protocol;
  $('host').value = parsed.host;
  $('port').value = parsed.port;
  $('username').value = parsed.username;
  $('password').value = parsed.password;
  setMessage('已把当前行填入表单');
});

$('clearBtn').addEventListener('click', () => {
  if (controller) controller.abort();
  urlInput.value = '';
  updateCount();
  clearResults();
  setMessage('');
  setBusy(false);
});

$('stopBtn').addEventListener('click', () => {
  if (controller) controller.abort();
});

$('togglePass').addEventListener('click', () => {
  const input = $('password');
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  $('togglePass').textContent = show ? '隐藏' : '显示';
});

$('proxyForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = readForm();
  if (form.error) {
    setMessage(form.error);
    return;
  }
  const proxy = form.proxy;
  await ProxyStore.upsertProxy(proxy);
  renderProxyTable();
  runChecks([{
    display: maskLine(formToLine(proxy)),
    payload: { proxy },
  }]);
});

$('appendBtn').addEventListener('click', async () => {
  const form = readForm();
  if (form.error) {
    setMessage(form.error);
    return;
  }
  const proxy = form.proxy;
  await ProxyStore.upsertProxy(proxy);
  renderProxyTable();
  const line = formToLine(proxy);
  const current = urlInput.value.replace(/\s*$/, '');
  urlInput.value = current ? current + '\n' + line : line;
  updateCount();
  setMessage('已追加到 URL 并保存到列表');
});

$('vaultSelectAll').addEventListener('click', () => {
  const rows = ProxyStore.listEntries();
  if (!rows.length) return;
  const allSelected = vaultSelection.size === rows.length;
  vaultSelection = allSelected ? new Set() : new Set(rows.map((r) => r.id));
  renderProxyTable();
});

$('vaultHeadCheck').addEventListener('change', (event) => {
  const rows = ProxyStore.listEntries();
  if (event.target.checked) vaultSelection = new Set(rows.map((r) => r.id));
  else vaultSelection.clear();
  renderProxyTable();
});

$('vaultCheckSelected').addEventListener('click', () => {
  checkVaultEntries([...vaultSelection]);
});

$('vaultCheckAll').addEventListener('click', () => {
  checkVaultEntries(null);
});

$('vaultDeleteSelected').addEventListener('click', () => {
  if (!vaultSelection.size) {
    setMessage('请先选择要删除的代理');
    return;
  }
  ProxyStore.removeByIds([...vaultSelection]);
  vaultSelection.clear();
  renderProxyTable();
  setMessage('已删除选中代理');
});

$('chainForm').addEventListener('submit', (event) => {
  event.preventDefault();
  if (!chainEditId) return;
  const result = ProxyStore.setChainIds(chainEditId, chainPickOrder);
  if (result.error) {
    setMessage(result.error);
    return;
  }
  chainDialog.close();
  renderProxyTable();
  setMessage('链式上游已保存');
});

$('chainCancel').addEventListener('click', () => chainDialog.close());
$('chainClose').addEventListener('click', () => chainDialog.close());

(async function boot() {
  await ProxyStore.initStore();
  renderProxyTable();
  updateCount();
  loadDirect();
})();
