const PROXIES_KEY = 'agent-test-proxies-v1';
const CRYPTO_KEY = 'agent-test-crypto-key-v1';
const MAX_CHAIN = 8;

/** @type {CryptoKey | null} */
let aesKey = null;
/** @type {Array<StoredProxy>} */
let entries = [];

/**
 * @typedef {Object} StoredProxy
 * @property {string} id
 * @property {string} protocol
 * @property {string} host
 * @property {number} port
 * @property {string} username
 * @property {{ iv: string, ct: string }} passwordEnc
 * @property {string[]} chainIds
 * @property {string} [note]
 * @property {number} updatedAt
 */

function b64(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin);
}

function fromB64(text) {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

async function loadAesKey() {
  let raw = localStorage.getItem(CRYPTO_KEY);
  if (!raw) {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    raw = b64(bytes);
    localStorage.setItem(CRYPTO_KEY, raw);
  }
  return crypto.subtle.importKey('raw', fromB64(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptPassword(password) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(password || ''),
  );
  return { iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}

async function decryptPassword(passwordEnc) {
  if (!passwordEnc || !passwordEnc.iv || !passwordEnc.ct) return '';
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(passwordEnc.iv) },
    aesKey,
    fromB64(passwordEnc.ct),
  );
  return new TextDecoder().decode(plain);
}

function dedupeKey(proxy) {
  return `${proxy.protocol}|${proxy.host}|${proxy.port}|${proxy.username || ''}`;
}

function loadRawEntries() {
  try {
    const raw = localStorage.getItem(PROXIES_KEY);
    if (!raw) return [];
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function saveRawEntries() {
  localStorage.setItem(PROXIES_KEY, JSON.stringify(entries));
}

function entryById(id) {
  return entries.find((item) => item.id === id) || null;
}

function listEntries() {
  return entries.slice();
}

function mapById() {
  return new Map(entries.map((item) => [item.id, item]));
}

/**
 * @param {{ protocol: string, host: string, port: number, username?: string, password?: string, note?: string, chainIds?: string[] }} proxy
 */
async function upsertProxy(proxy) {
  const normalized = {
    protocol: String(proxy.protocol || 'socks5').toLowerCase(),
    host: String(proxy.host || '').trim(),
    port: Number(proxy.port),
    username: proxy.username == null ? '' : String(proxy.username),
    password: proxy.password == null ? '' : String(proxy.password),
  };
  const key = dedupeKey(normalized);
  const existing = entries.find((item) => dedupeKey(item) === key);
  const passwordEnc = await encryptPassword(normalized.password);
  const now = Date.now();
  if (existing) {
    existing.passwordEnc = passwordEnc;
    existing.updatedAt = now;
    if (proxy.note != null) existing.note = String(proxy.note);
    saveRawEntries();
    return existing;
  }
  const row = {
    id: crypto.randomUUID(),
    protocol: normalized.protocol,
    host: normalized.host,
    port: normalized.port,
    username: normalized.username,
    passwordEnc,
    chainIds: Array.isArray(proxy.chainIds) ? proxy.chainIds.slice() : [],
    note: proxy.note ? String(proxy.note) : '',
    updatedAt: now,
  };
  entries.push(row);
  saveRawEntries();
  return row;
}

function removeByIds(ids) {
  const set = new Set(ids);
  entries = entries.filter((item) => !set.has(item.id));
  entries.forEach((item) => {
    item.chainIds = (item.chainIds || []).filter((cid) => !set.has(cid));
  });
  saveRawEntries();
}

function setChainIds(id, chainIds) {
  const row = entryById(id);
  if (!row) return { error: '代理不存在' };
  const cleaned = chainIds.filter((cid) => cid !== id);
  const err = validateChainIds(id, cleaned);
  if (err) return { error: err };
  row.chainIds = cleaned;
  row.updatedAt = Date.now();
  saveRawEntries();
  return { ok: true };
}

function validateChainIds(selfId, chainIds) {
  if (!Array.isArray(chainIds)) return '链式配置无效';
  if (chainIds.length + 1 > MAX_CHAIN) return `链式代理最多 ${MAX_CHAIN} 跳（含当前代理）`;
  const byId = mapById();
  for (const cid of chainIds) {
    if (!byId.has(cid)) return '链式中包含不存在的代理';
    if (cid === selfId) return '不能将自身设为上游';
  }
  if (hasCycle(selfId, chainIds, byId)) return '链式配置会形成环，请调整顺序';
  return '';
}

function hasCycle(selfId, chainIds, byId) {
  const visited = new Set([selfId]);
  function walk(id) {
    if (visited.has(id)) return true;
    visited.add(id);
    const row = byId.get(id);
    if (!row) return false;
    for (const cid of row.chainIds || []) {
      if (walk(cid)) return true;
    }
    return false;
  }
  for (const cid of chainIds) {
    if (walk(cid)) return true;
  }
  return false;
}

async function entryToProxy(row) {
  return {
    protocol: row.protocol,
    host: row.host,
    port: row.port,
    username: row.username,
    password: await decryptPassword(row.passwordEnc),
  };
}

async function resolveChainForEntry(row) {
  const byId = mapById();
  const upstream = [];
  for (const cid of row.chainIds || []) {
    const hop = byId.get(cid);
    if (!hop) continue;
    upstream.push(await entryToProxy(hop));
  }
  const self = await entryToProxy(row);
  return [...upstream, self];
}

function chainSummary(row, byId) {
  const ids = row.chainIds || [];
  if (!ids.length) return '—';
  const labels = ids.map((cid) => {
    const hop = byId.get(cid);
    if (!hop) return '?';
    return `${hop.host}:${hop.port}`;
  });
  return labels.join(' → ');
}

async function initStore() {
  aesKey = await loadAesKey();
  entries = loadRawEntries().map((item) => ({
    id: item.id || crypto.randomUUID(),
    protocol: item.protocol || 'socks5',
    host: item.host || '',
    port: Number(item.port) || 0,
    username: item.username || '',
    passwordEnc: item.passwordEnc || { iv: '', ct: '' },
    chainIds: Array.isArray(item.chainIds) ? item.chainIds : [],
    note: item.note || '',
    updatedAt: item.updatedAt || 0,
  }));
  saveRawEntries();
}

window.ProxyStore = {
  MAX_CHAIN,
  initStore,
  listEntries,
  entryById,
  mapById,
  upsertProxy,
  removeByIds,
  setChainIds,
  validateChainIds,
  decryptPassword,
  entryToProxy,
  resolveChainForEntry,
  chainSummary,
  dedupeKey,
};
