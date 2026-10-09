const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');

const PORT = 3002;
const CONNECT_TIMEOUT = 8000;
const IO_TIMEOUT = 12000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const PROTOCOLS = new Set(['socks5', 'socks4', 'http', 'https']);

const LOOKUPS = [
  {
    host: 'ipwho.is',
    port: 443,
    tls: true,
    path: '/',
    directUrl: 'https://ipwho.is/',
    parse: parseIpWho,
  },
  {
    host: 'ipinfo.io',
    port: 443,
    tls: true,
    path: '/json',
    directUrl: 'https://ipinfo.io/json',
    parse: parseIpInfo,
  },
  {
    host: 'ip-api.com',
    port: 80,
    path: '/json?lang=zh-CN&fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query',
    directUrl: 'http://ip-api.com/json?lang=zh-CN&fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query',
    parse: parseIpApi,
  },
  {
    host: 'myip.ipip.net',
    port: 80,
    path: '/',
    directUrl: 'http://myip.ipip.net/',
    parse: parseIpip,
  },
];

const STATIC_FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/store.js': ['store.js', 'text/javascript; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
};

const MAX_CHAIN = 8;

function fail(message, kind) {
  const err = new Error(message);
  err.kind = kind;
  return err;
}

function inputError(message) {
  return fail(message, 'input');
}

function netMessage(err) {
  const code = err && err.code;
  if (code === 'ECONNREFUSED') return '连接被拒绝';
  if (code === 'ETIMEDOUT' || code === 'ESOCKETTIMEDOUT') return '连接超时';
  if (code === 'ENOTFOUND') return '无法解析代理主机';
  if (code === 'ECONNRESET') return '连接被重置';
  if (code === 'EHOSTUNREACH') return '主机不可达';
  if (code === 'ENETUNREACH') return '网络不可达';
  if (code === 'EAI_AGAIN') return '域名解析暂时失败';
  return (err && err.message) || '连接失败';
}

function validHost(host) {
  if (/^[a-zA-Z0-9.-]+$/.test(host)) return true;
  return /^[0-9a-fA-F:]+$/.test(host) && host.includes(':');
}

function normalizeProxy(input) {
  const protocol = String(input.protocol || '').toLowerCase();
  const host = String(input.host || '').trim();
  const port = Number(input.port);
  const username = input.username == null ? '' : String(input.username);
  const password = input.password == null ? '' : String(input.password);
  if (!PROTOCOLS.has(protocol)) throw inputError('不支持的协议，请使用 socks5、socks4、http 或 https');
  if (!validHost(host)) throw inputError('主机地址无效');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw inputError('端口无效');
  if (/[\r\n]/.test(username) || /[\r\n]/.test(password)) {
    throw inputError('账号和密码不能包含换行');
  }
  if (Buffer.byteLength(username) > 255 || Buffer.byteLength(password) > 255) {
    throw inputError('账号或密码超过 255 字节');
  }
  return { protocol, host, port, username, password };
}

function maskProxy(proxy) {
  const auth = proxy.username || proxy.password ? `:${proxy.username}:***` : '';
  return `${proxy.protocol}://${proxy.host}:${proxy.port}${auth}`;
}

function parseProxyLine(line) {
  const raw = String(line || '').trim();
  if (!raw || raw.startsWith('#')) throw inputError('代理 URL 为空');

  const custom = /^(socks5|socks4|https?):\/\/([^:/\s]+):(\d+):([^:]*):(.*)$/i.exec(raw);
  const standard = /^(socks5|socks4|https?):\/\/(?:([^:@\s]*):([^@\s]*)@)?([^:/\s]+):(\d+)$/i.exec(raw);
  const bare = /^([^:/\s]+):(\d+)(?::([^:]*):(.*))?$/.exec(raw);

  let parsed = null;
  if (custom) {
    parsed = {
      protocol: custom[1],
      host: custom[2],
      port: Number(custom[3]),
      username: custom[4],
      password: custom[5],
    };
  } else if (standard) {
    parsed = {
      protocol: standard[1],
      host: standard[4],
      port: Number(standard[5]),
      username: safeDecode(standard[2] || ''),
      password: safeDecode(standard[3] || ''),
    };
  } else if (bare) {
    parsed = {
      protocol: 'socks5',
      host: bare[1],
      port: Number(bare[2]),
      username: bare[3] || '',
      password: bare[4] || '',
    };
  }
  if (!parsed) throw inputError('格式应为 socks5://主机:端口:账号:密码');
  return normalizeProxy(parsed);
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function proxyFromBody(body) {
  if (body && Array.isArray(body.chain) && body.chain.length) {
    if (body.chain.length > MAX_CHAIN) throw inputError(`链式代理最多 ${MAX_CHAIN} 跳`);
    return body.chain.map((item) => normalizeProxy(item));
  }
  if (body && typeof body.url === 'string') return [parseProxyLine(body.url)];
  if (body && body.proxy && typeof body.proxy === 'object') return [normalizeProxy(body.proxy)];
  throw inputError('请提供代理 URL、表单或 chain');
}

class ByteStream {
  constructor(socket) {
    this.socket = socket;
    this.buf = Buffer.alloc(0);
    this.ended = false;
    this.err = null;
    this.waiters = [];
    this.onData = (chunk) => {
      this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
      this.flush();
    };
    this.onEnd = () => {
      this.ended = true;
      this.flush();
    };
    this.onError = (err) => {
      this.err = err;
      this.flush();
    };
    socket.on('data', this.onData);
    socket.on('end', this.onEnd);
    socket.on('error', this.onError);
  }

  detach() {
    this.socket.off('data', this.onData);
    this.socket.off('end', this.onEnd);
    this.socket.off('error', this.onError);
  }

  flush() {
    const list = this.waiters.slice();
    for (const waiter of list) waiter();
  }

  waitFor(pred, timeoutMs, timeoutMessage, signal, kind = 'proxy') {
    return new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => finish(fail(timeoutMessage, kind)), timeoutMs);
      const onAbort = () => finish(fail('已停止', 'proxy'));
      if (signal) signal.addEventListener('abort', onAbort);
      const finish = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (signal) signal.removeEventListener('abort', onAbort);
        this.waiters = this.waiters.filter((waiter) => waiter !== check);
        if (err) reject(err);
        else resolve();
      };
      const check = () => {
        if (settled) return;
        if (signal && signal.aborted) return finish(fail('已停止', 'proxy'));
        let ready = false;
        try {
          ready = pred(this.buf, this.ended);
        } catch (err) {
          return finish(err);
        }
        if (this.err && !ready) return finish(fail(netMessage(this.err), kind));
        if (ready) return finish(null);
        if (this.ended || this.err) {
          return finish(fail(this.err ? netMessage(this.err) : '连接已关闭', kind));
        }
      };
      this.waiters.push(check);
      check();
    });
  }

  consume(n) {
    const out = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }
}

function openSocket(proxy, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      reject(fail('已停止', 'proxy'));
      return;
    }
    let settled = false;
    const socket = proxy.protocol === 'https'
      ? tls.connect({
        host: proxy.host,
        port: proxy.port,
        servername: proxy.host,
        rejectUnauthorized: false,
      })
      : net.connect({ host: proxy.host, port: proxy.port });

    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      socket.setTimeout(0);
      socket.off('timeout', onTimeout);
      socket.off('error', onError);
      socket.off('connect', onReady);
      socket.off('secureConnect', onReady);
      if (signal) signal.removeEventListener('abort', onAbort);
      if (err) {
        socket.on('error', () => {});
        socket.destroy();
        reject(err);
        return;
      }
      socket.setNoDelay(true);
      resolve(socket);
    };
    const onError = (err) => {
      finish(signal && signal.aborted ? fail('已停止', 'proxy') : fail(netMessage(err), 'proxy'));
    };
    const onTimeout = () => finish(fail('连接代理超时', 'proxy'));
    const onAbort = () => finish(fail('已停止', 'proxy'));
    const onReady = () => finish(null, socket);

    if (signal) signal.addEventListener('abort', onAbort);
    socket.setTimeout(CONNECT_TIMEOUT);
    socket.once('error', onError);
    socket.once('timeout', onTimeout);
    socket.once(proxy.protocol === 'https' ? 'secureConnect' : 'connect', onReady);
  });
}

function socks5ReplyLength(buf) {
  if (buf.length < 4) return 0;
  const atyp = buf[3];
  if (atyp === 1) return 10;
  if (atyp === 4) return 22;
  if (atyp === 3) {
    if (buf.length < 5) return 0;
    return 7 + buf[4];
  }
  return -1;
}

async function socks5Connect(stream, proxy, destHost, destPort, signal) {
  const useAuth = Boolean(proxy.username || proxy.password);
  stream.socket.write(Buffer.from(useAuth ? [0x05, 0x01, 0x02] : [0x05, 0x01, 0x00]));
  await stream.waitFor((buf) => buf.length >= 2, IO_TIMEOUT, 'SOCKS5 握手超时', signal);
  const ver = stream.buf[0];
  const method = stream.buf[1];
  stream.consume(2);
  if (ver !== 0x05) throw fail('对方不是 SOCKS5 代理', 'proxy');
  if (method === 0xff) throw fail('代理拒绝了认证方式', 'proxy');
  if (method === 0x02) {
    const user = Buffer.from(proxy.username);
    const pass = Buffer.from(proxy.password);
    stream.socket.write(Buffer.concat([
      Buffer.from([0x01, user.length]),
      user,
      Buffer.from([pass.length]),
      pass,
    ]));
    await stream.waitFor((buf) => buf.length >= 2, IO_TIMEOUT, 'SOCKS5 认证超时', signal);
    const status = stream.buf[1];
    stream.consume(2);
    if (status !== 0x00) throw fail('代理认证失败', 'proxy');
  } else if (method !== 0x00) {
    throw fail('代理要求了不支持的认证方式', 'proxy');
  }

  const hostBuf = Buffer.from(destHost);
  if (hostBuf.length > 255) throw fail('检测服务主机名过长', 'lookup');
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(destPort);
  stream.socket.write(Buffer.concat([
    Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
    hostBuf,
    portBuf,
  ]));
  await stream.waitFor((buf) => {
    const size = socks5ReplyLength(buf);
    return size < 0 || (size > 0 && buf.length >= size);
  }, IO_TIMEOUT, '通过代理连接检测服务超时', signal, 'lookup');
  const size = socks5ReplyLength(stream.buf);
  if (size < 0) throw fail('代理返回了未知地址类型', 'proxy');
  const rep = stream.buf[1];
  stream.consume(size);
  if (rep !== 0x00) throw fail(socks5RepMessage(rep), socks5RepKind(rep));
}

function socks5RepMessage(rep) {
  const map = {
    1: 'SOCKS 代理内部错误',
    2: '代理规则不允许连接',
    3: '网络不可达',
    4: '检测服务不可达',
    5: '检测服务拒绝连接',
    6: 'TTL 已过期',
    7: '代理不支持 CONNECT',
    8: '代理不支持该地址类型',
  };
  return map[rep] || `SOCKS5 连接失败 (${rep})`;
}

function socks5RepKind(rep) {
  if (rep === 1 || rep === 2 || rep === 7 || rep === 8) return 'proxy';
  return 'lookup';
}

async function socks4Connect(stream, proxy, destHost, destPort, signal) {
  const user = Buffer.from(proxy.username || 'user');
  const domain = Buffer.from(destHost);
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(destPort);
  stream.socket.write(Buffer.concat([
    Buffer.from([0x04, 0x01]),
    portBuf,
    Buffer.from([0x00, 0x00, 0x00, 0x01]),
    user,
    Buffer.from([0x00]),
    domain,
    Buffer.from([0x00]),
  ]));
  await stream.waitFor((buf) => buf.length >= 8, IO_TIMEOUT, 'SOCKS4 握手超时', signal, 'lookup');
  const cd = stream.buf[1];
  stream.consume(8);
  if (cd !== 0x5a) throw fail(socks4Message(cd), socks4Kind(cd));
}

function socks4Message(cd) {
  if (cd === 0x5b) return 'SOCKS4 代理拒绝连接';
  if (cd === 0x5c) return 'SOCKS4 identd 不可达';
  if (cd === 0x5d) return 'SOCKS4 用户校验失败';
  return `SOCKS4 连接失败 (${cd})`;
}

function socks4Kind(cd) {
  if (cd === 0x5c || cd === 0x5d) return 'proxy';
  return 'lookup';
}

function proxyAuthHeader(proxy) {
  if (!proxy.username && !proxy.password) return '';
  return `Proxy-Authorization: Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}\r\n`;
}

async function httpProxyConnect(stream, proxy, target, signal) {
  stream.socket.write(
    `CONNECT ${target.host}:${target.port} HTTP/1.1\r\n` +
    `Host: ${target.host}:${target.port}\r\n` +
    proxyAuthHeader(proxy) +
    '\r\n'
  );
  await stream.waitFor((buf) => buf.indexOf('\r\n\r\n') >= 0, IO_TIMEOUT, '代理 CONNECT 超时', signal, 'lookup');
  const sep = stream.buf.indexOf('\r\n\r\n');
  const code = statusCode(stream.buf.subarray(0, sep).toString('utf8'));
  stream.consume(sep + 4);
  if (code === 401 || code === 407) throw fail('代理认证失败', 'proxy');
  if (code !== 200) throw fail(code ? `代理 CONNECT 失败 HTTP ${code}` : '代理 CONNECT 失败', 'lookup');
}

async function tunnelViaProxy(stream, proxy, destHost, destPort, signal) {
  if (proxy.protocol === 'socks5') {
    await socks5Connect(stream, proxy, destHost, destPort, signal);
    return;
  }
  if (proxy.protocol === 'socks4') {
    await socks4Connect(stream, proxy, destHost, destPort, signal);
    return;
  }
  await httpProxyConnect(stream, proxy, { host: destHost, port: destPort }, signal);
}

async function connectProxyChain(chain, signal) {
  if (!chain.length) throw inputError('链式代理为空');
  if (chain.length > MAX_CHAIN) throw inputError(`链式代理最多 ${MAX_CHAIN} 跳`);
  const socket = await openSocket(chain[0], signal);
  let stream = new ByteStream(socket);
  let active = socket;
  for (let i = 0; i < chain.length - 1; i += 1) {
    const hop = chain[i];
    const next = chain[i + 1];
    await tunnelViaProxy(stream, hop, next.host, next.port, signal);
    stream.detach();
    stream = new ByteStream(socket);
    active = socket;
  }
  return { socket, stream, active, exit: chain[chain.length - 1] };
}

function wrapTls(socket, servername, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      reject(fail('已停止', 'lookup'));
      return;
    }
    let settled = false;
    const secure = tls.connect({ socket, servername, rejectUnauthorized: true });
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      secure.off('secureConnect', onReady);
      secure.off('error', onError);
      if (signal) signal.removeEventListener('abort', onAbort);
      if (err) {
        secure.on('error', () => {});
        secure.destroy();
        reject(err);
        return;
      }
      resolve(value);
    };
    const onError = (err) => finish(fail(`检测服务 TLS 失败：${netMessage(err)}`, 'lookup'));
    const onAbort = () => finish(fail('已停止', 'lookup'));
    const onReady = () => finish(null, secure);
    if (signal) signal.addEventListener('abort', onAbort);
    secure.once('error', onError);
    secure.once('secureConnect', onReady);
  });
}

function writeRequest(socket, proxy, target, tunneled) {
  const requestTarget = tunneled ? target.path : `http://${target.host}${target.path}`;
  const auth = tunneled ? '' : proxyAuthHeader(proxy);
  socket.write(
    `GET ${requestTarget} HTTP/1.1\r\n` +
    `Host: ${target.host}\r\n` +
    auth +
    'User-Agent: agent-test/1.0\r\n' +
    'Accept: */*\r\n' +
    'Accept-Encoding: identity\r\n' +
    'Connection: close\r\n\r\n'
  );
}

async function readHttpResponse(stream, signal) {
  await stream.waitFor((buf, ended) => httpReady(buf, ended), IO_TIMEOUT, '读取响应超时', signal, 'lookup');
  return parseHttpMessage(stream.buf);
}

function httpReady(buf, ended) {
  const sep = buf.indexOf('\r\n\r\n');
  if (sep < 0) return ended;
  const headers = parseHeaders(buf.subarray(0, sep).toString('utf8'));
  const body = buf.subarray(sep + 4);
  if (/chunked/i.test(headers['transfer-encoding'] || '')) {
    return decodeChunked(body) !== null || ended;
  }
  if (headers['content-length'] != null && headers['content-length'] !== '') {
    const len = Number(headers['content-length']);
    if (!Number.isFinite(len)) return ended;
    return body.length >= len || ended;
  }
  return ended;
}

function parseHeaders(headerText) {
  const headers = {};
  const lines = headerText.split('\r\n').slice(1);
  for (const line of lines) {
    const index = line.indexOf(':');
    if (index > 0) headers[line.slice(0, index).toLowerCase()] = line.slice(index + 1).trim();
  }
  return headers;
}

function statusCode(headerText) {
  const matched = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/i.exec(headerText);
  return matched ? Number(matched[1]) : 0;
}

function decodeChunked(buf) {
  const parts = [];
  let offset = 0;
  while (offset < buf.length) {
    const lineEnd = buf.indexOf('\r\n', offset);
    if (lineEnd < 0) return null;
    const sizeText = buf.subarray(offset, lineEnd).toString('utf8').split(';')[0].trim();
    if (!/^[0-9a-fA-F]+$/.test(sizeText)) return null;
    const size = parseInt(sizeText, 16);
    const dataStart = lineEnd + 2;
    if (size === 0) return Buffer.concat(parts);
    if (buf.length < dataStart + size + 2) return null;
    parts.push(buf.subarray(dataStart, dataStart + size));
    offset = dataStart + size + 2;
  }
  return null;
}

function parseHttpMessage(buf) {
  const sep = buf.indexOf('\r\n\r\n');
  if (sep < 0) throw fail('代理返回的响应不完整', 'lookup');
  const headerText = buf.subarray(0, sep).toString('utf8');
  const headers = parseHeaders(headerText);
  let body = buf.subarray(sep + 4);
  if (/chunked/i.test(headers['transfer-encoding'] || '')) {
    const decoded = decodeChunked(body);
    if (!decoded) throw fail('分块响应不完整', 'lookup');
    body = decoded;
  } else if (headers['content-length']) {
    const len = Number(headers['content-length']);
    if (Number.isFinite(len) && body.length > len) body = body.subarray(0, len);
  }
  return {
    code: statusCode(headerText),
    body: body.toString('utf8').replace(/^\uFEFF/, ''),
  };
}

function interpret(message, target) {
  if (message.code === 401 || message.code === 407) throw fail('代理认证失败', 'proxy');
  if (!message.code || message.code >= 400) {
    throw fail(message.code ? `检测服务返回 HTTP ${message.code}` : '代理返回了无法识别的数据', 'lookup');
  }
  return target.parse(message.body);
}

function parseIpApi(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw fail('出口信息不是有效 JSON', 'lookup');
  }
  if (!data || data.status !== 'success' || !data.query) {
    throw fail((data && data.message) || '出口信息查询失败', 'lookup');
  }
  return {
    ip: data.query,
    country: data.country || '',
    countryCode: data.countryCode || '',
    region: data.regionName || '',
    city: data.city || '',
    zip: data.zip || '',
    lat: typeof data.lat === 'number' ? data.lat : null,
    lon: typeof data.lon === 'number' ? data.lon : null,
    timezone: data.timezone || '',
    isp: data.isp || '',
    org: data.org || '',
    as: data.as || '',
  };
}

function readJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw fail('出口信息不是有效 JSON', 'lookup');
  }
}

function blankGeo(ip) {
  return {
    ip,
    country: '',
    countryCode: '',
    region: '',
    city: '',
    zip: '',
    lat: null,
    lon: null,
    timezone: '',
    isp: '',
    org: '',
    as: '',
  };
}

function parseIpWho(text) {
  const data = readJson(text);
  if (!data || data.success !== true || !isIp(data.ip || '')) {
    throw fail((data && data.message) || '出口信息查询失败', 'lookup');
  }
  const conn = data.connection || {};
  const zone = data.timezone || {};
  return {
    ...blankGeo(data.ip),
    country: data.country || '',
    countryCode: data.country_code || '',
    region: data.region || '',
    city: data.city || '',
    zip: data.postal || '',
    lat: typeof data.latitude === 'number' ? data.latitude : null,
    lon: typeof data.longitude === 'number' ? data.longitude : null,
    timezone: zone.id || '',
    isp: conn.isp || '',
    org: conn.org || '',
    as: conn.asn ? `AS${conn.asn}${conn.org ? ` ${conn.org}` : ''}` : '',
  };
}

function parseIpInfo(text) {
  const data = readJson(text);
  if (!data || data.error || !isIp(data.ip || '')) {
    throw fail((data && (data.error || data.message)) || '出口信息查询失败', 'lookup');
  }
  const loc = String(data.loc || '').split(',');
  const lat = loc.length === 2 ? Number(loc[0]) : NaN;
  const lon = loc.length === 2 ? Number(loc[1]) : NaN;
  const org = data.org || '';
  return {
    ...blankGeo(data.ip),
    country: data.country || '',
    countryCode: data.country || '',
    region: data.region || '',
    city: data.city || '',
    zip: data.postal || '',
    lat: Number.isFinite(lat) ? lat : null,
    lon: Number.isFinite(lon) ? lon : null,
    timezone: data.timezone || '',
    isp: org,
    org,
    as: org,
  };
}

function parseIpip(text) {
  const matched = /IP[:：]\s*([0-9a-fA-F:.]+)\s+来自于[:：]\s*(.*)/.exec(String(text || ''));
  if (!matched || !isIp(matched[1])) throw fail('未获得出口 IP', 'lookup');
  const parts = matched[2].trim().split(/\s+/).filter(Boolean);
  return {
    ...blankGeo(matched[1]),
    country: parts[0] || '',
    region: parts[1] || '',
    city: parts[2] || '',
    isp: parts.slice(3).join(' '),
  };
}

function parsePlainIp(text) {
  const ip = String(text || '').trim();
  if (!isIp(ip)) throw fail('未获得出口 IP', 'lookup');
  return {
    ip,
    country: '',
    countryCode: '',
    region: '',
    city: '',
    zip: '',
    lat: null,
    lon: null,
    timezone: '',
    isp: '',
    org: '',
    as: '',
  };
}

function isIp(ip) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    return ip.split('.').every((part) => Number(part) <= 255);
  }
  return ip.includes(':') && /^[0-9a-fA-F:]+$/.test(ip);
}

function resultBase(proxy) {
  return {
    display: maskProxy(proxy),
    protocol: proxy.protocol,
    host: proxy.host,
    port: proxy.port,
    username: proxy.username,
  };
}

async function checkProxy(proxyOrChain, signal, lookups = LOOKUPS) {
  const chain = Array.isArray(proxyOrChain) ? proxyOrChain : [proxyOrChain];
  const exit = chain[chain.length - 1];
  const started = Date.now();
  const base = {
    ...resultBase(exit),
    display: chain.length > 1 ? chain.map(maskProxy).join(' → ') : maskProxy(exit),
  };
  let connectMs = null;
  let lastLookup = null;
  let sawProxy = false;

  for (const target of lookups) {
    if (signal && signal.aborted) {
      return { ...base, ok: false, status: 'fail', error: '已停止', connectMs, totalMs: Date.now() - started };
    }
    let socket = null;
    let stream = null;
    let active = null;
    try {
      const t0 = Date.now();
      if (chain.length === 1) {
        socket = await openSocket(exit, signal);
        active = socket;
        stream = new ByteStream(socket);
      } else {
        const linked = await connectProxyChain(chain, signal);
        socket = linked.socket;
        active = linked.active;
        stream = linked.stream;
      }
      if (connectMs == null) connectMs = Date.now() - t0;
      sawProxy = true;
      let tunneled = false;
      if (exit.protocol === 'socks5') {
        await socks5Connect(stream, exit, target.host, target.port, signal);
        tunneled = true;
      } else if (exit.protocol === 'socks4') {
        await socks4Connect(stream, exit, target.host, target.port, signal);
        tunneled = true;
      } else if (target.tls) {
        await httpProxyConnect(stream, exit, target, signal);
        tunneled = true;
      }
      if (target.tls) {
        const leftover = stream.buf;
        socket.on('error', () => {});
        stream.detach();
        stream = null;
        if (leftover.length) socket.unshift(leftover);
        active = await wrapTls(socket, target.host, signal);
        stream = new ByteStream(active);
        tunneled = true;
      }
      writeRequest(active, exit, target, tunneled);
      const info = interpret(await readHttpResponse(stream, signal), target);
      return {
        ...base,
        ...info,
        ok: true,
        status: 'ok',
        connectMs,
        totalMs: Date.now() - started,
        querySource: target.host,
      };
    } catch (err) {
      const error = err instanceof Error ? err : fail(String(err), 'proxy');
      if ((signal && signal.aborted) || error.message === '已停止') {
        return { ...base, ok: false, status: 'fail', error: '已停止', connectMs, totalMs: Date.now() - started };
      }
      if (error.kind !== 'lookup') {
        return {
          ...base,
          ok: false,
          status: 'fail',
          error: error.message || '检测失败',
          connectMs,
          totalMs: Date.now() - started,
        };
      }
      lastLookup = error;
    } finally {
      if (stream) stream.detach();
      if (active && active !== socket) {
        active.on('error', () => {});
        active.destroy();
      }
      if (socket) {
        socket.on('error', () => {});
        socket.destroy();
      }
    }
  }

  return {
    ...base,
    ok: false,
    status: sawProxy ? 'warn' : 'fail',
    error: sawProxy
      ? `代理已连通，出口信息查询失败：${lastLookup ? lastLookup.message : '未知错误'}`
      : (lastLookup ? lastLookup.message : '检测失败'),
    connectMs,
    totalMs: Date.now() - started,
  };
}

function requestDirect(target) {
  return new Promise((resolve, reject) => {
    const lib = target.directUrl.startsWith('https:') ? https : http;
    const req = lib.get(target.directUrl, {
      timeout: IO_TIMEOUT,
      headers: {
        'User-Agent': 'agent-test/1.0',
        Accept: '*/*',
        'Accept-Encoding': 'identity',
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          code: res.statusCode || 0,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
    });
    req.on('error', (err) => reject(fail(netMessage(err), 'lookup')));
    req.on('timeout', () => {
      req.destroy();
      reject(fail('查询超时', 'lookup'));
    });
  });
}

async function checkDirect() {
  const started = Date.now();
  let last = null;
  for (const target of LOOKUPS) {
    try {
      const info = interpret(await requestDirect(target), target);
      return { ok: true, status: 'ok', totalMs: Date.now() - started, querySource: target.host, ...info };
    } catch (err) {
      last = err;
    }
  }
  return {
    ok: false,
    status: 'fail',
    error: last ? last.message : '查询失败',
    totalMs: Date.now() - started,
  };
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        req.destroy();
        reject(inputError('请求体过大'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res, code, data) {
  if (res.writableEnded) return;
  const body = JSON.stringify(data);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function sendFile(res, fileName, type) {
  const filePath = path.join(PUBLIC_DIR, fileName);
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not Found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': type,
      'Content-Length': data.length,
      'Cache-Control': 'no-store',
    });
    res.end(data);
  });
}

function clipError(err) {
  const text = String((err && err.message) || '检测失败');
  return text.length > 300 ? `${text.slice(0, 300)}…` : text;
}

async function handleCheck(req, res) {
  const ac = new AbortController();
  const onClose = () => {
    if (!res.writableEnded) ac.abort();
  };
  res.on('close', onClose);
  let raw = '';
  try {
    raw = await readBody(req, 64 * 1024);
  } catch (err) {
    sendJson(res, 400, { ok: false, status: 'fail', error: clipError(err), display: '请求无效' });
    return;
  }
  let body;
  try {
    body = raw ? JSON.parse(raw) : {};
  } catch {
    sendJson(res, 400, { ok: false, status: 'fail', error: '请求格式无效', display: '请求无效' });
    return;
  }
  let chain;
  try {
    chain = proxyFromBody(body);
  } catch (err) {
    sendJson(res, 200, { ok: false, status: 'fail', error: clipError(err), display: '' });
    return;
  }
  const result = await checkProxy(chain, ac.signal);
  if (!res.writableEnded && !ac.signal.aborted) sendJson(res, 200, result);
}

async function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
  try {
    if (req.method === 'GET' && STATIC_FILES[url.pathname]) {
      const [fileName, type] = STATIC_FILES[url.pathname];
      sendFile(res, fileName, type);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/favicon.ico') {
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/direct') {
      sendJson(res, 200, await checkDirect());
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/check') {
      await handleCheck(req, res);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not Found');
  } catch (err) {
    if (!res.writableEnded) {
      sendJson(res, 500, { ok: false, status: 'fail', error: clipError(err), display: '服务器错误' });
    }
  }
}

const server = http.createServer(handler);
server.requestTimeout = 45000;

if (require.main === module) {
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') console.error(`端口 ${PORT} 已被占用`);
    else console.error(err);
    process.exit(1);
  });
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`代理检测页面 http://127.0.0.1:${PORT}/`);
  });
}

module.exports = {
  parseProxyLine,
  checkProxy,
  maskProxy,
};
