#!/usr/bin/env node
/**
 * QianVPN Gateway —— 本地请求代理网关（用户端）
 *
 * 作者：白小谦　｜　反馈邮箱：qianxlfk@163.com　｜　协议：AGPL-3.0-or-later
 *
 * 工作方式：
 *  1. 监听 127.0.0.1:端口，作为 Windows 系统代理（HTTP 代理）。
 *  2. 针对模式：目标先尝试直连，直连失败（被墙/超时/重置）才转发到中转节点；
 *     全局模式：所有请求一律走中转节点；名单模式：名单内中转、名单外仅直连。
 *  3. 中转端点两种协议（config.json → relay.endpoints 自行部署后填入）：
 *     query 模式：https://<节点>/?url=<目标>&method=<方法>&head=<头JSON>&body=<体>&buffer=true
 *     透传模式：{"url":"https://<节点>/relay/<token>/","mode":"passthrough"}（原始请求原样转发）
 *  4. HTTPS 通过本地 CA 做中间人解密（首次运行自动生成 CA 并请求安装到系统）。
 */
'use strict';

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const ROOT = __dirname;
const CONFIG_FILE = path.join(ROOT, 'config.json');
const CERT_DIR = path.join(ROOT, 'certs');
const CA_CERT_FILE = path.join(CERT_DIR, 'ca.crt');
const CA_KEY_FILE = path.join(CERT_DIR, 'ca.key');

/* ---------------- 配置 ---------------- */

function deepMerge(base, extra) {
  if (Array.isArray(base) || Array.isArray(extra)) return extra === undefined ? base : extra;
  if (base && typeof base === 'object' && extra && typeof extra === 'object') {
    const out = Object.assign({}, base);
    for (const k of Object.keys(extra)) out[k] = deepMerge(base[k], extra[k]);
    return out;
  }
  return extra === undefined ? base : extra;
}

const DEFAULTS = {
  port: 8899,
  host: '127.0.0.1',
  mode: 'targeted', // global=全局模式 | targeted=针对模式 | list=名单模式
  relayList: [],     // 名单模式的域名名单：命中强制中转，名单外仅直连（失败也不中转）
  relay: {
    endpoints: [],  // 开源版不内置任何站点：请运行「一键部署中转服务.cmd」或在 Web UI 中添加
    timeout: 300000,
    firstByteTimeout: 30000,
    maxBodyBytes: 2097152
  },
  buffer: { enabled: false, domains: [] },
  targeted: {
    directTimeout: 4000,
    cacheSeconds: 300,
    forceRelayDomains: [],
    directDomains: []
  },
  headers: {
    overrideUserAgent: '',
    forceIdentity: true,
    strip: ['accept-encoding'],
    extra: {}
  },
  security: { allowPrivateTargets: false },
  cert: { autoInstall: true },
  log: { level: 'info' }
};

let config = DEFAULTS;
try {
  config = deepMerge(DEFAULTS, JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')));
} catch (e) {
  if (e.code !== 'ENOENT') console.warn(`[配置] config.json 解析失败（${e.message}），已使用默认配置`);
}
if (process.env.QGV_PORT) config.port = Number(process.env.QGV_PORT) || config.port;
if (process.env.QGV_MODE) config.mode = process.env.QGV_MODE;

/* ---------------- 日志 ---------------- */

const C = { r: '\x1b[0m', dim: '\x1b[2m', cyan: '\x1b[36m', green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', magenta: '\x1b[35m' };
const pad = s => String(s).padEnd(5, ' ');
function line(tag, color, msg) {
  if (config.log.level === 'quiet' && tag !== 'ERROR' && tag !== 'WARN') return;
  console.log(`${C.dim}[${new Date().toLocaleTimeString('zh-CN', { hour12: false })}]${C.r} ${color}${pad(tag)}${C.r}${msg}`);
}
const info = m => line('INFO', C.cyan, m);
const oklog = m => line('OK', C.green, m);
const warn = m => line('WARN', C.yellow, m);
const errlog = m => line('ERROR', C.red, m);

process.on('uncaughtException', e => errlog('未捕获异常：' + e.message));
process.on('unhandledRejection', e => errlog('未处理的 Promise 异常：' + ((e && e.message) || e)));

/* ---------------- CA 证书（node-forge） ---------------- */

let forge = null;
try { forge = require('node-forge'); } catch (_) { /* 未安装时 HTTPS 中转不可用 */ }
let caCert = null, caKey = null, leafPair = null;

function ensureCA() {
  if (!forge) return false;
  fs.mkdirSync(CERT_DIR, { recursive: true });
  if (fs.existsSync(CA_CERT_FILE) && fs.existsSync(CA_KEY_FILE)) {
    caCert = forge.pki.certificateFromPem(fs.readFileSync(CA_CERT_FILE, 'utf8'));
    caKey = forge.pki.privateKeyFromPem(fs.readFileSync(CA_KEY_FILE, 'utf8'));
  } else {
    info('正在生成本地 CA 根证书（仅首次，约需几秒）...');
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01' + crypto.randomBytes(8).toString('hex');
    cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000);
    cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000);
    const attrs = [
      { name: 'commonName', value: 'QianVPN Local Gateway Root CA' },
      { name: 'organizationName', value: 'QianVPN Gateway' }
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      { name: 'basicConstraints', cA: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true }
    ]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    caCert = cert;
    caKey = keys.privateKey;
    fs.writeFileSync(CA_CERT_FILE, forge.pki.certificateToPem(cert));
    fs.writeFileSync(CA_KEY_FILE, forge.pki.privateKeyToPem(keys.privateKey));
    oklog('CA 根证书已生成：' + CA_CERT_FILE);
  }
  // 所有域名共用一对叶子密钥（生成慢，持久化复用），证书按域名实时签发
  const leafPubFile = path.join(CERT_DIR, 'leaf.pub.key');
  const leafKeyFile = path.join(CERT_DIR, 'leaf.key');
  if (fs.existsSync(leafPubFile) && fs.existsSync(leafKeyFile)) {
    leafPair = {
      publicKey: forge.pki.publicKeyFromPem(fs.readFileSync(leafPubFile, 'utf8')),
      privateKey: forge.pki.privateKeyFromPem(fs.readFileSync(leafKeyFile, 'utf8'))
    };
  } else {
    info('正在生成站点证书密钥（仅首次）...');
    leafPair = forge.pki.rsa.generateKeyPair(2048);
    fs.writeFileSync(leafPubFile, forge.pki.publicKeyToPem(leafPair.publicKey));
    fs.writeFileSync(leafKeyFile, forge.pki.privateKeyToPem(leafPair.privateKey));
  }
  return true;
}

const hostCertCache = new Map();
function makeHostCert(host) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = leafPair.publicKey;
  cert.serialNumber = crypto.randomBytes(8).toString('hex');
  cert.validity.notBefore = new Date(Date.now() - 3600 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 825 * 24 * 3600 * 1000);
  cert.setSubject([{ name: 'commonName', value: host }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: 'subjectAltName', altNames: [net.isIP(host) ? { type: 7, value: host } : { type: 2, value: host }] },
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true }
  ]);
  cert.sign(caKey, forge.md.sha256.create());
  return {
    key: forge.pki.privateKeyToPem(leafPair.privateKey),
    cert: forge.pki.certificateToPem(cert) + forge.pki.certificateToPem(caCert)
  };
}
function getSecureContext(host) {
  let ctx = hostCertCache.get(host);
  if (!ctx) {
    ctx = tls.createSecureContext(makeHostCert(host));
    hostCertCache.set(host, ctx);
  }
  return ctx;
}

const FORGE_OK = ensureCA();

/* ---------------- 路由决策 ---------------- */

const routeCache = new Map(); // host -> { route, until }

function domainMatch(host, list) {
  host = String(host).toLowerCase().replace(/\.$/, '');
  return (list || []).some(d => {
    d = String(d).toLowerCase().trim();
    if (!d) return false;
    // 带点 = 域名匹配（等于或为其子域）；不带点 = 关键词（域名包含该词即命中，如 "claude" 命中 claude.ai）
    if (d.includes('.')) return host === d || host.endsWith('.' + d);
    return host.includes(d);
  });
}

function cachedRoute(host) {
  const e = routeCache.get(host);
  if (e && e.until > Date.now()) return e.route;
  if (e) routeCache.delete(host);
  return null;
}
function setRouteCache(host, route) {
  routeCache.set(host, { route, until: Date.now() + (config.targeted.cacheSeconds || 300) * 1000 });
}

function decideRoute(host) {
  if (config.mode === 'global') return 'relay';
  if (config.mode === 'list') {
    // 名单模式：名单内强制中转，名单外仅直连（直连失败也不中转）
    return domainMatch(host, config.relayList || []) ? 'relay' : 'direct';
  }
  const t = config.targeted || {};
  if (domainMatch(host, t.forceRelayDomains)) return 'relay';
  if (domainMatch(host, t.directDomains)) return 'direct';
  return cachedRoute(host) || 'probe';
}

function wantBuffer(host) {
  if (config.buffer.enabled) return true;
  return domainMatch(host, config.buffer.domains);
}

function isPrivateHost(hostname) {
  const h = String(hostname).toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (net.isIPv4(h)) {
    const [a, b, c] = h.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||           // CGNAT
      (a === 169 && b === 254) ||                      // 链路本地
      (a === 172 && b >= 16 && b <= 31) ||             // 私网
      (a === 192 && b === 168) ||                      // 私网
      (a === 192 && b === 0 && c === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||         // 基准测试保留
      a >= 224;                                        // 组播 + 保留
  }
  if (h.includes(':')) {
    const m = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (m) return isPrivateHost(m[1]);
    return h === '::' || h === '::1' || /^f[cd]/i.test(h) || /^fe[89ab]/i.test(h);
  }
  return false;
}

/* ---------------- 请求头 / 请求体处理 ---------------- */

const HOP_BY_HOP = new Set([
  'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding',
  'te', 'trailer', 'upgrade', 'expect', 'content-length',
  'proxy-authorization', 'proxy-authenticate'
]);

const UA_POOL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0'
];
const randomUA = () => UA_POOL[crypto.randomInt(UA_POOL.length)];

function buildForwardHeaders(req) {
  const strip = new Set([...HOP_BY_HOP, ...(config.headers.strip || [])]);
  const out = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (strip.has(k.toLowerCase())) continue;
    out[k] = Array.isArray(v) ? v.join(', ') : v;
  }
  if ((config.headers.forceIdentity !== false) && !('accept-encoding' in out)) {
    out['accept-encoding'] = 'identity';
  }
  if (config.headers.overrideUserAgent) out['user-agent'] = config.headers.overrideUserAgent;
  else if (!out['user-agent']) out['user-agent'] = randomUA();
  Object.assign(out, config.headers.extra || {});
  return out;
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0, done = false;
    req.on('data', c => {
      if (done) return;
      size += c.length;
      if (size > limit) {
        done = true;
        reject(Object.assign(new Error(`请求体超过中转上限 ${(limit / 1024 / 1024).toFixed(1)}MB`), { code: 'BODY_TOO_LARGE' }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => { if (!done) { done = true; resolve(Buffer.concat(chunks)); } });
    req.on('error', e => { if (!done) { done = true; reject(e); } });
    req.on('aborted', () => { if (!done) { done = true; reject(new Error('客户端中断')); } });
  });
}

function bodyParamValue(buf, headers) {
  const text = buf.toString('utf8');
  if (/json/i.test(String(headers['content-type'] || ''))) {
    try { return JSON.stringify(JSON.parse(text)); } catch (_) { /* 保持原文 */ }
  }
  return text;
}

/* ---------------- 中转节点调用 ---------------- */

// 端点支持两种配置形式：
//   "https://xxx.example.com/api/"                          —— query 模式（中转格式 url/method/head/body）
//   {"url":"https://xx.example.com/relay/<token>/","mode":"passthrough"} —— 透传模式（原始请求原样转发）
function normalizeEndpoint(e) {
  if (e && typeof e === 'object' && e.url) {
    let base = String(e.url).trim();
    if (!/^https?:\/\//i.test(base)) base = 'https://' + base;
    if (!/\/$/.test(base)) base += '/';
    return {
      base,
      passthrough: e.mode === 'passthrough',
      matchDomains: Array.isArray(e.matchDomains) ? e.matchDomains : null
    };
  }
  let base = String(e).trim();
  if (!/^https?:\/\//i.test(base)) base = 'https://' + base;
  if (!/\/$/.test(base)) base += '/';
  return { base, passthrough: false, matchDomains: null };
}

function relayEndpoints() {
  return (config.relay.endpoints || []).map(normalizeEndpoint);
}

function relayCallURL(ep, target, method, headers, bodyVal, buffer) {
  if (ep.passthrough) return ep.base + target.toString();
  const q = new URLSearchParams();
  q.set('url', target.toString());
  q.set('method', method);
  if (headers && Object.keys(headers).length) q.set('head', JSON.stringify(headers));
  if (bodyVal !== null && bodyVal !== undefined && bodyVal !== '') q.set('body', bodyVal);
  if (buffer) q.set('buffer', 'true');
  return ep.base + '?' + q.toString();
}

const keepAliveAgents = {
  'https:': new https.Agent({ keepAlive: true, maxSockets: 16 }),
  'http:': new http.Agent({ keepAlive: true, maxSockets: 16 })
};

function relayRequest(callUrl, buffer, init) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(callUrl); } catch (e) { return reject(e); }
    const mod = u.protocol === 'https:' ? https : http;
    let settled = false;
    const firstByteMs = buffer ? config.relay.timeout : (config.relay.firstByteTimeout || 20000);
    const opts = {
      agent: keepAliveAgents[u.protocol],
      timeout: config.relay.timeout,
      maxHeaderSize: 262144,
      headers: init && init.headers
        ? init.headers
        : { accept: '*/*', 'accept-encoding': 'identity', 'user-agent': 'QianVPN-Gateway/1.0' }
    };
    if (init && init.method) opts.method = init.method;
    const rreq = mod.request(u, opts, rres => {
      if (settled) { rres.resume(); return; }
      settled = true;
      clearTimeout(watchdog);
      resolve(rres);
    });
    if (init && init.body) rreq.write(init.body);
    rreq.end();
    const watchdog = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { rreq.destroy(); } catch (_) {}
      reject(new Error(`中转节点 ${Math.round(firstByteMs / 1000)}s 内无响应`));
    }, firstByteMs);
    rreq.on('timeout', () => {
      try { rreq.destroy(); } catch (_) {}
      if (!settled) { settled = true; clearTimeout(watchdog); reject(new Error('中转连接超时')); }
    });
    rreq.on('error', e => {
      if (!settled) { settled = true; clearTimeout(watchdog); reject(e); }
    });
  });
}

const RES_HOP = new Set(['connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'proxy-authenticate', 'proxy-authorization']);

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const RELAY_PARAM_KEYS = ['url', 'method', 'head', 'body', 'buffer'];

// 部分中转节点转发 30x 时会把自己的调用参数（url=/method=/head=...）拼进 Location 头，
// 浏览器跟随后会带着这串污染 query 请求跳转目标。这里识别该签名并剥离：
// 仅当 query 同时含 url（http/https 开头）与 method（合法 HTTP 动词）才清洗，正常站点的跳转不受影响。
function sanitizeLocation(loc) {
  if (!loc || loc.indexOf('?') === -1) return loc;
  const ci = loc.indexOf('?');
  const base = loc.slice(0, ci);
  const qs = loc.slice(ci + 1);
  const params = new URLSearchParams(qs);
  const urlv = params.get('url');
  const methodv = params.get('method');
  if (!/^https?:\/\//i.test(urlv || '') || !HTTP_METHODS.has((methodv || '').toUpperCase())) {
    return loc; // 不符合中转参数签名，原样返回
  }
  for (const k of RELAY_PARAM_KEYS) params.delete(k);
  const rest = params.toString();
  return rest ? base + '?' + rest : base;
}

function responseHeadersFor(res, sanitize) {
  const out = {};
  const raw = res.rawHeaders || [];
  for (let i = 0; i < raw.length; i += 2) {
    const k = raw[i], lk = k.toLowerCase();
    if (RES_HOP.has(lk)) continue;
    if (lk === 'set-cookie') { (out['set-cookie'] = out['set-cookie'] || []).push(raw[i + 1]); continue; }
    if (sanitize && lk === 'location') { out[k] = sanitizeLocation(raw[i + 1]); continue; }
    out[k] = raw[i + 1];
  }
  return out;
}

async function fetchViaRelay(target, method, headers, bodyBuf, buffer, res) {
  const eps = relayEndpoints();
  if (!eps.length) throw new Error('未配置任何中转节点：请先运行「一键部署中转服务.cmd」或在本页配置编辑器中添加');
  // 按 matchDomains 优先：命中目标域名的专属端点排最前（如某站点需要特定地区出口）
  const attempts = [];
  for (const ep of eps) {
    if (ep.matchDomains && ep.matchDomains.length && domainMatch(target.hostname, ep.matchDomains)) attempts.push(ep);
  }
  for (const ep of eps) if (!attempts.includes(ep)) attempts.push(ep);
  let lastErr = null;
  for (const ep of attempts) {
    try {
      let rres;
      if (ep.passthrough) {
        // 透传模式：原始 method/headers/body 原样转发（保留 Content-Type，表单/文件上传无损）
        const h = Object.assign({}, headers);
        delete h['host'];
        delete h['content-length'];
        const callUrl = relayCallURL(ep, target, method, headers, null, buffer);
        rres = await relayRequest(callUrl, buffer, {
          method,
          headers: h,
          body: bodyBuf && bodyBuf.length ? bodyBuf : null
        });
      } else {
        const bodyVal = bodyBuf && bodyBuf.length ? bodyParamValue(bodyBuf, headers) : null;
        const callUrl = relayCallURL(ep, target, method, headers, bodyVal, buffer);
        rres = await relayRequest(callUrl, buffer);
      }
      res.writeHead(rres.statusCode || 502, responseHeadersFor(rres, true));
      rres.on('error', () => { try { res.destroy(); } catch (_) {} });
      rres.pipe(res);
      return;
    } catch (e) {
      lastErr = e;
      warn(`中转节点不可用（${e.message}），切换下一个…`);
    }
  }
  throw lastErr || new Error('所有中转节点均不可用');
}

/* ---------------- 直连尝试 ---------------- */

function tryDirect(target, method, headers, bodyBuf, res, timeoutMs) {
  return new Promise(resolve => {
    const mod = target.protocol === 'https:' ? https : http;
    let settled = false;
    const dreq = mod.request(target, { method, headers, timeout: timeoutMs, agent: false, maxHeaderSize: 262144 });
    dreq.on('response', dres => {
      if (settled) { dres.resume(); return; }
      settled = true;
      res.writeHead(dres.statusCode || 502, responseHeadersFor(dres));
      dres.on('error', () => { try { res.destroy(); } catch (_) {} });
      dres.pipe(res);
      resolve(true);
    });
    dreq.on('timeout', () => { try { dreq.destroy(); } catch (_) {} });
    dreq.on('error', () => {
      if (settled) return;
      settled = true;
      resolve(false);
    });
    if (bodyBuf && bodyBuf.length) dreq.write(bodyBuf);
    dreq.end();
  });
}

/* ---------------- 页面 / 错误响应 ---------------- */

function plainError(res, code, msg) {
  if (res.headersSent) { try { res.destroy(); } catch (_) {} return; }
  res.writeHead(code, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
  res.end(msg);
}

const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function isLoopbackSelf(target) {
  const h = target.hostname;
  const loop = h === '127.0.0.1' || h === 'localhost' || h === '::1';
  const port = Number(target.port) || (target.protocol === 'https:' ? 443 : 80);
  return loop && port === Number(config.port);
}

// Firefox 一键证书配置：写入 Firefox 官方支持的 distribution\policies.json
// （Certificates.Install 指向本地 CA 文件，重启 Firefox 生效）。
// 要求 POST + 枚举白名单动作头，防止其他网页跨站伪造（跨源简单请求带不了自定义头）。
function findFirefoxDir() {
  try {
    const out = require('child_process').execFileSync('reg',
      ['query', 'HKLM\\SOFTWARE\\Mozilla\\Mozilla Firefox', '/s'],
      { windowsHide: true, encoding: 'utf8', timeout: 5000 });
    const m = String(out).match(/Install Directory\s+REG_SZ\s+(\S.*\S)\s*$/m);
    if (m && fs.existsSync(path.join(m[1], 'firefox.exe'))) return m[1];
  } catch (_) { /* 注册表无记录时走探测 */ }
  const candidates = [];
  if (process.env.ProgramFiles) candidates.push(path.join(process.env.ProgramFiles, 'Mozilla Firefox'));
  if (process.env['ProgramFiles(x86)']) candidates.push(path.join(process.env['ProgramFiles(x86)'], 'Mozilla Firefox'));
  if (process.env.LOCALAPPDATA) candidates.push(path.join(process.env.LOCALAPPDATA, 'Mozilla Firefox'));
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, 'firefox.exe'))) return c;
  }
  return null;
}

function handleFirefoxSetup(req, res) {
  req.resume();
  const action = req.headers['x-gw-action'];
  if (req.method !== 'POST' || (action !== 'setup' && action !== 'remove')) {
    plainError(res, 403, '拒绝：需 POST 且携带 X-GW-Action 头');
    return;
  }
  if (process.platform !== 'win32') { plainError(res, 500, '仅支持 Windows'); return; }
  if (!FORGE_OK || !fs.existsSync(CA_CERT_FILE)) { plainError(res, 500, 'CA 证书尚未生成，请先重启网关'); return; }
  const dir = findFirefoxDir();
  if (!dir) { plainError(res, 404, '未找到 Firefox 安装目录，请按手动步骤配置'); return; }
  const distDir = path.join(dir, 'distribution');
  const policyFile = path.join(distDir, 'policies.json');
  let data = {};
  try { data = JSON.parse(fs.readFileSync(policyFile, 'utf8')); } catch (_) { /* 无既有策略 */ }
  if (!data || typeof data !== 'object') data = {};
  data.policies = data.policies && typeof data.policies === 'object' ? data.policies : {};
  try {
    if (action === 'setup') {
      const certs = data.policies.Certificates = data.policies.Certificates || {};
      const list = Array.isArray(certs.Install) ? certs.Install.filter(x => typeof x === 'string') : [];
      if (!list.some(x => path.resolve(x) === path.resolve(CA_CERT_FILE))) list.push(CA_CERT_FILE);
      certs.Install = list;
      fs.mkdirSync(distDir, { recursive: true });
      fs.writeFileSync(policyFile, JSON.stringify(data, null, 2) + '\n');
      oklog('已写入 Firefox 证书策略 ' + policyFile + '，重启 Firefox 后生效');
    } else {
      const certs = data.policies.Certificates;
      if (certs && Array.isArray(certs.Install)) {
        certs.Install = certs.Install.filter(x => typeof x !== 'string' || path.resolve(x) !== path.resolve(CA_CERT_FILE));
        if (certs.Install.length === 0) delete data.policies.Certificates;
      }
      if (Object.keys(data.policies).length === 0) delete data.policies;
      if (Object.keys(data).length === 0 && fs.existsSync(policyFile)) fs.unlinkSync(policyFile);
      else { fs.mkdirSync(distDir, { recursive: true }); fs.writeFileSync(policyFile, JSON.stringify(data, null, 2) + '\n'); }
      oklog('已从 Firefox 证书策略移除本网关 CA：' + policyFile);
    }
  } catch (e) {
    errlog('Firefox 策略文件操作失败：' + e.message);
    plainError(res, 500, '策略文件写入失败（安装目录可能无写入权限），请按手动步骤配置');
    return;
  }
  res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
  res.end('{"ok":true}');
}

/* ---------------- Web 配置接口 ---------------- */

// 用户粘贴的列表做智能分割：支持换行、中英文逗号、分号（中文标点是手改配置的高频错误源）
function parseListInput(v) {
  if (Array.isArray(v)) return v.map(x => String(x).trim()).filter(Boolean);
  return String(v || '').split(/[\r\n,，、;；]+/).map(x => x.trim()).filter(Boolean);
}

function clampNum(v, min, max, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

// GET /api/config 返回当前生效配置；POST /api/config（X-GW-Action: save）保存新配置。
// 保存走白名单字段 + 类型强制，写入的是程序序列化的 JSON，杜绝手改语法错误。
function handleConfigApi(req, res) {
  if (req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(config, null, 2));
    return;
  }
  if (req.method !== 'POST' || req.headers['x-gw-action'] !== 'save') {
    plainError(res, 403, '拒绝：需 POST 且携带 X-GW-Action 头');
    return;
  }
  readBody(req, 1 << 20).then(buf => {
    let input;
    try { input = JSON.parse(buf.toString('utf8')); } catch (_) {
      return plainError(res, 400, '提交数据格式错误');
    }
    if (!input || typeof input !== 'object') return plainError(res, 400, '提交数据格式错误');

    const next = JSON.parse(JSON.stringify(config)); // 以当前生效配置为基底
    next.port = clampNum(input.port, 1, 65535, next.port);
    if (['targeted', 'global', 'list'].includes(input.mode)) next.mode = input.mode;
    next.relayList = parseListInput(input.relayList);
    next.buffer = next.buffer || {};
    next.buffer.enabled = !!(input.buffer && input.buffer.enabled);
    next.buffer.domains = parseListInput(input.buffer && input.buffer.domains);
    next.targeted = next.targeted || {};
    next.targeted.directTimeout = clampNum(input.targeted && input.targeted.directTimeout, 1000, 60000, next.targeted.directTimeout || 4000);
    next.targeted.cacheSeconds = clampNum(input.targeted && input.targeted.cacheSeconds, 0, 86400, next.targeted.cacheSeconds || 300);
    next.targeted.forceRelayDomains = parseListInput(input.targeted && input.targeted.forceRelayDomains);
    next.targeted.directDomains = parseListInput(input.targeted && input.targeted.directDomains);
    next.relay = next.relay || {};
    next.relay.timeout = clampNum(input.relay && input.relay.timeout, 10000, 3600000, next.relay.timeout || 300000);
    next.relay.firstByteTimeout = clampNum(input.relay && input.relay.firstByteTimeout, 3000, 300000, next.relay.firstByteTimeout || 30000);
    const rawEps = Array.isArray(input.relay && input.relay.endpoints) ? input.relay.endpoints : [];
    const prevEps = Array.isArray(next.relay.endpoints) ? next.relay.endpoints : [];
    next.relay.endpoints = rawEps.map(e => {
      if (!e || typeof e !== 'object') return null;
      const url = String(e.url || '').trim();
      if (!/^https?:\/\//i.test(url)) return null;
      const ep = { url };
      if (e.mode === 'passthrough') ep.mode = 'passthrough';
      const md = parseListInput(e.matchDomains);
      if (md.length) ep.matchDomains = md;
      return ep;
    }).filter(Boolean);
    if (!next.relay.endpoints.length && prevEps.length) {
      next.relay.endpoints = prevEps;
      warn('提交的端点列表为空或全部非法，已保留原有端点');
    }

    fs.writeFileSync(CONFIG_FILE, JSON.stringify(next, null, 2) + '\n');
    oklog('配置已通过 Web UI 保存：' + next.mode + ' / 名单 ' + next.relayList.length + ' 项 / 端点 ' + next.relay.endpoints.length + ' 个（重启网关后生效）');
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
    res.end('{"ok":true}');
  }).catch(() => plainError(res, 400, '请求体读取失败'));
}

// UI 一键重启：先 spawn 继任者（窗口模式弹窗、静默模式后台），再退出当前进程
function handleRestart(req, res) {
  req.resume();
  if (req.method !== 'POST' || req.headers['x-gw-action'] !== 'restart') {
    return plainError(res, 403, '拒绝：需 POST 且携带 X-GW-Action 头');
  }
  res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
  res.end('{"ok":true}');
  oklog('收到 UI 重启指令，正在拉起新实例…');
  setTimeout(() => {
    try {
      const { spawn } = require('child_process');
      if (process.env.QGW_CONSOLE === '1') {
        // 窗口模式：通过启动脚本重启（保持可见窗口交互）
        spawn('cmd.exe', ['/c', path.join(ROOT, 'start-gateway.cmd')], { detached: true, stdio: 'ignore' }).unref();
      } else {
        spawn(process.execPath, [path.join(ROOT, 'proxy.js')], {
          cwd: ROOT, detached: true, stdio: 'ignore', windowsHide: true
        }).unref();
      }
    } catch (e) {
      errlog('拉起新实例失败：' + e.message);
    }
    setTimeout(() => {
      try { server.close(() => process.exit(0)); } catch (_) { process.exit(0); }
      setTimeout(() => process.exit(0), 1500).unref();
    }, 600);
  }, 200);
}

// UI 停止服务：写停止标记（看门狗本轮不再拉起）后退出
function handleStop(req, res) {
  req.resume();
  if (req.method !== 'POST' || req.headers['x-gw-action'] !== 'stop') {
    return plainError(res, 403, '拒绝：需 POST 且携带 X-GW-Action 头');
  }
  try { fs.writeFileSync(path.join(ROOT, 'watchdog.stop'), new Date().toISOString()); } catch (_) {}
  res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
  res.end('{"ok":true}');
  oklog('收到 UI 停止指令，写入停止标记并退出（关闭所有浏览器后标记自动清除）');
  setTimeout(() => {
    try { server.close(() => process.exit(0)); } catch (_) { process.exit(0); }
    setTimeout(() => process.exit(0), 1000).unref();
  }, 500);
}

// 看门狗（跟随开启）：enable 写入 HKCU Run 自启并启动隐藏进程；disable 反向清理
function watchdogStatus(cb) {
  const { execFile } = require('child_process');
  execFile('netstat', ['-ano', '-p', 'tcp'], { windowsHide: true, timeout: 5000 }, (err, out) => {
    cb(!err && /127\.0\.0\.1:8898\s+\S+\s+LISTENING/.test(String(out || '')));
  });
}

function handleWatchdog(req, res) {
  const action = req.headers['x-gw-action'];
  if (req.method === 'GET') {
    return watchdogStatus(on => {
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ running: on }));
    });
  }
  req.resume();
  if (req.method !== 'POST' || (action !== 'enable' && action !== 'disable')) {
    return plainError(res, 403, '拒绝：需 POST 且携带 X-GW-Action 头');
  }
  const { execFile, spawn } = require('child_process');
  const runKey = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
  const vbsPath = path.join(ROOT, 'watchdog-hidden.vbs');
  if (action === 'enable') {
    execFile('reg', ['add', runKey, '/v', 'QianVPNWatchdog', '/t', 'REG_SZ',
      '/d', 'wscript.exe "' + vbsPath + '"', '/f'], { windowsHide: true }, err => {
      if (err) {
        errlog('写入自启注册表失败：' + err.message);
        return plainError(res, 500, '写入自启失败，详见网关日志');
      }
      watchdogStatus(on => {
        if (!on) {
          spawn('wscript.exe', [vbsPath], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
        }
        oklog('跟随开启已启用（看门狗随系统自启）');
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        res.end('{"ok":true}');
      });
    });
    return;
  }
  // disable：删自启键 + 结束看门狗进程（按 8898 端口定位）
  execFile('reg', ['delete', runKey, '/v', 'QianVPNWatchdog', '/f'], { windowsHide: true }, () => {
    execFile('netstat', ['-ano', '-p', 'tcp'], { windowsHide: true }, (err, out) => {
      if (!err && out) {
        const m = String(out).match(/127\.0\.0\.1:8898\s+\S+\s+LISTENING\s+(\d+)/);
        if (m) execFile('taskkill', ['/F', '/PID', m[1]], { windowsHide: true }, () => {});
      }
      oklog('跟随开启已关闭（看门狗已停止并移除自启）');
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      res.end('{"ok":true}');
    });
  });
}

function serveLocal(req, res) {
  if (req.url.startsWith('/firefox-setup')) { handleFirefoxSetup(req, res); return; }
  if (req.url.startsWith('/api/config')) { handleConfigApi(req, res); return; }
  if (req.url.startsWith('/api/restart')) { handleRestart(req, res); return; }
  if (req.url.startsWith('/api/stop')) { handleStop(req, res); return; }
  if (req.url.startsWith('/api/watchdog')) { handleWatchdog(req, res); return; }
  if (req.url === '/ca.crt' || req.url.startsWith('/ca.crt?')) {
    if (fs.existsSync(CA_CERT_FILE)) {
      // 带 ?firefox=1 时以 inline 返回：Firefox 顶级导航到 .crt 会直接弹出
      // 证书查看器（内含「信任此 CA」勾选），即一键配置入口；默认仍作附件下载
      const inline = req.url.includes('firefox=1');
      const headers = { 'content-type': 'application/x-x509-ca-cert' };
      if (!inline) headers['content-disposition'] = 'attachment; filename="qianvpn-gateway-ca.crt"';
      res.writeHead(200, headers);
      return res.end(fs.readFileSync(CA_CERT_FILE));
    }
    return plainError(res, 404, 'CA 证书尚未生成，请先启动一次网关');
  }
  const eps = relayEndpoints();
  const epItems = eps.length
    ? eps.map((e, i) => `<li>#${i + 1} <code>${escapeHtml(e.base)}</code>${e.passthrough ? ' <span style="color:#39d98a">[透传]</span>' : ''}</li>`).join('')
    : '<li style="color:#ff6b6b">未配置任何中转节点——请先运行「一键部署中转服务.cmd」</li>';
  const modeText = config.mode === 'global'
    ? '全局模式（所有流量走中转节点）'
    : config.mode === 'list'
      ? `名单模式（${(config.relayList || []).length} 个域名强制中转，其余仅直连）`
      : '针对模式（先直连，直连失败的目标自动走中转节点）';
  const bufText = config.buffer.enabled
    ? '开启（所有中转请求 buffer=true）'
    : `关闭（指定域名除外：${(config.buffer.domains || []).length} 个）`;
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>QianVPN Gateway · 运行中</title>
<style>body{font-family:system-ui,"Segoe UI",sans-serif;background:#0f172a;color:#e2e8f0;padding:40px;max-width:720px;margin:0 auto}
h1{font-size:22px}.card{background:#1e293b;border-radius:12px;padding:20px 24px;margin:16px 0}
.badge{display:inline-block;background:#059669;color:#fff;border-radius:999px;padding:2px 12px;font-size:13px}
code{background:#334155;padding:2px 6px;border-radius:4px}a{color:#7dd3fc}
table{border-collapse:collapse;width:100%}td{padding:8px 10px;border-bottom:1px solid #334155;vertical-align:top}
.k{color:#94a3b8;width:110px}ul{margin:0;padding-left:18px}</style></head><body>
<h1><span class="badge">● 运行中</span> QianVPN Gateway</h1>
<div class="card"><table>
<tr><td class="k">监听地址</td><td><code>${escapeHtml(config.host)}:${config.port}</code></td></tr>
<tr><td class="k">当前模式</td><td>${modeText}</td></tr>
<tr><td class="k">中转节点</td><td><ul>${epItems}</ul></td></tr>
<tr><td class="k">流缓冲</td><td>${bufText}</td></tr>
<tr><td class="k">CA 证书</td><td id="ca-cell">
<a href="/ca.crt">下载 ca.crt</a>　|　<a href="/ca.crt?firefox=1">证书查看器（Firefox 点此配置）</a><br>
<span style="color:#fbbf24">Firefox 用户</span>：Firefox 用独立证书库（SEC_ERROR_UNKNOWN_ISSUER 的原因），点上面「证书查看器」，
在弹出的证书页勾选 <b>「信任此 CA 以标识网站」</b> 后确认，一次即可。<br>
<span style="color:#94a3b8">Chrome/Edge 无需操作（自动安装已覆盖）。</span></td></tr>
</table></div>
<div class="card"><b>系统代理设置</b>：Windows 设置 → 网络和 Internet → 代理 → 手动设置代理 → 开，<br>
地址 <code>${escapeHtml(config.host)}</code> 端口 <code>${config.port}</code>。<br>
停止服务：使用下方「停止服务」按钮，或关闭启动窗口；停止前请先关闭系统代理开关。</div>

<div class="card">
<h2 style="margin:0 0 14px;font-size:17px">服务控制</h2>
<div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap">
<button id="s-restart" style="background:linear-gradient(180deg,#f59e0b,#d97706);color:#fff;border:0;border-radius:8px;padding:10px 24px;font-size:14px;font-weight:600;cursor:pointer">一键重启服务</button>
<button id="s-stop" style="background:linear-gradient(180deg,#ef4444,#b91c1c);color:#fff;border:0;border-radius:8px;padding:10px 24px;font-size:14px;font-weight:600;cursor:pointer">停止服务</button>
<label style="display:flex;gap:8px;align-items:center;font-size:13px;cursor:pointer">
<input type="checkbox" id="s-watchdog" style="width:16px;height:16px"> 跟随开启：检测到 Edge / Firefox / Chrome 启动时自动开启服务（后台静默，不弹窗；随系统自启）
</label>
</div>
<div id="s-status" style="margin-top:10px;font-size:13px;color:#94a3b2"></div>
<div style="margin-top:8px;font-size:12px;color:#64748b;line-height:1.7">停止规则：点「停止服务」后，看门狗本轮绝不再拉起（不会弹窗骚扰）；当你关闭所有浏览器后停止标记自动清除，下次打开浏览器时恢复跟随。跟随拉起的网关在后台静默运行（不弹窗）。</div>
</div>

<div class="card">
<h2 style="margin:0 0 14px;font-size:17px">配置编辑器</h2>
<div style="font-size:13px;color:#94a3b2;margin-bottom:12px">保存后由程序生成 config.json（不会出现语法错误）。<b style="color:#fbbf24">保存后点上方「一键重启服务」生效。</b></div>
<table style="width:100%;border-collapse:collapse">
<tr><td style="padding:6px 0;width:130px;color:#94a3b8;vertical-align:middle">模式</td>
<td><select id="c-mode" style="background:#1d212b;border:1px solid #2a2f3a;color:#e6e9ef;border-radius:6px;padding:6px 10px;width:100%">
<option value="targeted">针对模式（先直连，失败才中转）</option>
<option value="global">全局模式（全部走中转）</option>
<option value="list">名单模式（名单内中转，名单外仅直连）</option>
</select></td></tr>
<tr><td style="padding:6px 0;color:#94a3b8;vertical-align:top">代理名单<br><span style="font-size:11px">一行一条；不带点=关键词<br>（如 claude 命中 claude.ai）</span></td>
<td><textarea id="c-list" rows="5" style="width:100%;background:#1d212b;border:1px solid #2a2f3a;color:#e6e9ef;border-radius:6px;padding:8px;font-family:Consolas,monospace;font-size:13px" placeholder="claude&#10;google.com"></textarea>
<div style="font-size:11px;color:#64748b">支持中英文逗号/换行/分号分隔，粘贴时自动清洗</div></td></tr>
<tr><td style="padding:6px 0;color:#94a3b8;vertical-align:top">流缓冲 buffer<br><span style="font-size:11px">AI 长流域名单</span></td>
<td>
<label style="display:block;font-size:13px;margin-bottom:6px"><input type="checkbox" id="c-buf-all"> 全部请求开缓冲（buffer=true）</label>
<textarea id="c-buf" rows="3" style="width:100%;background:#1d212b;border:1px solid #2a2f3a;color:#e6e9ef;border-radius:6px;padding:8px;font-family:Consolas,monospace;font-size:13px" placeholder="gemini.google.com&#10;openai.com"></textarea></td></tr>
<tr><td style="padding:6px 0;color:#94a3b8;vertical-align:top">中转节点</td><td id="c-eps"></td></tr>
</table>
<div style="margin-top:14px;display:flex;gap:10px;align-items:center">
<button id="c-save" style="background:linear-gradient(180deg,#5b8cff,#3a6bff);color:#fff;border:0;border-radius:8px;padding:10px 26px;font-size:14px;font-weight:600;cursor:pointer">保存配置</button>
<span id="c-status" style="font-size:13px;color:#94a3b2"></span>
</div>
<details style="margin-top:14px;font-size:12px"><summary style="cursor:pointer;color:#7dd3fc">查看当前生效的完整配置（只读）</summary>
<pre id="c-raw" style="background:#0c0e12;border:1px solid #2a2f3a;border-radius:8px;padding:12px;overflow:auto;max-height:300px;font-size:12px"></pre></details>
</div>

<script>
(function () {
  var $ = function (id) { return document.getElementById(id); };
  fetch('/api/config').then(function (r) { return r.json(); }).then(function (cfg) {
    $('c-mode').value = cfg.mode || 'targeted';
    $('c-list').value = (cfg.relayList || []).join('\\n');
    $('c-buf-all').checked = !!(cfg.buffer && cfg.buffer.enabled);
    $('c-buf').value = ((cfg.buffer && cfg.buffer.domains) || []).join('\\n');
    $('c-raw').textContent = JSON.stringify(cfg, null, 2);
    renderEps((cfg.relay && cfg.relay.endpoints) || []);
  }).catch(function () { $('c-status').textContent = '加载配置失败'; });

  function renderEps(eps) {
    var box = $('c-eps');
    box.innerHTML = '';
    eps.forEach(function (ep, i) {
      var row = document.createElement('div');
      row.style.cssText = 'display:flex;gap:6px;margin-bottom:6px;align-items:center;flex-wrap:wrap';
      row.innerHTML =
        '<input class="ep-url" style="flex:1;min-width:260px;background:#1d212b;border:1px solid #2a2f3a;color:#e6e9ef;border-radius:6px;padding:7px;font-size:12px" placeholder="https://节点地址/" value="' + String(ep.url || '').replace(/"/g, '&quot;') + '">' +
        '<label style="font-size:12px;color:#94a3b8;white-space:nowrap"><input type="checkbox" class="ep-pass"' + (ep.mode === 'passthrough' ? ' checked' : '') + '> 透传</label>' +
        '<input class="ep-md" style="flex:1;min-width:150px;background:#1d212b;border:1px solid #2a2f3a;color:#e6e9ef;border-radius:6px;padding:7px;font-size:12px" placeholder="专属域名(选填)" value="' + ((ep.matchDomains || []).join(',')).replace(/"/g, '&quot;') + '">' +
        '<button type="button" class="ep-del" style="background:#7f1d1d;color:#fff;border:0;border-radius:6px;padding:7px 10px;cursor:pointer;font-size:12px">删</button>';
      box.appendChild(row);
    });
    var add = document.createElement('button');
    add.type = 'button';
    add.textContent = '+ 添加节点';
    add.style.cssText = 'background:#334155;color:#e6e9ef;border:1px solid #2a2f3a;border-radius:6px;padding:7px 14px;cursor:pointer;font-size:12px';
    add.onclick = function () { renderEps(collectEps().concat([{ url: '' }])); };
    box.appendChild(add);
  }

  function collectEps() {
    var out = [];
    var rows = document.querySelectorAll('#c-eps > div');
    rows.forEach(function (row) {
      var url = row.querySelector('.ep-url').value.trim();
      if (!url) return;
      var ep = { url: url };
      if (row.querySelector('.ep-pass').checked) ep.mode = 'passthrough';
      var md = row.querySelector('.ep-md').value.trim();
      if (md) ep.matchDomains = md;
      out.push(ep);
    });
    return out;
  }

  $('c-save').onclick = function () {
    var btn = $('c-save');
    btn.disabled = true;
    $('c-status').textContent = '保存中...';
    var payload = {
      mode: $('c-mode').value,
      relayList: $('c-list').value,
      buffer: { enabled: $('c-buf-all').checked, domains: $('c-buf').value },
      relay: { endpoints: collectEps() }
    };
    fetch('/api/config', { method: 'POST', headers: { 'X-GW-Action': 'save', 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function () { $('c-status').innerHTML = '<b style="color:#39d98a">已保存。</b>请点击上方「一键重启服务」生效。'; })
      .catch(function (e) { $('c-status').innerHTML = '<b style="color:#ff6b6b">保存失败：</b>' + e.message; })
      .finally(function () { btn.disabled = false; });
  };
})();
</script>

<script>
(function () {
  var rs = document.getElementById('s-restart');
  var sp = document.getElementById('s-stop');
  var wd = document.getElementById('s-watchdog');
  var st = document.getElementById('s-status');

  function xhr(method, url, action, onLoad, onErr) {
    var x = new XMLHttpRequest();
    x.open(method, url, true);
    if (action) x.setRequestHeader('X-GW-Action', action);
    x.onload = function () {
      var body = null;
      try { body = JSON.parse(x.responseText); } catch (_) {}
      onLoad(x.status, body);
    };
    x.onerror = onErr || function () {};
    x.send(action ? '' : null);
  }

  xhr('GET', '/api/watchdog', null, function (code, body) {
    if (code === 200 && body) {
      wd.checked = !!body.running;
      if (body.running) st.textContent = '跟随开启：运行中';
    }
  });

  rs.onclick = function () {
    rs.disabled = true;
    st.textContent = '重启中，页面将在几秒后自动刷新…';
    xhr('POST', '/api/restart', 'restart', function () {
      setTimeout(function () { location.reload(); }, 4000);
    }, function () { st.textContent = '重启指令已发出，请手动刷新本页'; });
  };

  sp.onclick = function () {
    if (!confirm('确定停止服务？停止后本轮浏览器会话内不再自动开启（关闭所有浏览器后恢复跟随）。')) return;
    sp.disabled = true;
    rs.disabled = true;
    st.textContent = '正在停止…';
    xhr('POST', '/api/stop', 'stop', function () {
      st.textContent = '服务已停止。本页已不可用，可关闭。';
    }, function () { st.textContent = '停止指令已发出。'; });
  };

  wd.onchange = function () {
    var action = wd.checked ? 'enable' : 'disable';
    st.textContent = wd.checked ? '正在启用跟随开启…' : '正在关闭跟随开启…';
    xhr('POST', '/api/watchdog', action, function (code) {
      if (code !== 200) {
        wd.checked = !wd.checked;
        st.textContent = '操作失败（HTTP ' + code + '）';
        return;
      }
      st.textContent = wd.checked ? '跟随开启：已启用（看门狗运行中）' : '跟随开启：已关闭';
    }, function () {
      wd.checked = !wd.checked;
      st.textContent = '操作失败：网络错误';
    });
  };
})();
</script>
<script>
(function () {
  var cell = document.getElementById('ca-cell');
  if (!cell) return;
  var isFirefox = /firefox/i.test(navigator.userAgent) && !/seamonkey/i.test(navigator.userAgent);
  if (!isFirefox) return;
  var box = document.createElement('div');
  box.style.cssText = 'margin:14px 0;padding:16px;border:1px solid #f59e0b;border-radius:10px;background:rgba(245,158,11,.08)';
  var btn = document.createElement('button');
  btn.textContent = 'Firefox 一键自动配置证书（推荐）';
  btn.style.cssText = 'background:linear-gradient(180deg,#f59e0b,#d97706);color:#fff;font-weight:600;padding:11px 24px;border:0;border-radius:8px;cursor:pointer;font-size:14px';
  var out = document.createElement('div');
  out.style.cssText = 'margin-top:10px;font-size:13px;line-height:1.7;display:none';
  btn.addEventListener('click', function () {
    btn.disabled = true;
    out.style.display = 'block';
    out.textContent = '正在写入 Firefox 证书策略...';
    fetch('/firefox-setup', { method: 'POST', headers: { 'X-GW-Action': 'setup' } })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function () {
        out.innerHTML = '<b style="color:#39d98a">配置成功。</b>请<b>完全重启 Firefox</b>（关闭所有 Firefox 窗口后重新打开），证书即生效。<br>重启后刷新此前报 SEC_ERROR_UNKNOWN_ISSUER 的页面即可。';
      })
      .catch(function (e) {
        btn.disabled = false;
        out.innerHTML = '<b style="color:#ff6b6b">自动配置失败：</b>' + e.message + '，请改用下方手动步骤。';
      });
  });
  box.appendChild(btn);
  box.appendChild(out);
  var manual = document.createElement('details');
  manual.style.cssText = 'margin-top:12px;font-size:13px';
  manual.innerHTML = '<summary style="cursor:pointer;color:#7dd3fc">手动配置步骤（不想用一键方式时）</summary>' +
    '<div style="margin-top:8px;line-height:1.8">' +
    'Firefox 出于安全策略禁止网页直接跳转 about: 设置页，需把下面地址粘贴到地址栏：<br>' +
    '<code>about:preferences#privacy</code> <button type="button" id="cp-pref" style="cursor:pointer">复制</button><br>' +
    '回车打开「隐私与安全」→ 滚动到最底部「证书」→ <b>查看证书</b> → <b>导入</b> → 选择 <a href="/ca.crt">下载的 ca.crt</a> → 勾选<b>「信任此 CA 以标识网站」</b> → 确定。<br>' +
    '<a href="#" id="undo-policy" style="color:#94a3b8;font-size:12px">撤销一键自动配置（删除策略）</a>' +
    '</div>';
  box.appendChild(manual);
  cell.insertBefore(box, cell.firstChild);
  manual.addEventListener('click', function (ev) {
    if (ev.target && ev.target.id === 'cp-pref') {
      ev.preventDefault();
      navigator.clipboard.writeText('about:preferences#privacy').then(function () { ev.target.textContent = '已复制'; });
    }
    if (ev.target && ev.target.id === 'undo-policy') {
      ev.preventDefault();
      fetch('/firefox-setup', { method: 'POST', headers: { 'X-GW-Action': 'remove' } })
        .then(function (r) { return r.json(); })
        .then(function () { alert('已删除策略，重启 Firefox 后生效'); });
    }
  });
})();
</script>
<div style="max-width:720px;margin:0 auto 30px;font-size:11px;color:#475569;line-height:1.7;border-top:1px solid #1e293b;padding-top:12px">
本项目为本地网络调试与开发辅助工具，仅供合法用途；使用者须遵守所在司法辖区法律法规并自行承担全部责任。
本项目不提供任何网络信道或服务节点，按「现状」提供且无任何保证。完整免责声明见项目根目录 DISCLAIMER.md。AGPL-3.0-or-later · 白小谦
</div>
</body></html>`);
}

/* ---------------- 主请求处理 ---------------- */

const RELAY_FORCED = Symbol('relayForced');
const schemeForPort = p => [80, 8080, 8000, 8888].includes(Number(p)) ? 'http' : 'https';

function targetFromMitmHost(hostHeader, reqPath) {
  const hp = String(hostHeader || '');
  let hostPart = hp, portPart = 443;
  if (hp.startsWith('[')) {
    const e = hp.indexOf(']');
    if (e > 0) {
      hostPart = hp.slice(1, e);
      const after = hp.slice(e + 1);
      if (after.startsWith(':')) portPart = Number(after.slice(1)) || 443;
    }
  } else {
    const ci = hp.lastIndexOf(':');
    if (ci > 0) { hostPart = hp.slice(0, ci); portPart = Number(hp.slice(ci + 1)) || 443; }
  }
  const portInUrl = (schemeForPort(portPart) === 'http' && portPart !== 80) || (schemeForPort(portPart) === 'https' && portPart !== 443);
  return new URL(`${schemeForPort(portPart)}://${hostPart}${portInUrl ? ':' + portPart : ''}${reqPath}`);
}

async function handleProxyRequest(req, res, opts) {
  opts = opts || {};
  let target;
  try {
    if (opts.httpsHost) {
      target = targetFromMitmHost(opts.httpsHost, req.url);
    } else if (/^https?:\/\//i.test(req.url)) {
      target = new URL(req.url);
    } else {
      return serveLocal(req, res);
    }
  } catch (e) {
    return plainError(res, 400, '无法解析目标地址：' + e.message);
  }

  if (!/^https?:$/.test(target.protocol)) return plainError(res, 400, '仅支持 http/https 目标');
  if (isLoopbackSelf(target)) return serveLocal(req, res);
  if (!config.security.allowPrivateTargets && isPrivateHost(target.hostname)) {
    return plainError(res, 403, '已按安全策略拦截内网/环回目标（config.json → security.allowPrivateTargets 可放开）');
  }

  const method = (req.method || 'GET').toUpperCase();
  const route = opts[RELAY_FORCED] ? 'relay' : decideRoute(target.hostname);

  try {
    let bodyBuf = null;
    const cl = Number(req.headers['content-length'] || 0);
    if (cl > 0 || /chunked/i.test(String(req.headers['transfer-encoding'] || ''))) {
      bodyBuf = await readBody(req, config.relay.maxBodyBytes);
    }

    if ((route === 'probe' || route === 'direct')) {
      const done = await tryDirect(target, method, buildForwardHeaders(req), bodyBuf, res, config.targeted.directTimeout);
      if (done) {
        if (route === 'probe') setRouteCache(target.hostname, 'direct');
        line('直连', C.green, target.hostname);
        return;
      }
      if (route === 'probe') setRouteCache(target.hostname, 'relay');
      else if (config.mode === 'list') {
        return plainError(res, 502, `名单模式：${target.hostname} 不在名单内且直连失败，已按规则拒绝中转`);
      }
    }

    await fetchViaRelay(target, method, buildForwardHeaders(req), bodyBuf, wantBuffer(target.hostname), res);
    line('中转', C.magenta, target.hostname);
  } catch (e) {
    if (e && e.code === 'BODY_TOO_LARGE') return plainError(res, 413, e.message);
    warn(`中转失败 ${target.href}：${e.message}`);
    if (!res.headersSent) plainError(res, 502, `网关中转失败：${e.message}`);
    else { try { res.destroy(); } catch (_) {} }
  }
}

/* ---------------- HTTPS 隧道（CONNECT） ---------------- */

function parseConnectTarget(raw) {
  let m = String(raw).match(/^\[([0-9a-fA-F:.]+)\]:(\d+)$/);
  if (m) return { host: m[1], port: Number(m[2]) };
  m = String(raw).match(/^([^:]+):(\d+)$/);
  if (m) return { host: m[1], port: Number(m[2]) };
  return { host: String(raw), port: 443 };
}

const mitmServer = http.createServer({ maxHeaderSize: 262144 }, (req, res) => {
  handleProxyRequest(req, res, { [RELAY_FORCED]: true, httpsHost: req.headers.host });
});
mitmServer.on('clientError', (e, sock) => { try { sock.destroy(); } catch (_) {} });

function onConnect(req, clientSock, head) {
  const { host, port } = parseConnectTarget(req.url);
  clientSock.on('error', () => {});
  let settled = false;

  if (!config.security.allowPrivateTargets && isPrivateHost(host)) {
    try { clientSock.end('HTTP/1.1 403 Forbidden\r\n\r\n'); } catch (_) {}
    return;
  }

  if (decideRoute(host) === 'relay') return startMitmRelay();
  if (config.mode === 'list') return spliceDirect(false); // 名单模式：仅直连，失败也不中转

  // 针对模式：先用 TLS 探测目标可达性（能发现 SNI 阻断/重置），探测成功后
  // 另开一条原始 TCP 连接做透明隧道——隧道内由浏览器与目标端到端握手并校验证书。
  const probe = tls.connect({ host, port, servername: host, timeout: config.targeted.directTimeout }, () => {
    if (settled) return;
    settled = true;
    setRouteCache(host, 'direct');
    try { probe.destroy(); } catch (_) {}
    spliceDirect(true);
  });
  const probeFail = () => {
    try { probe.destroy(); } catch (_) {}
    if (settled) return;
    settled = true;
    setRouteCache(host, 'relay');
    startMitmRelay();
  };
  probe.on('timeout', probeFail);
  probe.on('error', probeFail);

  function spliceDirect(fallbackRelay) {
    const raw = net.connect(port, host);
    raw.setNoDelay(true);
    let rawUp = false;
    raw.on('connect', () => {
      rawUp = true;
      clientSock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) raw.write(head);
      clientSock.pipe(raw);
      raw.pipe(clientSock);
      line('直连', C.green, host);
    });
    raw.on('error', () => {
      try { raw.destroy(); } catch (_) {}
      if (rawUp) { try { clientSock.destroy(); } catch (_) {} return; }
      if (fallbackRelay) startMitmRelay(); // 探测通过但隧道建不起来（极少数情况），退回中转
      else { try { clientSock.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); } catch (_) {} }
    });
    clientSock.on('close', () => { try { raw.destroy(); } catch (_) {} });
  }

  function startMitmRelay() {
    if (!FORGE_OK) {
      errlog(`HTTPS 中转需要依赖 node-forge（在网关目录执行 npm install），${host}:${port} 已放弃`);
      try { clientSock.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); } catch (_) {}
      return;
    }
    try {
      clientSock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) clientSock.unshift(head);
      const tlsSock = new tls.TLSSocket(clientSock, { isServer: true, secureContext: getSecureContext(host) });
      tlsSock.on('error', () => { try { tlsSock.destroy(); } catch (_) {} });
      mitmServer.emit('connection', tlsSock);
      line('中转', C.magenta, host);
    } catch (e) {
      errlog(`建立 HTTPS 隧道失败 ${host}：${e.message}`);
      try { clientSock.destroy(); } catch (_) {}
    }
  }
}

/* ---------------- 启动 ---------------- */

const server = http.createServer({ maxHeaderSize: 262144 }, (req, res) => handleProxyRequest(req, res, {}));
server.on('connect', onConnect);
server.on('clientError', (e, sock) => { try { sock.destroy(); } catch (_) {} });
let listenRetries = 0;
server.on('error', e => {
  if (e.code === 'EADDRINUSE' && listenRetries < 3) {
    listenRetries++;
    info(`端口 ${config.port} 暂被占用（新实例切换中），${listenRetries}/3 次重试…`);
    setTimeout(() => { try { server.close(); } catch (_) {} server.listen(config.port, config.host); }, 1200);
    return;
  }
  if (e.code === 'EADDRINUSE') {
    errlog(`端口 ${config.port} 被占用：服务可能已在后台运行。如需重启请先停止旧实例。`);
    process.exit(1);
  }
  errlog('服务错误：' + e.message);
});

function maybeAutoInstallCA() {
  if (process.platform !== 'win32' || !config.cert.autoInstall || !FORGE_OK) return;
  const marker = path.join(CERT_DIR, '.installed');
  if (fs.existsSync(marker)) return;
  fs.writeFileSync(marker, new Date().toISOString());
  info('正在请求安装本地 CA 证书，如弹出安全警告窗口请点击【是】...');
  const { spawn } = require('child_process');
  const ps = `Import-Certificate -FilePath "${CA_CERT_FILE}" -CertStoreLocation Cert:\\CurrentUser\\Root`;
  const child = spawn('powershell.exe', ['-NoProfile', '-Command', ps], { stdio: 'ignore' });
  child.on('exit', code => {
    if (code === 0) oklog('CA 证书已安装，HTTPS 中转可正常工作');
    else warn('CA 证书未安装（HTTPS 中转会报证书错误）。可双击「install-ca.cmd」重新安装');
  });
}

server.listen(config.port, config.host, () => {
  const eps = relayEndpoints();
  const modeText = config.mode === 'global' ? '全局模式（全部走中转）'
    : config.mode === 'list' ? `名单模式（${(config.relayList || []).length} 个域名强制中转，其余仅直连）`
    : '针对模式（先直连，失败才中转）';
  console.log('');
  console.log('  ┌─────────────────────────────────────────────────────┐');
  console.log('  │            QianVPN Gateway  ·  本地代理网关          │');
  console.log('  └─────────────────────────────────────────────────────┘');
  console.log('');
  console.log(`  监听地址 : http://${config.host}:${config.port}`);
  console.log(`  当前模式 : ${modeText}`);
  console.log(`  中转节点 : ${eps.length} 个`);
  eps.forEach((e, i) => console.log(`     #${i + 1} ${e.base}${e.passthrough ? '  [透传模式]' : ''}${e.matchDomains ? '  [专属: ' + e.matchDomains.join(',') + ']' : ''}`));
  if (!eps.length) {
    console.log('');
    console.log('  ⚠ 尚未配置任何中转节点——本项目不内置任何站点，请先部署你自己的：');
    console.log('     双击「一键部署中转服务.cmd」（约 2 分钟，自动部署并写入配置）');
  }
  console.log(`  流缓冲   : ${config.buffer.enabled ? '开启' : '关闭'}（buffer.domains 命中的域名强制 buffer=true）`);
  console.log(`  CA 证书  : ${FORGE_OK ? '已就绪 (' + path.relative(ROOT, CA_CERT_FILE) + ')' : '未生成（缺 node-forge，HTTPS 中转不可用）'}`);
  console.log('');
  console.log('  下一步：Windows 设置 → 网络和 Internet → 代理 → 手动设置代理');
  console.log(`     地址 ${config.host}    端口 ${config.port}`);
  console.log('');
  console.log('  关闭本窗口即停止服务。网关状态页：http://127.0.0.1:' + config.port + '/');
  console.log('');
  maybeAutoInstallCA();
});
