/**
 * QianVPN 透传中转（Netlify 普通 Function 版，备用端点）
 * 作者：白小谦 ｜ 协议：AGPL-3.0-or-later
 *
 * 与 Edge Function 版功能相同，但受 30 秒执行限制；出口地区可能与 Edge 不同，
 * 适合按 matchDomains 分流给对出口地区敏感的站点（详见网关 matchDomains 配置）。
 *
 * token 由 deploy-server.js 部署时随机生成并写入（REPLACE_WITH_TOKEN 占位）。
 */

const TOKEN = 'REPLACE_WITH_TOKEN';

function isPublicIPv4(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return true;
  const a = Number(m[1]), b = Number(m[2]);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  return true;
}

function isAllowedTarget(url) {
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return false;
  const h = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') ||
      h.endsWith('.internal') || h.endsWith('.localdomain')) return false;
  if (h.includes(':')) {
    if (h === '::1' || h === '::') return false;
    if (/^f[cd]/.test(h) || /^fe[89ab]/.test(h)) return false;
    const mapped = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPublicIPv4(mapped[1]);
    return true;
  }
  return isPublicIPv4(h);
}

const STRIP_HEADERS = new Set(['host', 'content-length', 'connection', 'accept-encoding',
  'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip', 'client-ip', 'via', 'forwarded']);

exports.handler = async (event) => {
  const m = event.path.match(/^\/(?:\.netlify\/functions\/)?relay\/([^/]+)\/(https?:\/\/.+)$/);
  if (!m) return { statusCode: 404, body: 'usage: /relay/<token>/<target-url>' };
  if (m[1] !== TOKEN) return { statusCode: 403, body: 'forbidden' };

  let target;
  try { target = new URL(m[2]); } catch (_) { return { statusCode: 400, body: 'bad url' }; }
  if (!isAllowedTarget(target)) return { statusCode: 403, body: 'blocked target' };

  const headers = {};
  for (const [k, v] of Object.entries(event.headers || {})) {
    if (STRIP_HEADERS.has(k.toLowerCase())) continue;
    headers[k] = Array.isArray(v) ? v.join(', ') : v;
  }
  headers['accept-encoding'] = 'identity';

  const hasBody = !['GET', 'HEAD'].includes(event.httpMethod);
  let body;
  if (hasBody && event.body) {
    body = event.isBase64Encoded ? Buffer.from(event.body, 'base64') : event.body;
  }

  let r;
  try {
    r = await fetch(target.href, {
      method: event.httpMethod,
      headers,
      body,
      redirect: 'manual'
    });
  } catch (e) {
    return { statusCode: 502, body: 'upstream: ' + e.message };
  }

  const buf = Buffer.from(await r.arrayBuffer());
  const outHeaders = {};
  const multi = {};
  for (const [k, v] of r.headers) {
    const lk = k.toLowerCase();
    if (['content-encoding', 'content-length', 'transfer-encoding', 'connection'].includes(lk)) continue;
    if (lk === 'set-cookie') { (multi['set-cookie'] = multi['set-cookie'] || []).push(v); continue; }
    outHeaders[k] = v;
  }
  return {
    statusCode: r.status,
    headers: outHeaders,
    multiValueHeaders: multi,
    body: buf.toString('base64'),
    isBase64Encoded: true
  };
};
