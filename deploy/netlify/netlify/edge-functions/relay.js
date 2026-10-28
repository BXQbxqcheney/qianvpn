/**
 * QianVPN 透传中转（Netlify Edge Function 版，主力端点）
 * 作者：白小谦 ｜ 协议：AGPL-3.0-or-later
 *
 * 路由：/relay/<token>/<目标URL>  —— 原始方法/请求头/请求体原样转发，支持流式响应（无 30 秒限制）
 * 自测：/__stream?duration=60     —— 模拟 AI 的 SSE 长流（首字节立即返回，每秒推送）
 *
 * token 由 deploy-server.js 部署时随机生成并写入（REPLACE_WITH_TOKEN 占位）。
 */

const TOKEN = 'REPLACE_WITH_TOKEN';

// 只允许公网目标：协议白名单 + 主机名/字面 IP 私网拦截
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

const STRIP_HEADERS = ['host', 'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip',
  'client-ip', 'via', 'forwarded'];

export default async (request) => {
  const u = new URL(request.url);

  // 自测端点：模拟 AI 的 SSE 长流（首字节立即返回，之后每秒推送一次）
  if (u.pathname.startsWith('/__stream')) {
    const dur = Math.min(Number(u.searchParams.get('duration') || 60), 300);
    const enc = new TextEncoder();
    const stream = new ReadableStream({
      async start(ctrl) {
        for (let i = 0; i < dur; i++) {
          ctrl.enqueue(enc.encode('data: tick ' + i + '\n\n'));
          await new Promise(r => setTimeout(r, 1000));
        }
        ctrl.close();
      }
    });
    return new Response(stream, {
      headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' }
    });
  }

  const m = request.url.match(/^https?:\/\/[^/]+\/relay\/([^/]+)\/(https?:\/\/.+)$/);
  if (!m) return new Response('usage: /relay/<token>/<target-url>', { status: 404 });
  if (m[1] !== TOKEN) return new Response('forbidden', { status: 403 });

  let target;
  try { target = new URL(m[2]); } catch (_) { return new Response('bad url', { status: 400 }); }
  if (!isAllowedTarget(target)) return new Response('blocked target', { status: 403 });

  const headers = new Headers(request.headers);
  for (const k of STRIP_HEADERS) headers.delete(k);
  headers.set('accept-encoding', 'identity');

  const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
  return fetch(target.href, {
    method: request.method,
    headers,
    body: hasBody ? request.body : undefined,
    redirect: 'manual' // 30x 原样交回网关处理
  });
};

export const config = { path: ['/relay/*', '/__stream', '/__stream/*'] };
