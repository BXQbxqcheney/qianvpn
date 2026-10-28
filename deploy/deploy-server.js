#!/usr/bin/env node
/**
 * QianVPN Gateway —— 服务端一键部署脚本
 * 作者：白小谦 ｜ 反馈邮箱：qianxlfk@163.com ｜ 协议：AGPL-3.0-or-later
 *
 * 做什么：
 *   1. 引导 Netlify 登录（首次会弹出浏览器授权页，点 Allow 即可）
 *   2. 生成随机 token 写入服务端代码
 *   3. 在 Netlify 创建站点并部署透传中转服务（Edge Function + 普通 Function）
 *   4. 把部署出的端点自动写入网关 config.json（透传模式，置于最前）
 *
 * 用法：在项目根目录执行  node deploy/deploy-server.js  （或双击 deploy-relay.cmd）
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const NETLIFY_DIR = __dirname;
const CONFIG_FILE = path.join(ROOT, 'config.json');
// 仅允许写入 netlify/ 下的两个固定服务端文件（部署前做路径边界校验）
const ALLOWED_FILES = ['netlify/edge-functions/relay.js', 'netlify/functions/relay.js'];

function log(msg) { console.log(msg); }
function die(msg) { console.error('\n[失败] ' + msg); process.exit(1); }

function netlifyCmd() {
  try {
    require('child_process').execFileSync('netlify', ['--version'], { stdio: 'ignore', timeout: 20000, shell: true });
    return ['netlify', []];
  } catch (_) {
    return [process.platform === 'win32' ? 'npx.cmd' : 'npx', ['--yes', 'netlify-cli']];
  }
}

function run(args, opts) {
  const [cmd, prefix] = netlifyCmd();
  const full = prefix.concat(args);
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, full, Object.assign({ cwd: NETLIFY_DIR, shell: true }, opts));
    let out = '';
    if (p.stdout) p.stdout.on('data', c => { out += c; if (!opts || opts.silent !== true) process.stdout.write(c); });
    if (p.stderr) p.stderr.on('data', c => process.stderr.write(c));
    p.on('error', reject);
    p.on('close', code => code === 0 ? resolve(out) : reject(new Error('命令退出码 ' + code)));
  });
}

async function main() {
  log('');
  log('=====================================================');
  log('   QianVPN Gateway · 服务端一键部署（Netlify 透传版）');
  log('   作者：白小谦 · AGPL-3.0-or-later');
  log('=====================================================');
  log('');

  // 1. 登录检查（未登录则弹浏览器授权）
  log('[1/4] 检查 Netlify 登录状态…');
  let loggedIn = false;
  try {
    await run(['status'], { silent: true });
    loggedIn = true;
    log('      已登录 ✓');
  } catch (_) {
    log('      未登录——即将弹出浏览器，请在页面完成登录/授权后回到本窗口…');
    await run(['login']).catch(e => die('登录失败：' + e.message));
    log('      登录成功 ✓');
  }

  // 2. 生成 token 写入服务端代码
  log('[2/4] 生成访问令牌并写入服务端代码…');
  const token = crypto.randomBytes(12).toString('hex');
  for (const rel of ALLOWED_FILES) {
    const f = path.resolve(NETLIFY_DIR, rel);
    if (f !== NETLIFY_DIR && !f.startsWith(NETLIFY_DIR + path.sep)) {
      die('文件路径越界：' + rel);
    }
    let s = fs.readFileSync(f, 'utf8');
    if (s.includes('REPLACE_WITH_TOKEN')) {
      s = s.split('REPLACE_WITH_TOKEN').join(token);
      fs.writeFileSync(f, s);
    }
  }
  log('      token: ' + token);

  // 3. 创建站点并部署
  log('[3/4] 创建 Netlify 站点并部署…');
  const name = 'qianrelay-' + crypto.randomBytes(3).toString('hex');
  const createOut = await run(['sites:create', '--name', name]).catch(e => die('创建站点失败：' + e.message));
  const m = String(createOut).match(/URL:\s*(https:\/\/\S+\.netlify\.app)/);
  if (!m) die('未能从输出中解析站点地址，请到 https://app.netlify.com 查看');
  const siteUrl = m[1];
  log('      站点：' + siteUrl);
  await run(['deploy', '--prod', '--dir', '.']).catch(e => die('部署失败：' + e.message));
  log('      部署完成 ✓');

  // 4. 写入网关配置
  log('[4/4] 写入网关配置…');
  const edgeEp = { url: siteUrl + '/relay/' + token + '/', mode: 'passthrough' };
  const funcEp = { url: siteUrl + '/.netlify/functions/relay/' + token + '/', mode: 'passthrough' };
  let cfg = {};
  try { cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch (_) { /* 新建 */ }
  cfg.relay = cfg.relay || {};
  const eps = Array.isArray(cfg.relay.endpoints) ? cfg.relay.endpoints : [];
  // 去掉同站旧端点，新端点置于最前
  const filtered = eps.filter(e => !(typeof e === 'object' && e.url && e.url.includes(siteUrl)));
  cfg.relay.endpoints = [edgeEp, funcEp].concat(filtered);
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + '\n');
  log('      config.json 已更新（透传端点 x2）');

  log('');
  log('=====================================================');
  log('   部署成功！');
  log('   下一步：双击 start-gateway.cmd 启动网关即可使用。');
  log('   状态页 http://127.0.0.1:8899/ 可查看端点与进一步配置。');
  log('   token 请妥善保管（已写入 config.json 与服务端代码）：');
  log('   ' + token);
  log('=====================================================');
}

main().catch(e => die(e.message));
