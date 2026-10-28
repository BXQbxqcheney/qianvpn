#!/usr/bin/env node
/**
 * QianVPN Gateway 看门狗（静默版）
 * 作者：白小谦 ｜ 协议：AGPL-3.0-or-later
 *
 *  - 检测 Edge/Firefox/Chrome 任一在运行、网关未启动、且无停止标记 → 后台静默拉起网关（不弹窗）
 *  - 停止标记（watchdog.stop）：用户在 UI 主动停止服务时写入，看门狗看到绝不拉起；
 *    当浏览器从「有在运行」变为「全部关闭」时自动清除标记（下次打开浏览器恢复跟随）
 *  - 由 watchdog-hidden.vbs 隐藏启动；单例锁占用 8898 端口
 */
'use strict';

const net = require('net');
const path = require('path');
const fs = require('fs');
const { spawn, execFile } = require('child_process');

const ROOT = __dirname;
const GW_ENTRY = path.join(ROOT, 'proxy.js');
const STOP_FILE = path.join(ROOT, 'watchdog.stop');
const GW_PORT = 8899;
const BROWSERS = ['msedge.exe', 'firefox.exe', 'chrome.exe'];
const CHECK_INTERVAL = 3000;

let lastBrowserSeen = false;

const lock = net.createServer(() => {});
lock.once('error', () => process.exit(0));
lock.listen(8898, '127.0.0.1', () => setInterval(check, CHECK_INTERVAL));

function gwAlive(cb) {
  const s = net.connect(GW_PORT, '127.0.0.1');
  let done = false;
  const finish = v => { if (!done) { done = true; try { s.destroy(); } catch (_) {} cb(v); } };
  s.on('connect', () => finish(true));
  s.on('error', () => finish(false));
  s.setTimeout(1500, () => finish(false));
}

function anyBrowserRunning(cb) {
  let left = BROWSERS.length, found = false;
  for (const name of BROWSERS) {
    execFile('tasklist', ['/FI', 'IMAGENAME eq ' + name, '/NH'], { windowsHide: true, timeout: 5000 }, (err, out) => {
      if (!err && out && !/INFO:/i.test(out) && out.toLowerCase().includes(name)) found = true;
      if (--left === 0) cb(found);
    });
  }
}

let launching = false;
function check() {
  anyBrowserRunning(hasBrowser => {
    // 浏览器从「有」到「全部关闭」：一轮会话结束，清除停止标记（下次开浏览器恢复跟随）
    if (lastBrowserSeen && !hasBrowser) {
      try { if (fs.existsSync(STOP_FILE)) fs.unlinkSync(STOP_FILE); } catch (_) {}
    }
    lastBrowserSeen = hasBrowser;
    if (!hasBrowser || launching) return;
    if (fs.existsSync(STOP_FILE)) return; // 用户主动停止过，本轮浏览器会话内不再拉起
    gwAlive(alive => {
      if (alive || launching) return;
      launching = true;
      const child = spawn(process.execPath, [GW_ENTRY], {
        cwd: ROOT, detached: true, stdio: 'ignore', windowsHide: true
      });
      child.on('error', () => {});
      child.unref();
      setTimeout(() => { launching = false; }, 20000);
    });
  });
}
