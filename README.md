# QianVPN Gateway · 本地请求代理网关

> ⚠️ **重要法律声明（务必阅读）**
>
> 本项目是一个**本地网络调试与开发辅助工具**，仅供计算机网络技术研究、软件开发调试、以及访问**您拥有合法权限的自有资源**等合法用途。
>
> - 本项目**不内置、不提供、不运营**任何网络信道或服务节点（全部由使用者自行部署）；
> - 使用者须**遵守所在司法辖区的一切法律法规**。在中国大陆，未经批准擅自建立、使用非法定信道进行国际联网属违法行为，本项目**不得**用于此类或任何违法用途；
> - 本项目按「现状」提供，**无任何保证**；作者对使用本项目产生的任何直接、间接损失**概不负责**；
> - 下载或使用本项目即视为您已阅读并同意[完整免责声明（DISCLAIMER.md）](DISCLAIMER.md)的全部条款。**不同意请勿使用。**

---

> 双击即用的本地代理网关：直连优先、失败自动中转——把「本机访问不了的内容」通过你**自己部署**的中转服务代理出去。
>
> **作者**：白小谦 ｜ **反馈邮箱**：[qianxlfk@163.com](mailto:qianxlfk@163.com) ｜ **协议**：[AGPL-3.0-or-later](LICENSE) ｜ **免责**：[DISCLAIMER.md](DISCLAIMER.md)

---

## 它是什么

一个跑在本机的小型 HTTP 代理网关（Windows 系统代理），核心思路是「**能直连的绝不绕路，直连失败的才走中转**」：

```
浏览器 ──系统代理──▶ 网关 (127.0.0.1:8899)
                      │
                      ├─ 目标直连可达？──▶ 直接转发（HTTPS 为透明隧道，不解密）
                      │
                      └─ 直连失败（被墙/超时/重置/DNS污染）
                             │
                             ▼
                     你自己部署的中转端点（Netlify / Cloudflare，免费）
                             │
                             ▼
                          目标站点
```

**本项目不内置任何中转站点**——服务端代码就在仓库里（`deploy/`、`cf-worker/`），双击 `deploy-relay.cmd` 一键部署到你自己的 Netlify 账号，2 分钟完成。

## 功能特性

- 🚀 **三种模式**：针对模式（自动探测直连/中转）、全局模式（全部中转）、名单模式（关键词/域名名单，名单内中转、名单外仅直连）
- 🔑 **关键词匹配**：名单里写 `claude` 即命中 `claude.ai`、`claude.com` 等任何包含它的域名；写 `google.com` 则按域名（含全部子域）匹配
- 📡 **透传中转**：原始方法/请求头/请求体原样转发——表单 POST、文件上传、流式响应（AI 对话逐字输出）无损
- 🌍 **按域名选出口**：端点支持 `matchDomains`（例如某站点需要特定地区的出口 IP 时分流）
- 🖥️ **Web 控制台**（`http://127.0.0.1:8899/`）：配置编辑器（程序生成 JSON，杜绝手改语法错误）、一键重启、停止服务、跟随开启
- 🐕 **跟随开启**：检测到 Edge / Firefox / Chrome 启动而服务未开时，后台**静默**自动开启（不弹窗）；可随系统自启
- 🔐 **本地 CA 自动管理**：首次运行自动生成并请求安装；Firefox 一键配置（策略方式导入）
- 🛡️ **安全默认**：拦截内网/环回目标（防 SSRF）、中转端点 token 鉴权 + 私网目标黑名单
- 🧹 **干净日志**：控制台只输出域名级别的路由日志（直连/中转）

## 快速开始（三步）

### 第 1 步：部署你自己的中转服务（约 2 分钟，免费）

前置：安装 [Node.js LTS](https://nodejs.org)。

双击 **`deploy-relay.cmd`**——会弹出浏览器让你登录/授权 Netlify（免费账号），之后全自动：创建站点 → 部署服务端 → 把端点写入 `config.json`。

<details>
<summary>手动部署（不想用一键脚本）</summary>

```bash
cd deploy/netlify
npm install -g netlify-cli   # 或使用 npx
netlify login                 # 浏览器授权
# 把两个 relay.js 里的 REPLACE_WITH_TOKEN 改成你编的随机串
netlify sites:create --name 你的站点名
netlify deploy --prod --dir .
```

然后在 `config.json` 的 `relay.endpoints` 里加：

```json
{ "url": "https://你的站点名.netlify.app/relay/你的TOKEN/", "mode": "passthrough" }
```
</details>

<details>
<summary>备选：Cloudflare Worker 版（需自有域名）</summary>

`cf-worker/src/worker.js` 是等价的 Cloudflare Worker 实现。注意 `*.workers.dev` 域名在中国大陆多数网络无法直连，建议有自己域名时绑定使用；Cloudflare 自家 IP 对部分带盾站点的通过率也更好。部署方法见文件头注释。
</details>

### 第 2 步：启动网关

双击 **`start-gateway.cmd`**（首次自动安装依赖）。看到启动横幅即成功；弹出的 CA 证书安全警告点【是】。

### 第 3 步：设置系统代理

Windows 设置 → 网络和 Internet → 代理 → 手动设置代理 → 开，地址 `127.0.0.1` 端口 `8899`。

浏览器访问 <http://127.0.0.1:8899/> 可看到状态页（配置编辑器 / 服务控制都在这里）。**Firefox 用户**在状态页点「一键自动配置证书」（Firefox 用独立证书库，需额外一步）。

## 三种模式

| 模式 | `"mode"` 值 | 行为 |
|---|---|---|
| 针对模式（默认） | `"targeted"` | 每个目标先尝试直连，失败（被墙/超时/重置）才自动转中转，判定结果按域名缓存 5 分钟 |
| 全局模式 | `"global"` | 所有请求一律走中转 |
| 名单模式 | `"list"` | `relayList` 名单内强制中转；名单外仅直连（直连失败也不中转） |

名单/域名类配置统一规则：**带点 = 域名匹配**（含全部子域），**不带点 = 关键词**（域名包含即命中）。

## 目录结构

```
├── start-gateway.cmd        # 双击启动网关（关窗口即停）
├── deploy-relay.cmd         # 双击一键部署中转服务（Netlify）
├── install-ca.cmd           # 手动安装本地 CA 证书
├── proxy.js                 # 网关主程序（用户端）
├── watchdog.js              # 跟随开启看门狗（静默）
├── watchdog-hidden.vbs      # 看门狗隐藏启动器
├── config.json              # 全部配置（建议用状态页 Web UI 修改）
├── deploy/
│   ├── deploy-server.js     # 一键部署逻辑（登录/建站/部署/写配置）
│   └── netlify/             # 服务端源码（Netlify 站点）
│       ├── netlify.toml
│       └── netlify/
│           ├── edge-functions/relay.js   # Edge Function 透传版（主力，无 30s 限制）
│           └── functions/relay.js        # 普通 Function 透传版（备用，出口地区不同）
└── cf-worker/               # 服务端源码（Cloudflare Worker 备选）
```

## 配置说明

推荐直接在状态页的「配置编辑器」改（保存后点「一键重启服务」生效）。手动编辑 `config.json` 时注意：JSON 语法严格（不要中文标点、不要尾随逗号），改完必须重启网关。

关键字段：

```jsonc
{
  "port": 8899,                  // 监听端口（系统代理里填的）
  "mode": "targeted",           // targeted / global / list
  "relayList": ["google"],      // 名单模式的关键词/域名名单

  "relay": {
    "endpoints": [              // 中转端点（一键部署后自动填好）
      { "url": "https://xxx.netlify.app/relay/token/", "mode": "passthrough" },
      "https://query格式节点/api/"          // 也兼容 query 参数格式节点
    ],
    "timeout": 300000,          // 中转整体超时（buffer 模式的最长等待）
    "firstByteTimeout": 30000,  // 非缓冲模式：首字节超时（超时换下一个端点）
    "maxBodyBytes": 2097152     // 走中转的请求体上限（query 格式节点受 URL 长度所限）
  },

  "buffer": {                   // 流缓冲：AI 长流域名建议加入（query 格式节点需要；透传端点无需）
    "enabled": false,
    "domains": ["gemini.google.com"]
  },

  "targeted": {
    "directTimeout": 4000,      // 直连探测超时
    "cacheSeconds": 300,        // 直连/中转判定缓存
    "forceRelayDomains": [],    // 强制中转（targeted 模式下）
    "directDomains": []         // 强制直连
  },

  "security": { "allowPrivateTargets": false }  // 是否放行内网目标（默认拦截）
}
```

端点对象还支持 `matchDomains`：命中域名的请求优先走该端点（例如对出口地区敏感的站点分流到特定端点）。

## 已知限制（实测经验）

- **Cloudflare 盾/风控站点**：部分 AI 站点（如 ChatGPT、Grok）对数据中心 IP 风控严格，且对出口地区敏感——Netlify Edge 出口在新加坡、普通 Function 出口在美国（可用 `matchDomains` 分流尝试），仍被拦时建议使用绑定了自有域名的 Cloudflare Worker（CF 自家 IP）或住宅出口
- **query 格式节点**（`?url=...&method=...`）：body 只支持 JSON 键值、受 30 秒平台限制——**建议优先使用透传端点**
- **WebSocket（wss://）** 无法经中转代理（直连的 wss 不受影响）
- 透传端点的请求体上限与平台相关；Netlify Edge 实测流式响应可稳定超过 60 秒
- 系统代理开启期间网关必须运行（看门狗的「跟随开启」可自动兜底）

## 常见问题

| 现象 | 处理 |
|---|---|
| HTTPS 站点报 `SEC_ERROR_UNKNOWN_ISSUER` | Firefox：状态页点「一键自动配置证书」；Chrome/Edge 重启网关后自动装过则无需处理 |
| 启动提示端口被占用 | 服务可能已在后台运行；或改 `config.json` 的 `port` |
| 修改配置不生效 | 必须重启（状态页「一键重启服务」或关窗口重开） |
| 想停服务但过会儿又自动开了 | 跟随开启在起作用：用状态页「停止服务」按钮（本轮浏览器会话内不再自动开）；或关掉跟随开启 |
| 某站直连可达但时好时坏 | 加进 `targeted.forceRelayDomains` 强制中转 |
| 中转节点死了 | 配置多个端点自动容灾切换；一键部署的站点含 Edge + Function 双端点 |

## 开发

```bash
npm install     # 安装 node-forge（HTTPS 中转证书）
npm start       # 启动网关
npm run deploy-relay   # 一键部署服务端
```

环境变量：`QGV_PORT`（覆盖端口）、`QGV_MODE`（覆盖模式）。

## 许可

本项目以 [AGPL-3.0-or-later](LICENSE) 协议开源。使用、修改、分发请遵循协议要求（衍生网络服务同样需要开源）。

## 致谢与反馈

- 作者：白小谦
- 反馈邮箱：[qianxlfk@163.com](mailto:qianxlfk@163.com)

问题反馈时请附：网关启动横幅截图、状态页路由日志（只含域名）、复现步骤。
