# HTTPS/SVCB Dns Inspector

一个用于可视化查询域名 HTTPS（SVCB/HTTPS type 65）记录并解码 ECH（Encrypted Client Hello）参数的前端应用。支持通过域名查询自动提取 `ech` 字段，也支持手动粘贴 Base64 ECH 进行解析。界面以 React + Vite + Tailwind CSS 构建，并使用 `lucide-react` 图标。

![preview](https://github.com/user-attachments/assets/1c08d725-cf90-4a93-b4d4-69a598c3bb08)

> Powered By models/gemini-3-pro-preview


## 功能特性
- 通过 Google Public DNS JSON API 查询域名 `HTTPS` 记录。
- 自动解析记录中的 `ech` 字段（Base64），展示各字段的含义与原始十六进制字节。
- 支持“手动输入 Base64”模式，便于离线或自定义调试。
- 提供原始字节流 Hex Dump 与偏移扫描提示（检测到非标准头部时自动偏移解码）。
- UI 使用 Tailwind CSS 实现配色与布局，图标使用 `lucide-react`。

## 技术栈
- `React`（函数组件）
- `Vite`（构建与开发服务器，配置文件为 `vite.config.mjs`）
- `Tailwind CSS`（原子化样式）+ `tailwindcss-animate`
- `PNPM`（包管理）
- `lucide-react`（SVG 图标组件，无内置 CSS）

## 系统要求
- 推荐 Node.js `>= 20.19` 或 `>= 22.12`。在 Node `18.x` 下可以构建与预览，但会出现版本警告。
- PNPM `>= 8`（项目中使用的是 `pnpm@10.7.0`）。

## 快速开始
```bash
# 安装依赖
pnpm install

# 开发模式（本地服务）
pnpm run dev

# 生产构建
pnpm run build

# 本地预览构建产物
pnpm run preview -- --port 4173
```

构建完成后，静态产物位于 `dist/`。你可以将 `dist` 的内容直接部署到任意静态托管平台（如 Vercel、Netlify、GitHub Pages）或自行使用 Nginx/Apache 提供服务。

### Nginx 部署示例
```nginx
server {
  listen 80;
  server_name your.domain.com;
  root /path/to/dist;
  index index.html;

  location / {
    try_files $uri $uri/ /index.html; # SPA 路由回退
  }
}
```

## 项目结构
```
├── index.html
├── package.json
├── pnpm-lock.yaml
├── postcss.config.js
├── tailwind.config.js
├── vite.config.mjs
└── src/
    ├── index.css        # Tailwind 入口样式（@tailwind base/components/utilities）
    ├── index.jsx        # 主应用组件（DNS 查询与 ECH 解码）
    └── main.jsx         # 入口挂载文件（导入 index.css）
```

## 使用说明
- 通过域名查询：输入域名（示例 `crypto.cloudflare.com`），点击“解析记录”。应用会调用 `https://dns.google/resolve?name=<domain>&type=HTTPS`，提取记录中的 `ech` 参数并解码展示。
- 手动输入 Base64：切换到“手动输入 Base64”模式，粘贴 `ech` 字段值，点击“解码 Base64”。
- 解析结果：
  - 展示版本（Draft-11/12/13）、配置长度、Key Config ID、KEM 算法、Public Key、Cipher Suites、Max Name Length、Public Name 等字段。
  - 同时展示各字段的原始字节十六进制（含长度前缀）。
  - 若检测到非标准头部（如存在额外前缀），会自动偏移一定字节后再解码，并在界面提示偏移量。

## Tailwind 集成说明
- 已在 `src/index.css` 中导入 Tailwind 指令：
  ```css
  @tailwind base;
  @tailwind components;
  @tailwind utilities;
  ```
- 已配置：
  - `tailwind.config.js` 使用 CommonJS（`module.exports`），以兼容当前 Node 与工具链。
  - `postcss.config.js` 使用 CommonJS（`module.exports`）。
  - `tailwindcss-animate` 插件已启用，可使用动画类（如 `animate-in`）。
- 自定义主题：可在 `tailwind.config.js` 的 `theme.extend` 下添加颜色、字体、阴影等自定义项。

## 关于 lucide-react（无内置 CSS）
- `lucide-react` 仅提供 React 图标组件（SVG），不附带样式。
- 大小与颜色可通过 props 控制：
  ```jsx
  <Shield size={16} color="#22c55e" strokeWidth={1.5} />
  ```
- 或者使用 Tailwind 类（图标继承 `currentColor`）：
  ```jsx
  <Shield className="w-4 h-4 text-emerald-400" />
  ```

## 解析原理（简述）
应用核心逻辑位于 `src/index.jsx`：

- Base64 处理：
  - 清理空白与引号，兼容 URL Safe（将 `-`→`+`、`_`→`/`），并补齐 `=` 填充。
  - 使用 `window.atob` 解码为二进制字符串，再转为 `Uint8Array`。

- 字节读取器 `BinaryReader`：
  - 提供 `readBytes(n) / readUint8 / readUint16` 等方法，带边界检查与偏移维护。

- 解析流程 `attemptParse(bytes, startOffset)`：
  - 可选的“列表长度”（前 2 字节），用于处理某些封装格式。
  - 严格版本检查：识别 `0xFE0D`（Draft-13）、`0xFE0C`（Draft-12）、`0xFE0B`（Draft-11）。未知版本会抛出错误。
  - 严格长度检查：每条配置的 `length` 不得超过剩余字节。
  - 字段读取顺序：`Key Config ID (1)` → `KEM ID (2)` → `Public Key (2+N)` → `Cipher Suites (2+N)` → `Max Name Length (1)` → `Public Name (1+N)`。
  - 解析时对 `Public Key` 与 `Cipher Suites` 等长度前缀与数据进行合并，以便原始 Hex 展示。

- 偏移扫描 `parseECHConfig`：
  - 默认从 offset `0` 尝试。
  - 额外扫描：当字节序列中出现 `0xFE 0x0D` 或 `0xFE 0x0C` 的位置，尝试从该位置以及其前 2 字节处进行解析，以适配非标准前缀。
  - 第一个成功解析且包含至少一条配置的结果将被采纳。

- 映射：
  - `KEM_MAP`：`0x0020`→`DHKEM(X25519, HKDF-SHA256)` 等。
  - `CIPHER_MAP`：`0x0001`→`AES_128_GCM_SHA256`、`0x0002`→`AES_256_GCM_SHA384`、`0x0003`→`CHACHA20_POLY1305_SHA256`。
  - `VERSION_MAP`：`0xFE0D / 0xFE0C / 0xFE0B`。

## 常见问题与排错
- Node 版本警告：
  - 提示 “Vite requires Node.js version 20.19+ or 22.12+”。升级 Node 可消除警告，提高兼容性。

- Vite 配置的 ESM/CJS 问题：
  - 使用 `vite.config.mjs`（ESM）作为 Vite 配置。
  - `postcss.config.js` 与 `tailwind.config.js` 使用 CommonJS 的 `module.exports`，避免 `export default` 在 CJS 环境报错。

- PostCSS 报错 `Unexpected token 'export'`：
  - 将 `postcss.config.js` 改为 CommonJS 格式即可（本项目已修复）。

- DNS 查询失败或无 `ech` 字段：
  - 可能是域名未配置 HTTPS 记录或记录中暂无 `ech` 参数。
  - 检查 `https://dns.google/resolve?name=<domain>&type=HTTPS` 返回数据，确认是否存在 `type=65` 的记录与 `ech=` 参数。

- Base64 解码失败：
  - 检查是否包含非法字符或丢失填充。项目会自动做 URL Safe 兼容与补齐 `=`，但原始数据需有效。

## 参考文档
- IETF ECH 规范（草案）：
  - https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-13
- SVCB/HTTPS 记录（RFC 9460）：
  - https://www.rfc-editor.org/rfc/rfc9460
- Cloudflare Encrypted Client Hello 介绍：
  - https://blog.cloudflare.com/encrypted-client-hello
- Google Public DNS JSON API：
  - https://dns.google/resolve
- Vite 文档：
  - https://vitejs.dev/guide/
- Tailwind CSS 文档：
  - https://tailwindcss.com/docs/installation
- lucide-react 文档：
  - https://lucide.dev/docs/lucide-react
- PNPM 文档：
  - https://pnpm.io/

## 许可证
- 本项目使用 `ISC` 许可证（见 `package.json`）。

## 安全与隐私
- 本项目为纯前端应用，默认使用公共 DNS 接口查询。请注意 API 速率与隐私需求。
- 解析仅展示 ECH 配置内容，不进行任何密钥验证或实际 TLS 握手参与。

