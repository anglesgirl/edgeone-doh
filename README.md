# EdgeOne Pages DoH 部署指南

免服务器 DoH：规则注入（域名→自定义 IP）+ ECH 注入 + iOS 描述文件。
EdgeOne Pages Functions + KV 存储，国际站免备案。

## 目录结构

```
dohd-edge/
├── functions/
│   ├── index.js               # DoH 主逻辑（/dns-query, /resolve）
│   ├── admin.js               # 管理 API（/admin, /admin?domain=X DELETE）
│   └── profile.mobileconfig.js # iOS 描述文件（/profile.mobileconfig）
├── edgeone.json               # 函数路由配置
└── README.md
```

## 部署步骤

### 1. 准备
- 注册 EdgeOne 国际站：https://pages.edgeone.ai （免备案）
- 安装 CLI：`npm install -g edgeone`

### 2. 创建项目
```bash
cd dohd-edge
edgeone pages init          # 初始化
edgeone pages link          # 关联项目
```

### 3. 绑定 KV 存储
控制台 → 项目 → KV 存储 → 创建命名空间（如 `doh-kv`）→ 绑定变量名 **`KV`**
（代码里用 `env.KV.get/put`）

### 4. 设置环境变量
| 变量 | 值 | 说明 |
|---|---|---|
| `ADMIN_TOKEN` | 自定义强密码 | 管理后台认证 |
| `DOH_DOMAIN` | `your-doh.edgeone.app` | iOS 描述文件里的 DoH 域名 |

### 5. 配置路由（edgeone.json 已带，或控制台配置）
- `/dns-query` → index（GET+POST）
- `/resolve` → index（GET）
- `/admin` → admin（GET/POST/DELETE）
- `/profile.mobileconfig` → profile.mobileconfig（GET）

### 6. 部署
```bash
git push   # 或 edgeone pages deploy
```

## 使用

### 添加规则（管理 API）
```bash
# 添加：AO3 → CF 共享 IP + ECH
curl -X POST https://your-doh.edgeone.app/admin \
  -H "X-Admin-Token: YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"archiveofourown.org","ips":["172.67.187.141","104.20.9.2"],"ech":true}'

# 列表
curl https://your-doh.edgeone.app/admin -H "X-Admin-Token: YOUR_TOKEN"

# 删除
curl -X DELETE "https://your-doh.edgeone.app/admin?domain=archiveofourown.org" \
  -H "X-Admin-Token: YOUR_TOKEN"
```

### iOS 用户配置
Safari 打开：`https://your-doh.edgeone.app/profile.mobileconfig` → 安装描述文件
（系统 DNS 全部走 DoH：防污染 + 规则域自定义 IP + ECH）

### 测试 DoH
```bash
# 标准 DoH（wire format）
curl -s -X POST https://your-doh.edgeone.app/dns-query \
  -H "Content-Type: application/dns-message" --data-binary @query.bin

# JSON 调试
curl -s "https://your-doh.edgeone.app/resolve?name=archiveofourown.org&type=A" \
  -H "Accept: application/dns-json"
```

## 架构

```
EdgeOne Pages（国际站，免备案，海外节点）
├─ /dns-query  POST wire / GET ?dns=
│    ├─ 规则命中 A  → 返回自定义 IP（绕过污染 + 封 IP）
│    ├─ 规则命中 HTTPS → 注入 ECH（从 cloudflare-ech.com 获取，KV 缓存 5min）
│    └─ 未命中 → 上游转发（CF Gateway / Google 8.8.8.8）
├─ /admin      规则管理（KV 存储，60s 最终一致）
└─ /profile.mobileconfig  iOS 描述文件（点装）
```

## 上游说明
- 上游用 CF Gateway（cloudflare-dns.com）+ Google（dns.google）双保险。
- CF 未被墙但国内直连慢——**注意**：EdgeOne 节点在海外，服务器侧访问 CF/Google 都是快的；
  国内用户访问的是 EdgeOne 边缘节点（快），不直连上游。
- 唯一注意：EdgeOne 若选中国站节点需要备案；国际站（pages.edgeone.ai）免备案。

## KV 键
| Key | 内容 |
|---|---|
| `rule:<domain>` | `{"domain":"...","ips":[...],"ech":true}` |
| `rules:index` | 域名列表 `["a.com","b.org"]` |
| `ech:config` | `{"ech":"base64...","ts":1234}`（5 分钟缓存） |

## 已知限制
- KV 最终一致性 ~60s：改规则后稍等生效。
- DoH 是低频协议（TTL 缓存），额度消耗极低，免费额度足够。
- /admin 无页面 UI（纯 API）；需要 UI 可后续加。
