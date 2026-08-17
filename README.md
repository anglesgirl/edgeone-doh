# 云端 DoH（Cloudflare Workers + D1）

免服务器 DoH：规则注入（域名→钦定 IP）+ ECH 注入 + 上游转发。
**Cloudflare Workers + D1 数据库**，配置全部 DB 驱动（改库即生效，不重新部署）。

**线上地址**：`https://res.anglesgirl.eu.org/dns-query`

## 处理逻辑（用户拍板）

| # | 规则 | 行为 |
|---|---|---|
| 1 | **默认** | 所有域名转发上游（CF Gateway，D1 配置，改库即生效） |
| 2 | **列表指定 A**（rules 表） | 用指定 A 记录 |
| 3 | **列表 ech 强注**（rules 表 ech=1） | ECH 注入 + 改解析（钦定 IP） |
| 4 | **CF 托管**（AS13335 判定） | 强注 ECH + 改钦定 IP |
| 5 | **视频域名**（googlevideo.com / c.youtube.com 及子域） | **强制 IPv6**（A 清空，AAAA 透传 —— IPv4 谷歌全段封） |
| 6 | **AAAA** | override/rule 命中 → 清空（强制 IPv4）；其他透传 |
| 7 | **谷歌全家桶**（override 组） | 阿里云专用 IP（47.103.34.63 等 7 个） |

## 目录结构

```
ech-doh-worker/
├── worker.js        # DoH 主逻辑（/dns-query /admin /admin/* API）
├── wrangler.toml    # Worker 配置（D1 绑定 + routes + vars）
└── schema.sql       # D1 建表
```

## 部署

```bash
# 凭证（Global API Key）
export CLOUDFLARE_API_KEY=$(grep -oP 'CF_GLOBAL_API_KEY=\K.*' /root/.credentials/cf-token)
export CLOUDFLARE_EMAIL=anglesgirlcn@gmail.com

cd /root/ech-doh-worker
wrangler deploy
```

**⚠️ 部署传播延迟**：部署后边缘节点 1~2 分钟才切换到新版本 —— 测试**必须等待**，否则测到旧版误判。

## 配置管理（DB 驱动，改库即生效）

全部配置存 D1（60s 缓存），**改配置 = 改库 = 立即生效，不重新部署**：

```bash
# 管理端点（X-Admin-Token: doh-admin-7f3k9）
GET  /admin/override            # 列表 override 组
POST /admin/override            # upsert（name/domains/ips/ech）
DELETE /admin/override?name=X   # 删除
GET/PUT /admin/upstreams        # 上游列表（JSON 数组）
GET/POST /admin/config          # 全局配置（fallback_ip/ech）
```

admin UI：`https://res.anglesgirl.eu.org/admin`

## 手机使用（Firefox/Iceraven）

about:config：
```
network.trr.uri = https://res.anglesgirl.eu.org/dns-query
network.trr.mode = 3
```

## 上游说明

- 上游 = CF Gateway（`pieqllv9i7.cloudflare-gateway.com` 等，D1 配置，当前只用 pieqllv9i7）
- 谷歌静态域名（youtube.com/gstatic/googleapis 等）→ override 阿里云 IP（不走上游）
- googlevideo（锁 IP）→ 强制 IPv6（不走 IPv4）

## D1 表

| 表 | 内容 |
|---|---|
| rules | domain / ips(JSON) / ech —— 指定 IP + ECH 强注 |
| overrides | name / domains(JSON) / ips(JSON) / ech —— 谷歌全家桶等覆写组 |
| config | fallback_ip / ech / upstreams(JSON) —— 全局 + 上游 |

## 凭证

- CF Global API Key + account_id：`/root/.credentials/cf-token`
- D1 数据库：ech-doh-db（account cce6c3a3b595692f6041a278411fb20e）

## 经验与坑

见 [docs/经验与坑.md](docs/经验与坑.md)（踩坑全集，避免重复犯错）。
