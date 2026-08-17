# 🤖 AI 部署清单：云端 DoH（Cloudflare Workers + D1）

> **给未来的 AI 代理/部署者的完整手册。照着做，别自由发挥。**
> 每一条都是真金白银买来的经验（2026-08-17 全程踩坑复盘）。
> 部署前**必须通读本文件** + `docs/经验与坑.md`。

---

## 0. 这个项目是干什么的

大陆网络（GFW）下，让浏览器能访问被墙/被污染域名：
- **x.com / AO3**：SNI 被墙 → 靠 **ECH 注入**（加密 SNI）
- **YouTube 视频**：googlevideo.com 的 **IPv4 谷歌全段封** → **只有 IPv6 可达** → 强制 IPv6
- **谷歌系静态域名**（youtube.com/gstatic/googleapis 等）→ **阿里云专用 IP**（谷歌 IPv4 全封）
- 其余域名 → 转发上游

**核心设计**：配置全部存 **D1 数据库**，**改库即生效（不重新部署）**。
线上：`https://res.anglesgirl.eu.org/dns-query`

---

## 1. 架构

```
手机浏览器 TRR
    ↓ https://res.anglesgirl.eu.org/dns-query（CF Workers 路由）
worker.js（edge-functions 处理）
    ├─ 1. 查 D1（60s 缓存）：rules / overrides / upstreams / config
    ├─ 2. 按处理逻辑（见 §5）构造应答
    ├─ 3. 需要上游解析 → 查 gateway（D1 配置的 upstreams）
    └─ 4. ECH 注入 → 查 cloudflare-ech.com 的 HTTPS 记录（上游）
admin API（/admin/override、/admin/upstreams、/admin/config）→ 写 D1 → 60s 内生效
```

## 2. 账号与凭证（部署必需）

| 项 | 值/位置 |
|---|---|
| CF 账号邮箱 | `anglesgirlcn@gmail.com` |
| **认证方式** | **Global API Key**：`X-Auth-Email` + `X-Auth-Key` 头（**不是 Bearer token**） |
| account_id | `cce6c3a3b595692f6041a278411fb20e` |
| 凭证文件 | `/root/.credentials/cf-token`（含全部 CF 凭证） |
| wrangler 部署 | `CLOUDFLARE_API_KEY=<Global Key> CLOUDFLARE_EMAIL=<邮箱> wrangler deploy` |
| D1 数据库 | `ech-doh-db`（id 见 wrangler.toml） |

**坑**：Global API Key（37 位 hex）**不能**用 `Authorization: Bearer`（报 Invalid format）—— 必须 X-Auth-Email/X-Auth-Key。

## 3. 部署步骤（照做）

```bash
cd /root/ech-doh-worker        # 工作目录（含 wrangler.toml + worker.js）
export CLOUDFLARE_API_KEY=<Global Key>
export CLOUDFLARE_EMAIL=anglesgirlcn@gmail.com
wrangler deploy                # 部署到 production
```

**部署后 ⚠️ 等 1-2 分钟再测试**（CF 边缘版本传播有延迟，15 秒内测会拿到旧版响应 → 误判"部署失败/代码坏了"）。

## 4. 验证（判定标准）

**⚠️ 测试脚本必须先自查**：DNS 查询包**必须带 0 终止符**：
```python
q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # 12B header
for label in name.split("."): q += bytes([len(label)]) + label.encode()
q += b"\x00"                    # ← 缺这个 = qtype 偏移错位 = 假"qtype=256"
q += struct.pack(">HH", qtype, 1)
```

**预期结果表**（对照检查）：

| 查询 | 预期 |
|---|---|
| youtube.com / i.ytimg.com / www.gstatic.com A | 阿里云 IP（7 个：47.103.34.63 等） |
| googlevideo.com A | **空**（强制 IPv6，A 清空） |
| googlevideo.com AAAA | IPv6（2607:f8b0 或 2a00:1450 段） |
| rr\*---sn-\*.googlevideo.com AAAA | CNAME 链 + AAAA，**AAAA owner 必须是 CNAME 目标**（不是查询名） |
| x.com A | 钦定 IP（172.64.53.55 等） |
| x.com HTTPS | **ECH 注入**（ANCOUNT≥1） |
| baidu.com A | 真实 IP（透传上游） |
| /admin/override GET | 谷歌全家桶 37 域名（含 gstatic.com） |

## 5. 处理逻辑（用户拍板，不能改）

1. **默认**：所有域名转发上游，不改
2. **列表有指定 A** → 用指定 A
3. **列表有 ech 强注** → ECH 注入 + 改解析
4. **CF 托管域名**（AS13335）→ 强注 ECH + 改钦定 IP
5. **视频域名**（googlevideo.com / c.youtube.com 及子域）→ **强制 IPv6**（A 清空，AAAA 透传）—— IPv4 谷歌全段封
6. **AAAA**：override/rule 命中 → 清空（强制 IPv4）；其他 → 透传
7. **谷歌系**：全家桶列表内（37 域名）→ 阿里云 7 IP；未指定的（googlevideo 等）→ 转发

## 6. 配置管理（改库即生效，禁止改源码部署）

| 端点 | 方法 | 作用 |
|---|---|---|
| /admin/override | GET/POST/DELETE | 覆写组（谷歌全家桶等） |
| /admin/upstreams | GET/PUT | 上游列表（**只留 pieqllv9i7.cloudflare-gateway.com**） |
| /admin/config | GET/PUT | 全局（fallbackIp/ech） |
| /admin | GET | 管理 UI |

所有写操作 → D1 → **60 秒内生效**（_cfgCache 过期）。**改配置绝不重新部署**。

## 7. 手机使用

Firefox/Iceraven → about:config：
```
network.trr.uri = https://res.anglesgirl.eu.org/dns-query
network.trr.mode = 3
```
改完**清 DNS 缓存**（about:networking#dns → Clear DNS Cache）再测。

## 8. 已知坑全集（每条都是花钱买来的）

1. **EdgeOne 已弃用**：`--area global` 含中国大陆要 ICP；路由/部署坑多，花 10 元无果。**禁止再试 EdgeOne**。
2. **部署传播延迟**：部署后 1-2 分钟边缘才切新版本。别 15 秒测就下结论。
3. **测试包 0 终止符**：缺了 → qtype 偏移（假 256）→ 误判 worker 坏（实际是测试脚本坏）。
4. **CNAME 链 owner**：CNAME 后的 A/AAAA 记录 owner **必须是 CNAME 目标**；`makeRR` 不能硬编码压缩指针 0xC00C（指向查询名会被浏览器丢弃 → no address → 播放不了）。**这是 YouTube 视频打不开的根因**。
5. **gateway 上游**：JSON 格式（?name=&type=）**不走 Zero Trust 策略**（返回被墙 IP）；标准 wire 格式才走策略。**上游只留 pieqllv9i7**（7 个轮换会导致 YouTube 播不了）。
6. **Buffer 兼容**：CF Workers 的 Buffer 与 Node 有差异（`buf.data` 是 EdgeOne polyfill 专属 —— CF 原生 Buffer 没有！）。解析用纯字节操作（`buf[i]` 或 `buf.data||buf`）。
7. **Google 认证**：Global API Key 用 X-Auth-Email/X-Auth-Key，不是 Bearer。
8. **D1 驱动**：rules/overrides/upstreams 存 D1，改库即生效。**别写死源码**（用户明确要求"改个上游也要重新部署吗"）。
9. **视频 IPv6**：googlevideo.com IPv4 全段封（漏的也会立马封）→ A 清空强制 IPv6。
10. **ECH 解析**：cloudflare-ech.com 的 ech= 可能带引号（alidns）也可能不带（1.1.1.1）—— 两种格式都要解析。
11. **凭证管理**：全部集中 /root/.credentials/，部署命令见 §2。别让用户重复提供。
12. **测试域名选型**：验证功能用 baidu.com（透传）/youtube.com（override）对照，别只测一个。
13. **手机测试**：改 TRR 后必须清 DNS 缓存（about:networking#dns），否则旧缓存（no address）误判。
14. **admin API token**：`X-Admin-Token: doh-admin-7f3k9`（wrangler.toml vars）。

## 9. 禁止事项

- ❌ 禁止用 EdgeOne（弃用）
- ❌ 禁止用 KV 替代 D1（KV 绑定/成本问题）
- ❌ 禁止改源码部署配置（必须 DB 驱动）
- ❌ 禁止在 CF Workers 用 `buf.data`（原生 Buffer 无此属性）
- ❌ 禁止把上游改成 7 个 gateway 轮换（YouTube 会播不了）
- ❌ 禁止怀疑用户已实测确认的事实（如"gateway 能播 YouTube"）—— 直接采信并往前推

---

*文档维护：新增坑必须补进 §8。踩坑后先读本文档，别让用户重复踩。*
