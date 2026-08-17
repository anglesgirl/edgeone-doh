# AGENTS.md — 给 AI 代理的项目指南

本仓库：**云端 DoH**（Cloudflare Workers + D1），线上 `https://res.anglesgirl.eu.org/dns-query`。
**worker.js 代码直接用仓库里的，不要重写。**

## 部署

```bash
export CLOUDFLARE_API_KEY=<Global API Key>   # 37位hex，存 /root/.credentials/cf-token
export CLOUDFLARE_EMAIL=anglesgirlcn@gmail.com
export CLOUDFLARE_ACCOUNT_ID=cce6c3a3b595692f6041a278411fb20e
cd /root/ech-doh-worker && wrangler deploy
# ⚠️ 等 1-2 分钟（CF 边缘版本传播延迟，别 15 秒就测说"没生效"）
```

## 部署后初始化 D1（必须，否则规则/上游为空）

```bash
curl -X PUT https://res.anglesgirl.eu.org/admin/upstreams \
  -H "X-Admin-Token: doh-admin-7f3k9" -H "Content-Type: application/json" \
  -d '{"upstreams":["https://pieqllv9i7.cloudflare-gateway.com/dns-query"]}'
# 覆写组：GET /admin/override 确认有谷歌全家桶数据
```

## 验证（判定成功）

测试包**必须带 0 终止符**（缺了 qtype 解析偏移，误判代码坏）：
```python
q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
for label in name.split("."): q += bytes([len(label)]) + label.encode()
q += b"\x00" + struct.pack(">HH", qtype, 1)
```

| 查询 | 预期（= 成功） |
|---|---|
| youtube.com A | 阿里云 IP（47.103.34.63 等） |
| googlevideo.com A | 空（强制 IPv6）；AAAA 有 IPv6 |
| x.com HTTPS | ECH 注入（有记录） |
| baidu.com A | 真实 IP（透传） |

## 关键坑

1. **Global Key 用 X-Auth-Email/X-Auth-Key 头**，不是 Bearer（报 Invalid format）
2. **改配置 = 改 D1（admin API），不是改源码重新部署**（用户明确要求）
3. **worker.js 别重写**：含 Buffer 兼容、CNAME 链 owner（makeRR 不能硬编码 0xC00C）、ECH 解析等全部修复 —— 改坏一处就播放不了
4. **上游只留 pieqllv9i7**（gateway JSON 不走策略返回被墙 IP，视频靠 IPv6 绕开）
5. **别用 EdgeOne**（弃用：区域/路由坑，费钱无果）

## 处理逻辑（用户拍板）

1. 默认：所有域名转发上游，不改
2. 列表有指定 A → 用指定 A
3. 列表有 ech 强注 → ECH 注入 + 改解析
4. CF 托管（AS13335）→ 强注 ECH + 改钦定 IP
5. 视频域名（googlevideo.com / c.youtube.com）→ 强制 IPv6（A 清空，AAAA 透传）
6. AAAA：override/rule 命中 → 清空（强制 IPv4）；其他 → 透传
7. 谷歌系：全家桶列表内 → 阿里云 7 IP；未指定 → 转发

## 配置管理（改库即生效，禁止改源码部署）

- `/admin/override` GET/POST/DELETE —— 覆写组（谷歌全家桶）
- `/admin/upstreams` GET/PUT —— 上游列表
- `/admin/config` GET/PUT —— 全局（fallbackIp/ech）
- `X-Admin-Token: doh-admin-7f3k9`

详细排错：`docs/经验与坑.md`（部署卡住时再读）。
