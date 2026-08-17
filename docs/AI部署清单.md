# AI 部署清单（精简版 —— 部署成功的要点）

> 给 AI 代理：照这个部署就能成功。**worker.js 代码直接用仓库里的，不要重写。**

## 部署步骤

```bash
# 1. 凭证（Global API Key 认证，不是 Bearer）
export CLOUDFLARE_API_KEY=<Global API Key>   # 37位hex，存 /root/.credentials/cf-token
export CLOUDFLARE_EMAIL=anglesgirlcn@gmail.com
export CLOUDFLARE_ACCOUNT_ID=cce6c3a3b595692f6041a278411fb20e

# 2. 部署（工作目录 /root/ech-doh-worker，wrangler.toml 已配好 D1/路由/vars）
cd /root/ech-doh-worker && wrangler deploy

# 3. ⚠️ 等 1-2 分钟（CF 边缘版本传播延迟，别 15 秒就测说"没生效"）
```

## 部署后必须初始化 D1（不然规则/上游是空的）

```bash
# 上游（只留 pieqllv9i7 —— 7 个轮换会导致 YouTube 播不了）
curl -X PUT https://res.anglesgirl.eu.org/admin/upstreams \
  -H "X-Admin-Token: doh-admin-7f3k9" -H "Content-Type: application/json" \
  -d '{"upstreams":["https://pieqllv9i7.cloudflare-gateway.com/dns-query"]}'

# 覆写组（谷歌全家桶等）→ GET /admin/override 看有没有数据，没有就补
```

## 验证（判定部署成功）

**测试包必须带 0 终止符**（缺了 qtype 解析偏移，误判代码坏）：
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

## 关键坑（部署相关）

1. **Global Key 用 X-Auth-Email/X-Auth-Key 头**，不是 Bearer（报 Invalid format）
2. **改配置 = 改 D1（admin API），不是改源码重新部署**（用户明确要求）
3. **worker.js 别重写**：含 Buffer 兼容、CNAME 链 owner（makeRR 不能硬编码 0xC00C）、ECH 解析等全部修复 —— 改坏一处就播放不了
4. **上游只留 pieqllv9i7**（gateway JSON 不走策略返回被墙 IP，视频靠 IPv6 绕开）
5. **别用 EdgeOne**（弃用：区域/路由坑，费钱无果）

*详细排错见 docs/经验与坑.md（部署卡住时再读）。*
