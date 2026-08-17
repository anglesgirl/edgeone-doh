// EdgeOne Pages Functions — DoH 服务器（免服务器版）
// 路由：/dns-query（标准 DoH wire format）+ /resolve（JSON 调试）
// 规则存 KV（key: rule:<domain> → JSON {ips:[],ech:true}）
// 上游：CF Gateway DoH（海外节点可达）
// ECH：从 cloudflare-ech.com 的 HTTPS 记录获取（缓存到 KV）

const ECH_SOURCE = 'cloudflare-ech.com';
// 2026-08-17：上游从 D1 config 表读取（改库即生效，不重新部署）；兜底内置
const FALLBACK_UPSTREAMS = [
  'https://pieqllv9i7.cloudflare-gateway.com/dns-query',
  'https://al62jgpda0.cloudflare-gateway.com/dns-query',
  'https://2w59vnepne.cloudflare-gateway.com/dns-query',
  'https://dz1598pphb.cloudflare-gateway.com/dns-query',
  'https://e6i0vltnvu.cloudflare-gateway.com/dns-query',
  'https://m2b4x7vw98.cloudflare-gateway.com/dns-query',
  'https://xzam891f5d.cloudflare-gateway.com/dns-query',
];
let _upIdx = 0;

async function loadUpstreams(env) {
  try {
    if (env && env.DB) {
      const row = await env.DB.prepare('SELECT upstreams FROM config WHERE id = 1').first();
      if (row && row.upstreams) {
        const arr = JSON.parse(row.upstreams);
        if (Array.isArray(arr) && arr.length > 0) return arr;
      }
    }
  } catch (e) {}
  return FALLBACK_UPSTREAMS;
}

const KV_ECH_TTL = 300; // 5 分钟

// ---------- AS13335 (Cloudflare) 判断 ----------
// 用 Team Cymru 反查（origin.asn.cymru.com TXT），官方 ips-v4 只是落地 IP 段，
// 不是 AS13335 完整前缀集（实际有 2400+ 前缀），不能用于判断"IP 属于 CF"。

// ipAsnCache：内存缓存 IP → ASN（避免重复反查）
const ipAsnCache = new Map();
const IP_ASN_TTL = 3600 * 1000; // 1 小时

// lookupASN：反查 IP 的 ASN（通过 DoH JSON 查 TXT）
async function lookupASN(ipStr, env) {
  const now = Date.now();
  const cached = ipAsnCache.get(ipStr);
  if (cached && now - cached.ts < IP_ASN_TTL) return cached.asn;

  // Team Cymru：d.c.b.a.origin.asn.cymru.com → TXT "AS13335 | ..."
  const parts = ipStr.split('.');
  const reversed = parts.slice().reverse().join('.');
  const name = `${reversed}.origin.asn.cymru.com`;
  const jr = await upstreamJSON(name, 16, env); // 16 = TXT
  let asn = '';
  if (jr && jr.Answer) {
    for (const a of jr.Answer) {
      if (a.type !== 16 || !a.data) continue;
      const m = a.data.match(/(\d+)\s*\|/);
      if (m) { asn = m[1]; break; }
    }
  }
  ipAsnCache.set(ipStr, { asn, ts: now });
  return asn;
}

// isCloudflareIP：判断 IP 是否属于 AS13335
async function isCloudflareIP(ipStr, env) {
  const asn = await lookupASN(ipStr, env);
  return asn === '13335';
}

// ---------- DNS wire format 编解码 ----------

function encodeName(name) {
  // 'archiveofourown.org' → wire format（尾点自动补）
  let s = name.endsWith('.') ? name.slice(0, -1) : name;
  const parts = s.split('.');
  let out = Buffer.alloc(0);
  for (const p of parts) {
    const b = Buffer.from(p, 'ascii');
    const len = Buffer.from([b.length]);
    out = Buffer.concat([out, len, b]);
  }
  return Buffer.concat([out, Buffer.from([0])]);
}

function decodeName(buf, off) {
  // 2026-08-17：纯 Uint8Array 解析（CF Workers 的 Buffer 与 Node 行为有差异：
  // readUInt16BE/slice/toString 不可靠 → 全部手动字节操作）
  const b = (buf && buf.data) ? buf.data : buf; // 兼容 polyfill Buffer(.data) / 原生 Buffer / Uint8Array
  let labels = [];
  let pos = off;
  let jumped = false;
  let jumpTarget = -1;
  let guard = 0;
  while (guard++ < 64) {
    const len = b[pos];
    if (len === 0) {
      pos += 1;
      break;
    }
    if ((len & 0xC0) === 0xC0) {
      if (!jumped) {
        jumpTarget = ((len & 0x3F) << 8) | b[pos + 1];
      }
      pos += 2;
      jumped = true;
      if (jumpTarget < 0) break;
      pos = jumpTarget;
      continue;
    }
    // 手动 ASCII 解码（避免 Buffer.toString('ascii') 差异）
    let s = '';
    for (let i = pos + 1; i < pos + 1 + len; i++) s += String.fromCharCode(b[i]);
    labels.push(s);
    pos += 1 + len;
  }
  let nextOff = jumped ? off + 2 : pos;
  return { name: labels.join('.'), nextOff };
}

function buildQuery(header, questions, answers) {
  // 简化应答构造：header(12) + questions + answers
  let qd = Buffer.alloc(0);
  for (const q of questions) {
    qd = Buffer.concat([qd, q]);
  }
  let an = Buffer.alloc(0);
  for (const a of answers) {
    an = Buffer.concat([an, a]);
  }
  return Buffer.concat([header, qd, an]);
}

function makeHeader(id, flags, qdcount, ancount) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(flags, 2);
  h.writeUInt16BE(qdcount, 4);
  h.writeUInt16BE(ancount, 6);
  h.writeUInt16BE(0, 8); // nscount
  h.writeUInt16BE(0, 10); // arcount
  return h;
}

function buildAAnswer(qnameWire, qtype, ips, ttl) {
  // 一条 A 记录 answer
  const answers = [];
  for (const ipStr of ips) {
    const parts = ipStr.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) continue;
    const rdata = Buffer.from(parts);
    answers.push(makeRR(qnameWire, 1, ttl, rdata));
  }
  return answers;
}

function makeRR(nameWire, rtype, ttl, rdata) {
  // name(压缩指针 0xC00C) + type + class + ttl + rdlength + rdata = 12 字节头
  const head = Buffer.alloc(12);
  head.writeUInt16BE(0xC00C, 0); // 指针到偏移 12
  head.writeUInt16BE(rtype, 2);
  head.writeUInt16BE(1, 4); // IN
  head.writeUInt32BE(ttl, 6);
  head.writeUInt16BE(rdata.length, 10); // rdlength
  return Buffer.concat([head, rdata]);
}

// HTTPS 记录：priority(2) + target(name) + params
// 参数：5 = ech（ECHConfigList bytes）
function buildHTTPSAnswer(qnameWire, echB64, ttl) {
  const echRaw = Buffer.from(echB64, 'base64');
  const param = Buffer.alloc(4 + echRaw.length);
  param.writeUInt16BE(5, 0); // key = ech
  param.writeUInt16BE(echRaw.length, 2);
  echRaw.copy(param, 4);
  // priority=1, target="."(0x00), params
  const svcb = Buffer.concat([
    Buffer.from([0, 1]), // priority 1
    Buffer.from([0]),    // target = "."
    param,
  ]);
  return [makeRR(qnameWire, 65, ttl, svcb)];
}

// ---------- 上游查询（JSON 格式） ----------

// 谷歌未指定域名（锁 IP）也走 gateway 上游（用户 2026-08-17：统一 CF Gateway）

async function pickUpstream(qname, env) {
  const list = await loadUpstreams(env);
  const base = list[_upIdx % list.length];
  _upIdx = (_upIdx + 1) % list.length;
  return base;
}

async function upstreamJSON(name, type, env) {
  const list = await loadUpstreams(env);
  const base = list[_upIdx % list.length];
  const url = `${base}?name=${encodeURIComponent(name)}&type=${type}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const resp = await fetch(url, {
      headers: { Accept: 'application/dns-json' },
      signal: ctrl.signal,
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch (e) {
    // 换一个上游重试
    try {
      const url2 = `${list[(_upIdx + 1) % list.length]}?name=${encodeURIComponent(name)}&type=${type}`;
      const resp2 = await fetch(url2, {
        headers: { Accept: 'application/dns-json' },
        signal: ctrl.signal,
      });
      if (!resp2.ok) return null;
      return await resp2.json();
    } catch (e2) {
      return null;
    }
  } finally {
    clearTimeout(timer);
  }
}

// 从 JSON 应答中解析 ech= 参数（兼容 CF Gateway \# hex 和 alidns 文本两种格式）
function extractEchFromJSON(jr) {
  if (!jr || !jr.Answer) return null;
  for (const a of jr.Answer) {
    if (!a.data) continue;
    const d = String(a.data);
    // CF Gateway 格式: "\# 136 00 01 00 00 ..."（hex）
    if (d.includes('#')) {
      const m = d.match(/#\s*\d+\s+([0-9a-fA-F ]+)/);
      if (m) {
        const raw = Buffer.from(m[1].replace(/\s+/g, ''), 'hex');
        const ech = extractEchFromSVCB(raw);
        if (ech) return ech.toString('base64');
      }
    }
    // alidns 文本格式: '1 . alpn="h3,h2" ipv4hint="..." ech="AEX+..."'
    const m = d.match(/ech="([A-Za-z0-9+/=]+)"/);
    if (m) {
      // alidns 的 ech= 同样是完整 ECHConfigList（含 2 字节整体长度前缀），原样返回
      return m[1];
    }
    // SVCB 文本格式（1.1.1.1/cloudflare-dns.com）: '1 . alpn=h3,h2 ech=AEX+DQ...'
    // 2026-08-17：无引号变体（1.1.1.1 返回），base64url 编码（AEX+ 开头 = ECHConfigList）
    const m2 = d.match(/\bech=([A-Za-z0-9+/_-]+)/);
    if (m2 && m2[1].length > 20) {
      return m2[1].replace(/-/g, '+').replace(/_/g, '/');
    }
  }
  return null;
}

// 从 SVCB RDATA（含 priority+target+params）中提取 ech 参数
function extractEchFromSVCB(rdata) {
  if (rdata.length < 3) return null;
  let pos = 2;
  // 解析 target
  while (pos < rdata.length) {
    const l = rdata[pos];
    if (l === 0) { pos++; break; }
    if ((l & 0xC0) === 0xC0) { pos += 2; break; }
    pos += 1 + l;
  }
  while (pos + 4 <= rdata.length) {
    const key = rdata.readUInt16BE(pos);
    const len = rdata.readUInt16BE(pos + 2);
    pos += 4;
    if (pos + len > rdata.length) return null;
    if (key === 5) {
      // RFC 9460: ech 参数 value = ECHConfigList，格式 = ECHConfigList<len>(2) + ECHConfigs。
      // 上游返回的 `00 45 fe 0d 00 41...` 中 `00 45`(2字节) 是 ECHConfigList 的整体长度前缀，
      // 是 ECHConfigList 的组成部分，必须保留——Chrome/OpenSSL 需要完整 ECHConfigList，
      // 剥掉会得到 ERR_INVALID_ECH_CONFIG_LIST。
      return rdata.slice(pos, pos + len);
    }
    pos += len;
  }
  return null;
}

// 获取 ECH 配置（2026-08-17：内存缓存 → 上游查询，无数据库）
const _echCache = { ech: null, ts: 0 };
async function getECH(env) {
  if (_echCache.ech && Date.now() - _echCache.ts < KV_ECH_TTL * 1000) return _echCache.ech;
  const jr = await upstreamJSON(ECH_SOURCE, 65, env);
  const ech = extractEchFromJSON(jr);
  if (ech) { _echCache.ech = ech; _echCache.ts = Date.now(); }
  return ech;
}

// ---------- 配置（2026-08-17：EdgeOne 无数据库版 —— env 变量 + 内存缓存）----------
// env.RULES_JSON = {"x.com":{"ips":["172.64.146.66"],"ech":true}, ...}
// 2026-08-17：改回 D1 驱动（env.RULES_JSON 是 EdgeOne 改造遗留，CF 部署无此变量）
const _cfgCache = { rules: null, overrides: null, cfg: null, ts: 0 };

async function loadRules(env) {
  if (_cfgCache.rules && Date.now() - _cfgCache.ts < 60000) return _cfgCache.rules;
  try {
    const { results } = await env.DB.prepare('SELECT domain, ips, ech FROM rules').all();
    const rules = {};
    for (const r of (results || [])) {
      try { rules[r.domain] = { ips: JSON.parse(r.ips || '[]'), ech: !!r.ech }; }
      catch (e) { rules[r.domain] = { ips: [], ech: !!r.ech }; }
    }
    _cfgCache.rules = rules;
    _cfgCache.ts = Date.now();
  } catch (e) { _cfgCache.rules = {}; }
  return _cfgCache.rules;
}

async function loadOverrides(env) {
  try {
    const { results } = await env.DB.prepare('SELECT name, domains, ips, ech FROM overrides').all();
    return (results || []).map(r => {
      try { return { name: r.name, domains: JSON.parse(r.domains || '[]'), ips: JSON.parse(r.ips || '[]'), ech: !!r.ech }; }
      catch (e) { return { name: r.name, domains: [], ips: [], ech: !!r.ech }; }
    });
  } catch (e) { return []; }
}

async function getGlobalConfig(env) {
  return { fallbackIp: env.FALLBACK_IP || '', ech: !!env.GLOBAL_ECH };
}

async function getRule(env, domain) {
  // 查询的域名去掉尾点
  domain = domain.replace(/\.$/, '');
  const rules = await loadRules(env);
  // 直接匹配（含子域：x.com 规则覆盖 api.x.com —— 后缀匹配）
  for (const [k, v] of Object.entries(rules)) {
    const kd = String(k).toLowerCase().replace(/\.$/, '');
    if (domain === kd || domain.endsWith('.' + kd)) {
      const ips = Array.isArray(v.ips) ? v.ips : [];
      return { domain: k, ips, ech: !!v.ech };
    }
  }
  return null;
}

// 查覆写集合（override 组）：遍历 overrides，若 qname 后缀匹配某集合的某个域名，
// 返回该集合的覆写 IP + ech 标志。如「谷歌全家桶」domains=[google.com,...] 命中含子域。
async function getOverrideMatch(env, qname) {
  const n = qname.toLowerCase().replace(/\.$/, '');
  for (const row of await loadOverrides(env)) {
    const doms = Array.isArray(row.domains) ? row.domains : [];
    for (const g of doms) {
      const gd = String(g).toLowerCase().replace(/\.$/, '');
      if (!gd) continue;
      // 匹配：域相等，或 x 是 gd 的子域，或 ".后缀" 顶级匹配
      const match =
        n === gd ||
        (gd.startsWith('.') && n.endsWith(gd)) ||
        (!gd.startsWith('.') && n.endsWith('.' + gd));
      if (match) {
        const ips = Array.isArray(row.ips) ? row.ips : [];
        return { name: row.name, ips, ech: !!row.ech };
      }
    }
  }
  return null;
}

// ---------- 主处理 ----------

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (e) {
      return new Response(JSON.stringify({ error: String(e), stack: String(e && e.stack || '') }), {
        status: 500,
        headers: { 'content-type': 'application/json' },
      });
    }
  }
};

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // ---- 管理后台路由 ----
  if (path === '/admin' || path.startsWith('/admin/')) {
    return handleAdmin(request, env, url);
  }
  // ---- iOS 描述文件 ----
  if (path === '/profile.mobileconfig') {
    return handleProfile(env);
  }
  // ---- DoH ----
  // 伪装策略：
  //  - /          → 普通 HTML 页面（伪装成网站首页，隐藏 DoH 身份）
  //  - /api/v1/sync → 伪装 POST 接口（App 通道，body 承载 DNS 包）
  //  - /dns-query  → 标准 DoH（iOS 描述文件必需，保留）
  if (path === '/' || path === '/index.html') {
    return new Response(
      '<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>Angles 网络服务</title></head><body>' +
      '<div style="font-family:sans-serif;max-width:600px;margin:80px auto;text-align:center;color:#555">' +
      '<h1>💚 Angles Network</h1>' +
      '<p>Network infrastructure service. Status: operational.</p>' +
      '<p style="font-size:12px;color:#aaa">© 2026 — All systems normal</p>' +
      '</div></body></html>',
      { headers: { 'content-type': 'text/html; charset=utf-8' } }
    );
  }
  if (path !== '/dns-query' && path !== '/resolve' && path !== '/api/v1/sync' && path !== '/api') {
    return new Response('<html><body>Page not found</body></html>', { status: 404, headers: { 'content-type': 'text/html' } });
  }
  // 标记是否为伪装通道（决定响应行为；现在 Content-Type 已统一为标准 dns-message）
  const isStealth = path === '/api/v1/sync' || path === '/api';

  // 解析请求：POST body 或 GET ?dns= 都支持（兼容浏览器 DoH 的 GET 偏好）
  let qbuf = null;
  if (request.method === 'POST') {
    qbuf = Buffer.from(await request.arrayBuffer());
  } else {
    const dnsParam = url.searchParams.get('dns');
    if (dnsParam) {
      qbuf = Buffer.from(dnsParam.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    }
  }
  // 伪装路径的 GET 也兼容：若没有 ?dns= 参数，尝试从 query 其他字段取
  if (!qbuf && isStealth) {
    for (const [k, v] of url.searchParams) {
      if (k !== 'cb' && v) {
        try {
          qbuf = Buffer.from(v.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
          if (qbuf.length >= 12) break;
        } catch (e) { /* ignore */ }
      }
    }
  }
  if (!qbuf || qbuf.length < 12) {
    // 空查询（浏览器探测 endpoint 有效性时）→ 返回合法空应答，而非 400。
    // 浏览器 DoH 探测（如 use-application-dns.net）得不到合法响应会判定 endpoint 无效。
    const hdr = Buffer.alloc(12);
    try { hdr.writeUInt16BE(qbuf ? qbuf.readUInt16BE(0) : 0x1234, 0); } catch (e) { hdr.writeUInt16BE(0x1234, 0); }
    hdr.writeUInt16BE(0x8180, 2); // QR + RD + RA, RCODE=0, 0 answers
    return new Response(hdr, {
      headers: { 'content-type': 'application/dns-message', 'cache-control': 'max-age=300' },
    });
  }

  // 解析 question
  const qdcount = qbuf.readUInt16BE(4);
  let off = 12;
  let qnameWire = null;
  let qname = '';
  let qtype = 1;
  for (let i = 0; i < qdcount; i++) {
    const d = decodeName(qbuf, off);
    qname = d.name;
    qnameWire = qbuf.slice(off, d.nextOff); // name wire（nextOff 是 name 结束位置，type 之前）
    qtype = (qbuf[d.nextOff] << 8) | qbuf[d.nextOff + 1]; // 手动读 type（避免 Buffer 差异）
    off = d.nextOff + 4;
    break; // 只处理第一个 question
  }
  const id = qbuf.readUInt16BE(0);

  // 规则命中？
  const rule = await getRule(env, qname.toLowerCase());
  const override = await getOverrideMatch(env, qname.toLowerCase());
  const gcfg = await getGlobalConfig(env);
  let answers = [];

  if (override && override.ips && override.ips.length > 0 && qtype === 1) {
    // 覆写集合命中（如「谷歌全家桶」）：返回覆写 IP；ech 按集合设置
    answers = buildAAnswer(qnameWire, qtype, override.ips, 300);
  } else if (rule && rule.ips && rule.ips.length > 0 && qtype === 1) {
    // 手动规则命中 A 记录：返回自定义 IP
    answers = buildAAnswer(qnameWire, qtype, rule.ips, 300);
  } else if (qtype === 1) {
    // 未命中 override / 手动规则 → 上游解析，然后检查是否 AS13335
    const jr = await upstreamJSON(qname, qtype, env);
    if (jr && jr.Answer) {
      answers = jsonToAnswers(qnameWire, qname, jr.Answer);
    }
    // 全局配置：如果域名是 CF 托管（AS13335 或 CNAME 链指向 cloudflare），
    // 且配置了 fallbackIp → 替换为自定义 IP（换 CF 共享 IP 绕过封 IP）
    if (gcfg.fallbackIp && jr && jr.Answer && !override) {
      let isCF = false;
      // 判定 1：任一 A 记录 IP 属于 AS13335
      for (const a of jr.Answer) {
        if (a.type === 1 && await isCloudflareIP(a.data, env)) { isCF = true; break; }
      }
      // 判定 2：CNAME 链指向 Cloudflare（*.cdn.cloudflare.net / *.cloudflare.net）
      // 覆盖"CF 托管但 Geo DNS 返回非 CF IP"的域名（如 video.twimg.com → Fastly IP）
      if (!isCF) {
        for (const a of jr.Answer) {
          if (a.type === 5 && typeof a.data === 'string' &&
              /(^|\.)cdn\.cloudflare\.net\.?$|(^|\.)cloudflare\.net\.?$|(^|\.)workers\.dev\.?$/i.test(a.data)) {
            isCF = true; break;
          }
        }
      }
      if (isCF) {
        answers = buildAAnswer(qnameWire, qtype, [gcfg.fallbackIp], 300);
      }
    }
  } else if (qtype === 28) {
    // AAAA（2026-08-17）：规则/覆写命中的域名 → 清空（强制 IPv4，避免浏览器
    // 拿 IPv6 去连大陆不通的地址）；其他域名透传上游 AAAA
    if (override || rule) {
      answers = [];
    } else {
      const jr = await upstreamJSON(qname, qtype, env);
      if (jr && jr.Answer) {
        answers = jsonToAnswers(qnameWire, qname, jr.Answer);
      }
    }
  } else if (qtype === 65) {
    // HTTPS 记录：覆写集合（ech 按集合设置）/ 手动规则（ech=true）或 CF 托管 → 注入 ECH
    let injectECH = false;
    if (override && override.ech) {
      // 覆写集合明确要求注 ECH（如某些站）
      injectECH = true;
    } else if (override && !override.ech) {
      // 覆写集合适用（如谷歌全家桶，ech=false）→ 不强注
      injectECH = false;
    } else if (!override) {
      if (rule && rule.ech) {
        injectECH = true;
      } else {
        // 未命中手动规则：查 A 记录判断是否 CF 托管（AS13335 反查 + CNAME 链）
        const jrA = await upstreamJSON(qname, 1, env);
        if (jrA && jrA.Answer) {
          for (const a of jrA.Answer) {
            if (a.type === 1 && await isCloudflareIP(a.data, env)) { injectECH = true; break; }
          }
          if (!injectECH) {
            for (const a of jrA.Answer) {
              if (a.type === 5 && typeof a.data === 'string' &&
                  /(^|\.)cdn\.cloudflare\.net\.?$|(^|\.)cloudflare\.net\.?$|(^|\.)workers\.dev\.?$/i.test(a.data)) {
                injectECH = true; break;
              }
            }
          }
        }
      }
    }
    if (injectECH) {
      const ech = await getECH(env);
      if (ech) {
        answers = buildHTTPSAnswer(qnameWire, ech, 300);
      }
    } else {
      // 非 CF 域名：正常上游转发 HTTPS 记录
      const jr = await upstreamJSON(qname, qtype, env);
      if (jr && jr.Answer) {
        answers = jsonToAnswers(qnameWire, qname, jr.Answer);
      }
    }
  } else {
    // 其他类型 → 上游转发
    const jr = await upstreamJSON(qname, qtype, env);
    if (jr && jr.Answer) {
      answers = jsonToAnswers(qnameWire, qname, jr.Answer);
    }
  }

  const flags = 0x8180; // QR + RD + RA
  const header = makeHeader(id, flags, qdcount, answers.length);
  const respBuf = buildQuery(header, [qbuf.slice(12, off)], answers);

  // /resolve 返回 JSON（调试）
  if (path === '/resolve') {
    const jsonAnswers = answers.map((a, i) => {
      // 简化：返回原始 hex 便于调试
      return { index: i, hex: a.toString('hex').slice(0, 120) };
    });
    return new Response(JSON.stringify({ status: 0, question: qname, type: qtype, answers: jsonAnswers }), {
      headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
    });
  }

  // 响应 Content-Type：浏览器/系统 DoH 探测要求 application/dns-message 才认可。
  // 真正规避 GFW 靠干净的域名（res.），路径/Content-Type 必须标准否则浏览器不认。
  return new Response(respBuf, {
    headers: {
      'content-type': 'application/dns-message',
      'cache-control': 'max-age=300',
    },
  });
}

// JSON 应答 → wire answers（支持 A/AAAA/CNAME）
function jsonToAnswers(qnameWire, qname, jsonAnswers) {
  const out = [];
  for (const a of jsonAnswers) {
    const type = a.type || 1;
    if (type === 1) {
      const ip = a.data;
      const parts = ip.split('.').map(Number);
      if (parts.length === 4 && parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
        out.push(makeRR(qnameWire, 1, a.TTL || 300, Buffer.from(parts)));
      }
    } else if (type === 28) {
      // AAAA
      const ip = a.data;
      const m = ip.match(/^([0-9a-fA-F:]+)$/);
      if (m) {
        try {
          // 简化的 IPv6 解析（冒号分组）
          const groups = ip.split(':');
          let bytes = Buffer.alloc(16);
          let idx = 0;
          for (const g of groups) {
            if (g === '') { idx += 16 - (groups.length - 1) * 2; continue; }
            const b = Buffer.from(g.padStart(4, '0'), 'hex');
            b.copy(bytes, idx); idx += 2;
          }
          out.push(makeRR(qnameWire, 28, a.TTL || 300, bytes));
        } catch (e) { /* skip */ }
      }
    } else if (type === 5) {
      // CNAME
      const target = a.data.endsWith('.') ? a.data : a.data + '.';
      const tWire = encodeName(target);
      out.push(makeRR(qnameWire, 5, a.TTL || 300, tWire));
    }
  }
  return out;
}

// ==================== 管理后台 ====================

function authAdmin(request, env) {
  const url = new URL(request.url);
  const h = request.headers.get('X-Admin-Token');
  const q = url.searchParams.get('token');
  // 默认 token（环境变量优先，未设置时用内置值）
  const token = (env && env.ADMIN_TOKEN) || 'doh-admin-7f3k9';
  return (h === token) || (q === token);
}

// 2026-08-17：EdgeOne 无数据库版 —— 规则/覆写/全局配置全部存 env 变量
// （RULES_JSON / OVERRIDES_JSON / FALLBACK_IP / GLOBAL_ECH），管理接口只读，
// 写操作提示改 env（edgeone makers env set + 重新部署）。
const NO_DB_MSG = 'EdgeOne 无数据库版：配置存环境变量（env.RULES_JSON / env.OVERRIDES_JSON / env.FALLBACK_IP / env.GLOBAL_ECH），用 edgeone makers env set 修改后重新部署';

async function listRules(env) {
  return Object.entries(await loadRules(env)).map(([domain, v]) => ({ domain, ips: (v.ips || []), ech: !!v.ech }));
}

async function addRule(env, domain, ips, ech) {
  domain = (domain || '').trim().toLowerCase().replace(/\.$/, '');
  if (!domain) return { ok: false, error: 'domain empty' };
  if (domain.startsWith('*.')) domain = domain.slice(2);
  if (domain.startsWith('.')) domain = domain.slice(1);
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) {
    return { ok: false, error: `invalid domain: ${domain}` };
  }
  return { ok: false, error: NO_DB_MSG };
}

async function delRule(env, domain) {
  return { ok: false, error: NO_DB_MSG };
}

// ---------- 覆写集合（override 组）管理 ----------

async function listOverrides(env) {
  return await loadOverrides(env);
}

async function upsertOverride(env, name, domains, ips, ech) {
  try {
    // 2026-08-17：改回 D1 写（EdgeOne 无库提示是改造残留）
    await env.DB.prepare(`DELETE FROM overrides WHERE name = ?`).bind(name).run();
    await env.DB.prepare(`INSERT INTO overrides (name, domains, ips, ech) VALUES (?, ?, ?, ?)`)
      .bind(name, JSON.stringify(domains), JSON.stringify(ips), ech ? 1 : 0).run();
    _cfgCache.ts = 0;
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

async function delOverride(env, name) {
  try {
    await env.DB.prepare(`DELETE FROM overrides WHERE name = ?`).bind(name).run();
    _cfgCache.ts = 0;
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

async function getGlobal(env) {
  // 2026-08-17：D1 config 表优先（可管理），兜底 env
  try {
    const row = await env.DB.prepare(`SELECT fallback_ip, ech FROM config WHERE id = 1`).first();
    if (row) return { fallbackIp: row.fallback_ip || '', ech: !!row.ech };
  } catch (e) {}
  return { fallbackIp: env.FALLBACK_IP || '', ech: !!(env && env.GLOBAL_ECH) };
}

async function setGlobal(env, cfg) {
  try {
    await env.DB.prepare(`UPDATE config SET fallback_ip = ?, ech = ? WHERE id = 1`)
      .bind(cfg.fallbackIp || '', cfg.ech ? 1 : 0).run();
    _cfgCache.ts = 0;
    return await getGlobal(env);
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function renderUI(env) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ECH DoH 管理</title>
<style>
body{font-family:system-ui,sans-serif;max-width:860px;margin:32px auto;padding:0 16px;background:#0f172a;color:#e2e8f0}
h1{font-size:20px;margin-bottom:4px}.sub{color:#94a3b8;font-size:13px;margin-bottom:24px}
h2{font-size:15px;color:#60a5fa;margin:28px 0 10px}
input{background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:9px 12px;border-radius:8px;font-size:14px;width:100%;box-sizing:border-box}
button{background:#2563eb;border:none;color:#fff;padding:10px 18px;border-radius:8px;font-size:14px;cursor:pointer;margin-top:6px}
button:hover{background:#1d4ed8}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:14px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #1e293b}
th{color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
a{color:#f87171;text-decoration:none;cursor:pointer}
.code{background:#1e293b;padding:3px 8px;border-radius:6px;font-family:monospace;font-size:12px}
.card{background:#111c33;border:1px solid #1e293b;border-radius:12px;padding:16px;margin-top:12px}
.row{display:flex;gap:8px;flex-wrap:wrap}.row input{flex:1;min-width:150px}
#status{margin-top:10px;font-size:13px;color:#4ade80;min-height:18px}
label{display:flex;align-items:center;gap:6px;font-size:13px;color:#94a3b8;margin-top:8px}
.tip{font-size:12px;color:#64748b;margin-top:6px;line-height:1.6}
</style></head><body>
<h1>🛡️ ECH DoH 管理后台</h1>
<div class="sub">EdgeOne Pages · 免服务器 DoH · 规则注入 + ECH + AS13335 自动替换</div>

<h2>🔑 管理令牌</h2>
<div class="card">
  <div class="row">
    <input id="tokenInput" placeholder="输入管理 Token 后点击保存" style="flex:2">
    <button onclick="saveToken()" style="flex:0;white-space:nowrap">保存 Token</button>
  </div>
  <div class="tip" id="tokenStatus">首次进入请在此输入管理 Token（默认 <span class="code">doh-admin-7f3k9</span>，如部署时改过环境变量 ADMIN_TOKEN 则用你设置的值）。</div>
</div>

<h2>🌐 全局配置（AS13335 自动替换）</h2>
<div class="card">
  <div class="row">
    <input id="fbIp" placeholder="CF 共享 IP（如 172.67.187.141）——解析出的 IP 属 Cloudflare 时自动替换为它">
  </div>
  <label style="margin-top:10px"><input type="checkbox" id="gbEch" style="width:auto"> 自动注入 ECH（替换 IP 时保留 ECH 配置）</label>
  <button onclick="saveGlobal()">保存全局配置</button>
  <div class="tip">规则：上游解析 A 记录 → 若任一 IP 属于 AS13335（Cloudflare）→ 替换为你指定的 IP，同时注入 ECH。用于绕过"IP 被封但站点在 CF"的情况。</div>
  <div id="status"></div>
</div>

<h2>➕ 添加规则（手动指定域名 → IP）</h2>
<div class="card">
  <div class="row">
    <input id="domain" placeholder="域名，如 archiveofourown.org（支持通配符 *.example.com 覆盖所有子域）">
    <input id="ips" placeholder="IP（逗号分隔，如 172.67.187.141,104.20.9.2）">
  </div>
  <label><input type="checkbox" id="ech" checked style="width:auto"> 注入 ECH</label>
  <button onclick="addRule()">添加规则</button>
</div>

<h2>📋 规则列表</h2>
<table><thead><tr><th>域名</th><th>自定义 IP</th><th>ECH</th><th></th></tr></thead><tbody id="rules"></tbody></table>

<h2>📦 覆写集合（Override 组）</h2>
<div class="card">
  <div class="tip">把一组域名整体覆写到指定 IP（如「谷歌全家桶」→ 阿里云 IP）。集合内域名（含子域）解析到覆写 IP；IP 失效换一个即可，不用改代码。多个域名空格分隔，多个 IP 空格或逗号分隔。</div>
  <div class="row">
    <input id="ovName" placeholder="集合名，如：谷歌全家桶" style="flex:1">
    <input id="ovIps" placeholder="覆写 IP（如 47.103.34.63 121.43.186.252）" style="flex:2">
  </div>
  <input id="ovDomains" placeholder="域名列表（空格分隔，如 google.com youtube.com ytimg.com .google）" style="width:100%;margin-top:8px">
  <label><input type="checkbox" id="ovEch" style="width:auto"> 注入 ECH（Google 类不需要）</label>
  <button onclick="saveOverride()">保存覆写集合</button>
  <div id="ovStatus"></div>
</div>
<div class="card">
  <h3 style="margin:0 0 8px">已有覆写集合</h3>
  <div id="ovList"></div>
</div>

<h2>📱 iOS 用户</h2>
<div class="card">
  Safari 打开 <span class="code" id="profileUrl">…</span> 安装描述文件，系统 DNS 全部走本 DoH（防污染 + 自定义 IP + ECH）。
</div>

<script>
let TOKEN = localStorage.getItem('doh_token') || '';
function saveToken() {
  const t = document.getElementById('tokenInput').value.trim();
  if (t) {
    TOKEN = t;
    localStorage.setItem('doh_token', t);
    document.getElementById('tokenStatus').textContent = '✅ Token 已保存：' + t;
    refresh();
  } else {
    document.getElementById('tokenStatus').textContent = '❌ 请输入 Token';
  }
}
window.saveToken = saveToken;
document.addEventListener('DOMContentLoaded', () => {
  if (TOKEN) {
    document.getElementById('tokenInput').value = TOKEN;
    document.getElementById('tokenStatus').textContent = '已使用保存的 Token：' + TOKEN;
  }
});
async function api(path, opts={}) {
  opts.headers = Object.assign({'X-Admin-Token': TOKEN}, opts.headers||{});
  if (opts.body) opts.headers['Content-Type'] = 'application/json';
  const r = await fetch(path, opts);
  if (r.status === 401) {
    const ts = document.getElementById('tokenStatus');
    if (ts) ts.textContent = '❌ Token 无效，请在"管理令牌"处重新输入';
    return null;
  }
  return r.json();
}
async function refresh() {
  const d = await api('/admin/api');
  if (!d) return;
  const tb = document.getElementById('rules');
  tb.innerHTML = (d.rules||[]).map(r =>
    '<tr><td>'+r.domain+'</td><td class="code">'+r.ips.join(', ')+'</td><td>'+(r.ech?'✅':'—')+'</td><td><button class="delbtn" data-d="'+encodeURIComponent(r.domain)+'">删除</button></td></tr>'
  ).join('');
  // 事件委托：点击删除按钮
  tb.onclick = (e) => {
    const btn = e.target.closest('.delbtn');
    if (btn) del(decodeURIComponent(btn.dataset.d));
  };
  const g = await api('/admin/config');
  if (g && g.fallbackIp) document.getElementById('fbIp').value = g.fallbackIp;
  if (g && g.ech !== undefined) document.getElementById('gbEch').checked = g.ech;
  document.getElementById('profileUrl').textContent = location.origin + '/profile.mobileconfig';
  loadOverrides();
}
async function saveOverride() {
  const name = document.getElementById('ovName').value.trim();
  const doms = document.getElementById('ovDomains').value.trim().split(/[\s,]+/).map(s=>s.trim()).filter(Boolean);
  const ips = document.getElementById('ovIps').value.trim().split(/[\s,]+/).map(s=>s.trim()).filter(Boolean);
  const ech = document.getElementById('ovEch').checked;
  const d = await api('/admin/override', {method:'POST', body: JSON.stringify({name, domains: doms, ips, ech})});
  document.getElementById('ovStatus').textContent = d && d.ok ? '✅ 已保存 ' + name : (d && d.error ? '❌ ' + d.error : '失败');
  if (d && d.ok) { document.getElementById('ovName').value=''; document.getElementById('ovIps').value=''; document.getElementById('ovDomains').value=''; }
  loadOverrides();
}
async function loadOverrides() {
  const d = await api('/admin/override');
  if (!d) return;
  const box = document.getElementById('ovList');
  if (!d.overrides || d.overrides.length === 0) { box.textContent = '（暂无覆写集合）'; return; }
  const rows = d.overrides.map(o => {
    const ips = o.ips.join(' ');
    return '<div style="padding:8px;border:1px solid #1e293b;border-radius:8px;margin-bottom:8px">' +
      '<strong>'+o.name+'</strong>' +
      '<div class="tip">IP: <span class="code">'+ips+'</span> · ECH: '+(o.ech?'✅':'—')+'</div>' +
      '<div class="tip">域名: '+o.domains.join(', ')+'</div>' +
      '<button class="editovbtn" data-n="'+encodeURIComponent(o.name)+'">✏️ 编辑</button> ' +
      '<button class="delovbtn" data-n="'+encodeURIComponent(o.name)+'">删除</button>' +
      '</div>';
  }).join('');
  box.innerHTML = rows;
  box.onclick = (e) => {
    const delbtn = e.target.closest('.delovbtn');
    if (delbtn) { delOverride(decodeURIComponent(delbtn.dataset.n)); return; }
    const edbtn = e.target.closest('.editovbtn');
    if (edbtn) editOverride(decodeURIComponent(edbtn.dataset.n));
  };
}
async function editOverride(name) {
  const list = await api('/admin/override');
  if (!list || !list.overrides) return;
  const o = list.overrides.find(x => x.name === name);
  if (!o) return;
  document.getElementById('ovName').value = o.name;
  document.getElementById('ovDomains').value = o.domains.join(' ');
  document.getElementById('ovIps').value = o.ips.join(' ');
  document.getElementById('ovEch').checked = !!o.ech;
  const st = document.getElementById('ovStatus');
  st.textContent = '✏️ 正在编辑「' + o.name + '」：改好 IP 后点"保存覆写集合"即更新（同名覆盖，立即生效）。';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
async function delOverride(name) {
  await api('/admin/override?name='+encodeURIComponent(name), {method:'DELETE'});
  loadOverrides();
}
window.saveOverride = saveOverride;
window.loadOverrides = loadOverrides;
window.delOverride = delOverride;
window.editOverride = editOverride;
async function addRule() {
  const body = {domain: document.getElementById('domain').value.trim(),
    ips: document.getElementById('ips').value.split(',').map(s=>s.trim()).filter(Boolean),
    ech: document.getElementById('ech').checked};
  const d = await api('/admin/api', {method:'POST', body: JSON.stringify(body)});
  document.getElementById('status').textContent = d && d.ok ? '✅ 已添加 ' + body.domain : (d && d.error ? '❌ ' + d.error : '操作失败');
  refresh();
}
async function del(domain) {
  await api('/admin/api?domain='+encodeURIComponent(domain), {method:'DELETE'});
  refresh();
}
async function saveGlobal() {
  const body = {fallbackIp: document.getElementById('fbIp').value.trim(),
    ech: document.getElementById('gbEch').checked};
  const d = await api('/admin/config', {method:'PUT', body: JSON.stringify(body)});
  document.getElementById('status').textContent = d && d.ok ? '✅ 已保存全局配置' : '❌ 保存失败';
  refresh();
}
// DOM 加载完再刷新（避免元素未就绪）
document.addEventListener('DOMContentLoaded', () => {
  if (TOKEN) refresh();
});
</script></body></html>`;
}

async function handleAdmin(request, env, url) {
  const path = url.pathname;
  // UI 页面（浏览器直接访问 /admin）
  if (path === '/admin' && request.method === 'GET' && !url.searchParams.get('token')) {
    return new Response(renderUI(env), {
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  }
  if (!authAdmin(request, env)) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), {
      status: 401,
      headers: { 'content-type': 'application/json' },
    });
  }
  if (path === '/admin/config') {
    if (request.method === 'GET') {
      const g = await getGlobal(env);
      return new Response(JSON.stringify({ ok: true, ...g }), {
        headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }
    if (request.method === 'PUT') {
      const body = await request.json();
      const g = await setGlobal(env, body);
      return new Response(JSON.stringify({ ok: true, ...g }), {
        headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }
  }
  if (path === '/admin/upstreams') {
    if (request.method === 'GET') {
      const list = await loadUpstreams(env);
      return new Response(JSON.stringify({ ok: true, upstreams: list }), {
        headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }
    if (request.method === 'PUT') {
      const body = await request.json();
      const arr = Array.isArray(body.upstreams) ? body.upstreams : [];
      if (arr.length === 0) {
        return new Response(JSON.stringify({ ok: false, error: 'empty' }), {
          headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
        });
      }
      try {
        await env.DB.prepare('UPDATE config SET upstreams = ? WHERE id = 1').bind(JSON.stringify(arr)).run();
        return new Response(JSON.stringify({ ok: true, upstreams: arr }), {
          headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
        });
      }
    }
  }
  if (path === '/admin/override') {
    if (request.method === 'GET') {
      const ovs = await listOverrides(env);
      return new Response(JSON.stringify({ ok: true, overrides: ovs }), {
        headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }
    if (request.method === 'POST') {
      const body = await request.json();
      const r = await upsertOverride(env, body.name || '', body.domains || [], body.ips || [], body.ech);
      return new Response(JSON.stringify(r), {
        headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }
    if (request.method === 'DELETE') {
      const name = url.searchParams.get('name') || '';
      const r = await delOverride(env, name);
      return new Response(JSON.stringify(r), {
        headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }
  }
  if (path === '/admin/api' || path === '/admin') {
    if (request.method === 'GET') {
      const rules = await listRules(env);
      return new Response(JSON.stringify({ ok: true, rules }), {
        headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }
    if (request.method === 'POST') {
      const body = await request.json();
      const r = await addRule(env, body.domain || '', body.ips || [], body.ech);
      return new Response(JSON.stringify(r), {
        headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }
    if (request.method === 'DELETE') {
      const domain = url.searchParams.get('domain') || '';
      const r = await delRule(env, domain);
      return new Response(JSON.stringify(r), {
        headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }
  }
  return new Response(JSON.stringify({ ok: false, error: 'not found' }), { status: 404 });
}

// ==================== iOS 描述文件 ====================

async function handleProfile(env) {
  const dohDomain = (env && env.DOH_DOMAIN) || 'edgeone-doh.edgeone.cool';
  const uuid = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  };
  const uuid1 = uuid();
  const uuid2 = uuid();
  const profile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>https://${dohDomain}/api/v1/sync</string>
			</dict>
			<key>PayloadDescription</key>
			<string>Encrypted DNS (DoH) via ${dohDomain}</string>
			<key>PayloadDisplayName</key>
			<string>ECH DoH</string>
			<key>PayloadIdentifier</key>
			<string>com.anglesgirl.doh.dns</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>${uuid1}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>系统 DNS 走 DoH：防污染 + 指定域名走自定义 IP + ECH</string>
	<key>PayloadDisplayName</key>
	<string>ECH DoH 配置</string>
	<key>PayloadIdentifier</key>
	<string>com.anglesgirl.doh.profile</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>${uuid2}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`;
  return new Response(profile, {
    headers: {
      'content-type': 'application/x-apple-aspen-config',
      'content-disposition': 'attachment; filename=ech-doh.mobileconfig',
    },
  });
}
