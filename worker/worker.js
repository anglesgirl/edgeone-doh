// EdgeOne Pages Functions — DoH 服务器（免服务器版）
// 路由：/dns-query（标准 DoH wire format）+ /resolve（JSON 调试）
// 规则存 KV（key: rule:<domain> → JSON {ips:[],ech:true}）
// 上游：CF Gateway DoH（海外节点可达）
// ECH：从 cloudflare-ech.com 的 HTTPS 记录获取（缓存到 KV）

const ECH_SOURCE = 'cloudflare-ech.com';
const UPSTREAMS = [
  'https://cloudflare-dns.com/dns-query', // CF 公共 DoH（未墙但慢）
  'https://dns.google/resolve',           // Google 公共 DoH（dns-query 也支持）
];
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
  // 返回 {name, nextOff}，支持压缩指针
  let labels = [];
  let pos = off;
  let jumped = false;
  let jumpTarget = -1;
  let guard = 0;
  while (guard++ < 64) {
    const len = buf[pos];
    if (len === 0) {
      pos += 1;
      break;
    }
    if ((len & 0xC0) === 0xC0) {
      if (!jumped) {
        jumpTarget = ((len & 0x3F) << 8) | buf[pos + 1];
      }
      pos += 2;
      jumped = true;
      if (jumpTarget < 0) break;
      pos = jumpTarget;
      continue;
    }
    labels.push(buf.slice(pos + 1, pos + 1 + len).toString('ascii'));
    pos += 1 + len;
  }
  let nextOff = jumped ? off + 2 : pos;
  // 跳过压缩指针后的 2 字节（如果跳转发生，nextOff 是原始偏移+2）
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

async function upstreamJSON(name, type, env) {
  const url = `${UPSTREAMS[0]}?name=${encodeURIComponent(name)}&type=${type}`;
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
    // 尝试 Google
    try {
      const url2 = `${UPSTREAMS[1]}?name=${encodeURIComponent(name)}&type=${type}`;
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
    if (m) return m[1];
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
    if (key === 5) return rdata.slice(pos, pos + len);
    pos += len;
  }
  return null;
}

// 获取 ECH 配置（D1 缓存 → 上游查询）
async function getECH(env) {
  // D1 缓存
  try {
    const row = await env.DB.prepare('SELECT ech, ts FROM ech_cache WHERE id = 1').first();
    if (row && row.ech && Date.now() - row.ts < KV_ECH_TTL * 1000) return row.ech;
  } catch (e) { /* D1 不可用则跳过 */ }

  const jr = await upstreamJSON(ECH_SOURCE, 65, env);
  const ech = extractEchFromJSON(jr);
  if (ech) {
    try {
      await env.DB.prepare('UPDATE ech_cache SET ech = ?, ts = ? WHERE id = 1').bind(ech, Date.now()).run();
    } catch (e) { /* ignore */ }
  }
  return ech;
}

// ---------- 全局配置 ----------

// getGlobalConfig 读取全局配置 {fallbackIp, ech}
async function getGlobalConfig(env) {
  try {
    const row = await env.DB.prepare('SELECT fallback_ip, ech FROM config WHERE id = 1').first();
    if (row) return { fallbackIp: row.fallback_ip || '', ech: !!row.ech };
  } catch (e) { /* ignore */ }
  return {};
}

// ---------- 规则管理 ----------

async function getRule(env, domain) {
  try {
    const row = await env.DB.prepare('SELECT domain, ips, ech FROM rules WHERE domain = ?').bind(domain).first();
    if (row) return { domain: row.domain, ips: JSON.parse(row.ips), ech: !!row.ech };
  } catch (e) { /* ignore */ }
  // 子域匹配：向上找
  let d = domain;
  while (d.includes('.')) {
    d = d.slice(d.indexOf('.') + 1);
    try {
      const row = await env.DB.prepare('SELECT domain, ips, ech FROM rules WHERE domain = ?').bind(d).first();
      if (row) return { domain: row.domain, ips: JSON.parse(row.ips), ech: !!row.ech };
    } catch (e) { /* ignore */ }
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
  if (path !== '/dns-query' && path !== '/resolve' && path !== '/') {
    return new Response('ECH DoH on EdgeOne. Use /dns-query', { status: 404 });
  }

  // 解析请求
  let qbuf = null;
  if (request.method === 'POST') {
    qbuf = Buffer.from(await request.arrayBuffer());
  } else {
    const dnsParam = url.searchParams.get('dns');
    if (dnsParam) {
      qbuf = Buffer.from(dnsParam.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    }
  }
  if (!qbuf || qbuf.length < 12) {
    return new Response('missing dns query', { status: 400 });
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
    qtype = qbuf.readUInt16BE(d.nextOff);
    off = d.nextOff + 4;
    break; // 只处理第一个 question
  }
  const id = qbuf.readUInt16BE(0);

  // 规则命中？
  const rule = await getRule(env, qname.toLowerCase());
  const gcfg = await getGlobalConfig(env);
  let answers = [];

  if (rule && rule.ips && rule.ips.length > 0 && qtype === 1) {
    // 手动规则命中 A 记录：返回自定义 IP
    answers = buildAAnswer(qnameWire, qtype, rule.ips, 300);
  } else if (qtype === 1) {
    // 未命中手动规则 → 上游解析，然后检查是否 AS13335
    const jr = await upstreamJSON(qname, qtype, env);
    if (jr && jr.Answer) {
      answers = jsonToAnswers(qnameWire, qname, jr.Answer);
    }
    // 全局配置：如果解析出的 IP 属于 Cloudflare (AS13335)，
    // 且配置了 fallbackIp → 替换为自定义 IP（换 CF 共享 IP 绕过封 IP）
    if (gcfg.fallbackIp && jr && jr.Answer) {
      // 上游解析出的任一 A 记录 IP 属于 AS13335 → 替换为 fallbackIp
      let upCF = false;
      for (const a of jr.Answer) {
        if (a.type === 1 && await isCloudflareIP(a.data, env)) { upCF = true; break; }
      }
      if (upCF) {
        answers = buildAAnswer(qnameWire, qtype, [gcfg.fallbackIp], 300);
      }
    }
  } else if (qtype === 65) {
    // HTTPS 记录：手动规则（ech=true）或 域名是 CF 托管（A 记录属 AS13335）→ 注入 ECH
    let injectECH = false;
    if (rule && rule.ech) {
      injectECH = true;
    } else {
      // 未命中手动规则：查 A 记录判断是否 CF 托管（AS13335 反查）
      const jrA = await upstreamJSON(qname, 1, env);
      if (jrA && jrA.Answer) {
        for (const a of jrA.Answer) {
          if (a.type === 1 && await isCloudflareIP(a.data, env)) { injectECH = true; break; }
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

  // Workers 原生 Buffer 即 Uint8Array，可直接作为 Response body
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

async function listRules(env) {
  try {
    const { results } = await env.DB.prepare('SELECT domain, ips, ech FROM rules ORDER BY domain').all();
    return (results || []).map(r => ({ domain: r.domain, ips: JSON.parse(r.ips), ech: !!r.ech }));
  } catch (e) { return []; }
}

async function addRule(env, domain, ips, ech) {
  domain = domain.trim().toLowerCase().replace(/\.$/, '');
  if (!domain) return { ok: false, error: 'domain empty' };
  for (const ip of ips) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return { ok: false, error: `invalid IP: ${ip}` };
    }
  }
  try {
    await env.DB.prepare('INSERT INTO rules (domain, ips, ech) VALUES (?, ?, ?) ON CONFLICT(domain) DO UPDATE SET ips = excluded.ips, ech = excluded.ech')
      .bind(domain, JSON.stringify(ips), ech ? 1 : 0).run();
  } catch (e) { return { ok: false, error: String(e) }; }
  return { ok: true };
}

async function delRule(env, domain) {
  domain = domain.trim().toLowerCase().replace(/\.$/, '');
  try {
    await env.DB.prepare('DELETE FROM rules WHERE domain = ?').bind(domain).run();
  } catch (e) { /* ignore */ }
  return { ok: true };
}

async function getGlobal(env) {
  try {
    const row = await env.DB.prepare('SELECT fallback_ip, ech FROM config WHERE id = 1').first();
    if (row) return { fallbackIp: row.fallback_ip || '', ech: !!row.ech };
  } catch (e) { /* ignore */ }
  return {};
}

async function setGlobal(env, cfg) {
  const cur = await getGlobal(env);
  if (cfg.fallbackIp !== undefined) cur.fallbackIp = cfg.fallbackIp.trim() || '';
  if (cfg.ech !== undefined) cur.ech = !!cfg.ech;
  try {
    await env.DB.prepare('UPDATE config SET fallback_ip = ?, ech = ? WHERE id = 1')
      .bind(cur.fallbackIp, cur.ech ? 1 : 0).run();
  } catch (e) { /* ignore */ }
  return cur;
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
    <input id="domain" placeholder="域名，如 archiveofourown.org">
    <input id="ips" placeholder="IP（逗号分隔，如 172.67.187.141,104.20.9.2）">
  </div>
  <label><input type="checkbox" id="ech" checked style="width:auto"> 注入 ECH</label>
  <button onclick="addRule()">添加规则</button>
</div>

<h2>📋 规则列表</h2>
<table><thead><tr><th>域名</th><th>自定义 IP</th><th>ECH</th><th></th></tr></thead><tbody id="rules"></tbody></table>

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
}
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
				<string>https://${dohDomain}/dns-query</string>
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
