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
const KV_ECH_KEY = 'ech:config';
const KV_ECH_TTL = 300; // 5 分钟

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

// 获取 ECH 配置（KV 缓存 → 上游查询）
async function getECH(env) {
  // KV 缓存
  try {
    const cached = await env.KV.get(KV_ECH_KEY);
    if (cached) {
      const c = JSON.parse(cached);
      if (Date.now() - c.ts < KV_ECH_TTL * 1000) return c.ech;
    }
  } catch (e) { /* KV 不可用则跳过 */ }

  const jr = await upstreamJSON(ECH_SOURCE, 65, env);
  const ech = extractEchFromJSON(jr);
  if (ech) {
    try {
      await env.KV.put(KV_ECH_KEY, JSON.stringify({ ech, ts: Date.now() }));
    } catch (e) { /* ignore */ }
  }
  return ech;
}

// ---------- 规则管理 ----------

async function getRule(env, domain) {
  try {
    const raw = await env.KV.get(`rule:${domain}`);
    if (raw) return JSON.parse(raw);
  } catch (e) { /* ignore */ }
  // 子域匹配：向上找
  let d = domain;
  while (d.includes('.')) {
    d = d.slice(d.indexOf('.') + 1);
    try {
      const raw = await env.KV.get(`rule:${d}`);
      if (raw) return JSON.parse(raw);
    } catch (e) { /* ignore */ }
  }
  return null;
}

// ---------- 主处理 ----------

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname;

  // 只处理 /dns-query 和 /resolve
  if (path !== '/dns-query' && path !== '/resolve') {
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
  let answers = [];

  if (rule && rule.ips && rule.ips.length > 0 && qtype === 1) {
    // A 记录：返回自定义 IP
    answers = buildAAnswer(qnameWire, qtype, rule.ips, 300);
  } else if (rule && rule.ech && qtype === 65) {
    // HTTPS 记录：注入 ECH
    const ech = await getECH(env);
    if (ech) {
      answers = buildHTTPSAnswer(qnameWire, ech, 300);
    }
  } else {
    // 未命中 → 上游转发（JSON → wire）
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
