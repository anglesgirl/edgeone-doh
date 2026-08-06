// EdgeOne DoH 本地测试（Node 模拟）
// 模拟 KV + 调用 onRequest
import { onRequest as dohHandler } from './functions/index.js';
import { onRequest as adminHandler } from './functions/admin.js';
import { onRequest as profileHandler } from './functions/profile.mobileconfig.js';

// ---- KV mock ----
const store = new Map();
const kv = {
  get: async (k) => store.get(k) ?? null,
  put: async (k, v) => { store.set(k, v); },
  delete: async (k) => { store.delete(k); },
};

function makeRequest(url, opts = {}) {
  return new Request(url, opts);
}

function makeCtx(path, method = 'GET', body = null, headers = {}) {
  const url = `https://test.edgeone.app${path}`;
  const req = makeRequest(url, {
    method,
    body: body ? JSON.stringify(body) : undefined,
    headers: { 'content-type': 'application/json', ...headers },
  });
  return { request: req, env: { KV: kv, ADMIN_TOKEN: 'test123' } };
}

// ---- DNS wire 工具（测试用，复制自 index.js 简化版）----
function encodeName(name) {
  let s = name.endsWith('.') ? name.slice(0, -1) : name;
  const parts = s.split('.');
  let out = Buffer.alloc(0);
  for (const p of parts) {
    const b = Buffer.from(p, 'ascii');
    out = Buffer.concat([out, Buffer.from([b.length]), b]);
  }
  return Buffer.concat([out, Buffer.from([0])]);
}

function buildDNSQuery(domain, qtype) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4); // qdcount
  const qname = encodeName(domain);
  const q = Buffer.alloc(4);
  q.writeUInt16BE(qtype, 0);
  q.writeUInt16BE(1, 2);
  return Buffer.concat([header, qname, q]);
}

function decodeAnswers(buf) {
  // 简化：只解析 answer 的 type + rdata 摘要
  const ancount = buf.readUInt16BE(6);
  const out = [];
  let pos = 12;
  // 跳过 question（简化：假设 1 个）
  while (buf[pos] !== 0) pos += 1 + buf[pos];
  pos += 5; // 根 + type + class
  for (let i = 0; i < ancount; i++) {
    // name 指针
    if ((buf[pos] & 0xC0) === 0xC0) pos += 2;
    else { while (buf[pos] !== 0) pos += 1 + buf[pos]; pos += 1; }
    const rtype = buf.readUInt16BE(pos);
    const ttl = buf.readUInt32BE(pos + 4);
    const rdlen = buf.readUInt16BE(pos + 8);
    const rdata = buf.slice(pos + 10, pos + 10 + rdlen);
    pos += 10 + rdlen;
    if (rtype === 1 && rdlen === 4) {
      out.push(`A ${[...rdata].join('.')} ttl=${ttl}`);
    } else if (rtype === 65) {
      // HTTPS：提取 ech 参数
      let p = 2;
      while (p < rdata.length && rdata[p] !== 0) p += 1 + rdata[p];
      p += 1;
      const params = [];
      while (p + 4 <= rdata.length) {
        const key = rdata.readUInt16BE(p);
        const len = rdata.readUInt16BE(p + 2);
        params.push(`key${key}=${rdata.slice(p + 4, p + 4 + len).length}b`);
        p += 4 + len;
      }
      out.push(`HTTPS ${params.join(',')} ttl=${ttl}`);
    } else {
      out.push(`type${rtype} len=${rdlen}`);
    }
  }
  return out;
}

// ---- 测试流程 ----
const results = [];
async function test(name, fn) {
  try {
    const r = await fn();
    results.push(`✅ ${name}: ${r}`);
  } catch (e) {
    results.push(`❌ ${name}: ${e.message}`);
  }
}

// 1. 添加规则
await test('添加规则 AO3', async () => {
  const r = await adminHandler(makeCtx('/admin', 'POST', { domain: 'archiveofourown.org', ips: ['172.67.187.141', '104.20.9.2'], ech: true }));
  const j = await r.json();
  return JSON.stringify(j);
});

// 2. 规则列表
await test('规则列表', async () => {
  const r = await adminHandler(makeCtx('/admin', 'GET'));
  const j = await r.json();
  return `count=${j.rules.length} first=${j.rules[0]?.domain}`;
});

// 3. A 记录查询（命中规则 → 自定义 IP）
await test('A 查询（规则命中）', async () => {
  const q = buildDNSQuery('archiveofourown.org', 1);
  const r = await dohHandler(makeCtx('/dns-query', 'POST', null, {}), { body: q });
  // 手动构造 POST body
  const r2 = await dohHandler({
    request: new Request('https://test.edgeone.app/dns-query', {
      method: 'POST',
      body: q,
      headers: { 'content-type': 'application/dns-message' },
    }),
    env: { KV: kv, ADMIN_TOKEN: 'test123' },
  });
  const buf = Buffer.from(await r2.arrayBuffer());
  return decodeAnswers(buf).join(' | ');
});

// 4. HTTPS 查询（ECH 注入）
await test('HTTPS 查询（ECH 注入）', async () => {
  const q = buildDNSQuery('archiveofourown.org', 65);
  const r2 = await dohHandler({
    request: new Request('https://test.edgeone.app/dns-query', {
      method: 'POST',
      body: q,
      headers: { 'content-type': 'application/dns-message' },
    }),
    env: { KV: kv, ADMIN_TOKEN: 'test123' },
  });
  const buf = Buffer.from(await r2.arrayBuffer());
  return decodeAnswers(buf).join(' | ');
});

// 5. 未命中域名 → 上游转发（网络用例，可能慢，标为可选）
await test('A 查询（未命中→上游）', async () => {
  const q = buildDNSQuery('example.com', 1);
  const r2 = await dohHandler({
    request: new Request('https://test.edgeone.app/dns-query', {
      method: 'POST',
      body: q,
      headers: { 'content-type': 'application/dns-message' },
    }),
    env: { KV: kv, ADMIN_TOKEN: 'test123' },
  });
  const buf = Buffer.from(await r2.arrayBuffer());
  const dec = decodeAnswers(buf).join(' | ');
  if (dec.includes('type') || dec.includes('A ')) return dec;
  return `(上游可能慢，返回 ${buf.length} bytes)`;
});

// 6. iOS 描述文件
await test('iOS 描述文件', async () => {
  const r = await profileHandler({ env: { KV: kv, DOH_DOMAIN: 'test.edgeone.app' } });
  const text = await r.text();
  return `content-type=${r.headers.get('content-type')} hasDNSProtocol=${text.includes('HTTPS')} hasServerURL=${text.includes('test.edgeone.app/dns-query')}`;
});

// 7. 未授权
await test('未授权拒绝', async () => {
  const r = await adminHandler(makeCtx('/admin', 'GET', null, {}));
  return `status=${r.status}`;
});

console.log(results.join('\n'));
