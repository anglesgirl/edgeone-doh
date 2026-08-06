// 全流程测试：全局 AS13335 替换 + ECH 保留 + UI + 管理 API
import { onRequest as dohHandler } from './functions/index.js';
import { onRequest as adminHandler } from './functions/admin.js';

const store = new Map();
const kv = {
  get: async (k) => store.get(k) ?? null,
  put: async (k, v) => { store.set(k, v); },
  delete: async (k) => { store.delete(k); },
};

function encodeName(name) {
  let s = name.endsWith('.') ? name.slice(0, -1) : name;
  let out = Buffer.alloc(0);
  for (const p of s.split('.')) {
    const b = Buffer.from(p, 'ascii');
    out = Buffer.concat([out, Buffer.from([b.length]), b]);
  }
  return Buffer.concat([out, Buffer.from([0])]);
}
function buildQuery(domain, type) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(0x1234, 0); h.writeUInt16BE(0x0100, 2); h.writeUInt16BE(1, 4);
  const q = Buffer.alloc(4);
  q.writeUInt16BE(type, 0); q.writeUInt16BE(1, 2);
  return Buffer.concat([h, encodeName(domain), q]);
}
function parseFull(buf) {
  const ancount = buf.readUInt16BE(6);
  let pos = 12;
  while (buf[pos] !== 0) pos += 1 + buf[pos];
  pos += 5;
  const out = [];
  for (let i = 0; i < ancount; i++) {
    pos += 2;
    const rtype = buf.readUInt16BE(pos);
    const ttl = buf.readUInt32BE(pos + 4);
    const rdlen = buf.readUInt16BE(pos + 8);
    const rdata = buf.slice(pos + 10, pos + 10 + rdlen);
    pos += 10 + rdlen;
    if (rtype === 1 && rdlen === 4) out.push(`A ${[...rdata].join('.')} ttl=${ttl}`);
    else if (rtype === 65) {
      let p = 2;
      while (p < rdata.length && rdata[p] !== 0) p += 1 + rdata[p];
      p += 1;
      const params = [];
      while (p + 4 <= rdata.length) {
        const key = rdata.readUInt16BE(p);
        const len = rdata.readUInt16BE(p + 2);
        params.push(key === 5 ? `ech=${len}B` : `key${key}`);
        p += 4 + len;
      }
      out.push(`HTTPS ${params.join(' ')}`);
    } else out.push(`type${rtype} len=${rdlen}`);
  }
  return out.join(' | ');
}

const env = { KV: kv, ADMIN_TOKEN: 'test123' };
const doh = (q) => dohHandler({
  request: new Request('https://t/dns-query', { method: 'POST', body: q, headers: { 'content-type': 'application/dns-message' } }),
  env,
});
const admin = (path, opts = {}) => adminHandler({
  request: new Request('https://t' + path, { ...opts, headers: { 'X-Admin-Token': 'test123', 'content-type': 'application/json', ...(opts.headers || {}) } }),
  env,
});

// 1. 设置全局配置：fallbackIp + ech
console.log('1. 设置全局配置:');
let r = await admin('/admin/config', { method: 'PUT', body: JSON.stringify({ fallbackIp: '172.67.187.141', ech: true }) });
console.log('  ', await r.text());

// 2. 查询 CF 托管域名（未加手动规则，走自动 AS13335 替换）
//    archiveofourown.org 是 CF 托管 → 应替换为 172.67.187.141
console.log('2. A 查询 AO3（CF 托管 → 自动替换为 fallbackIp）:');
const q1 = buildQuery('archiveofourown.org', 1);
const r1 = await Promise.race([doh(q1), new Promise((_, rej) => setTimeout(() => rej(new Error('超时')), 30000))]);
console.log('  ', parseFull(Buffer.from(await r1.arrayBuffer())));

// 3. HTTPS 查询 AO3 → 应注入 ECH（即使没手动规则，CF 托管自动注入）
console.log('3. HTTPS 查询 AO3（自动 ECH 注入）:');
const q2 = buildQuery('archiveofourown.org', 65);
const r2 = await Promise.race([doh(q2), new Promise((_, rej) => setTimeout(() => rej(new Error('超时')), 30000))]);
console.log('  ', parseFull(Buffer.from(await r2.arrayBuffer())));

// 4. 非 CF 域名 → 不替换，正常返回
console.log('4. A 查询 example.com（非 CF，正常返回）:');
const q3 = buildQuery('example.com', 1);
const r3 = await Promise.race([doh(q3), new Promise((_, rej) => setTimeout(() => rej(new Error('超时')), 30000))]);
console.log('  ', parseFull(Buffer.from(await r3.arrayBuffer())));

// 5. 手动规则优先级高于全局
console.log('5. 手动规则（example.org → 1.2.3.4）:');
await admin('/admin/api', { method: 'POST', body: JSON.stringify({ domain: 'example.org', ips: ['1.2.3.4'], ech: false }) });
const q4 = buildQuery('example.org', 1);
const r4 = await Promise.race([doh(q4), new Promise((_, rej) => setTimeout(() => rej(new Error('超时')), 30000))]);
console.log('  ', parseFull(Buffer.from(await r4.arrayBuffer())));

// 6. UI 页面
console.log('6. UI 页面:');
const ui = await adminHandler({ request: new Request('https://t/admin', {}), env });
const uiText = await ui.text();
console.log('  ', `status=${ui.status} hasTitle=${uiText.includes('ECH DoH 管理')} hasForm=${uiText.includes('addRule')} hasGlobal=${uiText.includes('AS13335')}`);

// 7. 管理 API 列表（含自动规则标记逻辑——当前规则都是手动的）
console.log('7. 规则列表:');
const lst = await admin('/admin/api');
const lj = await lst.json();
console.log('  ', lj.rules.map(x => x.domain).join(', '));

console.log('\n全部测试完成 ✅');
process.exit(0);
