// 验证 ECH 内容 + 未命中转发 + 管理 API
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
    pos += 2; // name ptr
    const rtype = buf.readUInt16BE(pos);
    const ttl = buf.readUInt32BE(pos + 4);
    const rdlen = buf.readUInt16BE(pos + 8);
    const rdata = buf.slice(pos + 10, pos + 10 + rdlen);
    pos += 10 + rdlen;
    if (rtype === 1 && rdlen === 4) out.push(`A ${[...rdata].join('.')} ttl=${ttl}`);
    else if (rtype === 65) {
      // 解析 HTTPS: priority + target + ech param
      let p = 2;
      while (p < rdata.length && rdata[p] !== 0) p += 1 + rdata[p];
      p += 1;
      const params = [];
      while (p + 4 <= rdata.length) {
        const key = rdata.readUInt16BE(p);
        const len = rdata.readUInt16BE(p + 2);
        const val = rdata.slice(p + 4, p + 4 + len);
        params.push(key === 5 ? `ech=${len}B(${val.toString('hex').slice(0, 24)}...)` : `key${key}=${len}B`);
        p += 4 + len;
      }
      out.push(`HTTPS ttl=${ttl} ${params.join(' ')}`);
    }
  }
  return out.join(' | ');
}

const env = { KV: kv, ADMIN_TOKEN: 'test123' };
await kv.put('rule:archiveofourown.org', JSON.stringify({ domain: 'archiveofourown.org', ips: ['172.67.187.141'], ech: true }));

// 1. HTTPS 应答内容验证
console.log('1. HTTPS/ECH 内容:');
const q65 = buildQuery('archiveofourown.org', 65);
const r65 = await dohHandler({ request: new Request('https://t/dns-query', { method: 'POST', body: q65, headers: { 'content-type': 'application/dns-message' } }), env });
console.log('  ', parseFull(Buffer.from(await r65.arrayBuffer())));

// 2. 未命中域名 → 上游（真实网络，可能慢）
console.log('2. 未命中 example.com → 上游:');
try {
  const q1 = buildQuery('example.com', 1);
  const r1 = await Promise.race([
    dohHandler({ request: new Request('https://t/dns-query', { method: 'POST', body: q1, headers: { 'content-type': 'application/dns-message' } }), env }),
    new Promise((_, rej) => setTimeout(() => rej(new Error('上游超时 20s')), 20000)),
  ]);
  console.log('  ', parseFull(Buffer.from(await r1.arrayBuffer())));
} catch (e) {
  console.log('  ⚠️', e.message);
}

// 3. 管理 API 完整流程
console.log('3. 管理 API:');
const add = await adminHandler({ request: new Request('https://t/admin', { method: 'POST', body: JSON.stringify({ domain: 'example.org', ips: ['1.2.3.4'], ech: false }), headers: { 'content-type': 'application/json', 'X-Admin-Token': 'test123' } }), env });
console.log('   添加:', await add.text());
const list = await adminHandler({ request: new Request('https://t/admin', { headers: { 'X-Admin-Token': 'test123' } }), env });
const lj = await list.json();
console.log('   列表:', lj.rules.map(r => `${r.domain}(${r.ips.join(',')}${r.ech ? ',ech' : ''})`).join(' '));
const del = await adminHandler({ request: new Request('https://t/admin?domain=example.org', { method: 'DELETE', headers: { 'X-Admin-Token': 'test123' } }), env });
console.log('   删除:', await del.text());
const unauth = await adminHandler({ request: new Request('https://t/admin', {}), env });
console.log('   未授权 status:', unauth.status);

process.exit(0);
