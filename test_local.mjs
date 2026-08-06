// 只测本地用例（1-4,6-7），带整体超时
import { onRequest as dohHandler } from './functions/index.js';
import { onRequest as adminHandler } from './functions/admin.js';
import { onRequest as profileHandler } from './functions/profile.mobileconfig.js';

const store = new Map();
const kv = {
  get: async (k) => store.get(k) ?? null,
  put: async (k, v) => { store.set(k, v); },
  delete: async (k) => { store.delete(k); },
};

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
  header.writeUInt16BE(1, 4);
  const qname = encodeName(domain);
  const q = Buffer.alloc(4);
  q.writeUInt16BE(qtype, 0);
  q.writeUInt16BE(1, 2);
  return Buffer.concat([header, qname, q]);
}

function decodeAnswers(buf) {
  const ancount = buf.readUInt16BE(6);
  const out = [];
  let pos = 12;
  let guard = 0;
  while (buf[pos] !== 0 && guard++ < 64) pos += 1 + buf[pos];
  pos += 5;
  for (let i = 0; i < ancount && i < 20; i++) {
    if ((buf[pos] & 0xC0) === 0xC0) pos += 2;
    else { while (buf[pos] !== 0 && guard++ < 64) pos += 1 + buf[pos]; pos += 1; }
    const rtype = buf.readUInt16BE(pos);
    const ttl = buf.readUInt32BE(pos + 4);
    const rdlen = buf.readUInt16BE(pos + 8);
    const rdata = buf.slice(pos + 10, pos + 10 + rdlen);
    pos += 10 + rdlen;
    if (rtype === 1 && rdlen === 4) out.push(`A ${[...rdata].join('.')} ttl=${ttl}`);
    else if (rtype === 65) out.push(`HTTPS len=${rdlen} ttl=${ttl}`);
    else out.push(`type${rtype} len=${rdlen}`);
  }
  return out;
}

function dohReq(q) {
  return dohHandler({
    request: new Request('https://test.edgeone.app/dns-query', {
      method: 'POST', body: q, headers: { 'content-type': 'application/dns-message' },
    }),
    env: { KV: kv, ADMIN_TOKEN: 'test123' },
  });
}

const t0 = Date.now();
console.log('1. 添加规则...');
const r1 = await adminHandler({
  request: new Request('https://test.edgeone.app/admin', {
    method: 'POST', body: JSON.stringify({ domain: 'archiveofourown.org', ips: ['172.67.187.141'], ech: true }),
    headers: { 'content-type': 'application/json', 'X-Admin-Token': 'test123' },
  }),
  env: { KV: kv, ADMIN_TOKEN: 'test123' },
});
console.log('  ', await r1.text());

console.log('2. A 查询（规则命中，本地）...');
const q = buildDNSQuery('archiveofourown.org', 1);
const r2 = await dohReq(q);
const buf2 = Buffer.from(await r2.arrayBuffer());
console.log('  ', decodeAnswers(buf2).join(' | '));

console.log('3. HTTPS 查询（ECH，需要网络——可能慢）...');
const q3 = buildDNSQuery('archiveofourown.org', 65);
try {
  const r3 = await Promise.race([
    dohReq(q3),
    new Promise((_, rej) => setTimeout(() => rej(new Error('ECH 网络超时')), 20000)),
  ]);
  const buf3 = Buffer.from(await r3.arrayBuffer());
  console.log('  ', decodeAnswers(buf3).join(' | '));
} catch (e) {
  console.log('  ⚠️', e.message);
}

console.log('4. iOS 描述文件...');
const r4 = await profileHandler({ env: { KV: kv, DOH_DOMAIN: 'test.edgeone.app' } });
const t4 = await r4.text();
console.log('  ', t4.includes('test.edgeone.app/dns-query') ? 'OK' : 'FAIL');

console.log(`完成，耗时 ${Date.now() - t0}ms`);
process.exit(0);
