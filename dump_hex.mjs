// dump 应答 hex 定位问题
import { onRequest as dohHandler } from './functions/index.js';

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

// 加规则
await kv.put('rule:archiveofourown.org', JSON.stringify({ domain: 'archiveofourown.org', ips: ['172.67.187.141'], ech: true }));

const q = buildDNSQuery('archiveofourown.org', 1);
const r = await dohHandler({
  request: new Request('https://test.edgeone.app/dns-query', {
    method: 'POST', body: q, headers: { 'content-type': 'application/dns-message' },
  }),
  env: { KV: kv, ADMIN_TOKEN: 'test123' },
});
const buf = Buffer.from(await r.arrayBuffer());
console.log('A 应答 len:', buf.length);
console.log('hex:', buf.toString('hex').match(/.{1,32}/g).join('\n    '));
process.exit(0);
