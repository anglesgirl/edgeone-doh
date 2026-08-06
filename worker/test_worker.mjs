// Workers 版本地测试（模拟 CF Workers 环境：env.KV + fetch）
import worker from './worker.js';

const store = new Map();
const kv = {
  get: async (k) => store.get(k) ?? null,
  put: async (k, v) => { store.set(k, v); },
  delete: async (k) => { store.delete(k); },
};

function enc(name) {
  let s = name.endsWith('.') ? name.slice(0, -1) : name;
  let out = Buffer.alloc(0);
  for (const p of s.split('.')) {
    const b = Buffer.from(p);
    out = Buffer.concat([out, Buffer.from([b.length]), b]);
  }
  return Buffer.concat([out, Buffer.from([0])]);
}
function bq(d, t) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(0x1234, 0); h.writeUInt16BE(0x0100, 2); h.writeUInt16BE(1, 4);
  const q = Buffer.alloc(4);
  q.writeUInt16BE(t, 0); q.writeUInt16BE(1, 2);
  return Buffer.concat([h, enc(d), q]);
}
function parseFull(buf) {
  const an = buf.readUInt16BE(6);
  let pos = 12;
  while (buf[pos] !== 0) pos += 1 + buf[pos];
  pos += 5;
  const out = [];
  for (let i = 0; i < an; i++) {
    pos += 2;
    const rt = buf.readUInt16BE(pos);
    const ttl = buf.readUInt32BE(pos + 4);
    const rd = buf.readUInt16BE(pos + 8);
    const rd2 = buf.slice(pos + 10, pos + 10 + rd);
    pos += 10 + rd;
    if (rt === 1 && rd === 4) out.push(`A ${[...rd2].join('.')} ttl=${ttl}`);
    else if (rt === 65) out.push(`HTTPS len=${rd} ttl=${ttl}`);
    else out.push(`type${rt} len=${rd}`);
  }
  return out.join(' | ') || '(空)';
}

const env = { KV: kv, ADMIN_TOKEN: 'test-token' };
const doh = (q) => worker.fetch(new Request('https://doh.example/dns-query', { method: 'POST', body: q, headers: { 'content-type': 'application/dns-message' } }), env);
const admin = (path, opts = {}) => worker.fetch(new Request('https://doh.example' + path, { ...opts, headers: { 'X-Admin-Token': 'test-token', ...(opts.headers || {}) } }), env);

// 1. 加规则
console.log('1. 加规则:');
let r = await admin('/admin/api', { method: 'POST', body: JSON.stringify({ domain: 'archiveofourown.org', ips: ['172.67.187.141'], ech: true }), headers: { 'content-type': 'application/json' } });
console.log('  ', await r.text());

// 2. A 查询（规则命中，本地）
console.log('2. A 查询 AO3（规则命中）:');
const r2 = await doh(bq('archiveofourown.org', 1));
console.log('  ', parseFull(Buffer.from(await r2.arrayBuffer())));

// 3. 全局配置 + AS13335（网络）
console.log('3. 设置全局 fallbackIp:');
r = await admin('/admin/config', { method: 'PUT', body: JSON.stringify({ fallbackIp: '172.67.187.141', ech: true }), headers: { 'content-type': 'application/json' } });
console.log('  ', await r.text());

// 4. UI
console.log('4. UI:');
r = await worker.fetch(new Request('https://doh.example/admin'), env);
const uiText = await r.text();
console.log('  ', r.status, uiText.includes('ECH DoH 管理'));

// 5. profile
console.log('5. profile:');
r = await worker.fetch(new Request('https://doh.example/profile.mobileconfig'), env);
console.log('  ', (await r.text()).includes('dns-query'));

// 6. 未授权
console.log('6. 未授权:');
r = await worker.fetch(new Request('https://doh.example/admin/api'), env);
console.log('  ', r.status);

process.exit(0);
