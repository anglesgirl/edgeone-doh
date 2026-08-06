// 通配符规则测试：*.cloudflare.com → 覆盖所有子域
import worker from '/tmp/dohd-edge/worker/worker.js';

const tables = {
  rules: new Map(),
  config: new Map([['1', { id: 1, fallback_ip: '172.67.187.141', ech: 1 }]]),
  ech_cache: new Map([['1', { id: 1, ech: '', ts: 0 }]]),
};
const DB = {
  prepare(sql) { this.sql = sql; return this; },
  bind(...a) { this.args = a; return this; },
  async run() {
    const s = this.sql, a = this.args;
    if (s.startsWith('INSERT INTO rules')) tables.rules.set(a[0], { domain: a[0], ips: a[1], ech: a[2] });
    else if (s.startsWith('DELETE FROM rules')) tables.rules.delete(a[0]);
    else if (s.startsWith('UPDATE config')) { const c = tables.config.get('1'); c.fallback_ip = a[0]; c.ech = a[1]; }
    else if (s.startsWith('UPDATE ech_cache')) { const c = tables.ech_cache.get('1'); c.ech = a[0]; c.ts = a[1]; }
    return {};
  },
  async first() {
    const s = this.sql;
    if (s.includes('FROM ech_cache')) { const c = tables.ech_cache.get('1'); return { ech: c.ech, ts: c.ts }; }
    if (s.includes('FROM config')) { const c = tables.config.get('1'); return { fallback_ip: c.fallback_ip, ech: c.ech }; }
    if (s.includes('FROM rules')) { const r = tables.rules.get(this.args[0]); return r ? { domain: r.domain, ips: r.ips, ech: r.ech } : null; }
    return null;
  },
  async all() {
    if (this.sql.includes('FROM rules')) return { results: [...tables.rules.values()].map(r => ({ domain: r.domain, ips: r.ips, ech: r.ech })) };
    return { results: [] };
  },
};
const env = { DB, ADMIN_TOKEN: 't' };
const admin = (path, opts = {}) => worker.fetch(new Request('https://t' + path, { ...opts, headers: { 'X-Admin-Token': 't', 'content-type': 'application/json', ...(opts.headers || {}) } }), env);

// 1. 加通配符规则
console.log('1. 加 *.cloudflare.com 规则:');
let r = await admin('/admin/api', { method: 'POST', body: JSON.stringify({ domain: '*.cloudflare.com', ips: ['1.2.3.4'], ech: false }) });
console.log('  ', await r.text());

// 2. 验证存储规范化（应存 cloudflare.com）
console.log('2. 规则列表:');
r = await admin('/admin/api');
console.log('  ', await r.text());

// 3. 查询子域应命中
function enc(name) {
  let s = name.endsWith('.') ? name.slice(0, -1) : name;
  let out = Buffer.alloc(0);
  for (const p of s.split('.')) { const b = Buffer.from(p); out = Buffer.concat([out, Buffer.from([b.length]), b]); }
  return Buffer.concat([out, Buffer.from([0])]);
}
function bq(d, t) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(0x1234, 0); h.writeUInt16BE(0x100, 2); h.writeUInt16BE(1, 4);
  const q = Buffer.alloc(4); q.writeUInt16BE(t, 0); q.writeUInt16BE(1, 2);
  return Buffer.concat([h, enc(d), q]);
}
async function query(dom) {
  const b64 = Buffer.from(bq(dom, 1)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const resp = await worker.fetch(new Request('https://t/dns-query?dns=' + b64), env);
  const data = Buffer.from(await resp.arrayBuffer());
  const ancount = data.readUInt16BE(6);
  let pos = 12; while (data[pos] !== 0) pos += 1 + data[pos]; pos += 5;
  const res = [];
  for (let i = 0; i < ancount; i++) {
    pos += 2; const rt = data.readUInt16BE(pos); const rd = data.readUInt16BE(pos + 8);
    const rd2 = data.slice(pos + 10, pos + 10 + rd); pos += 10 + rd;
    if (rt === 1 && rd === 4) res.push([...rd2].join('.'));
  }
  return res.join(',') || '(空)';
}
console.log('3. 子域命中测试:');
console.log('  a.b.cloudflare.com →', await query('a.b.cloudflare.com'), '（期望 1.2.3.4）');
console.log('  cloudflare.com →', await query('cloudflare.com'), '（期望 1.2.3.4）');
console.log('  unrelated.com →', await query('unrelated.com'), '（应非 1.2.3.4）');

// 4. 删除通配符
console.log('4. 删除 *.cloudflare.com:');
r = await admin('/admin/api?domain=*.cloudflare.com', { method: 'DELETE' });
console.log('  ', await r.text());
r = await admin('/admin/api');
console.log('  列表:', await r.text());
process.exit(0);
