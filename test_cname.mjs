// 测试 CNAME 链判定：video.twimg.com（解析到 Fastly IP 但 CNAME 链含 CF）
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
async function query(dom, type) {
  const b64 = Buffer.from(bq(dom, type)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const r = await worker.fetch(new Request('https://t/dns-query?dns=' + b64), env);
  const data = Buffer.from(await r.arrayBuffer());
  const ancount = data.readUInt16BE(6);
  let pos = 12; while (data[pos] !== 0) pos += 1 + data[pos]; pos += 5;
  const res = [];
  for (let i = 0; i < ancount; i++) {
    pos += 2; const rt = data.readUInt16BE(pos); const rd = data.readUInt16BE(pos + 8);
    const rd2 = data.slice(pos + 10, pos + 10 + rd); pos += 10 + rd;
    if (rt === 1 && rd === 4) res.push([...rd2].join('.'));
    else if (rt === 65) res.push('HTTPS(len=' + rd + ')');
    else if (rt === 5) res.push('CNAME');
  }
  return res.join(' | ') || '(空)';
}
console.log('video.twimg.com A →', await query('video.twimg.com', 1), '（期望 172.67.187.141）');
console.log('video.twimg.com HTTPS →', await query('video.twimg.com', 65), '（期望 HTTPS）');
console.log('cdn.syndication.twimg.com A →', await query('cdn.syndication.twimg.com', 1));
process.exit(0);
