// D1 版本地测试：模拟 env.DB（prepare/bind/run/first/all）
import worker from '/tmp/dohd-edge/worker/worker.js';

// 内存 SQL 模拟（只支持本项目用到的查询）
const tables = {
  rules: new Map(),   // domain -> {domain, ips, ech}
  config: new Map([['1', { id: 1, fallback_ip: '', ech: 1 }]]),
  ech_cache: new Map([['1', { id: 1, ech: '', ts: 0 }]]),
};
const DB = {
  prepare(sql) {
    this.sql = sql;
    return this;
  },
  bind(...args) {
    this.args = args;
    return this;
  },
  async run() {
    const s = this.sql, a = this.args;
    if (s.startsWith('INSERT INTO rules')) {
      tables.rules.set(a[0], { domain: a[0], ips: a[1], ech: a[2] });
    } else if (s.startsWith('DELETE FROM rules')) {
      tables.rules.delete(a[0]);
    } else if (s.startsWith('UPDATE config')) {
      const c = tables.config.get('1');
      c.fallback_ip = a[0]; c.ech = a[1];
    } else if (s.startsWith('UPDATE ech_cache')) {
      const c = tables.ech_cache.get('1');
      c.ech = a[0]; c.ts = a[1];
    }
    return {};
  },
  async first() {
    const s = this.sql, a = this.args;
    if (s.includes('FROM ech_cache')) {
      const c = tables.ech_cache.get('1');
      return { ech: c.ech, ts: c.ts };
    }
    if (s.includes('FROM config')) {
      const c = tables.config.get('1');
      return { fallback_ip: c.fallback_ip, ech: c.ech };
    }
    if (s.includes('FROM rules')) {
      const r = tables.rules.get(a[0]);
      return r ? { domain: r.domain, ips: r.ips, ech: r.ech } : null;
    }
    return null;
  },
  async all() {
    const s = this.sql;
    if (s.includes('FROM rules')) {
      return { results: [...tables.rules.values()].map(r => ({ domain: r.domain, ips: r.ips, ech: r.ech })) };
    }
    return { results: [] };
  },
};

const env = { DB, ADMIN_TOKEN: 't' };
const admin = (path, opts = {}) => worker.fetch(new Request('https://t' + path, { ...opts, headers: { 'X-Admin-Token': 't', 'content-type': 'application/json', ...(opts.headers || {}) } }), env);

// 1. 加规则
console.log('1. 加规则:');
let r = await admin('/admin/api', { method: 'POST', body: JSON.stringify({ domain: 'archiveofourown.org', ips: ['172.67.187.141', '104.20.9.2'], ech: true }) });
console.log('  ', await r.text());

// 2. 规则列表
console.log('2. 规则列表:');
r = await admin('/admin/api');
console.log('  ', await r.text());

// 3. 设全局配置
console.log('3. 全局配置:');
r = await admin('/admin/config', { method: 'PUT', body: JSON.stringify({ fallbackIp: '172.67.187.141', ech: true }) });
console.log('  ', await r.text());

// 4. 读全局配置
console.log('4. 读全局:');
r = await admin('/admin/config');
console.log('  ', await r.text());

// 5. 重复加同域名（UPSERT 覆盖）
console.log('5. UPSERT 覆盖:');
r = await admin('/admin/api', { method: 'POST', body: JSON.stringify({ domain: 'archiveofourown.org', ips: ['9.9.9.9'], ech: false }) });
console.log('  ', await r.text());
r = await admin('/admin/api');
console.log('  列表:', await r.text());

// 6. 删除
console.log('6. 删除:');
r = await admin('/admin/api?domain=archiveofourown.org', { method: 'DELETE' });
console.log('  ', await r.text());
r = await admin('/admin/api');
console.log('  列表:', await r.text());

// 7. UI
console.log('7. UI:');
r = await worker.fetch(new Request('https://t/admin'), env);
const ui = await r.text();
console.log('  status:', r.status, '含tokenInput:', ui.includes('tokenInput'));

process.exit(0);
