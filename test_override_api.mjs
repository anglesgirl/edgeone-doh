import worker from '/tmp/dohd-edge/worker/worker.js';
const tables = { rules: new Map(), overrides: new Map(), config: new Map([['1',{id:1,fallback_ip:'',ech:1}]]), ech_cache: new Map([['1',{id:1,ech:'',ts:0}]]) };
const DB = {
  prepare(s){this.sql=s;return this;}, bind(...a){this.args=a;return this;},
  async run(){
    const s=this.sql,a=this.args;
    if(s.includes('INSERT INTO overrides')) tables.overrides.set(a[0],{name:a[0],domains:a[1],ips:a[2],ech:a[3]});
    else if(s.startsWith('DELETE FROM overrides')) tables.overrides.delete(a[0]);
    return {};
  },
  async first(){return null;},
  async all(){
    if(this.sql.includes('FROM overrides')) return { results:[...tables.overrides.values()].map(r=>({name:r.name,domains:r.domains,ips:r.ips,ech:r.ech})) };
    if(this.sql.includes('FROM rules')) return { results:[] };
    return { results:[] };
  },
};
const env = { DB, ADMIN_TOKEN: 't' };
const hdr = { 'X-Admin-Token':'t', 'content-type':'application/json' };
let r = await worker.fetch(new Request('https://t/admin/override',{headers:hdr}), env);
console.log('GET 列表:', await r.text());
r = await worker.fetch(new Request('https://t/admin/override',{method:'POST',headers:hdr,body:JSON.stringify({name:'谷歌全家桶',domains:['google.com','youtube.com'],ips:['1.2.3.4','5.6.7.8'],ech:false})}), env);
console.log('POST 添加:', await r.text());
r = await worker.fetch(new Request('https://t/admin/override',{headers:hdr}), env);
console.log('GET 再查:', await r.text());
r = await worker.fetch(new Request('https://t/admin/override?name=%E8%B0%B7%E6%AD%8C%E5%85%A8%E5%AE%B6%E6%A1%B6',{method:'DELETE',headers:hdr}), env);
console.log('DELETE:', await r.text());
process.exit(0);
