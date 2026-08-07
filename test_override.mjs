// 测试 override 集合：DB 里配「谷歌全家桶」→ 覆写IP；其他域名真实
import worker from '/tmp/dohd-edge/worker/worker.js';
const tables = {
  rules: new Map(),
  overrides: new Map([
    ['谷歌全家桶', { name: '谷歌全家桶', domains: JSON.stringify(['google.com','youtube.com','ytimg.com']), ips: JSON.stringify(['47.103.34.63','121.43.186.252']), ech: 0 }]
  ]),
  config: new Map([['1',{id:1,fallback_ip:'172.67.187.141',ech:1}]]),
  ech_cache: new Map([['1',{id:1,ech:'',ts:0}]]),
};
const DB = {
  prepare(s){this.sql=s;return this;}, bind(...a){this.args=a;return this;},
  async run(){return{};},
  async first(){
    const s=this.sql;
    if(s.includes('FROM overrides')) return null;
    if(s.includes('FROM rules')) { const r=tables.rules.get(this.args[0]); return r?{domain:r.domain,ips:r.ips,ech:r.ech}:null; }
    if(s.includes('FROM config')) { const c=tables.config.get('1'); return {fallback_ip:c.fallback_ip,ech:c.ech}; }
    if(s.includes('FROM ech_cache')) return {ech:'',ts:0};
    return null;
  },
  async all(){
    if(s=>this.sql&&s.includes('FROM overrides')) return { results: [...tables.overrides.values()].map(r=>({name:r.name,domains:r.domains,ips:r.ips,ech:r.ech})) };
    if(this.sql.includes('FROM rules')) return { results: [] };
    return { results: [] };
  },
};
const env = { DB, ADMIN_TOKEN: 't' };
function enc(n){n=n.endsWith('.')?n.slice(0,-1):n;let o=Buffer.alloc(0);for(const p of n.split('.')){const b=Buffer.from(p);o=Buffer.concat([o,Buffer.from([b.length]),b]);}return Buffer.concat([o,Buffer.from([0])]);}
function wire(d,t){const h=Buffer.alloc(12);h.writeUInt16BE(0x1234,0);h.writeUInt16BE(0x100,2);h.writeUInt16BE(1,4);const q=Buffer.alloc(4);q.writeUInt16BE(t,0);q.writeUInt16BE(1,2);return Buffer.concat([h,enc(d),q]);}
async function q(d,t){const b64=Buffer.from(wire(d,t)).toString('base64');const r=await worker.fetch(new Request('https://t/api?dns='+b64),env);const data=Buffer.from(await r.arrayBuffer());const an=data.readUInt16BE(6);let p=12;while(data[p]!==0)p+=1+data[p];p+=5;const res=[];for(let i=0;i<an;i++){p+=2;const rt=data.readUInt16BE(p);const rd=data.readUInt16BE(p+8);const rd2=data.slice(p+10,p+10+rd);p+=10+rd;if(rt===1&&rd===4)res.push([...rd2].join('.'));}return res.join(',')||'(空)';}
console.log('google.com →', await q('google.com',1), '(应覆写 47.103.34.28)');
console.log('i.ytimg.com →', await q('i.ytimg.com',1), '(应覆写)');
console.log('baidu.com →', await q('baidu.com',1), '(真实解析)');
process.exit(0);