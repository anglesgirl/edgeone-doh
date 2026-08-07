import worker from '/tmp/dohd-edge/worker/worker.js';
const tbl = { rules: new Map(), config: new Map([['1',{id:1,fallback_ip:'172.67.187.141',ech:1}]]), ech_cache: new Map([['1',{id:1,ech:'',ts:0}]]) };
const DB = { prepare(s){this.sql=s;return this;}, bind(...a){this.args=a;return this;}, async run(){return{};}, async first(){return null;}, async all(){return{results:[]};} };
const env = { DB, ADMIN_TOKEN: 't' };
function enc(n){n=n.endsWith('.')?n.slice(0,-1):n;let o=Buffer.alloc(0);for(const p of n.split('.')){const b=Buffer.from(p);o=Buffer.concat([o,Buffer.from([b.length]),b]);}return Buffer.concat([o,Buffer.from([0])]);}
function wire(d,t){const h=Buffer.alloc(12);h.writeUInt16BE(0x1234,0);h.writeUInt16BE(0x100,2);h.writeUInt16BE(1,4);const q=Buffer.alloc(4);q.writeUInt16BE(t,0);q.writeUInt16BE(1,2);return Buffer.concat([h,enc(d),q]);}
async function q(d,t){const b64=Buffer.from(wire(d,t)).toString('base64');const r=await worker.fetch(new Request('https://t/api?dns='+b64),env);const data=Buffer.from(await r.arrayBuffer());const an=data.readUInt16BE(6);let p=12;while(data[p]!==0)p+=1+data[p];p+=5;const res=[];for(let i=0;i<an;i++){p+=2;const rt=data.readUInt16BE(p);const rd=data.readUInt16BE(p+8);const rd2=data.slice(p+10,p+10+rd);p+=10+rd;if(rt===1&&rd===4)res.push([...rd2].join('.'));else if(rt===5)res.push('CNAME');}return res.join(',')||'(空)';}
console.log('google.com →', await q('google.com',1), '(应47.103覆写)');
console.log('i.ytimg.com →', await q('i.ytimg.com',1), '(应真实IP不覆写)');
console.log('rr1.googlevideo.com →', await q('rr1.googlevideo.com',1), '(应真实IP不覆写)');
process.exit(0);
