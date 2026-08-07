import worker from '/tmp/dohd-edge/worker/worker.js';
const tbl = { rules: new Map(), config: new Map(), ech_cache: new Map() };
const DB = {
  prepare(s){this.sql=s;return this;}, bind(...a){this.args=a;return this;},
  async run(){return{};}, async first(){return null;}, async all(){return{results:[]};},
};
const env = { DB, ADMIN_TOKEN: 't' };
function enc(name) {
  let s = name.endsWith('.') ? name.slice(0,-1) : name;
  let out = Buffer.alloc(0);
  for (const p of s.split('.')) { const b = Buffer.from(p); out = Buffer.concat([out, Buffer.from([b.length]), b]); }
  return Buffer.concat([out, Buffer.from([0])]);
}
function wire() {
  const h=Buffer.alloc(12); h.writeUInt16BE(0x1234,0); h.writeUInt16BE(0x100,2); h.writeUInt16BE(1,4);
  const q=Buffer.alloc(4); q.writeUInt16BE(1,0); q.writeUInt16BE(1,2);
  return Buffer.concat([h,enc('example.com'),q]);
}
async function t(req) {
  const r = await worker.fetch(req, env);
  return r.status + ' CT=' + r.headers.get('content-type');
}
console.log('POST伪装 :', await t(new Request('https://t/api/v1/sync',{method:'POST',body:wire()})));
console.log('GET?dns=:', await t(new Request('https://t/api/v1/sync?dns='+Buffer.from(wire()).toString('base64'))));
console.log('GET?q=  :', await t(new Request('https://t/api/v1/sync?q='+Buffer.from(wire()).toString('base64'))));
console.log('标准/query:', await t(new Request('https://t/dns-query?dns='+Buffer.from(wire()).toString('base64'))));
process.exit(0);