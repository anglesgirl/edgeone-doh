// EdgeOne 无库版功能测试 v2（标准 DoH POST wire format，2026-08-17）
import { onRequest } from './functions/[[default]].js';

const env = {
  RULES_JSON: JSON.stringify({
    'x.com': { ips: ['172.64.146.66', '104.18.41.190'], ech: true },
    'pixiv.net': { ips: ['104.18.41.190'], ech: true },
    'archiveofourown.org': { ips: ['172.64.146.66'], ech: true },
  }),
  OVERRIDES_JSON: JSON.stringify([
    { name: '谷歌全家桶', domains: ['google.com', 'youtube.com'], ips: [], ech: true },
  ]),
  FALLBACK_IP: '172.64.146.66',
  GLOBAL_ECH: '1',
  ADMIN_TOKEN: 'doh-admin-7f3k9',
};

function buildQuery(name, type) {
  const buf = [];
  buf.push(0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0); // header
  for (const label of name.split('.')) { buf.push(label.length); for (const c of label) buf.push(c.charCodeAt(0)); }
  buf.push(0);
  buf.push(0, type, 0, 1); // qtype, qclass
  return new Uint8Array(buf);
}

function decodeAnswers(body) {
  const b = new Uint8Array(body);
  const out = { A: [], HTTPS: [] };
  let i = 12;
  while (b[i] !== 0) i++;
  i += 5;
  while (i < b.length - 11) {
    if (b[i] & 0xc0) i += 2;
    else { while (b[i] !== 0) i++; i += 1; }
    if (i + 10 > b.length) break;
    const type = (b[i] << 8) | b[i+1];
    const rdlen = (b[i+8] << 8) | b[i+9];
    if (type === 1 && rdlen === 4) out.A.push(`${b[i+10]}.${b[i+11]}.${b[i+12]}.${b[i+13]}`);
    if (type === 65) out.HTTPS.push('ech=' + (rdlen > 4 ? 'yes' : 'empty'));
    i += 10 + rdlen;
  }
  return out;
}

async function test(name, type, expectIPs, expectEch) {
  const req = new Request('https://doh.test/dns-query', {
    method: 'POST',
    headers: { 'content-type': 'application/dns-message' },
    body: buildQuery(name, type),
  });
  const res = await onRequest({ request: req, env });
  const buf = await res.arrayBuffer();
  const ans = decodeAnswers(buf);
  const okIP = expectIPs === null ? true : (expectIPs === false ? ans.A.length === 0 : ans.A.some(ip => expectIPs.includes(ip)));
  const okEch = expectEch ? ans.HTTPS.length > 0 : true;
  console.log(`${name.padEnd(24)} A=${ans.A.join(',') || '(无)'} HTTPS=${ans.HTTPS.join(',') || '-'} → ${okIP && okEch ? 'PASS' : 'FAIL'}`);
}

await test('x.com', 1, ['172.64.146.66', '104.18.41.190'], false);
await test('api.x.com', 1, ['172.64.146.66', '104.18.41.190'], false);
await test('x.com', 65, null, true);
await test('pixiv.net', 1, ['104.18.41.190'], false);
await test('archiveofourown.org', 1, ['172.64.146.66'], false);
await test('google.com', 1, null, false);
console.log('done');
