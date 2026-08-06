// EdgeOne Pages Functions — 管理后台（规则增删查）
// 认证：X-Admin-Token header 或 ?token= 查询参数，与环境变量 ADMIN_TOKEN 比对

function auth(request, env) {
  const url = new URL(request.url);
  const h = request.headers.get('X-Admin-Token');
  const q = url.searchParams.get('token');
  const token = (env && env.ADMIN_TOKEN) || 'changeme';
  return (h === token) || (q === token);
}

async function listRules(env) {
  // KV 不支持 list，用固定 key 存规则列表索引
  const idx = await env.KV.get('rules:index');
  const domains = idx ? JSON.parse(idx) : [];
  const rules = [];
  for (const d of domains) {
    try {
      const raw = await env.KV.get(`rule:${d}`);
      if (raw) rules.push(JSON.parse(raw));
    } catch (e) { /* skip */ }
  }
  return rules;
}

async function addRule(env, domain, ips, ech) {
  domain = domain.trim().toLowerCase().replace(/\.$/, '');
  if (!domain) return { ok: false, error: 'domain empty' };
  for (const ip of ips) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return { ok: false, error: `invalid IP: ${ip}` };
    }
  }
  const rule = { domain, ips, ech: !!ech };
  await env.KV.put(`rule:${domain}`, JSON.stringify(rule));
  // 更新索引
  const idxRaw = await env.KV.get('rules:index');
  const idx = idxRaw ? JSON.parse(idxRaw) : [];
  if (!idx.includes(domain)) idx.push(domain);
  await env.KV.put('rules:index', JSON.stringify(idx));
  return { ok: true };
}

async function delRule(env, domain) {
  domain = domain.trim().toLowerCase().replace(/\.$/, '');
  await env.KV.delete(`rule:${domain}`);
  const idxRaw = await env.KV.get('rules:index');
  if (idxRaw) {
    const idx = JSON.parse(idxRaw).filter(d => d !== domain);
    await env.KV.put('rules:index', JSON.stringify(idx));
  }
  return { ok: true };
}

export async function onRequest({ request, env }) {
  if (!auth(request, env)) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), {
      status: 401,
      headers: { 'content-type': 'application/json' },
    });
  }
  const url = new URL(request.url);

  if (request.method === 'GET') {
    const rules = await listRules(env);
    return new Response(JSON.stringify({ ok: true, rules }), {
      headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
    });
  }

  if (request.method === 'POST') {
    const body = await request.json();
    const r = await addRule(env, body.domain || '', body.ips || [], body.ech);
    return new Response(JSON.stringify(r), {
      headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
    });
  }

  if (request.method === 'DELETE') {
    const domain = url.searchParams.get('domain') || '';
    const r = await delRule(env, domain);
    return new Response(JSON.stringify(r), {
      headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
    });
  }

  return new Response(JSON.stringify({ ok: false, error: 'method not allowed' }), { status: 405 });
}
