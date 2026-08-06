// EdgeOne Pages Functions — 管理后台（规则增删查 + 全局配置 + UI）
// 认证：X-Admin-Token header 或 ?token= 查询参数，与 KV/环境变量 ADMIN_TOKEN 比对

const KV_GLOBAL_KEY = 'config:global';

function auth(request, env) {
  const url = new URL(request.url);
  const h = request.headers.get('X-Admin-Token');
  const q = url.searchParams.get('token');
  const token = (env && env.ADMIN_TOKEN) || 'changeme';
  return (h === token) || (q === token);
}

async function listRules(env) {
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

async function getGlobal(env) {
  try {
    const raw = await env.KV.get(KV_GLOBAL_KEY);
    if (raw) return JSON.parse(raw);
  } catch (e) { /* ignore */ }
  return {};
}

async function setGlobal(env, cfg) {
  const cur = await getGlobal(env);
  if (cfg.fallbackIp !== undefined) cur.fallbackIp = cfg.fallbackIp.trim() || '';
  if (cfg.ech !== undefined) cur.ech = !!cfg.ech;
  await env.KV.put(KV_GLOBAL_KEY, JSON.stringify(cur));
  return cur;
}

// ---------- UI 页面 ----------

function renderUI(env) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ECH DoH 管理</title>
<style>
body{font-family:system-ui,sans-serif;max-width:860px;margin:32px auto;padding:0 16px;background:#0f172a;color:#e2e8f0}
h1{font-size:20px;margin-bottom:4px}.sub{color:#94a3b8;font-size:13px;margin-bottom:24px}
h2{font-size:15px;color:#60a5fa;margin:28px 0 10px}
input,select{background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:9px 12px;border-radius:8px;font-size:14px;width:100%;box-sizing:border-box}
button{background:#2563eb;border:none;color:#fff;padding:10px 18px;border-radius:8px;font-size:14px;cursor:pointer;margin-top:6px}
button:hover{background:#1d4ed8}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:14px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #1e293b}
th{color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
a{color:#f87171;text-decoration:none;cursor:pointer}
.code{background:#1e293b;padding:3px 8px;border-radius:6px;font-family:monospace;font-size:12px}
.card{background:#111c33;border:1px solid #1e293b;border-radius:12px;padding:16px;margin-top:12px}
.row{display:flex;gap:8px;flex-wrap:wrap}.row input{flex:1;min-width:150px}
#status{margin-top:10px;font-size:13px;color:#4ade80;min-height:18px}
label{display:flex;align-items:center;gap:6px;font-size:13px;color:#94a3b8;margin-top:8px}
.tip{font-size:12px;color:#64748b;margin-top:6px;line-height:1.6}
</style></head><body>
<h1>🛡️ ECH DoH 管理后台</h1>
<div class="sub">EdgeOne Pages · 免服务器 DoH · 规则注入 + ECH + AS13335 自动替换</div>

<h2>🌐 全局配置（AS13335 自动替换）</h2>
<div class="card">
  <div class="row">
    <input id="fbIp" placeholder="CF 共享 IP（如 172.67.187.141）——解析出的 IP 属 Cloudflare 时自动替换为它">
  </div>
  <label style="margin-top:10px"><input type="checkbox" id="gbEch" style="width:auto"> 自动注入 ECH（替换 IP 时保留 ECH 配置）</label>
  <button onclick="saveGlobal()">保存全局配置</button>
  <div class="tip">规则：上游解析 A 记录 → 若任一 IP 属于 AS13335（Cloudflare）→ 替换为你指定的 IP，同时注入 ECH。用于绕过"IP 被封但站点在 CF"的情况。</div>
  <div id="status"></div>
</div>

<h2>➕ 添加规则（手动指定域名 → IP）</h2>
<div class="card">
  <div class="row">
    <input id="domain" placeholder="域名，如 archiveofourown.org">
    <input id="ips" placeholder="IP（逗号分隔，如 172.67.187.141,104.20.9.2）">
  </div>
  <label><input type="checkbox" id="ech" checked style="width:auto"> 注入 ECH</label>
  <button onclick="addRule()">添加规则</button>
</div>

<h2>📋 规则列表</h2>
<table><thead><tr><th>域名</th><th>自定义 IP</th><th>ECH</th><th>来源</th><th></th></tr></thead><tbody id="rules"></tbody></table>

<h2>📱 iOS 用户</h2>
<div class="card">
  Safari 打开 <span class="code" id="profileUrl">…</span> 安装描述文件，系统 DNS 全部走本 DoH（防污染 + 自定义 IP + ECH）。
</div>

<script>
let TOKEN = localStorage.getItem('doh_token') || '';
(async () => {
  const t = prompt('管理 Token：');
  if (t) { TOKEN = t; localStorage.setItem('doh_token', t); }
})();
async function api(path, opts={}) {
  opts.headers = Object.assign({'X-Admin-Token': TOKEN}, opts.headers||{});
  if (opts.body) opts.headers['Content-Type'] = 'application/json';
  const r = await fetch(path, opts);
  if (r.status === 401) { document.getElementById('status').textContent = '❌ 未授权，请刷新页重新输入 Token'; return null; }
  return r.json();
}
async function refresh() {
  const d = await api('/admin/api');
  if (!d) return;
  const tb = document.getElementById('rules');
  tb.innerHTML = (d.rules||[]).map(r =>
    '<tr><td>'+r.domain+'</td><td class="code">'+r.ips.join(', ')+'</td><td>'+(r.ech?'✅':'—')+'</td><td>'+(r.auto?'自动(AS13335)':'手动')+'</td><td><a onclick="del(\''+r.domain+'\')">删除</a></td></tr>'
  ).join('');
  const g = await api('/admin/config');
  if (g && g.fallbackIp) document.getElementById('fbIp').value = g.fallbackIp;
  if (g && g.ech !== undefined) document.getElementById('gbEch').checked = g.ech;
  const origin = location.origin;
  document.getElementById('profileUrl').textContent = origin + '/profile.mobileconfig';
}
async function addRule() {
  const body = {domain: document.getElementById('domain').value.trim(),
    ips: document.getElementById('ips').value.split(',').map(s=>s.trim()).filter(Boolean),
    ech: document.getElementById('ech').checked};
  const d = await api('/admin/api', {method:'POST', body: JSON.stringify(body)});
  document.getElementById('status').textContent = d && d.ok ? '✅ 已添加 ' + body.domain : (d && d.error ? '❌ ' + d.error : '操作失败');
  refresh();
}
async function del(domain) {
  await api('/admin/api?domain='+encodeURIComponent(domain), {method:'DELETE'});
  refresh();
}
async function saveGlobal() {
  const body = {fallbackIp: document.getElementById('fbIp').value.trim(),
    ech: document.getElementById('gbEch').checked};
  const d = await api('/admin/config', {method:'PUT', body: JSON.stringify(body)});
  document.getElementById('status').textContent = d && d.ok ? '✅ 已保存全局配置' : '❌ 保存失败';
  refresh();
}
refresh();
</script></body></html>`;
}

// ---------- 路由 ----------

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname;

  // UI 页面（浏览器直接访问 /admin）
  if (path === '/admin' && (request.method === 'GET') && !url.searchParams.get('token')) {
    return new Response(renderUI(env), {
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  }

  if (!auth(request, env)) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), {
      status: 401,
      headers: { 'content-type': 'application/json' },
    });
  }

  // 全局配置 API
  if (path === '/admin/config') {
    if (request.method === 'GET') {
      const g = await getGlobal(env);
      return new Response(JSON.stringify({ ok: true, ...g }), {
        headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }
    if (request.method === 'PUT') {
      const body = await request.json();
      const g = await setGlobal(env, body);
      return new Response(JSON.stringify({ ok: true, ...g }), {
        headers: { 'content-type': 'application/json; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }
  }

  // 规则 API
  if (path === '/admin/api' || path === '/admin') {
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
  }

  return new Response(JSON.stringify({ ok: false, error: 'not found' }), { status: 404 });
}
