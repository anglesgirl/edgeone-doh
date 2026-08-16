#!/bin/bash
# EdgeOne 部署（2026-08-17 v3）：自包含函数版，注入 Turso token → 部署 → 恢复
set -e
cd /root/work/edgeone-doh
export EO_TOKEN=$(cat /root/.edgeone-token)
TT=$(cat /root/.turso-token)
FILES="edge-functions/dns-query.js edge-functions/admin.js edge-functions/kv.js"
for F in $FILES; do
  sed -i "s|__TURSO_TOKEN__|$TT|g" "$F"
done
echo "token 已注入，部署中..."
edgeone makers deploy . -n "ech-doh-ov" --area overseas --json 2>&1 | tee /tmp/deploy_out.txt | grep -oE '"url":"[^"]*"' | head -1 | cut -d'"' -f4 > /tmp/last_deploy_url
for F in $FILES; do
  sed -i "s|$TT|__TURSO_TOKEN__|g" "$F"
done
echo "已恢复占位符"
echo "URL: $(cat /tmp/last_deploy_url)"
