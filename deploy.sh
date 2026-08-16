#!/bin/bash
# EdgeOne 部署脚本（2026-08-17 v2）：edge-functions 目录 + 占位符注入 Turso token
set -e
cd /root/work/edgeone-doh
export EO_TOKEN=$(cat /root/.edgeone-token)
TT=$(cat /root/.turso-token)
F="edge-functions/[[default]].js"
# 注入
sed -i "s|__TURSO_TOKEN__|$TT|g" "$F"
echo "token 已注入，部署中..."
edgeone makers deploy . -n "ech-doh" --area overseas --json 2>&1 | grep -oE '"status":"[a-z]+"|"deploymentId":"[^"]+"' | head -2
# 恢复占位符（token 不进仓库）
sed -i "s|$TT|__TURSO_TOKEN__|g" "$F"
echo "已恢复占位符"
