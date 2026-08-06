-- ech-doh D1 数据库 schema
-- 规则表：域名 → 自定义 IP + ECH
CREATE TABLE IF NOT EXISTS rules (
  domain TEXT PRIMARY KEY,
  ips TEXT NOT NULL DEFAULT '[]',  -- JSON 数组字符串
  ech INTEGER NOT NULL DEFAULT 1
);

-- 全局配置表（单行：id=1）
CREATE TABLE IF NOT EXISTS config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  fallback_ip TEXT DEFAULT '',
  ech INTEGER NOT NULL DEFAULT 1
);
INSERT OR IGNORE INTO config (id, fallback_ip, ech) VALUES (1, '', 1);

-- ECH 配置缓存表（单行：id=1）
CREATE TABLE IF NOT EXISTS ech_cache (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  ech TEXT DEFAULT '',
  ts INTEGER DEFAULT 0
);
INSERT OR IGNORE INTO ech_cache (id, ech, ts) VALUES (1, '', 0);
