-- ech-doh D1 数据库 schema（追加 overrides 表）
-- 覆写集合（override 组）：如「谷歌全家桶」
--   name：集合名；domains：域名列表(JSON)；ips：覆写 IP 列表(JSON)；ech：是否注 ECH
CREATE TABLE IF NOT EXISTS overrides (
  name TEXT PRIMARY KEY,
  domains TEXT NOT NULL DEFAULT '[]',
  ips TEXT NOT NULL DEFAULT '[]',
  ech INTEGER NOT NULL DEFAULT 0
);