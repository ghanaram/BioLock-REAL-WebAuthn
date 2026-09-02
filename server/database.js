const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "biolock.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT UNIQUE NOT NULL,
  device_type TEXT NOT NULL,
  device_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT UNIQUE NOT NULL,
  owner_name TEXT NOT NULL,
  authentication_method TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'trusted',
  paired_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT UNIQUE NOT NULL,
  pc_device_id TEXT NOT NULL,
  phone_device_id TEXT,
  challenge TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  used_at TEXT
);

CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  challenge TEXT NOT NULL,
  request_id TEXT,
  created_at TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS authentication_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT,
  device_id TEXT,
  authentication_method TEXT,
  result TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  device_id TEXT,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pc_devices (
  pc_device_id TEXT PRIMARY KEY,
  hostname TEXT,
  platform TEXT,
  status TEXT DEFAULT 'offline',
  authorized INTEGER DEFAULT 0,
  authorized_device TEXT,
  authorized_at TEXT,
  last_seen TEXT,
  created_at TEXT,
  updated_at TEXT
);

`);

// ===============================
// BIOLOCK AUDIT LOG
// ===============================

db.exec(`
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    pc_device_id TEXT,
    device_id TEXT,
    result TEXT,
    message TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at
  ON audit_logs(created_at);

  CREATE INDEX IF NOT EXISTS idx_audit_logs_pc_device
  ON audit_logs(pc_device_id);

  CREATE INDEX IF NOT EXISTS idx_audit_logs_device
  ON audit_logs(device_id);
`);

function createAuditLog({
  eventType,
  pcDeviceId = null,
  deviceId = null,
  result = "SUCCESS",
  message = null,
  metadata = null,
}) {
  const createdAt = new Date().toISOString();

  db.prepare(`
    INSERT INTO audit_logs (
      event_type,
      pc_device_id,
      device_id,
      result,
      message,
      metadata,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    eventType,
    pcDeviceId,
    deviceId,
    result,
    message,
    metadata
      ? JSON.stringify(metadata)
      : null,
    createdAt
  );

  return createdAt;
}


module.exports = db;
module.exports.createAuditLog = createAuditLog;
