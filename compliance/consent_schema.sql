CREATE TABLE IF NOT EXISTS consent_master (
  principal_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  granted INTEGER NOT NULL DEFAULT 0,
  withdrawn_at TEXT,
  expires_at TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (principal_id, purpose)
);

CREATE TABLE IF NOT EXISTS consent_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  principal_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT NOT NULL,
  recorded_at TEXT NOT NULL
);
