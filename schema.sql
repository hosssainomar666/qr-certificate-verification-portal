CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  organization TEXT,
  email TEXT NOT NULL UNIQUE,
  phone TEXT,
  member_type TEXT NOT NULL DEFAULT 'individual',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  doc_type TEXT NOT NULL CHECK (doc_type IN ('CERT','NOC')),
  doc_no TEXT NOT NULL UNIQUE,
  token TEXT NOT NULL UNIQUE,
  purpose TEXT,
  issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT,
  status TEXT NOT NULL DEFAULT 'valid' CHECK (status IN ('valid','revoked'))
);

CREATE TABLE IF NOT EXISTS verification_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id INTEGER NOT NULL REFERENCES documents(id),
  checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ip TEXT
);

CREATE INDEX IF NOT EXISTS idx_members_status ON members(status);
CREATE INDEX IF NOT EXISTS idx_log_document ON verification_log(document_id);
