PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, username TEXT NOT NULL UNIQUE,
 role TEXT NOT NULL CHECK(role IN ('admin','supervisor','instructor')),
 salt TEXT NOT NULL, password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cars (
 id TEXT PRIMARY KEY, model TEXT NOT NULL, plate TEXT NOT NULL UNIQUE,
 km INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checks (
 id TEXT PRIMARY KEY, car_id TEXT NOT NULL REFERENCES cars(id), user_id TEXT NOT NULL REFERENCES users(id),
 km INTEGER NOT NULL, tires INTEGER NOT NULL, oil INTEGER NOT NULL, fuel INTEGER NOT NULL,
 clean INTEGER NOT NULL, notes TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
 id TEXT PRIMARY KEY, car_id TEXT NOT NULL REFERENCES cars(id), user_id TEXT NOT NULL REFERENCES users(id),
 severity TEXT NOT NULL, description TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attachments (
 id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
 file_key TEXT NOT NULL, file_name TEXT NOT NULL, content_type TEXT NOT NULL, size INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_checks_created ON checks(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_checks_car ON checks(car_id);
CREATE INDEX IF NOT EXISTS idx_incidents_car ON incidents(car_id);
