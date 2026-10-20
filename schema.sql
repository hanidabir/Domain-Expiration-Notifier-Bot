-- SQLite schema for the domain expiration reminder bot.
-- The bot runs this file automatically at startup.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    telegram_id INTEGER PRIMARY KEY,
    owner       TEXT NOT NULL,
    email       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id     INTEGER NOT NULL,
    domain          TEXT NOT NULL COLLATE NOCASE,
    expiration_date TEXT NOT NULL, -- YYYY-MM-DD
    days_left       INTEGER NOT NULL,
    added_at        TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_whois_at   TEXT,
    FOREIGN KEY (telegram_id) REFERENCES users (telegram_id),
    UNIQUE (telegram_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_domains_telegram_id
    ON domains (telegram_id);

CREATE INDEX IF NOT EXISTS idx_domains_days_left
    ON domains (days_left);
