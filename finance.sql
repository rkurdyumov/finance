CREATE TABLE IF NOT EXISTS 'users' (
    'id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    'username' TEXT NOT NULL,
    'hash' TEXT NOT NULL,
    'cash' NUMERIC NOT NULL DEFAULT 10000.00
);
CREATE UNIQUE INDEX 'username' ON "users" ("username");

CREATE TABLE IF NOT EXISTS 'transactions' (
    'id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    'user_id' INTEGER NOT NULL,
    'symbol' TEXT NOT NULL,
    'shares' INTEGER NOT NULL,
    'price' NUMERIC NOT NULL,
    'time' DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);