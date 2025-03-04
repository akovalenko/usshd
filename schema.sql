PRAGMA user_version = 1;
CREATE TABLE users(id text PRIMARY KEY NOT NULL, payhash TEXT UNIQUE, shortname TEXT UNIQUE);
