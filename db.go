package main

import (
	"database/sql"
	_ "embed"
	"fmt"

	_ "modernc.org/sqlite"
)

// baselineSchema is the initial database layout, applied once to a fresh
// database. It sets PRAGMA user_version = 1 (see openDB) and creates the users
// table.
//
//go:embed schema.sql
var baselineSchema string

// openDB opens the sqlite database at path, creating and initializing it on
// first run so no manual provisioning step is needed.
//
// The schema version lives in sqlite's built-in PRAGMA user_version — a value
// in the database header, so it needs no separate bookkeeping table. A brand
// new database reports version 0; we then apply baselineSchema (which bumps the
// version to 1) exactly once. An already-initialized database reports 1 and is
// left untouched.
//
// This is the migration seam, deliberately without a migration framework: the
// schema is a single table today, so a future change is just another version
// step here — `if ver < 2 { apply delta; PRAGMA user_version = 2 }` — gated on
// the same header value.
func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	var ver int
	if err := db.QueryRow("PRAGMA user_version").Scan(&ver); err != nil {
		db.Close()
		return nil, fmt.Errorf("read schema version: %w", err)
	}
	if ver == 0 {
		if _, err := db.Exec(baselineSchema); err != nil {
			db.Close()
			return nil, fmt.Errorf("apply baseline schema: %w", err)
		}
	}
	// Future migrations land here: for ver < N, apply the delta and bump
	// user_version so the next start sees the new version.
	return db, nil
}
