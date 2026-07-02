package main

import (
	"path/filepath"
	"testing"
)

// TestOpenDB covers the startup bootstrap: a missing database is created and
// initialized to schema version 1 with a queryable users table, and reopening
// an already-initialized file is a clean no-op — the baseline is not re-applied
// and existing rows survive.
func TestOpenDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.db")

	db, err := openDB(path)
	if err != nil {
		t.Fatalf("openDB (create): %v", err)
	}
	var ver int
	if err := db.QueryRow("PRAGMA user_version").Scan(&ver); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if ver != 1 {
		t.Errorf("user_version = %d, want 1", ver)
	}
	// The users table must exist and accept a row.
	if _, err := db.Exec("INSERT INTO users(id, payhash) VALUES(?, ?)", "fp", "ph"); err != nil {
		t.Errorf("insert into users: %v", err)
	}
	db.Close()

	// Reopen: must be a no-op — the row survives, the baseline is not re-run.
	db2, err := openDB(path)
	if err != nil {
		t.Fatalf("openDB (reopen): %v", err)
	}
	defer db2.Close()
	var n int
	if err := db2.QueryRow("SELECT count(*) FROM users").Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 1 {
		t.Errorf("row count after reopen = %d, want 1", n)
	}
}
