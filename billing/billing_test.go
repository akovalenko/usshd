package billing

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/akovalenko/usshd/lnbits"
	_ "modernc.org/sqlite"
)

// newTestDB opens a throwaway sqlite database carrying the users table
// (mirrors schema.sql, which lives in the main package).
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE users(id text PRIMARY KEY NOT NULL,
		payhash TEXT UNIQUE, shortname TEXT UNIQUE)`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// TestAdmitIdempotent pins that a duplicate paid signal cannot change an
// admitted user's shortname. One payment may signal several times (websocket
// vs poller race; lnbits 1.x double-notifies an internal payment's receiver),
// and before this guard the second dbAdmitUser generated a fresh shortname
// and overwrote the one already shown to the user's session.
func TestAdmitIdempotent(t *testing.T) {
	db := newTestDB(t)
	b := NewBilling(&BillingConf{ShortNameLen: 4}, db, nil)
	if _, err := db.Exec("INSERT INTO users (id, payhash) VALUES(?,?)",
		"fp", "ph"); err != nil {
		t.Fatal(err)
	}

	if err := b.dbAdmitUser(context.Background(), "fp"); err != nil {
		t.Fatal(err)
	}
	first := b.uc.Get("fp").ShortName
	if first == "" {
		t.Fatal("no shortname after admission")
	}

	if err := b.dbAdmitUser(context.Background(), "fp"); err != nil {
		t.Fatal(err)
	}
	if got := b.uc.Get("fp").ShortName; got != first {
		t.Fatalf("re-admission changed shortname: %q -> %q", first, got)
	}
	var dbName string
	if err := db.QueryRow("SELECT shortname FROM users WHERE id=?",
		"fp").Scan(&dbName); err != nil {
		t.Fatal(err)
	}
	if dbName != first {
		t.Fatalf("db shortname %q != announced %q", dbName, first)
	}
}

// TestAdmitCollisionRetries pins the collision loop: a shortname that is
// already taken must be rolled again, not abort the admission. (The original
// loop returned nil on collision, silently leaving the paid user without a
// shortname until the poller retried.)
func TestAdmitCollisionRetries(t *testing.T) {
	db := newTestDB(t)
	b := NewBilling(&BillingConf{ShortNameLen: 1}, db, nil)
	// Occupy every single-letter name but one; the loop must keep rolling
	// until it lands on the only free name.
	const free = "q"
	for c := 'a'; c <= 'z'; c++ {
		if string(c) == free {
			continue
		}
		if _, err := db.Exec("INSERT INTO users (id, shortname) VALUES(?,?)",
			"holder-"+string(c), string(c)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("INSERT INTO users (id, payhash) VALUES(?,?)",
		"fp", "ph"); err != nil {
		t.Fatal(err)
	}
	if err := b.dbAdmitUser(context.Background(), "fp"); err != nil {
		t.Fatal(err)
	}
	if got := b.uc.Get("fp").ShortName; got != free {
		t.Fatalf("admitted shortname %q, want the only free name %q", got, free)
	}
}

// TestInvoiceDead pins the reinvoice decision for a fetched (non-error) invoice.
// The trigger is "unpaid and not pending" rather than "== failed": paid invoices
// are handled earlier, so any non-empty, non-pending status is terminal (lnbits
// reports an expired/cancelled invoice as "failed"). Matching "not pending" also
// catches any other terminal status without hardcoding a literal.
func TestInvoiceDead(t *testing.T) {
	cases := []struct {
		name   string
		paid   bool
		status string
		dead   bool
	}{
		{"pending", false, "pending", false},
		{"paid", true, "", false},
		{"paid-with-status", true, "success", false},
		{"failed", false, "failed", true},
		{"other-terminal", false, "cancelled", true},
		{"unknown-empty-status", false, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := &lnbits.InvoiceData{Paid: c.paid, Status: c.status}
			if got := invoiceDead(inv); got != c.dead {
				t.Fatalf("invoiceDead(paid=%v status=%q) = %v, want %v",
					c.paid, c.status, got, c.dead)
			}
		})
	}
}
