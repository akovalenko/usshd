package billing

import (
	"testing"

	"github.com/akovalenko/usshd/lnbits"
)

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
