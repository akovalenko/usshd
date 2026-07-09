package billing

import (
	"testing"

	"github.com/akovalenko/usshd/lnbits"
)

// TestInvoiceDead pins the reinvoice decision for a fetched (non-error) invoice.
// The trigger is "unpaid and not pending", not "== failed", because lnbits
// serialises the status enum and a just-flipped invoice can report
// "PaymentState.FAILED" on the first read before settling to "failed".
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
		{"failed-enum-str", false, "PaymentState.FAILED", true},
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
