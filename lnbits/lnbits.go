package lnbits

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"gopkg.in/cenkalti/backoff.v1"
)

type InvoiceData struct {
	Paid     bool   `json:"paid"`
	Status   string `json:"status"`
	Preimage string `json:"preimage"`
	Details  struct {
		Pending     bool         `json:"pending"`
		Amount      int64        `json:"amount"`
		Memo        string       `json:"memo"`
		Bolt11      string       `json:"bolt11"`
		Preimage    string       `json:"preimage"`
		PaymentHash string       `json:"payment_hash"`
		Extra       InvoiceExtra `json:"extra"`
		WalletId    string       `json:"wallet_id"`
	} `json:"details"`
}

type InvoiceEventData struct {
	Pending     bool         `json:"pending"`
	Amount      int64        `json:"amount"`
	Memo        string       `json:"memo"`
	PaymentHash string       `json:"payment_hash"`
	Bolt11      string       `json:"bolt11"`
	Preimage    string       `json:"preimage"`
	Extra       InvoiceExtra `json:"extra"`
}

type InvoiceExtra struct {
	FiatCurrency       string  `json:"fiat_currency"`
	FiatAmount         float64 `json:"fiat_amount"`
	FiatRate           float64 `json:"fiat_rate"`
	WalletFiatCurrency string  `json:"wallet_fiat_currency"`
	WalletFiatAmount   float64 `json:"wallet_fiat_amount"`
	WalletFiatRate     float64 `json:"wallet_fiat_rate"`
}

type Client struct {
	Url        string
	ApiKey     string
	HttpClient *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HttpClient != nil {
		return c.HttpClient
	}
	return http.DefaultClient
}

func roundtrip[T any](c *Client, ctx context.Context, path string,
	param any, expectStatusCode int) (T, error) {

	var null, value T

	method := "GET"
	var body io.Reader = http.NoBody
	if param != nil {
		method = "POST"
		bodyBytes, err := json.Marshal(param)
		if err != nil {
			return null, err
		}
		body = bytes.NewReader(bodyBytes)
	}

	hr, err := http.NewRequestWithContext(ctx, method, c.Url+path, body)
	if err != nil {
		return null, err
	}
	hr.Header.Set("X-Api-Key", c.ApiKey)
	hr.Header.Set("accept", "application/json")

	if param != nil {
		hr.Header.Set("content-type", "application/json")
	}
	resp, err := c.httpClient().Do(hr)
	if err != nil {
		return null, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != expectStatusCode {
		if resp.StatusCode == 404 {
			return null, ErrNotFound
		}
		return null, fmt.Errorf("unexpected status %v", resp.Status)
	}

	cType := resp.Header.Get("content-type")

	if cType != "application/json" {
		return null, fmt.Errorf("unexpected content type: %v", cType)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return null, err
	}

	err = json.Unmarshal(respBytes, &value)
	if err != nil {
		return null, err
	}

	return value, nil
}

var ErrParseJson = errors.New("lnbits reply json fields unparseable")
var ErrNotFound = errors.New("lnbits gives 404 Not found")

// StatusPending is the lnbits payment status of an unsettled invoice. An unpaid
// invoice with any other non-empty status — notably "failed", to which lnbits
// 1.x flips an expired invoice instead of deleting it — is terminally unpayable.
// Comparing against pending (rather than matching "failed") keeps the reinvoice
// trigger from hardcoding the terminal string and covers any future terminal
// state.
const StatusPending = "pending"

func (c *Client) AddInvoice(ctx context.Context,
	amount int, memo string, expiry int, unit string) (
	ph string, pr string, er error) {

	param := map[string]any{
		"out":    false,
		"amount": amount,
		"memo":   memo,
		"expiry": expiry,
	}
	if unit != "" {
		param["unit"] = unit
	}

	res, err := roundtrip[map[string]any](c, ctx, "/api/v1/payments", param, 201)

	if err != nil {
		return "", "", err
	}
	defer func() {
		if recover() != nil {
			er = ErrParseJson
		}
	}()

	ph = res["payment_hash"].(string)
	pr = res["payment_request"].(string)

	return
}

func (c *Client) GetInvoice(ctx context.Context, ph string) (*InvoiceData, error) {
	iData, err := roundtrip[*InvoiceData](c, ctx, "/api/v1/payments/"+ph, nil, 200)
	if err != nil {
		return nil, err
	}
	if iData == nil {
		return nil, ErrParseJson
	}
	return iData, nil
}

// wsPayment mirrors the payment-notification frame lnbits pushes over the
// websocket channel /api/v1/ws/<key>: {"wallet_balance": N, "payment": {...}}.
// Only the fields we consume are declared; unlisted JSON keys (time, expiry,
// extra — which carry non-int types) are ignored so they can't break decoding.
type wsPayment struct {
	Payment struct {
		PaymentHash string `json:"payment_hash"`
		Amount      int64  `json:"amount"` // msat; negative for outgoing
		Memo        string `json:"memo"`
		Bolt11      string `json:"bolt11"`
		Preimage    string `json:"preimage"`
	} `json:"payment"`
}

// Subscribe streams payment notifications for the wallet identified by ApiKey.
// lnbits removed the old SSE endpoint (/api/v1/payments/sse) in the 1.x line;
// real-time now flows over a websocket at /api/v1/ws/<key>, where every frame
// on the channel is a payment for that wallet (both directions). We preserve
// the original SSE semantics — fire the handler only for incoming payments —
// by filtering on a positive amount. The call blocks until ctx is cancelled,
// reconnecting with exponential backoff so a dropped socket is not fatal.
func (c *Client) Subscribe(ctx context.Context, handler func(*InvoiceEventData)) error {
	wsURL := c.Url
	if strings.HasPrefix(wsURL, "https://") {
		wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
	} else if strings.HasPrefix(wsURL, "http://") {
		wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
	}
	wsURL += "/api/v1/ws/" + c.ApiKey

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0 // reconnect indefinitely, like the old SSE client

	for {
		if ctx.Err() != nil {
			return nil
		}
		c.subscribeOnce(ctx, wsURL, handler, bo)
		if ctx.Err() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(bo.NextBackOff()):
		}
	}
}

// subscribeOnce holds one websocket connection open, dispatching incoming
// payments until the socket errors or ctx is cancelled. Backoff is reset only
// after a frame is actually read, so an endpoint that accepts then immediately
// drops keeps escalating the reconnect delay instead of hot-looping.
func (c *Client) subscribeOnce(ctx context.Context, wsURL string,
	handler func(*InvoiceEventData), bo *backoff.ExponentialBackOff) {

	conn, _, err := websocket.Dial(ctx, wsURL,
		&websocket.DialOptions{HTTPClient: c.httpClient()})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)

	firstRead := true
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if firstRead {
			bo.Reset()
			firstRead = false
		}
		var msg wsPayment
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		p := msg.Payment
		if p.PaymentHash == "" || p.Amount <= 0 {
			continue // skip malformed frames and outgoing payments
		}
		handler(&InvoiceEventData{
			PaymentHash: p.PaymentHash,
			Amount:      p.Amount,
			Memo:        p.Memo,
			Bolt11:      p.Bolt11,
			Preimage:    p.Preimage,
		})
	}
}
