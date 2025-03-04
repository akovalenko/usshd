package lnbits

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/r3labs/sse"
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
		Time        int64        `json:"time"`
		Bolt11      string       `json:"bolt11"`
		Preimage    string       `json:"preimage"`
		PaymentHash string       `json:"payment_hash"`
		Expiry      float64      `json:"expiry"`
		Extra       InvoiceExtra `json:"extra"`
		WalletId    string       `json:"wallet_id"`
	} `json:"details"`
}

type InvoiceEventData struct {
	Pending     bool         `json:"pending"`
	Time        int64        `json:"time"`
	Amount      int64        `json:"amount"`
	Memo        string       `json:"memo"`
	PaymentHash string       `json:"payment_hash"`
	Bolt11      string       `json:"bolt11"`
	Preimage    string       `json:"preimage"`
	Expiry      float64      `json:"expiry"`
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

func (c *Client) Subscribe(ctx context.Context, handler func(*InvoiceEventData)) error {
	clnt := sse.NewClient(c.Url + "/api/v1/payments/sse")

	rs := backoff.NewExponentialBackOff()
	bofc := backoff.WithContext(rs, ctx)

	clnt.ReconnectStrategy = bofc

	clnt.Headers["X-Api-Key"] = c.ApiKey
	return clnt.SubscribeWithContext(ctx,"",
		func(msg *sse.Event) {
			if string(msg.Event) != "payment-received" {
				return
			}
			var v *InvoiceEventData
			err := json.Unmarshal(msg.Data, &v)
			if err != nil {
				return
			}
			if v == nil {
				return
			}
			handler(v)
			return
		},
	)
}
