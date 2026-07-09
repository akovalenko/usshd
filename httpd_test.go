package main

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strings"
	"testing"
)

func parseReq(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// TestForceConnClose pins the one-shot contract of forwarded requests: the
// head passed into the tunnel must demand Connection: close (so the backend
// hangs up after one response and the front proxy cannot pool the spliced
// connection for other subdomains), while everything past the head — body
// bytes the header read may have buffered — passes through unchanged.
func TestForceConnClose(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\n" +
		"Host: front\r\n" +
		"Connection: keep-alive\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"Content-Length: 4\r\n" +
		"\r\n" +
		"body"
	got := string(forceConnClose([]byte(raw), parseReq(t, raw)))

	head, body, found := strings.Cut(got, "\r\n\r\n")
	if !found {
		t.Fatalf("no header terminator in %q", got)
	}
	if body != "body" {
		t.Fatalf("body corrupted: %q", body)
	}
	if strings.Contains(strings.ToLower(head), "keep-alive") {
		t.Fatalf("keep-alive survived: %q", head)
	}
	if !strings.HasSuffix(head, "Connection: close") {
		t.Fatalf("no Connection: close in %q", head)
	}
	if !strings.HasPrefix(head, "POST /x HTTP/1.1\r\n") {
		t.Fatalf("request line corrupted: %q", head)
	}
}

// TestForceConnCloseUpgrade pins that upgrade handshakes pass untouched — a
// websocket connection must not be demoted to one-shot.
func TestForceConnCloseUpgrade(t *testing.T) {
	raw := "GET /ws HTTP/1.1\r\n" +
		"Host: front\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"\r\n"
	if got := string(forceConnClose([]byte(raw), parseReq(t, raw))); got != raw {
		t.Fatalf("upgrade request modified: %q", got)
	}
}

type captureForwarder struct {
	hdr chan []byte
}

func (c *captureForwarder) Pass(conn net.Conn, hdr []byte) {
	conn.Close()
	c.hdr <- hdr
}

func (c *captureForwarder) Overtake() {}

// TestHandleConnForwardsOneShot drives handleConn end to end: the head that
// reaches the registered forwarder carries Connection: close.
func TestHandleConnForwardsOneShot(t *testing.T) {
	fwd := &captureForwarder{hdr: make(chan []byte, 1)}
	uh := &Ushttpd{forwarders: map[string]Forwarder{
		"abcd.app.example": fwd,
	}}
	client, server := net.Pipe()
	defer client.Close()
	go uh.handleConn(server)

	raw := "GET / HTTP/1.1\r\n" +
		"Host: front\r\n" +
		"X-Forwarded-Host: abcd.app.example\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n"
	if _, err := client.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	hdr := <-fwd.hdr
	if !bytes.Contains(hdr, []byte("Connection: close")) {
		t.Fatalf("forwarded head lacks Connection: close: %q", hdr)
	}
	if bytes.Contains(bytes.ToLower(hdr), []byte("keep-alive")) {
		t.Fatalf("keep-alive leaked into tunnel: %q", hdr)
	}
}
