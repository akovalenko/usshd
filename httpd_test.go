package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tcpForwarder backs a Forwarder with a plain TCP dial to a test server,
// standing in for the SSH-channel dial of a live tunnel.
type tcpForwarder struct {
	addr string
}

func (f *tcpForwarder) Dial(originHost string, originPort uint32) (net.Conn, error) {
	return net.Dial("tcp", f.addr)
}

func (f *tcpForwarder) Overtake() {}

// TestProxyRoutesPerRequest pins the per-request routing contract: requests
// arriving over ONE keep-alive front connection but bearing different
// x-forwarded-host values must reach their respective tunnels, and an
// unknown host must get 502 — never someone else's backend. (The previous
// splice design routed once per connection; a pooling front proxy then fed
// every subdomain into whichever tunnel the connection was first routed to.)
func TestProxyRoutesPerRequest(t *testing.T) {
	echoHost := func(tag string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s:%s", tag, r.Host)
		})
	}
	backendA := httptest.NewServer(echoHost("A"))
	defer backendA.Close()
	backendB := httptest.NewServer(echoHost("B"))
	defer backendB.Close()

	uh := newUshttpd(nil)
	uh.RegisterForwarder("a.app.example",
		&tcpForwarder{addr: backendA.Listener.Addr().String()})
	uh.RegisterForwarder("b.app.example",
		&tcpForwarder{addr: backendB.Listener.Addr().String()})

	front := httptest.NewServer(uh)
	defer front.Close()

	// One client with keep-alive: connections to the front are reused
	// across requests, like Caddy's upstream pool.
	client := front.Client()
	get := func(host string) (int, string) {
		t.Helper()
		req, err := http.NewRequest("GET", front.URL+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		// model Caddy: original Host preserved, x-forwarded-host set
		req.Host = host
		req.Header.Set("X-Forwarded-Host", host)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(body)
	}

	for i := 0; i < 3; i++ {
		if code, body := get("a.app.example"); code != 200 || body != "A:a.app.example" {
			t.Fatalf("host a: got %d %q", code, body)
		}
		if code, body := get("b.app.example"); code != 200 || body != "B:b.app.example" {
			t.Fatalf("host b: got %d %q", code, body)
		}
		if code, _ := get("nosuch.app.example"); code != http.StatusBadGateway {
			t.Fatalf("unknown host: got %d, want 502", code)
		}
	}
}

// TestProxyUpgradePassthrough drives a protocol upgrade (the websocket shape)
// through the proxy: the 101 handshake must reach the client and the
// connection must turn into a transparent bidirectional pipe.
func TestProxyUpgradePassthrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Upgrade") != "echo" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			conn, buf, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
				"Connection: Upgrade\r\nUpgrade: echo\r\n\r\n")
			buf.Flush()
			io.Copy(conn, buf) // echo
		}))
	defer backend.Close()

	uh := newUshttpd(nil)
	uh.RegisterForwarder("a.app.example",
		&tcpForwarder{addr: backend.Listener.Addr().String()})
	front := httptest.NewServer(uh)
	defer front.Close()

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\n" +
		"Host: a.app.example\r\n" +
		"X-Forwarded-Host: a.app.example\r\n" +
		"Connection: Upgrade\r\nUpgrade: echo\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	rd := bufio.NewReader(conn)
	status, err := rd.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status line %q, want 101", status)
	}
	for { // skip response headers
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(rd, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ping" {
		t.Fatalf("echo %q, want %q", echo, "ping")
	}
}

// TestProxyKeepsForwardedHeaders pins that the front proxy's X-Forwarded-*
// headers reach the backend verbatim (ReverseProxy.Rewrite strips them by
// default; parity with the raw splice requires handing them through).
func TestProxyKeepsForwardedHeaders(t *testing.T) {
	headers := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			headers <- r.Header.Clone()
		}))
	defer backend.Close()

	uh := newUshttpd(nil)
	uh.RegisterForwarder("a.app.example",
		&tcpForwarder{addr: backend.Listener.Addr().String()})
	front := httptest.NewServer(uh)
	defer front.Close()

	req, err := http.NewRequest("GET", front.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-Host", "a.app.example")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	got := <-headers
	for h, want := range map[string]string{
		"X-Forwarded-Host":  "a.app.example",
		"X-Forwarded-For":   "203.0.113.7",
		"X-Forwarded-Proto": "https",
	} {
		if v := got.Get(h); v != want {
			t.Errorf("%s = %q, want %q", h, v, want)
		}
	}
}
