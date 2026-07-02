package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func testConf() *Config {
	return &Config{
		SSHUser:       "app",
		SSHHost:       "ssh.example.com",
		AppDomain:     "app.example.com",
		ShortLen:      5,
		Cost:          1000,
		InvoiceExpiry: 3600,
		LandingHost:   "app.example.com",
		SourceURL:     "https://github.com/akovalenko/usshd",
	}
}

func render(t *testing.T, name string, v view) string {
	t.Helper()
	v.Config = testConf()
	var b bytes.Buffer
	if err := messages.ExecuteTemplate(&b, name, v); err != nil {
		t.Fatalf("render %q: %v", name, err)
	}
	return b.String()
}

// TestMessagesRender exercises every user-facing template, confirming the
// embedded *Config fields promote through text/template and the per-session
// values land where expected.
func TestMessagesRender(t *testing.T) {
	cases := []struct {
		name string
		v    view
		want string
	}{
		{"banner", view{}, "https://<YOUR>.app.example.com"},
		{"banner", view{}, "random 5-letter shortname"},
		{"banner", view{}, "ssh -R80:localhost:5000 app@ssh.example.com"},
		{"greeting", view{PubKey: "ssh-ed25519 AAAA\n"}, "APP@SSH.EXAMPLE.COM knows you"},
		{"greeting", view{PubKey: "ssh-ed25519 AAAA\n"}, "Authorizing key: ssh-ed25519 AAAA"},
		{"pleasePay", view{Bolt11: "lnbc1abc"}, "Please pay: lnbc1abc"},
		{"qrTooLarge", view{QRW: 10, QRH: 10, W: 80, H: 24}, "too large for the screen (80x24)"},
		{"site", view{ShortName: "jxrz"}, "https://jxrz.app.example.com"},
		{"hint", view{}, "app@ssh.example.com"},
		{"forwarding", view{}, "forwarded until you exit"},
		{"backendDown", view{}, "not responding"},
		{"goodbye", view{}, "Good bye"},
	}
	for _, c := range cases {
		got := render(t, c.name, c.v)
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: want substring %q, got %q", c.name, c.want, got)
		}
	}
}

// TestMarkerContracts pins the two machine-parsed stability markers. Scripts,
// agents and SKILL.md grep for the exact line prefixes "Please pay:" and
// "Your forwarded site:", so the rendered output must *lead* with them verbatim
// — not merely contain the payload somewhere (as TestMessagesRender's
// substring cases do). If either prefix drifts, every downstream parser breaks
// silently; this test is the tripwire, mirroring the STABILITY CONTRACT comment
// in assets/messages.tmpl.
func TestMarkerContracts(t *testing.T) {
	for _, c := range []struct {
		name, prefix string
		v            view
	}{
		{"pleasePay", "Please pay: ", view{Bolt11: "lnbc1abc"}},
		{"site", "Your forwarded site: ", view{ShortName: "jxrz"}},
	} {
		got := render(t, c.name, c.v)
		if !strings.HasPrefix(got, c.prefix) {
			t.Errorf("%s: render must begin with %q, got %q", c.name, c.prefix, got)
		}
	}
}

// TestDescriptionsRender renders the landing page and SKILL.md against a Config,
// checking the installation values substitute and the stable markers survive.
func TestDescriptionsRender(t *testing.T) {
	cases := []struct {
		tmpl string
		want []string
	}{
		{"landing.html.tmpl", []string{
			"ssh -R80:localhost:5000 app@ssh.example.com",
			"1000 satoshi",
			"1 hour",
			"&lt;name&gt;.app.example.com",
			`href="/SKILL.md"`,
			"https://github.com/akovalenko/usshd",
		}},
		{"skill.md.tmpl", []string{
			"name: usshd-onboarding",
			"ssh app@ssh.example.com </dev/null",          // port-less status check (Steps 1/3)
			"ssh -R80:localhost:<PORT> app@ssh.example.com", // the actual forward (Step 4)
			"Please pay:",
			"Your forwarded site:",
			"1000 sat",
		}},
	}
	for _, c := range cases {
		var b bytes.Buffer
		if err := descriptions.ExecuteTemplate(&b, c.tmpl, testConf()); err != nil {
			t.Fatalf("render %q: %v", c.tmpl, err)
		}
		got := b.String()
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing substring %q", c.tmpl, w)
			}
		}
	}
}

// TestServeLanding drives serveLanding over an in-memory pipe and parses the
// response back, verifying the hand-rolled HTTP framing (status, content-type,
// body) for both served paths and the 404 fallback.
func TestServeLanding(t *testing.T) {
	uh := &Ushttpd{conf: testConf()}
	for _, tc := range []struct {
		path, ctype, want string
		code              int
	}{
		{"/", "text/html", "Share your local web app", 200},
		{"/SKILL.md", "text/markdown", "usshd-onboarding", 200},
		{"/nope", "", "", 404},
	} {
		cli, srv := net.Pipe()
		req, err := http.NewRequest("GET", "http://"+uh.conf.LandingHost+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		go uh.serveLanding(srv, req)
		resp, err := http.ReadResponse(bufio.NewReader(cli), req)
		if err != nil {
			t.Fatalf("%s: read response: %v", tc.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cli.Close()
		if resp.StatusCode != tc.code {
			t.Errorf("%s: status %d, want %d", tc.path, resp.StatusCode, tc.code)
		}
		if tc.ctype != "" && !strings.Contains(resp.Header.Get("Content-Type"), tc.ctype) {
			t.Errorf("%s: content-type %q, want ~%q", tc.path, resp.Header.Get("Content-Type"), tc.ctype)
		}
		if tc.want != "" && !strings.Contains(string(body), tc.want) {
			t.Errorf("%s: body missing %q", tc.path, tc.want)
		}
	}
}

func TestExpiryText(t *testing.T) {
	for _, c := range []struct {
		secs int
		want string
	}{
		{3600, "1 hour"},
		{7200, "2 hours"},
		{1800, "30 minutes"},
		{60, "1 minute"},
		{45, "45 seconds"},
	} {
		got := (&Config{InvoiceExpiry: c.secs}).ExpiryText()
		if got != c.want {
			t.Errorf("ExpiryText(%d) = %q, want %q", c.secs, got, c.want)
		}
	}
}
