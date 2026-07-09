package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
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

// testHostKey returns a fresh ed25519 public key for landing/known_hosts tests.
func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return spub
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

// TestDescriptionsRender renders the landing page and SKILL.md against the
// landing data (config + host keys), checking the installation values
// substitute, the stable markers survive and the pinning material shows up.
func TestDescriptionsRender(t *testing.T) {
	uh := newUshttpd(testConf())
	uh.hostKeys = []ssh.PublicKey{testHostKey(t)}
	data := uh.landingData()
	fprint := data.HostKeys[0].Fingerprint

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
			"curl -s https://app.example.com/known_hosts",
			`href="/known_hosts"`,
			fprint + " (ssh-ed25519)",
		}},
		{"skill.md.tmpl", []string{
			"name: usshd-onboarding",
			"ssh app@ssh.example.com </dev/null",            // port-less status check (Steps 1/3)
			"ssh -R80:localhost:<PORT> app@ssh.example.com", // the actual forward (Step 4)
			"Please pay:",
			"Your forwarded site:",
			"1000 sat",
			"https://app.example.com/known_hosts", // Step 0: pin before first connect
		}},
	}
	for _, c := range cases {
		var b bytes.Buffer
		if err := descriptions.ExecuteTemplate(&b, c.tmpl, data); err != nil {
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

// TestKnownHostsFragment parses the /known_hosts payload back with the ssh
// library: every line must be a valid known_hosts entry naming the
// installation's SSH host, one per host key.
func TestKnownHostsFragment(t *testing.T) {
	uh := newUshttpd(testConf())
	uh.hostKeys = []ssh.PublicKey{testHostKey(t), testHostKey(t)}

	rest := []byte(uh.knownHostsText())
	seen := 0
	for len(rest) > 0 {
		_, hosts, pub, _, r, err := ssh.ParseKnownHosts(rest)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		if len(hosts) != 1 || hosts[0] != "ssh.example.com" {
			t.Errorf("entry %d: hosts %v, want [ssh.example.com]", seen, hosts)
		}
		if pub.Type() != "ssh-ed25519" {
			t.Errorf("entry %d: type %s, want ssh-ed25519", seen, pub.Type())
		}
		rest = r
		seen++
	}
	if seen != 2 {
		t.Errorf("parsed %d known_hosts entries, want 2", seen)
	}
}

// TestServeLanding drives the landing pages through ServeHTTP (routed by
// x-forwarded-host), verifying status, content-type and body for both served
// paths and the 404 fallback.
func TestServeLanding(t *testing.T) {
	uh := newUshttpd(testConf())
	uh.hostKeys = []ssh.PublicKey{testHostKey(t)}
	for _, tc := range []struct {
		path, ctype, want string
		code              int
	}{
		{"/", "text/html", "Share your local web app", 200},
		{"/SKILL.md", "text/markdown", "usshd-onboarding", 200},
		{"/known_hosts", "text/plain", "ssh.example.com ssh-ed25519 ", 200},
		{"/nope", "", "", 404},
	} {
		req := httptest.NewRequest("GET", "http://front"+tc.path, nil)
		req.Header.Set("X-Forwarded-Host", uh.conf.LandingHost)
		rec := httptest.NewRecorder()
		uh.ServeHTTP(rec, req)
		resp := rec.Result()
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
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
