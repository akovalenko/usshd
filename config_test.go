package main

import (
	"bytes"
	"strings"
	"testing"
)

func testConf() *Config {
	return &Config{
		SSHUser:   "app",
		SSHHost:   "ssh.example.com",
		AppDomain: "app.example.com",
		ShortLen:  5,
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
