package main

import (
	"embed"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"text/template"
)

// Config holds everything that binds this daemon to a particular installation:
// the SSH identity shown to users, the domain their subdomains hang off, the
// billing parameters and the lnbits backend. All of it is read from the
// environment once at startup (see loadConfig); nothing here is hardcoded to a
// specific host anymore, so the same binary serves any installation.
type Config struct {
	// SSH-facing identity, echoed in the user-visible copy.
	SSHUser   string // USSHD_SSH_USER      — the only accepted login (e.g. "app")
	SSHHost   string // USSHD_SSH_HOST       — hostname users ssh into
	AppDomain string // USSHD_APP_DOMAIN     — parent of <shortname>.<AppDomain>
	ShortLen  int    // USSHD_SHORTNAME_LEN  — length of the random shortname

	// Billing.
	Cost          int    // USSHD_COST            — invoice amount
	InvoiceExpiry int    // USSHD_INVOICE_EXPIRY  — invoice lifetime, seconds
	InvoiceMemo   string // USSHD_INVOICE_MEMO    — memo on the invoice

	// lnbits backend.
	LnbitsHost   string // LNBITS_HOST
	LnbitsApiKey string // LNBITS_API_KEY

	// Listeners. LISTEN_SSH is where the process binds, not what users are
	// told: the public SSH endpoint is <SSHHost>:22 by design — every printed
	// instruction, the SKILL.md contract and the /known_hosts fragment assume
	// ssh with no -p. Production binds 0.0.0.0:22 (or otherwise routes port 22
	// here); the unprivileged 8024 default exists for development.
	ListenSSH  string // LISTEN_SSH
	ListenHTTP string // LISTEN_HTTP

	// Storage.
	DBPath string // USSHD_DB_PATH — sqlite database file (created on first run)

	// Landing site — the host on which usshd serves the description page and
	// SKILL.md (see Ushttpd.serveLanding). Defaults to the AppDomain apex; set
	// it to e.g. description.<AppDomain> to use a subdomain the wildcard route
	// already covers. Whatever host you pick must be routed to usshd's HTTP
	// listener by the reverse proxy.
	LandingHost string // USSHD_LANDING_HOST
	SourceURL   string // USSHD_SOURCE_URL — "powered by" link on the landing
}

// UserHost is the "user@host" pair as users type it in ssh — reused across the
// banner, the hint and the invoice memo.
func (c *Config) UserHost() string { return c.SSHUser + "@" + c.SSHHost }

func loadConfig() *Config {
	c := &Config{
		SSHUser:   env("USSHD_SSH_USER", "app"),
		SSHHost:   env("USSHD_SSH_HOST", "ssh.my-ns.me"),
		AppDomain: env("USSHD_APP_DOMAIN", "app.my-ns.me"),
		ShortLen:  envInt("USSHD_SHORTNAME_LEN", 4),

		Cost:          envInt("USSHD_COST", 1000),
		InvoiceExpiry: envInt("USSHD_INVOICE_EXPIRY", 3600),

		LnbitsHost:   env("LNBITS_HOST", "https://bs.se.my-ns.me"),
		LnbitsApiKey: os.Getenv("LNBITS_API_KEY"),

		ListenSSH:  env("LISTEN_SSH", "127.0.0.1:8024"),
		ListenHTTP: env("LISTEN_HTTP", "127.0.0.1:8088"),

		DBPath: env("USSHD_DB_PATH", "users.db"),

		SourceURL: env("USSHD_SOURCE_URL", "https://github.com/akovalenko/usshd"),
	}
	if c.ShortLen < 1 {
		log.Printf("USSHD_SHORTNAME_LEN must be >= 1, using 4")
		c.ShortLen = 4
	}
	// Memo defaults to the user@host pair, but stays overridable.
	c.InvoiceMemo = env("USSHD_INVOICE_MEMO", c.UserHost())
	// Landing defaults to the app-domain apex.
	c.LandingHost = env("USSHD_LANDING_HOST", c.AppDomain)
	return c
}

// ExpiryText renders the invoice lifetime for humans ("1 hour", "30 minutes").
func (c *Config) ExpiryText() string {
	switch s := c.InvoiceExpiry; {
	case s >= 3600 && s%3600 == 0:
		return plural(s/3600, "hour")
	case s >= 60 && s%60 == 0:
		return plural(s/60, "minute")
	default:
		return plural(s, "second")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// env returns the value of key, or def when unset/empty.
func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envInt is env for integers; a malformed value logs and falls back to def.
func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Printf("%s=%q is not an integer, using default %d", key, v, def)
		return def
	}
	return n
}

//go:embed assets
var assetsFS embed.FS

// messages is the parsed terminal copy, rendered per-session via view.
var messages = template.Must(template.New("messages").
	Funcs(template.FuncMap{"upper": strings.ToUpper}).
	ParseFS(assetsFS, "assets/messages.tmpl"))

// descriptions are the whole-file templates for the landing site, rendered
// straight against a *Config. Templates are named by their base filename.
var descriptions = template.Must(template.New("descriptions").
	ParseFS(assetsFS, "assets/landing.html.tmpl", "assets/skill.md.tmpl"))

// view is the data a message template renders against: installation fields come
// from the embedded *Config, the rest are per-session values filled by the
// caller. Any field a given template does not reference is simply ignored.
type view struct {
	*Config
	PubKey    string
	Bolt11    string
	ShortName string
	QRW, QRH  uint32
	W, H      uint32
}

// emit renders the named message template to w, injecting this connection's
// installation config. Write/template errors are swallowed like the rest of the
// terminal I/O in this daemon — a dead client is handled by the session ctx.
func (uc *usshConn) emit(w io.Writer, name string, v view) {
	v.Config = uc.sshd.conf
	if err := messages.ExecuteTemplate(w, name, v); err != nil {
		log.Printf("render %q: %v", name, err)
	}
}
