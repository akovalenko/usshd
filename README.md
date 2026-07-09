# usshd

Self-hosted ngrok-style tunnels with a Bitcoin Lightning paywall.

A user runs one SSH command and their local HTTP app becomes reachable at a
permanent public HTTPS subdomain:

```
ssh -R80:localhost:5000 app@ssh.example.com
```

On the first login with a given SSH key the terminal shows a Lightning invoice
(as text and as a QR code). Pay it once and the key is admitted: it gets a
permanent subdomain like `https://<name>.app.example.com`, and reconnecting
with the same key always brings the same subdomain back. No signup, no
password — the SSH key *is* the account.

## How it works

- **Identity is the SSH key.** Any public key is accepted; the key's SHA-256
  fingerprint is the user id.
- **Billing via [lnbits](https://lnbits.com/).** A fresh key gets an invoice;
  payment is detected over the lnbits websocket with a 15-second poller as the
  fallback and source of truth. Expired invoices are replaced automatically.
- **Tunnels.** An admitted key may open an SSH remote forward (`-R80:...`).
  Incoming HTTP requests are routed per request by `X-Forwarded-Host` and
  reverse-proxied into the SSH channel back to the user's local app. TLS is
  terminated by a front proxy (Caddy in the reference setup).
- **Scriptable onboarding.** The flow needs no PTY and is driven by two stable
  marker lines — `Please pay: <bolt11>` and `Your forwarded site: <url>` —
  so scripts and AI agents can onboard themselves; `/SKILL.md` on the landing
  host is a machine-readable guide.

## Endpoints on the landing host

- `/` — landing page for humans (also lists the host key fingerprints)
- `/SKILL.md` — onboarding guide for agents and scripts
- `/known_hosts` — ready-to-append known_hosts fragment with the live SSH host
  keys, so clients can pin them over HTTPS instead of trusting first use:

  ```
  curl -s https://app.example.com/known_hosts >> ~/.ssh/known_hosts
  ```

## Deploying

You need:

- a server where the **public SSH endpoint can live on port 22** (see below);
- **wildcard DNS** for the app domain (`*.app.example.com` → the server);
- a **TLS-terminating reverse proxy** with a wildcard certificate that passes
  `X-Forwarded-Host` (Caddy does by default; wildcard certs need the DNS
  challenge);
- an **lnbits instance** and a wallet **invoice/read key**;
- **Go ≥ 1.25** to build.

Build and run:

```
go build -o usshd .
LNBITS_HOST=https://your.lnbits LNBITS_API_KEY=... \
USSHD_SSH_HOST=ssh.example.com USSHD_APP_DOMAIN=app.example.com \
LISTEN_SSH=0.0.0.0:22 ./usshd
```

The first start bootstraps a working installation in the current directory:
missing host keys are generated (`id_ecdsa`, `id_rsa`, `id_ed25519`) and the
sqlite database is created. Existing host keys are never regenerated — an
unparseable key file is a startup error, not a rotation.

A reverse-proxy sketch (Caddy):

```
app.example.com, *.app.example.com {
	tls {
		dns <your-dns-provider> ...
	}
	reverse_proxy 127.0.0.1:8088
}
```

The apex (`app.example.com`) route serves the landing page; the wildcard
serves the tunnels.

### The public SSH endpoint is port 22, by design

Every instruction the daemon prints, the SKILL.md contract and the
`/known_hosts` fragment assume `ssh <user>@<host>` with **no `-p`** — the
one-command simplicity is the point of the user side, and a nonstandard port
would leak a `-p` into every instruction and a `[host]:port` form into
known_hosts. So: bind `LISTEN_SSH=0.0.0.0:22` in production (or otherwise
arrange for port 22 to reach the daemon). `USSHD_SSH_HOST` is a hostname of
its own, separate from the app domain — point it at any address where port 22
is free. To bind :22 as a non-root user:

```
setcap 'cap_net_bind_service=+ep' usshd
```

The unprivileged default `127.0.0.1:8024` exists for development.

### Environment

Everything binding the daemon to an installation is read from the environment
at startup (defaults in parentheses reflect the author's instance):

| Variable | Default | Meaning |
|---|---|---|
| `USSHD_SSH_USER` | `app` | the only accepted SSH login |
| `USSHD_SSH_HOST` | `ssh.my-ns.me` | hostname users ssh into |
| `USSHD_APP_DOMAIN` | `app.my-ns.me` | parent of `<name>.<domain>` subdomains |
| `USSHD_SHORTNAME_LEN` | `4` | length of the random subdomain name |
| `USSHD_COST` | `1000` | invoice amount, satoshi |
| `USSHD_INVOICE_EXPIRY` | `3600` | invoice lifetime, seconds |
| `USSHD_INVOICE_MEMO` | `<user>@<host>` | memo on the invoice |
| `LNBITS_HOST` | — | lnbits base URL |
| `LNBITS_API_KEY` | — | lnbits wallet invoice/read key |
| `LISTEN_SSH` | `127.0.0.1:8024` | SSH bind address (`0.0.0.0:22` in production) |
| `LISTEN_HTTP` | `127.0.0.1:8088` | HTTP bind address (behind the front proxy) |
| `USSHD_DB_PATH` | `users.db` | sqlite database file (created on first run) |
| `USSHD_LANDING_HOST` | app domain apex | host that serves `/`, `/SKILL.md`, `/known_hosts` |
| `USSHD_SOURCE_URL` | this repo | "powered by" link on the landing page |

## Development

```
go build ./... && go vet ./... && go test ./...
```

The tests run against a real (pure-Go) sqlite and cover billing state
transitions, the per-request proxy routing, host key bootstrap and the
rendered user-facing templates. The dev defaults bind SSH on
`127.0.0.1:8024` and HTTP on `127.0.0.1:8088`, so no privileges are needed.

## License

[CC0 1.0 Universal](LICENSE) — public domain dedication.
