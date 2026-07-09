package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/sha256"
	"encoding/hex"

	"github.com/akovalenko/usshd/billing"
	"github.com/akovalenko/usshd/limiter"
	"github.com/akovalenko/usshd/utils"

	"github.com/akovalenko/usshd/lnbits"

	"golang.org/x/crypto/ssh"

	"sync/atomic"

	"github.com/mdp/qrterminal/v3"
	"os/signal"
	"syscall"
)

var qrConfig = qrterminal.Config{
	HalfBlocks:     true,
	Level:          qrterminal.L,
	BlackChar:      " ",
	BlackWhiteChar: "▄",
	WhiteChar:      "█",
	WhiteBlackChar: "▀",
}

func qrEncode(s string) []byte {
	cfg := qrConfig
	buf := bytes.Buffer{}
	cfg.Writer = &buf
	qrterminal.GenerateWithConfig(s, cfg)
	return buf.Bytes()
}

func qrDimensions(b []byte) (uint32, uint32) {
	lines := bytes.Count(b, []byte{'\n'})
	lfpos := bytes.IndexByte(b, '\n')
	return uint32(len([]rune(string(b[:lfpos])))),
		uint32(lines)
}

func netAddrIp(a net.Addr) string {
	hostPort := a.String()
	colon := strings.LastIndexByte(hostPort, ':')
	if colon == -1 {
		return "<unknown>"
	}
	return hostPort[:colon]
}

// makeAuthCallback accepts any public key, provided the login name matches the
// installation's configured SSH user. Identity is the key's sha256 fingerprint.
func makeAuthCallback(user string) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		fp := sha256.Sum256(key.Marshal())
		hexFp := hex.EncodeToString(fp[:])
		if md.User() != user {
			return nil, fmt.Errorf("only %s@ for now", user)
		}

		return &ssh.Permissions{
			Extensions: map[string]string{
				"public-key": string(ssh.MarshalAuthorizedKey(key)),
				"fprint":     hexFp,
			},
		}, nil
	}
}

type CrWriter struct {
	W io.Writer
}

func (c *CrWriter) Write(p []byte) (int, error) {
	n := 0
	for {
		lfpos := bytes.IndexByte(p, '\n')
		if lfpos == -1 {
			nb, err := c.W.Write(p)
			n += nb
			return n, err
		}
		nb, err := c.W.Write(p[:lfpos])
		n += nb
		if err != nil {
			return n, err
		}
		nb, err = c.W.Write([]byte("\r\n"))
		n += 1
		if err != nil {
			return n, err
		}
		p = p[lfpos+1:]
	}
}

// Forwarder is one live tunnel: Dial opens a fresh stream to the tunneled
// backend (a forwarded-tcpip channel), Overtake is called when a newer
// connection claims the same shortname.
type Forwarder interface {
	Dial(originHost string, originPort uint32) (net.Conn, error)
	Overtake()
}

// Ushttpd is a per-request reverse proxy: every request is routed by its own
// x-forwarded-host, so the front proxy (Caddy) may keep-alive and pool its
// connections to us freely. (A previous design routed once per TCP connection
// and spliced the rest raw — a pooling front proxy then reused a spliced
// connection for other subdomains, serving one user's tunnel for every
// shortname.) The Transport below pools backend streams BY TARGET HOST, so
// tunnel keep-alive cannot cross subdomains structurally.
type Ushttpd struct {
	conf       *Config
	hostKeys   []ssh.PublicKey // published for pinning: landing + /known_hosts
	mu         sync.Mutex
	forwarders map[string]Forwarder
	transport  *http.Transport
	proxy      *httputil.ReverseProxy
}

// originKey carries the front proxy's address (the socket the request came in
// on) from ServeHTTP to dialTunnel, which reports it as the forwarded-tcpip
// originator. With pooling this is best-effort — a reused stream keeps the
// originator that first opened it; the per-request truth stays in
// X-Forwarded-For.
type originKey struct{}

func newUshttpd(conf *Config) *Ushttpd {
	uh := &Ushttpd{
		conf:       conf,
		forwarders: make(map[string]Forwarder),
	}
	uh.transport = &http.Transport{
		DialContext:         uh.dialTunnel,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	uh.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			host := strings.ToLower(pr.In.Header.Get("x-forwarded-host"))
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = host
			pr.Out.Host = pr.In.Host
			// ReverseProxy strips Forwarded/X-Forwarded-* before Rewrite;
			// hand the front proxy's originals through verbatim, like the
			// raw splice this proxy replaced did.
			for _, h := range []string{"Forwarded", "X-Forwarded-For",
				"X-Forwarded-Host", "X-Forwarded-Proto"} {
				if v := pr.In.Header.Values(h); len(v) > 0 {
					pr.Out.Header[h] = v
				}
			}
		},
		Transport:     uh.transport,
		FlushInterval: -1, // flush as the tunnel speaks: SSE etc. stay live
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy %s: %v", r.Header.Get("x-forwarded-host"), err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	return uh
}

// dialTunnel resolves the target host to a live tunnel and opens a stream
// into it. Runs on the Transport's schedule: once per pooled connection, not
// once per request.
func (uh *Ushttpd) dialTunnel(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	uh.mu.Lock()
	fwd, ok := uh.forwarders[host]
	uh.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no tunnel for %v", host)
	}
	originHost, originPort := "0.0.0.0", uint32(0)
	if origin, ok := ctx.Value(originKey{}).(string); ok {
		if h, p, err := net.SplitHostPort(origin); err == nil {
			originHost = h
			if pn, err := strconv.Atoi(p); err == nil {
				originPort = uint32(pn)
			}
		}
	}
	return fwd.Dial(originHost, originPort)
}

func (uh *Ushttpd) ListenAndServe(ctx0 context.Context, addr string) error {
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx0, "tcp", addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx0)
	defer cancel()

	srv := &http.Server{Handler: uh}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (uh *Ushttpd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Header.Get("x-forwarded-host"))
	if uh.conf != nil && host == strings.ToLower(uh.conf.LandingHost) {
		uh.serveLanding(w, r)
		return
	}
	uh.mu.Lock()
	_, ok := uh.forwarders[host]
	uh.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), originKey{}, r.RemoteAddr))
	uh.proxy.ServeHTTP(w, r)
}

func (uh *Ushttpd) RegisterForwarder(host string, io Forwarder) {
	uh.mu.Lock()
	old, ok := uh.forwarders[host]
	uh.forwarders[host] = io
	uh.mu.Unlock()
	if ok {
		old.Overtake()
		// pooled streams into the overtaken connection are dead; drop them
		// now rather than letting requests trip over them
		uh.transport.CloseIdleConnections()
	}
}

func (uh *Ushttpd) RemoveForwarder(host string, io Forwarder) {
	uh.mu.Lock()
	if uh.forwarders[host] == io {
		delete(uh.forwarders, host)
	}
	uh.mu.Unlock()
}

// hostKeyView is one host key as the landing publishes it for pinning.
type hostKeyView struct {
	Type        string // key algorithm, e.g. "ssh-ed25519"
	Fingerprint string // OpenSSH-style "SHA256:…" — what the TOFU prompt shows
	Line        string // ready known_hosts line: "<sshhost> <type> <base64>"
}

// landingData is what the landing templates render against: the installation
// config (fields promote as before) plus the live host keys. Deriving the
// published material from the keys the daemon actually serves with keeps it
// congruent with reality — including after a key rotation — with nothing to
// configure.
type landingData struct {
	*Config
	HostKeys []hostKeyView
}

func (uh *Ushttpd) landingData() *landingData {
	d := &landingData{Config: uh.conf}
	for _, pub := range uh.hostKeys {
		d.HostKeys = append(d.HostKeys, hostKeyView{
			Type:        pub.Type(),
			Fingerprint: ssh.FingerprintSHA256(pub),
			Line: uh.conf.SSHHost + " " +
				strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		})
	}
	return d
}

// knownHostsText renders the ready-to-append known_hosts fragment served on
// /known_hosts: one line per host key, named for the installation's SSH host.
func (uh *Ushttpd) knownHostsText() string {
	var b strings.Builder
	for _, k := range uh.landingData().HostKeys {
		b.WriteString(k.Line)
		b.WriteByte('\n')
	}
	return b.String()
}

// serveLanding answers the landing host itself (the description page, SKILL.md
// and the known_hosts fragment), rendering the whole-file templates against
// the installation config and host keys.
func (uh *Ushttpd) serveLanding(w http.ResponseWriter, r *http.Request) {
	var tmpl, ctype string
	switch r.URL.Path {
	case "/", "/index.html":
		tmpl, ctype = "landing.html.tmpl", "text/html; charset=utf-8"
	case "/SKILL.md":
		tmpl, ctype = "skill.md.tmpl", "text/markdown; charset=utf-8"
	case "/known_hosts":
		// The page is served over HTTPS, so this fragment lets clients pin
		// the SSH host keys through WebPKI instead of trusting first use.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(uh.knownHostsText()))
		return
	default:
		http.NotFound(w, r)
		return
	}
	var body bytes.Buffer
	if err := descriptions.ExecuteTemplate(&body, tmpl, uh.landingData()); err != nil {
		log.Printf("render %s: %v", tmpl, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Write(body.Bytes())
}

type Usshd struct {
	conf    *Config
	sshConf *ssh.ServerConfig
	biller  *billing.Billing
	perIp   *limiter.Limiter[string]
	httpd   *Ushttpd
}

type usshConn struct {
	sshd         *Usshd
	sc           *ssh.ServerConn
	shortname    string
	haveForwards atomic.Bool
	admitted     chan struct{}
	fwhost       string
}

func (sshd *Usshd) ListenAndServe(ctx0 context.Context, addr string) error {
	ctx, cancel := context.WithCancel(ctx0)
	defer cancel()

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx0, "tcp", addr)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		if !sshd.perIp.Allow(netAddrIp(conn.RemoteAddr())) {
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := sshd.serveConn(ctx, conn)
			if err != nil {
				log.Println(err)
			}
		}()
	}
}

func (sshd *Usshd) serveConn(ctx0 context.Context, conn net.Conn) error {
	sshsc, newCh, reqCh, err := ssh.NewServerConn(conn, sshd.sshConf)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx0)
	defer cancel()

	usub := sshd.biller.Subscribe(sshsc.Permissions.Extensions["fprint"])

	go func() {
		<-ctx.Done()
		sshsc.Close()
		sshd.biller.Unsubscribe(usub)
	}()

	uc := &usshConn{
		sshd:     sshd,
		sc:       sshsc,
		admitted: make(chan struct{}),
	}

	go func() {
		for u := range usub {
			if u.ShortName != "" {
				uc.shortname = u.ShortName
				close(uc.admitted)
				sshd.biller.Unsubscribe(usub)
			}
		}
	}()

	go func() {
		for req := range newCh {
			if req.ChannelType() != "session" {
				req.Reject(ssh.Prohibited, "only session channels may be requested")
				continue
			}
			// todo session limiter
			go uc.ServeSession(ctx, req)
		}
	}()
	go func() {
		for req := range reqCh {
			if !req.WantReply {
				continue
			}
			if req.Type != "tcpip-forward" {
				req.Reply(false, nil)
				continue
			}
			go uc.HandleForwarding(ctx, req)
		}
	}()

	err = sshsc.Wait()
	if uc.shortname != "" {
		uc.sshd.httpd.RemoveForwarder(uc.shortname+"."+sshd.conf.AppDomain, uc)
	}
	return err
}

// preInvoiceTimeout bounds the "producing" phase — the wait for lnbits to mint
// the first invoice (or for the DB to resolve an admitted key). Interrupts are
// disabled during that phase, so if the payment backend is wedged we must not
// block the client forever: past this deadline we say so and hang up.
const preInvoiceTimeout = 20 * time.Second

func (uc *usshConn) ServeSession(ctx0 context.Context, newCh ssh.NewChannel) error {

	ctx, cancel := context.WithCancelCause(ctx0)
	defer cancel(nil)

	sess, reqs, err := newCh.Accept()
	if err != nil {
		return err
	}
	var term struct {
		Terminal     string
		W, H, Pw, Ph uint32
		Modes        string
	}
	haveTerm := false

	for req := range reqs {
		if req.Type == "pty-req" {
			err = ssh.Unmarshal(req.Payload, &term)
			if err != nil {
				log.Println("pty-req error parsing")
				continue
			}
			haveTerm = true
			req.Reply(true, nil)
		}
		if req.Type == "shell" || req.Type == "exec" {
			req.Reply(true, nil)
			goto nonLarval
		}
	}
	return nil // closed before reaching shell or exec

nonLarval:
	go ssh.DiscardRequests(reqs) // except possible window-change

	// armed is closed by the main loop once the first actionable line (the
	// invoice, or the subdomain for an already-admitted key) has been printed.
	// Until then the session is still "producing" its answer and must not be
	// torn down by the client's stdin closing — a non-interactive client
	// (ssh host </dev/null | grep 'Please pay:') would otherwise never see it.
	// Interrupts detected before arming are held and honored the instant we arm.
	armed := make(chan struct{})

	// waitArmed blocks until the gate is armed, or the session ends first
	// (timeout / real disconnect). Returns false in the latter case: nothing
	// left to interrupt.
	waitArmed := func() bool {
		select {
		case <-armed:
			return true
		case <-ctx.Done():
			return false
		}
	}

	go func() {
		// onEOF: the client closed its stdin. Honor it as "exit" only once
		// armed, and — variant B — never while a forward is active: a silent
		// `ssh -R ... </dev/null` tunnel then lives until a real disconnect,
		// while an interactive user still exits via the Ctrl+C/Ctrl+D bytes
		// below or by dropping the connection. haveForwards is read only after
		// arming, by when a `-R` request has long since registered.
		onEOF := func(cause error) {
			if !waitArmed() {
				return
			}
			if uc.haveForwards.Load() {
				return
			}
			cancel(cause)
		}
		// onInterrupt: an explicit Ctrl+C/Ctrl+D byte (PTY only). Always tears
		// the session down once armed, even with a forward active.
		onInterrupt := func() {
			if waitArmed() {
				cancel(nil)
			}
		}
		if haveTerm {
			for {
				var buf [128]byte
				n, err := sess.Read(buf[:])
				if n > 0 && bytes.ContainsAny(buf[:n], "\003\004") {
					onInterrupt()
					return
				}
				if err != nil {
					onEOF(err)
					return
				}
			}
		} else {
			_, err := io.Copy(io.Discard, sess)
			onEOF(err)
		}
	}()

	var stdout io.Writer = sess
	if haveTerm {
		stdout = &CrWriter{stdout}
	}

	userId := uc.sc.Permissions.Extensions["fprint"]

	uc.emit(stdout, "greeting",
		view{PubKey: uc.sc.Permissions.Extensions["public-key"]})

	usub := uc.sshd.biller.Subscribe(userId)
	defer uc.sshd.biller.Unsubscribe(usub)

	printedIntro := false
	gateArmed := false

	invoiceTimeout := time.NewTimer(preInvoiceTimeout)
	defer invoiceTimeout.Stop()
	timeoutC := invoiceTimeout.C

	for {
		select {
		case rec := <-usub:
			if rec.Id == "" {
				goto cancelling
			}
			if rec.Bolt11 != "" {
				if !printedIntro {
					uc.emit(stdout, "banner", view{})
					printedIntro = true
				}
			}
			uc.printUserRec(stdout, rec, term.W, term.H)
			if rec.Bolt11 != "" || rec.ShortName != "" {
				// First actionable line is out: arm interrupts and retire the
				// pre-invoice timeout — a pending payment may take arbitrarily
				// long (bounded only by the invoice's own expiry).
				if !gateArmed {
					close(armed)
					gateArmed = true
				}
				invoiceTimeout.Stop()
				timeoutC = nil
			}
			if rec.ShortName != "" {
				goto finish
			}
		case <-timeoutC:
			uc.emit(stdout, "backendDown", view{})
			goto cancelling
		case <-ctx.Done():
			goto cancelling
		}
	}
finish:
	if uc.haveForwards.Load() {
		uc.emit(stdout, "forwarding", view{})
	} else {
		uc.emit(stdout, "hint", view{})
	}
	<-ctx.Done()

cancelling:
	uc.emit(stdout, "goodbye", view{})
	sess.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
	sess.Close()
	return context.Cause(ctx)
}

func (uc *usshConn) printUserRec(out io.Writer, rec *billing.UserRecord, w, h uint32) {
	if rec.Bolt11 != "" {
		uc.emit(out, "pleasePay", view{Bolt11: rec.Bolt11})
		if w == 0 || h == 0 {
			return
		}
		qr := qrEncode(strings.ToUpper(rec.Bolt11))
		qrw, qrh := qrDimensions(qr)
		if qrw+1 < w && qrh+1 < h {
			out.Write(qr)
		} else {
			uc.emit(out, "qrTooLarge",
				view{QRW: qrw + 1, QRH: qrh + 1, W: w, H: h})
		}
	}
	if rec.ShortName != "" {
		uc.emit(out, "site", view{ShortName: rec.ShortName})
	}
}

func (uc *usshConn) HandleForwarding(ctx context.Context, req *ssh.Request) error {
	var fwd struct {
		Addr  string
		Rport uint32
	}
	err := ssh.Unmarshal(req.Payload, &fwd)
	if err != nil {
		return err
	}
	if fwd.Rport != 80 {
		req.Reply(false, nil)
		return nil
	}

	// we're going to allow forwarding, maybe waiting for payment
	uc.haveForwards.Store(true)

	// here we wait for user admission, having user shortname
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-uc.admitted:
	}
	// by here we definitely have a shortname
	fwdOk := struct {
		Rport uint32
	}{
		Rport: fwd.Rport,
	}
	req.Reply(true, ssh.Marshal(fwdOk))
	log.Println("forwarding requested for: ", fwd.Addr)
	uc.fwhost = fwd.Addr
	uc.sshd.httpd.RegisterForwarder(uc.shortname+"."+uc.sshd.conf.AppDomain, uc)
	return nil
}

// chanConn adapts an ssh.Channel to net.Conn for http.Transport. Deadlines
// are accepted and ignored: the Transport paces itself with timers, and the
// channel dies with its SSH connection.
type chanConn struct {
	ssh.Channel
}

var chanConnAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 0}

func (c chanConn) LocalAddr() net.Addr                { return chanConnAddr }
func (c chanConn) RemoteAddr() net.Addr               { return chanConnAddr }
func (c chanConn) SetDeadline(t time.Time) error      { return nil }
func (c chanConn) SetReadDeadline(t time.Time) error  { return nil }
func (c chanConn) SetWriteDeadline(t time.Time) error { return nil }

func (uc *usshConn) Dial(originHost string, originPort uint32) (net.Conn, error) {
	payload := struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{
		DestAddr:   uc.fwhost,
		DestPort:   80,
		OriginAddr: originHost,
		OriginPort: originPort,
	}
	sshch, reqs, err := uc.sc.OpenChannel("forwarded-tcpip",
		ssh.Marshal(payload))
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	return chanConn{Channel: sshch}, nil
}

func (uc *usshConn) Overtake() {
	uc.sc.Close()
}

func main() {

	conf := loadConfig()

	db, err := openDB(conf.DBPath)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	biller := billing.NewBilling(
		&billing.BillingConf{
			Cost:         conf.Cost,
			Memo:         conf.InvoiceMemo,
			Expiry:       conf.InvoiceExpiry,
			ShortNameLen: conf.ShortLen,
		},
		db,
		&lnbits.Client{
			Url:    conf.LnbitsHost,
			ApiKey: conf.LnbitsApiKey,
		})

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := biller.Serve(ctx)
		log.Println("billing error: ", err)
		cancel(err)
	}()

	perIp := limiter.NewLimiter[string](
		&limiter.LimiterConfig{
			Period: 2 * time.Second,
			Burst:  5,
		})
	utils.Run(ctx, time.Minute, false, perIp.Gc)

	svrCfg := &ssh.ServerConfig{
		PublicKeyCallback: makeAuthCallback(conf.SSHUser),
	}

	hostSigners, err := loadHostKeys()
	if err != nil {
		log.Fatal(err)
	}
	httpd := newUshttpd(conf)
	for _, signer := range hostSigners {
		svrCfg.AddHostKey(signer)
		httpd.hostKeys = append(httpd.hostKeys, signer.PublicKey())
	}

	sshd := &Usshd{
		conf:    conf,
		sshConf: svrCfg,
		biller:  biller,
		perIp:   perIp,
		httpd:   httpd,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := httpd.ListenAndServe(ctx, conf.ListenHTTP)

		log.Println("canceled httpd: ", err)
		if err != nil {
			cancel(err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := sshd.ListenAndServe(ctx, conf.ListenSSH)
		log.Println("canceled sshd: ", err)
		if err != nil {
			cancel(err)
		}
	}()

	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		cancel(nil)
	}()

	wg.Wait()
}
