package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/sha256"
	"encoding/hex"
	mr "math/rand/v2"

	"github.com/akovalenko/usshd/billing"
	"github.com/akovalenko/usshd/limiter"
	"github.com/akovalenko/usshd/utils"

	"github.com/akovalenko/usshd/lnbits"

	"golang.org/x/crypto/ssh"

	"sync/atomic"

	"github.com/mdp/qrterminal/v3"
	_ "modernc.org/sqlite"
	"os/signal"
	"syscall"
)

const banner = `
Welcome to app@ssh.my-ns.me. Make your local http application available
on a subdomain https://<YOUR>.app.my-ns.me.

<YOUR> stands for a random four-letter shortname that you receive
after paying a Bitcoin Lightning invoice. Payment is required once for
each SSH key you use for logging in. As long as you use the same key
again, your subdomain name will be always yours, for the lifetime of
this project.

If you're running a web application locally on http://localhost:5000,
forwarding it to your subdomain is done like this:

  ssh -R80:localhost:5000 app@ssh.my-ns.me

Port 80 ^ here is just a convention, as you're forwarding your
unencrypted server to the remote machine. Our reverse proxy (caddy
server) handles HTTPS for your subdomain.

`

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

func randomShortName(n int) string {
	rns := make([]rune, n)
	for i, _ := range rns {
		rns[i] = rune('a' + mr.IntN(26))
	}
	return string(rns)
}

func netAddrIp(a net.Addr) string {
	hostPort := a.String()
	colon := strings.LastIndexByte(hostPort, ':')
	if colon == -1 {
		return "<unknown>"
	}
	return hostPort[:colon]
}

func netAddrIpPort(a net.Addr) (string, uint32) {
	hostPort := a.String()
	colon := strings.LastIndexByte(hostPort, ':')
	if colon == -1 {
		return "0.0.0.0", 0
	}
	port, err := strconv.Atoi(hostPort[colon+1:])
	if err != nil {
		return hostPort[:colon], 0
	}
	return hostPort[:colon], uint32(port)
}

func acceptAnyPublicKey(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp := sha256.Sum256(key.Marshal())
	hexFp := hex.EncodeToString(fp[:])
	if md.User() != "app" {
		return nil, errors.New("Only app@ for now")
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"public-key": string(ssh.MarshalAuthorizedKey(key)),
			"fprint":     hexFp,
		},
	}, nil
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

type Forwarder interface {
	Pass(net.Conn, []byte)
	Overtake()
}

type Ushttpd struct {
	mu         sync.Mutex
	forwarders map[string]Forwarder
}

func (uh *Ushttpd) ListenAndServe(ctx0 context.Context, addr string) error {
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx0, "tcp", addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx0)
	defer cancel()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go uh.handleConn(conn)
	}
}

func (uh *Ushttpd) RegisterForwarder(host string, io Forwarder) {
	uh.mu.Lock()
	old, ok := uh.forwarders[host]
	uh.forwarders[host] = io
	uh.mu.Unlock()
	if ok {
		old.Overtake()
	}
}

func (uh *Ushttpd) RemoveForwarder(host string, io Forwarder) {
	uh.mu.Lock()
	if uh.forwarders[host] == io {
		delete(uh.forwarders, host)
	}
	uh.mu.Unlock()
}

func (uh *Ushttpd) Say502(conn net.Conn) {
	resp := &http.Response{
		Proto:      "http",
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: http.StatusBadGateway,
		Status:     http.StatusText(http.StatusBadGateway),
	}
	resp.Write(conn)
	conn.Close()
}

func (uh *Ushttpd) handleConn(conn net.Conn) {
	hbuff := &bytes.Buffer{}
	hread := io.TeeReader(conn, hbuff)
	req, err := http.ReadRequest(bufio.NewReader(hread))
	if err != nil {
		log.Println(err)
		return
	}
	host := req.Header.Get("x-forwarded-host")
	host = strings.ToLower(host)
	uh.mu.Lock()
	fwd, ok := uh.forwarders[host]
	uh.mu.Unlock()
	if !ok {
		uh.Say502(conn)
		return
	}
	fwd.Pass(conn, hbuff.Bytes())
}

type Usshd struct {
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
		uc.sshd.httpd.RemoveForwarder(uc.shortname+".app.my-ns.me", uc)
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

	io.WriteString(stdout, "APP@SSH.MY-NS.ME knows you...\n")
	fmt.Fprintf(stdout, "\nAuthorizing key: %v\n",
		uc.sc.Permissions.Extensions["public-key"])

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
					stdout.Write([]byte(banner))
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
			fmt.Fprint(stdout, "\nPayment backend is not responding, please try again later.\n")
			goto cancelling
		case <-ctx.Done():
			goto cancelling
		}
	}
finish:
	if uc.haveForwards.Load() {
		fmt.Fprint(stdout, "Connections are forwarded until you exit.\n")
	} else {
		fmt.Fprint(stdout, "Hint: use ssh -R80:localhost:5000 app@ssh.my-ns.me\nif you have your application listening on port 5000\n")
	}
	<-ctx.Done()

cancelling:
	fmt.Fprint(stdout, "\nGood bye!\n")
	sess.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
	sess.Close()
	return context.Cause(ctx)
}

func (uc *usshConn) printUserRec(out io.Writer, rec *billing.UserRecord, w, h uint32) error {
	if rec.Bolt11 != "" {
		if _, err := fmt.Fprintf(out, "Please pay: %v\n", rec.Bolt11); err != nil {
			return err
		}
		if w == 0 || h == 0 {
			return nil
		}
		qr := qrEncode(strings.ToUpper(rec.Bolt11))
		qrw, qrh := qrDimensions(qr)
		if qrw+1 < w && qrh+1 < h {
			out.Write(qr)
		} else {
			if _, err := fmt.Fprintf(out, "\nQR code (%vx%v) too large for the screen (%vx%v)\nRelogin with larger window / smaller font to get it.\n\n",
				qrw+1, qrh+1, w, h); err != nil {
				return err
			}
		}
	}
	if rec.ShortName != "" {
		_, err := fmt.Fprintf(out,
			"Your forwarded site: https://%v.app.my-ns.me\n", rec.ShortName,
		)
		return err
	}
	return nil
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
	uc.sshd.httpd.RegisterForwarder(uc.shortname+".app.my-ns.me", uc)
	return nil
}

func (uc *usshConn) Pass(conn net.Conn, hdr []byte) {
	orig := conn.RemoteAddr()
	origHost, origPort := netAddrIpPort(orig)

	payload := struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{
		DestAddr:   uc.fwhost,
		DestPort:   80,
		OriginAddr: origHost,
		OriginPort: origPort,
	}
	sshch, reqs, err := uc.sc.OpenChannel("forwarded-tcpip",
		ssh.Marshal(payload))
	if err != nil {
		uc.sshd.httpd.Say502(conn)
		return
	}

	go ssh.DiscardRequests(reqs)
	_, err = sshch.Write(hdr)

	if err != nil {
		uc.sshd.httpd.Say502(conn)
		sshch.Close()
		return
	}

	func() {
		defer conn.Close()
		defer sshch.Close()
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(conn, sshch)
			if tcp, ok := conn.(*net.TCPConn); ok {
				tcp.CloseWrite()
			} else {
				conn.Close()
			}
		}()
		go func() {
			defer wg.Done()
			io.Copy(sshch, conn)
			sshch.CloseWrite()
		}()
		wg.Wait()
	}()
}

func (uc *usshConn) Overtake() {
	uc.sc.Close()
}

func mustLoadPrivateKey(filename string) ssh.Signer {
	idh, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal("readfile: ", err)
	}
	signer, err := ssh.ParsePrivateKey(idh)
	if err != nil {
		log.Fatal("parse: ", err)
	}
	return signer
}

func coalesce(s1, s2 string) string {
	if s1 != "" {
		return s1
	}
	return s2
}

func main() {

	db, err := sql.Open("sqlite", "users.db")
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	biller := billing.NewBilling(
		&billing.BillingConf{
			Cost:   1000,
			Memo:   "app@ssh.my-ns.me",
			Expiry: 3600,
		},
		db,
		&lnbits.Client{
			Url: coalesce(os.Getenv("LNBITS_HOST"),
				"https://bs.se.my-ns.me"),
			ApiKey: os.Getenv("LNBITS_API_KEY"),
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
		PublicKeyCallback: acceptAnyPublicKey,
	}

	svrCfg.AddHostKey(mustLoadPrivateKey("id_ecdsa"))
	svrCfg.AddHostKey(mustLoadPrivateKey("id_rsa"))
	svrCfg.AddHostKey(mustLoadPrivateKey("id_ed25519"))

	httpd := &Ushttpd{
		forwarders: make(map[string]Forwarder),
	}

	sshd := &Usshd{
		sshConf: svrCfg,
		biller:  biller,
		perIp:   perIp,
		httpd:   httpd,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := httpd.ListenAndServe(ctx,
			coalesce(os.Getenv("LISTEN_HTTP"), "127.0.0.1:8088"))

		log.Println("canceled httpd: ", err)
		if err != nil {
			cancel(err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := sshd.ListenAndServe(ctx,
			coalesce(os.Getenv("LISTEN_SSH"), "127.0.0.1:8024"))
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

