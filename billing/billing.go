package billing

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"sync"
	"time"
	"github.com/akovalenko/usshd/lnbits"
)

type UserRecord struct {
	Id        string
	Bolt11    string
	Payhash   string
	ShortName string
}

type userCacheEntry struct {
	rec         *UserRecord                   // last known
	subscribers map[chan *UserRecord]struct{} // interested parties
	interest    time.Time                     // for eviction
}

type userCache struct {
	mu          sync.Mutex                  // deep lock for entire structure
	payhashes   map[string]string           // payhash -> username
	entries     map[string]*userCacheEntry  // username -> record
	subscribers map[chan *UserRecord]string // subscriber -> username
}

func newUserCache() *userCache {
	return &userCache{
		payhashes:   make(map[string]string),
		entries:     make(map[string]*userCacheEntry),
		subscribers: make(map[chan *UserRecord]string),
	}
}

func (uc *userCache) ensure(id string) *userCacheEntry {
	entry, hasOldEntry := uc.entries[id]
	if !hasOldEntry {
		entry = &userCacheEntry{
			rec:         &UserRecord{Id: id},
			subscribers: make(map[chan *UserRecord]struct{}),
		}
		uc.entries[id] = entry
	}
	return entry
}

func (uc *userCache) Put(rec *UserRecord) {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	entry := uc.ensure(rec.Id)

	if *entry.rec == *rec {
		return // noop
	}

	if entry.rec.Payhash != rec.Payhash {
		if entry.rec.Payhash != "" {
			delete(uc.payhashes, entry.rec.Payhash)
		}
		if rec.Payhash != "" {
			uc.payhashes[rec.Payhash] = rec.Id
		}
	}

	uc.entries[rec.Id].rec = rec
	for ch := range entry.subscribers {
		ch <- rec
	}
}

func (uc *userCache) Get(id string) *UserRecord {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	entry := uc.ensure(id)
	entry.interest = time.Now()
	return entry.rec
}

func (uc *userCache) Subscribe(id string) chan *UserRecord {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	entry := uc.ensure(id)
	ch := make(chan *UserRecord, 4)
	ch <- entry.rec
	entry.subscribers[ch] = struct{}{}
	uc.subscribers[ch] = id
	return ch
}

func (uc *userCache) Unsubscribe(ch chan *UserRecord) {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	id, ok := uc.subscribers[ch]
	if !ok {
		return
	}
	entry := uc.ensure(id)
	delete(entry.subscribers, ch)
	delete(uc.subscribers, ch)
	close(ch)
	if len(entry.subscribers) == 0 {
		entry.interest = time.Now()
	}
	go func() {
		for range ch {
		}
	}() // drain
}

func (uc *userCache) Gc() {
	now := time.Now()
	uc.mu.Lock()
	defer uc.mu.Unlock()

	for id, ent := range uc.entries {
		if len(ent.subscribers) > 0 {
			continue
		}
		age := now.Sub(ent.interest)
		if age < 30*time.Second {
			continue
		}
		if ent.rec.Payhash != "" {
			delete(uc.payhashes, ent.rec.Payhash)
		}
		delete(uc.entries, id)
	}
}

func (uc *userCache) Content() []*UserRecord {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	r := []*UserRecord{}
	for _, v := range uc.entries {
		r = append(r, v.rec)
	}
	return r
}

type BillingConf struct {
	Cost         int
	Memo         string
	Expiry       int
	Unit         string
	ShortNameLen int
}

type Billing struct {
	conf       *BillingConf
	db         *sql.DB
	lnbc       *lnbits.Client
	uc         *userCache
	interested chan string
	paid       chan string
	expired    chan string
}

func NewBilling(conf *BillingConf, db *sql.DB, lnbc *lnbits.Client) *Billing {
	return &Billing{
		conf:       conf,
		db:         db,
		lnbc:       lnbc,
		uc:         newUserCache(),
		interested: make(chan string, 16),
		paid:       make(chan string, 16),
		expired:    make(chan string, 16),
	}
}

func (b *Billing) Serve(ctx0 context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx0)
	defer cancel(nil)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := b.lnbc.Subscribe(ctx, b.gotPaid)
		if err != nil {
			cancel(err)
			return
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := b.serveDb(ctx)
		if err != nil {
			cancel(err)
			return
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			t := time.NewTimer(60 * time.Second)
			select {
			case <-t.C:
				b.uc.Gc()
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			t := time.NewTimer(15 * time.Second)
			select {
			case <-t.C:
				if err := b.check(ctx); err != nil {
					log.Printf("billing: check: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	return context.Cause(ctx)
}

func (b *Billing) Subscribe(u string) chan *UserRecord {
	e := b.uc.Get(u)
	if e.ShortName == "" && e.Bolt11 == "" {
		// not loaded (yet)
		b.interested <- u
	}
	return b.uc.Subscribe(u)
}

func (b *Billing) Unsubscribe(ch chan *UserRecord) {
	b.uc.Unsubscribe(ch)
}

// the only routine doing all database operations
func (b *Billing) serveDb(ctx context.Context) error {
	for {
		select {
		case u := <-b.interested:
			if err := b.dbInterested(ctx, u); err != nil {
				log.Printf("billing: interested %s: %v", u, err)
			}
		case u := <-b.paid:
			if err := b.dbAdmitUser(ctx, u); err != nil {
				log.Printf("billing: admit %s: %v", u, err)
			}
		case u := <-b.expired:
			if err := b.dbReinvoiceUser(ctx, u); err != nil {
				log.Printf("billing: reinvoice %s: %v", u, err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (b *Billing) dbInterested(ctx context.Context, u string) error {
	rec := b.uc.Get(u)
	if rec.ShortName != "" || rec.Bolt11 != "" {
		// user already loaded
		log.Print("user already loaded: ", u)
		return nil
	}

	row := b.db.QueryRow("SELECT payhash, shortname FROM users WHERE id=?", u)

	var payhash, shortname *string
	err := row.Scan(&payhash, &shortname)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return b.dbFreshUser(ctx, u)
		}
		// some other database error
		return err
	}
	if shortname != nil {
		// nothing to recheck, the user is admitted
		b.uc.Put(&UserRecord{
			Id:        u,
			ShortName: *shortname,
		})
		return nil
	}
	if payhash == nil {
		return fmt.Errorf("user %v registered with no payhash and no shortname", u)
	}
	invData, err := b.lnbc.GetInvoice(ctx, *payhash)
	if err != nil {
		if errors.Is(err, lnbits.ErrNotFound) {
			// expired
			return b.dbReinvoiceUser(ctx, u)
		}
		return err
	}

	if invData.Paid {
		return b.dbAdmitUser(ctx, u)
	}
	b.uc.Put(&UserRecord{
		Id:      u,
		Bolt11:  invData.Details.Bolt11,
		Payhash: *payhash,
	})

	return nil
}

func (b *Billing) addInvoice(ctx context.Context) (string, string, error) {
	return b.lnbc.AddInvoice(ctx, b.conf.Cost, b.conf.Memo,
		b.conf.Expiry, b.conf.Unit)
}

func (b *Billing) dbFreshUser(ctx context.Context, u string) error {
	// fresh user
	ph, pr, err := b.addInvoice(ctx)
	if err != nil {
		// may be temporary
		return err
	}
	// bind payhash to user
	_, err = b.db.Exec("INSERT INTO users (id, payhash) VALUES(?,?)", u, ph)
	if err != nil {
		// should always work
		return err
	}
	// now we publish the invoice locally
	b.uc.Put(&UserRecord{
		Id:      u,
		Payhash: ph,
		Bolt11:  pr,
	})
	return nil
}

func (b *Billing) dbReinvoiceUser(ctx context.Context, u string) error {
	// reinvoiced user
	ph, pr, err := b.addInvoice(ctx)
	if err != nil {
		// may be temporary
		return err
	}
	// bind payhash to user
	_, err = b.db.Exec("UPDATE users SET payhash=? WHERE id=?", ph, u)
	if err != nil {
		// should always work
		return err
	}

	// now we publish the invoice locally
	b.uc.Put(&UserRecord{
		Id:      u,
		Payhash: ph,
		Bolt11:  pr,
	})
	return nil
}

func (b *Billing) dbAdmitUser(ctx context.Context, u string) error {
	// mark as admitted
	n := b.conf.ShortNameLen
	if n < 1 {
		n = 4
	}
	shortName := ""
	for {
		shortName = randomShortName(n)
		row := b.db.QueryRow("SELECT id FROM users WHERE shortname=?", shortName)
		var r string
		err := row.Scan(&r)
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err != nil {
			break
		}
	}
	_, err := b.db.Exec("UPDATE users SET payhash = NULL, shortname = ? WHERE id = ?", shortName, u)
	if err != nil {
		return err
	}
	b.uc.Put(&UserRecord{
		Id:        u,
		ShortName: shortName,
	})
	return nil
}

func (b *Billing) gotPaid(ied *lnbits.InvoiceEventData) {
	ids := []string{}
	b.uc.mu.Lock()
	if id, ok := b.uc.payhashes[ied.PaymentHash]; ok {
		ids = append(ids, id)
	}
	b.uc.mu.Unlock()
	for _, id := range ids {
		b.paid <- id
	}
}

func (b *Billing) check(ctx context.Context) error {
	ct := b.uc.Content()
	for _, rec := range ct {
		if rec.Payhash == "" {
			continue
		}
		invData, err := b.lnbc.GetInvoice(ctx, rec.Payhash)
		if err != nil {
			if errors.Is(err, lnbits.ErrNotFound) {
				b.expired <- rec.Id
				continue
			}
			return err
		}
		if invData.Paid {
			b.paid <- rec.Id
		}
	}
	return nil
}

func randomShortName(n int) string {
	rns := make([]rune, n)
	for i, _ := range rns {
		rns[i] = rune('a' + rand.IntN(26))
	}
	return string(rns)
}
