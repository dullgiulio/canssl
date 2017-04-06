package main

import (
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"sync"

	_ "github.com/go-sql-driver/mysql"
)

type deeperr struct {
	err  error
	orig error
}

func (e *deeperr) Error() string {
	return e.err.Error()
}

func (e *deeperr) Orig() error {
	return e.orig
}

func errorf(sfmt string, args ...interface{}) *deeperr {
	var (
		oerr *deeperr
		orig error
	)
	for a := range args {
		if e, ok := args[a].(error); ok {
			if e, ok := args[a].(*deeperr); ok {
				oerr = e
				break
			}
			orig = e
			break
		}
	}
	if oerr == nil {
		oerr = &deeperr{orig: orig}
	}
	oerr.err = fmt.Errorf(sfmt, args...)
	if oerr.orig == nil {
		oerr.orig = oerr.err
	}
	return oerr
}

func explain(err error) string {
	if err == nil {
		return "domain not in certificate or certificate not installed"
	}
	e, ok := err.(*deeperr)
	if ok {
		err = e.orig
	}
	switch te := err.(type) {
	case *net.OpError:
		if _, ok := te.Err.(*os.SyscallError); ok {
			return "vhost is not configured for port 443"
		}
		return explain(te.Err)
	case *net.DNSError:
		return "host not registered in DNS"
	}
	return fmt.Sprintf("original error: %s", err.Error())
}

type temporary interface {
	Temporary() bool
}

type entry struct {
	src    string
	domain string
	err    error
}

func (e *entry) toCsv() string {
	var estr, esrc string
	// TODO: This should be done by the filter
	esrc = e.src
	if e.src[0:4] == "dev_" {
		esrc = e.src[4:]
	}
	estr = strings.Replace(explain(e.err), `"`, `\"`, 0)
	return fmt.Sprintf(`"%s","%s","%s"`, e.domain, esrc, estr)
}

func newEntry(src, domain string) *entry {
	return &entry{src: src, domain: domain}
}

func (e *entry) error(err error) {
	e.err = err
}

type db struct {
	name string
	conn *sql.DB
}

func (db *db) databases(f *filter) ([]string, error) {
	rows, err := db.conn.Query("SHOW DATABASES")
	if err != nil {
		return nil, errorf("cannot query databases: %s", err)
	}
	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, errorf("cannot scan row: %s", err)
		}
		if f.database(name) {
			names = append(names, name)
		}
	}
	return names, nil
}

func (db *db) domains(gen *generator) error {
	rows, err := db.conn.Query("SELECT domainName FROM sys_domain")
	if err != nil {
		return errorf("cannot query domains: %s", err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return errorf("cannot scan row: %s", err)
		}
		if gen.filter.record(name) {
			gen.generate(newEntry(db.name, name))
		}
	}
	return nil
}

func (db *db) connect(dsn string) error {
	var err error
	if db.conn, err = sql.Open("mysql", fmt.Sprintf("%s/%s", dsn, db.name)); err != nil {
		return errorf("cannot connect to db: %s", err)
	}
	return nil
}

func (db *db) close() {
	db.conn.Close()
}

type filter struct {
	prefixes []string
}

func newFilter() *filter {
	return &filter{
		prefixes: []string{".dev.", "dev.", ".hotfix.", "hotfix.", ".uat.", "uat."},
	}
}

func (*filter) database(name string) bool {
	return len(name) > 3 && name[0:4] == "dev_"
}

func (f *filter) record(name string) bool {
	if strings.Contains(name, ".int.kn") {
		return false
	}
	for p := range f.prefixes {
		if strings.Contains(name, "."+f.prefixes[p]) {
			return false
		}
		if len(name) > len(f.prefixes[p]) && name[0:len(f.prefixes[p])] == f.prefixes[p] {
			return false
		}
	}
	return true
}

type generator struct {
	ch     chan<- *entry
	filter *filter
}

func newGenerator(f *filter, ch chan<- *entry) *generator {
	return &generator{
		filter: f,
		ch:     ch,
	}
}

func (g *generator) generate(entry *entry) {
	g.ch <- entry
}

func (g *generator) Close() {
	close(g.ch)
}

type dbscanner struct {
	dsn string
	wg  *sync.WaitGroup
}

func newDBScanner(dsn string, wg *sync.WaitGroup) *dbscanner {
	return &dbscanner{dsn, wg}
}

func (s *dbscanner) scan(name string, gen *generator) error {
	db := &db{name: name}
	if err := db.connect(s.dsn); err != nil {
		return errorf("cannot scan table %s: %s", name, err)
	}
	if err := db.domains(gen); err != nil {
		return errorf("cannot scan table %s: %s", name, err)
	}
	db.close()
	return nil
}

func (s *dbscanner) run(dbnames <-chan string, gen *generator) {
	for name := range dbnames {
		if err := s.scan(name, gen); err != nil {
			log.Print("canssl: ", err)
		}
	}
	s.wg.Done()
}

type prober struct {
	in      <-chan *entry
	out     chan<- *entry
	retries int
}

func (p *prober) hasTLS(url string) (bool, error) {
	var err error
	for i := 0; i < p.retries; i++ {
		// Do not perform any redirect
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		_, err = client.Head(fmt.Sprintf("https://%s/", url))
		if err == nil {
			return true, nil
		}
		if te, ok := err.(temporary); ok {
			if te.Temporary() {
				continue
			}
		}
	}
	if e, ok := err.(*neturl.Error); ok {
		err = e.Err
		_, ok := err.(x509.HostnameError)
		if ok {
			return false, nil
		}
	}
	return false, errorf("cannot HEAD: %s", err)
}

func (p *prober) run(wg *sync.WaitGroup) {
	for entry := range p.in {
		ok, err := p.hasTLS(entry.domain)
		if err != nil {
			entry.error(err)
		}
		if !ok {
			p.out <- entry
		}
	}
	wg.Done()
}

func probeUrls(in <-chan *entry, out chan<- *entry, nworkers, nretries int) {
	var wg sync.WaitGroup
	wg.Add(nworkers)
	for i := 0; i < nworkers; i++ {
		p := &prober{in, out, nretries}
		go p.run(&wg)
	}
	wg.Wait()
	close(out)
}

func scanDatabases(dsn string, names []string, nworkers int, gen *generator) {
	var wg sync.WaitGroup
	wg.Add(nworkers)
	ch := make(chan string)
	for i := 0; i < nworkers; i++ {
		scanner := newDBScanner(dsn, &wg)
		go scanner.run(ch, gen)
	}
	for i := range names {
		ch <- names[i]
	}
	close(ch)
	wg.Wait()
	gen.Close()
}

func main() {
	usr := flag.String("user", "root", "User name for MySQL DB")
	pwd := flag.String("pass", "12345", "Password for MySQL DB")
	flag.Parse()
	nretries := 2
	ndbworkers := 3
	nprobeworkers := 8
	dsn := fmt.Sprintf("%s:%s@tcp(localhost:3306)", *usr, *pwd)
	filter := newFilter()
	db := &db{name: "information_schema"}
	if err := db.connect(dsn); err != nil {
		log.Fatal("canssl: ", err)
	}
	names, err := db.databases(filter)
	if err != nil {
		log.Fatal("canssl: ", err)
	}
	db.close()
	domains := make(chan *entry, 500)
	broken := make(chan *entry)
	gen := newGenerator(filter, domains)
	go scanDatabases(dsn, names, ndbworkers, gen)
	go probeUrls(domains, broken, nprobeworkers, nretries)
	for entry := range broken {
		fmt.Printf("%s\n", entry.toCsv())
	}
}
