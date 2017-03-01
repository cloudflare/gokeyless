package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/transport/core"
	"github.com/cloudflare/gokeyless"
	"github.com/lziest/ttlcache"
	"github.com/miekg/dns"
)

const (
	connPoolSize = 512
	defaultTTL   = 1 * time.Hour
)

// ConnHealthCheck, when set to true, will automaically start
// a healthcheck goroutine for each Conn created.
var ConnHealthCheck = true

// connPoolType is a async safe pool of established gokeyless Conn
// so we don't need to do TLS handshake unnecessarily.
type connPoolType struct {
	pool *ttlcache.LRU
}

// connPool keeps all active Conn
var connPool *connPoolType

// A Remote represents some number of remote keyless server(s)
type Remote interface {
	Dial(*Client) (*Conn, error)
	PingAll(*Client, int)
}

// A Conn represents a long-lived client connection to a keyserver.
type Conn struct {
	*gokeyless.Conn
	addr string
}

// A singleRemote is an individual remote server
type singleRemote struct {
	net.Addr          // actual address
	ServerName string // hostname for TLS verification
}

func init() {
	connPool = &connPoolType{
		pool: ttlcache.NewLRU(connPoolSize, defaultTTL, nil),
	}
}

// NewConn creates a new Conn based on a gokeyless.Conn
func NewConn(addr string, conn *gokeyless.Conn) *Conn {
	c := Conn{
		Conn: conn,
		addr: addr,
	}

	if ConnHealthCheck {
		go healthchecker(&c)
	}
	return &c
}

// Close closes a Conn and remove it from the conn pool
func (conn *Conn) Close() {
	conn.Conn.Close()
	connPool.Remove(conn.addr)
}

// KeepAlive keeps Conn reusable in the conn pool
func (conn *Conn) KeepAlive() {
	connPool.Add(conn.addr, conn)
}

// healthchecker is a recurrent timer function that tests the connections
func healthchecker(conn *Conn) {
	backoff := core.NewWithoutJitter(1*time.Hour, 1*time.Second)
	// automatic reset timer to 1*second,  if backoff is greater than 20 minutes.
	backoff.SetDecay(20 * time.Minute)

	for {
		time.Sleep(backoff.Duration())

		err := conn.Ping(nil)
		if err != nil {
			log.Debug("health check ping failed:", err)
			// shut down the conn and remove it from the
			// conn pool.
			conn.Close()
			return
		}

		log.Debug("start a new health check timer")
	}
}

// Get returns a Conn from the pool if there is any.
func (p *connPoolType) Get(key string) *Conn {
	// ignore stale indicator
	value, _ := p.pool.Get(key)
	conn, ok := value.(*Conn)
	if ok {
		return conn
	}
	return nil
}

// Add adds a Conn to the pool.
func (p *connPoolType) Add(key string, conn *Conn) {
	p.pool.Set(key, conn, defaultTTL)
	log.Debug("add conn with key:", key)
}

// Remove removes a Conn keyed by key.
func (p *connPoolType) Remove(key string) {
	p.pool.Remove(key)
	log.Debug("remove conn with key:", key)
}

// NewServer creates a new remote based a given addr and server name.
func NewServer(addr net.Addr, serverName string) Remote {
	return &singleRemote{
		Addr:       addr,
		ServerName: serverName,
	}
}

// UnixRemote returns a Remote constructed from the Unix address
func UnixRemote(unixAddr, serverName string) (Remote, error) {
	addr, err := net.ResolveUnixAddr("unix", unixAddr)
	if err != nil {
		return nil, err
	}

	return NewServer(addr, serverName), nil
}

// LookupIPs resolves host with resolvers list sequentially unitl
// one resolver can answer the request. It falls
// back to use system default for final resolution if none of resolvers
// can answer.
func LookupIPs(resolvers []string, host string) (ips []net.IP, err error) {
	m := new(dns.Msg)
	dnsClient := new(dns.Client)
	dnsClient.Net = "tcp"
	for _, resolver := range resolvers {
		m.SetQuestion(dns.Fqdn(host), dns.TypeA)
		if in, _, err := dnsClient.Exchange(m, resolver); err == nil {
			for _, rr := range in.Answer {
				if a, ok := rr.(*dns.A); ok {
					log.Debugf("resolve %s to %s", host, a)
					ips = append(ips, a.A)
				}
			}
		} else {
			log.Warningf("fail to get A records for %s with %s: %v", host, resolver, err)
		}

		m.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
		if in, _, err := dnsClient.Exchange(m, resolver); err == nil {
			for _, rr := range in.Answer {
				if aaaa, ok := rr.(*dns.AAAA); ok {
					log.Debugf("resolve %s to %s", host, aaaa)
					ips = append(ips, aaaa.AAAA)
				}
			}
		} else {
			log.Warningf("fail to get AAAA records for %s with %s: %v", host, resolver, err)
		}
	}
	if len(ips) != 0 {
		return ips, nil
	}

	return net.LookupIP(host)
}

// LookupServerWithName uses DNS to look up an a group of Remote servers with
// optional TLS server name.
func (c *Client) LookupServerWithName(serverName, host, port string) (Remote, error) {
	if serverName == "" {
		serverName = host
	}

	ips, err := LookupIPs(c.Resolvers, host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("fail to resolve %s", host)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}

	var servers []Remote
	for _, ip := range ips {
		addr := &net.TCPAddr{IP: ip, Port: portNumber}
		if !c.Blacklist.Contains(addr) {
			servers = append(servers, NewServer(addr, serverName))
		}
	}
	log.Infof("server lookup: %s has %d usable upstream", host, len(servers))
	return NewGroup(servers)
}

// LookupServer with default ServerName.
func (c *Client) LookupServer(hostport string) (Remote, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}

	return c.LookupServerWithName(host, host, port)
}

// Dial dials a remote server, returning an existing connection if possible.
func (s *singleRemote) Dial(c *Client) (*Conn, error) {
	if c.Blacklist.Contains(s) {
		return nil, fmt.Errorf("server %s on client blacklist", s.String())
	}

	conn := connPool.Get(s.String())
	if conn != nil {
		return conn, nil
	}

	config := copyTLSConfig(c.Config)
	config.ServerName = s.ServerName
	log.Debugf("Dialing %s at %s\n", s.ServerName, s.String())
	inner, err := tls.DialWithDialer(c.Dialer, s.Network(), s.String(), config)
	if err != nil {
		return nil, err
	}

	gconn := gokeyless.NewConn(inner)
	conn = NewConn(s.String(), gconn)
	connPool.Add(s.String(), conn)
	go func() {
		for {
			err := conn.DoRead()
			if err != nil {
				if err == io.EOF {
					log.Debug("connection closed by server")
				} else {
					log.Errorf("failed to read next header from %v: %v", s.String(), err)
				}
				break
			}
		}

		conn.Close()
	}()

	return conn, nil
}

// PingAll simply attempts to ping the singleRemote
func (s *singleRemote) PingAll(c *Client, concurrency int) {
	conn, err := s.Dial(c)
	if err != nil {
		return
	}

	err = conn.Ping(nil)
	if err != nil {
		conn.Close()
	}
}

func copyTLSConfig(c *tls.Config) *tls.Config {
	return &tls.Config{
		Certificates:             c.Certificates,
		NameToCertificate:        c.NameToCertificate,
		GetCertificate:           c.GetCertificate,
		RootCAs:                  c.RootCAs,
		NextProtos:               c.NextProtos,
		ServerName:               c.ServerName,
		ClientAuth:               c.ClientAuth,
		ClientCAs:                c.ClientCAs,
		InsecureSkipVerify:       c.InsecureSkipVerify,
		CipherSuites:             c.CipherSuites,
		PreferServerCipherSuites: c.PreferServerCipherSuites,
		SessionTicketsDisabled:   c.SessionTicketsDisabled,
		SessionTicketKey:         c.SessionTicketKey,
		ClientSessionCache:       c.ClientSessionCache,
		MinVersion:               c.MinVersion,
		MaxVersion:               c.MaxVersion,
		CurvePreferences:         c.CurvePreferences,
	}
}

// ewmaLatency is exponentially weighted moving average of latency
type ewmaLatency struct {
	val      time.Duration
	measured bool
}

func (l ewmaLatency) Update(val time.Duration) {
	l.measured = true
	l.val /= 2
	l.val += (val / 2)
}

func (l ewmaLatency) Reset() {
	l.val = 0
	l.measured = false
}

func (l ewmaLatency) Better(r ewmaLatency) bool {
	// if l is not measured (it also means last measurement was
	// a failure), any updated/measured latency is better than
	// l. Also if neither l or r is measured, l can't be better
	// than r.
	if !l.measured {
		return false
	}

	if l.measured && !r.measured {
		return true
	}

	return l.val < r.val
}

// mRemote denotes Remote with latency measurements.
type mRemote struct {
	Remote
	latency ewmaLatency
}

type mRemoteSorter []mRemote

// A Group is a Remote consisting of a load-balanced set of external servers.
type Group struct {
	sync.RWMutex
	remotes     []mRemote
	lastPingAll time.Time
}

// NewGroup creates a new group from a set of remotes.
func NewGroup(remotes []Remote) (*Group, error) {
	if len(remotes) == 0 {
		return nil, errors.New("attempted to create empty remote group")
	}
	g := new(Group)

	for _, r := range remotes {
		g.remotes = append(g.remotes, mRemote{Remote: r})
	}

	return g, nil
}

// Dial returns a connection with best latency measurement.
func (g *Group) Dial(c *Client) (conn *Conn, err error) {
	g.RLock()
	if len(g.remotes) == 0 {
		err = errors.New("remote group empty")
		return nil, err
	}
	// n is the number of trials.
	// Because of potential expensive fresh tls dial operation,
	// we limit total dial candidates to a small number.
	// Also it solves a subtle problem of test 'localhost'
	// server discovery due to dual ipv6/ipv4 ip resolution.
	n := 3
	if len(g.remotes) < n {
		n = len(g.remotes)
	}

	remotes := make([]mRemote, n)
	// copy and shuffle first n remotes for load balancing
	for i := 0; i < n; i++ {
		j := rand.Intn(i + 1)
		if i != j {
			remotes[i] = remotes[j]
		}
		remotes[j] = g.remotes[i]
	}
	g.RUnlock()

	defer func() {
		g.Lock()
		if time.Since(g.lastPingAll) > 30*time.Minute {
			g.lastPingAll = time.Now()
			go g.PingAll(c, 1)
		}
		g.Unlock()

	}()

	for _, r := range remotes {
		conn, err = r.Dial(c)
		if err != nil {
			log.Debugf("retry due to dial failure: %v", err)
		} else {
			break
		}
	}

	return conn, err
}

// PingAll loops through all remote servers for performance measurement
// in a separate goroutine. It allows a separate goroutine to
// asynchronously sort remotes by ping latencies. It also serves
// as a service discovery tool.
func (g *Group) PingAll(c *Client, concurrency int) {
	g.RLock()
	remotes := make([]mRemote, len(g.remotes))
	copy(remotes, g.remotes)
	g.RUnlock()

	if concurrency <= 0 {
		concurrency = 1
	}
	// ch receives all tested remote back
	ch := make(chan mRemote, len(remotes))
	// jobQueue controls concurrency
	jobQueue := make(chan bool, concurrency)
	// fill the queue
	for i := 0; i < cap(jobQueue); i++ {
		jobQueue <- true
	}

	// each goroutine dials a remote
	for _, r := range remotes {
		// take a job slot from the queue
		<-jobQueue
		go func(r mRemote) {
			// defer returns a job slot to the queue
			defer func() { jobQueue <- true }()
			conn, err := r.Dial(c)
			if err != nil {
				r.latency.Reset()
				log.Infof("PingAll's dial failed: %v", err)
				ch <- r
				return
			}

			start := time.Now()
			err = conn.Ping(nil)
			duration := time.Since(start)

			if err != nil {
				defer conn.Close()
				r.latency.Reset()
				log.Infof("PingAll's ping failed: %v", err)
			} else {
				r.latency.Update(duration)
			}
			ch <- r
		}(r)
	}

	for i := 0; i < len(remotes); i++ {
		remotes[i] = <-ch
	}

	sort.Sort(mRemoteSorter(remotes))

	g.Lock()
	g.remotes = remotes
	g.lastPingAll = time.Now()
	g.Unlock()
}

// Len(), Less(i, j) and Swap(i,j) implements sort.Interface

// Len returns the number of remote
func (s mRemoteSorter) Len() int {
	return len(s)
}

// Swap swaps remote i and remote j in the list
func (s mRemoteSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less compares two Remotes at position i and j based on latency
func (s mRemoteSorter) Less(i, j int) bool {
	pi, pj := s[i].latency, s[j].latency
	return pi.Better(pj)
}
