package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
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
	poolEvict := func(key string, value interface{}) {
		conn, ok := value.(*Conn)
		if ok && !conn.Conn.IsClosed() {
			conn.Close()
		}
	}
	connPool = &connPoolType{
		pool: ttlcache.NewLRU(connPoolSize, defaultTTL, poolEvict),
	}
}

// NewConn creates a new Conn based on a gokeyless.Conn
func NewConn(addr string, conn *gokeyless.Conn) *Conn {
	c := Conn{
		Conn: conn,
		addr: addr,
	}

	go healthchecker(&c)
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
		if !conn.Conn.IsClosed() {
			err := conn.Ping(nil)
			if err != nil {
				log.Debug("health check ping failed:", err)
				// shut down the conn and remove it from the
				// conn pool.
				conn.Close()
				return
			}

			log.Debug("start a new health check timer")
		} else { // bail out
			return
		}
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
	if conn != nil && !conn.IsClosed() {
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
	return conn, nil
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

// latency is exponentially weighted moving average of latency
type latency struct {
	val        time.Duration
	errorCount int
	measured   bool
}

func (l latency) Update(val time.Duration) {
	l.measured = true
	l.val /= 2
	l.val += (val / 2)
}

func (l latency) Reset() {
	l.val = 0
	l.measured = false
}

func (l latency) Better(r latency) bool {
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

	return (l.val < r.val) || (l.val == r.val && l.errorCount < r.errorCount)
}

// A Group is a Remote consisting of a load-balanced set of external servers.
type Group struct {
	remotes     []Remote
	latencies   []latency
	lastPingAll time.Time
	sync.RWMutex
}

// NewGroup creates a new group from a set of remotes.
func NewGroup(remotes []Remote) (*Group, error) {
	if len(remotes) == 0 {
		return nil, errors.New("attempted to create empty remote group")
	}
	g := new(Group)
	g.remotes = remotes
	g.latencies = make([]latency, len(remotes))

	return g, nil
}

// Dial returns a connection with best latency measurement.
func (g *Group) Dial(c *Client) (*Conn, error) {
	if len(g.remotes) == 0 {
		return nil, errors.New("remote group empty")
	}

	g.RLock()
	bestr := g.remotes[0]
	bestl := g.latencies[0]
	// use a O(n) loop to find best remote, without
	// maintaining mutex on a heap object
	for i, l := range g.latencies {
		if l.Better(bestl) {
			bestr = g.remotes[i]
		}
	}
	g.RUnlock()

	g.Lock()
	if time.Since(g.lastPingAll) > time.Minute {
		g.lastPingAll = time.Now()
		go g.pingAll(c)
	}
	g.Unlock()

	conn, err := bestr.Dial(c)
	return conn, err
}

func (g *Group) pingAll(c *Client) {
	// make/copy a separate latencies slice
	g.RLock()
	latencies := make([]latency, len(g.remotes))
	copy(latencies, g.latencies)
	g.RUnlock()

	// update on the latencies slice owned by the goroutine
	// so there is no need to lock.
	for i, l := range latencies {
		r := g.remotes[i]
		conn, err := r.Dial(c)
		if err != nil {
			l.Reset()
			l.errorCount++
			latencies[i] = l
			log.Infof("ping failed: %v", err)
			continue
		}
		start := time.Now()
		err = conn.Ping(nil)
		duration := time.Since(start)
		if err != nil {
			defer conn.Close()
			l.Reset()
			l.errorCount++
			log.Infof("ping failed: %v", err)
		} else {
			l.Update(duration)
		}
		latencies[i] = l
	}

	// lock the write on g.latencies
	g.Lock()
	g.latencies = latencies
	g.Unlock()
}
