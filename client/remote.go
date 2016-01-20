package client

import (
	"container/heap"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless"
	"github.com/miekg/dns"
)

// A Remote represents some number of remote keyless server(s)
type Remote interface {
	Dial(*Client) (*gokeyless.Conn, error)
	Add(Remote) Remote
}

// A server is an individual remote server
type server struct {
	net.Addr
	ServerName string
	conn       *gokeyless.Conn
}

// NewServer creates a new remote based a given addr and server name.
func NewServer(addr net.Addr, serverName string) Remote {
	return &server{
		Addr:       addr,
		ServerName: serverName,
	}
}

func (c *Client) lookupIPs(host string) (ips []net.IP, err error) {
	m := new(dns.Msg)
	for _, resolver := range c.Resolvers {
		m.SetQuestion(dns.Fqdn(host), dns.TypeA)
		if in, err := dns.Exchange(m, resolver); err == nil {
			for _, rr := range in.Answer {
				if a, ok := rr.(*dns.A); ok {
					ips = append(ips, a.A)
				}
			}
		} else {
			log.Debug(err)
		}

		m.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
		if in, err := dns.Exchange(m, resolver); err == nil {
			for _, rr := range in.Answer {
				if aaaa, ok := rr.(*dns.AAAA); ok {
					ips = append(ips, aaaa.AAAA)
				}
			}
		} else {
			log.Debug(err)
		}
	}
	if len(ips) != 0 {
		return ips, nil
	}

	return net.LookupIP(host)
}

// LookupServerWithName uses DNS to look up an a group of Remote servers with
// optional TLS server name.
func (c *Client) LookupServerWithName(serverName, host string, port int) (Remote, error) {
	if serverName == "" {
		serverName = host
	}

	ips, err := c.lookupIPs(host)
	if err != nil {
		return nil, err
	}

	var servers []Remote
	for _, ip := range ips {
		addr := &net.TCPAddr{IP: ip, Port: port}
		if !c.Blacklist.Contains(addr) {
			servers = append(servers, NewServer(addr, serverName))
		}
	}
	return NewGroup(servers)
}

// LookupServer with default ServerName.
func (c *Client) LookupServer(hostport string) (Remote, error) {
	host, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(p)
	if err != nil {
		return nil, err
	}

	return c.LookupServerWithName(host, host, port)
}

// Dial dials a remote server, returning an existing connection if possible.
func (s *server) Dial(c *Client) (*gokeyless.Conn, error) {
	if c.Blacklist.Contains(s) {
		return nil, fmt.Errorf("server %s on client blacklist", s.String())
	}

	if s.conn != nil && s.conn.Use() {
		return s.conn, nil
	}

	config := *c.Config
	config.ServerName = s.ServerName
	log.Debugf("Dialing %s at %s\n", s.ServerName, s.String())
	inner, err := tls.DialWithDialer(c.Dialer, s.Network(), s.String(), &config)
	if err != nil {
		return nil, err
	}

	s.conn = gokeyless.NewConn(inner)
	return s.conn, nil
}

func (s *server) Add(r Remote) Remote {
	g, _ := NewGroup([]Remote{s, r})
	return g
}

type priority float64

func (p *priority) Update(val float64) {
	*p /= 2
	*p += priority(val / 2)
}

type item struct {
	Remote
	index int
	p     priority
	errs  []error
}

// A group is a Remote consisting of a load-balanced set of external servers.
type group struct {
	sync.Mutex
	remotes []*item
}

// NewGroup creates a new group from a set of remotes.
func NewGroup(remotes []Remote) (Remote, error) {
	if len(remotes) == 0 {
		return nil, errors.New("attempted to create empty remote group")
	}
	g := new(group)
	for _, r := range remotes {
		heap.Push(g, &item{Remote: r})
	}

	return g, nil
}

func (g *group) Dial(c *Client) (conn *gokeyless.Conn, err error) {
	g.Lock()
	defer g.Unlock()

	if g.Len() == 0 {
		err = errors.New("remote group empty")
		return
	}

	var i *item
	var popped []*item
	for g.Len() > 0 {
		i = heap.Pop(g).(*item)
		popped = append(popped, i)
		if conn, err = i.Dial(c); err == nil {
			break
		}

		i.p = 0
		i.errs = append(i.errs, err)
	}

	for _, f := range popped {
		heap.Push(g, f)
	}

	if err != nil {
		return
	}

	go func() {
		defer conn.Close()
		for {
			start := time.Now()
			err := conn.Ping(nil)
			duration := time.Since(start)

			g.Lock()
			if err != nil {
				i.p = 0
				i.errs = append(i.errs, err)
			} else {
				i.p.Update(1 / float64(duration))
			}
			heap.Fix(g, i.index)
			g.Unlock()

			if err != nil {
				log.Infof("Ping failed: %v", err)
				return
			}

			time.Sleep(time.Minute)
		}
	}()
	return
}

func (g *group) Add(r Remote) Remote {
	if g != r {
		heap.Push(g, &item{Remote: r})
	}
	return g
}

func (g *group) Len() int {
	return len(g.remotes)
}

func (g *group) Swap(i, j int) {
	g.remotes[i], g.remotes[j] = g.remotes[j], g.remotes[i]
	g.remotes[i].index = i
	g.remotes[j].index = j
}

func (g *group) Less(i, j int) bool {
	// TODO: incorporate more logic about open connections and failure rate
	pi, pj := g.remotes[i].p, g.remotes[j].p
	errsi, errsj := len(g.remotes[i].errs), len(g.remotes[j].errs)
	return pi < pj || pi == pj && errsi < errsj
}

func (g *group) Push(x interface{}) {
	i := x.(*item)
	i.index = len(g.remotes)
	g.remotes = append(g.remotes, i)
}

func (g *group) Pop() interface{} {
	i := g.remotes[len(g.remotes)-1]
	g.remotes = g.remotes[0 : len(g.remotes)-1]
	return i
}
