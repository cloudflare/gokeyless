package client

import (
	"container/heap"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless"
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

// LookupServer uses DNS to look up an a group of Remote servers with
// optional TLS server name.
func (c *Client) LookupServer(host, serverName string, port int) (Remote, error) {
	if serverName == "" {
		serverName = host
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	servers := make([]Remote, len(ips))
	for _, ip := range ips {
		if err := c.ValidIP(ip); port != c.BlacklistPort || err == nil {
			servers = append(servers, &server{
				Addr: &net.TCPAddr{
					IP:   ip,
					Port: port,
				},
				ServerName: serverName,
			})
		}
	}
	return NewGroup(servers), nil
}

// Dial dials a remote server, returning an existing connection if possible.
func (s *server) Dial(c *Client) (*gokeyless.Conn, error) {
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
	return NewGroup([]Remote{s, r})
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
func NewGroup(remotes []Remote) Remote {
	g := new(group)
	heap.Init(g)
	for _, r := range remotes {
		heap.Push(g, &item{Remote: r})
	}

	return g
}

func (g *group) Dial(c *Client) (conn *gokeyless.Conn, err error) {
	g.Lock()
	defer g.Unlock()

	var i *item
	var failed []*item
	for err = errors.New("remote group empty"); g.Len() > 0; i = heap.Pop(g).(*item) {
		if conn, err = i.Dial(c); err == nil {
			break
		}

		i.p = 0
		i.errs = append(i.errs, err)
		failed = append(failed, i)
	}

	for _, f := range failed {
		heap.Push(g, f)
	}

	if err != nil {
		return nil, err
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

	return conn, nil
}

func (g *group) Add(r Remote) Remote {
	heap.Push(g, &item{Remote: r})
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
	return g.remotes[i].p < g.remotes[j].p
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
