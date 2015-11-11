package client

import (
	"container/heap"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/cloudflare/gokeyless"
	"github.com/rcrowley/go-metrics"
	"github.com/siddontang/go/log"
)

// A Remote is a load-balanced set of external servers.
type Remote struct {
	serverHeap
	sync.Mutex
	host string
}

// NewRemote creates a new Remote set by looking up IPs through DNS.
func NewRemote(host string, port int) (*Remote, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	r := &Remote{host: host}

	heap.Init(r)
	for _, ip := range ips {
		heap.Push(r, newServer(&net.TCPAddr{
			IP:   ip,
			Port: port,
		}))
	}

	return r, nil
}

func (r *Remote) String() string {
	return r.host
}

// DialRemote uses picks the optimal
func (c *Client) DialRemote(r *Remote) (*gokeyless.Conn, error) {
	r.Lock()
	defer r.Unlock()

	s := heap.Pop(r).(*server)
	defer heap.Push(r, s)

	if s.conn != nil && s.conn.Use() {
		return s.conn, nil
	}

	config := *c.Config
	config.ServerName = r.host
	inner, err := tls.DialWithDialer(c.Dialer, s.Network(), s.String(), &config)
	if err != nil {
		return nil, err
	}

	conn := gokeyless.NewConn(inner)
	go func() {
		defer conn.Close()
		for {
			start := time.Now()
			if err := conn.Ping(nil); err != nil {
				log.Infof("Connection to %s failed: %v", s, err)
				return
			}
			duration := time.Since(start)

			r.Lock()
			s.latency.Update(duration)
			if s.index >= 0 {
				heap.Fix(r, s.index)
			}
			r.Unlock()

			time.Sleep(time.Minute)
		}
	}()

	s.conn = conn
	return s.conn, nil
}

type server struct {
	net.Addr
	latency metrics.Timer
	conn    *gokeyless.Conn
	index   int
}

func newServer(addr net.Addr) *server {
	return &server{
		Addr:    addr,
		latency: metrics.NewTimer(),
	}
}

type serverHeap []*server

func (sh serverHeap) Len() int {
	return len(sh)
}

func (sh serverHeap) Swap(i, j int) {
	sh[i], sh[j] = sh[j], sh[i]
	sh[i].index = i
	sh[j].index = j
}

func (sh serverHeap) Less(i, j int) bool {
	return sh[j].conn == nil || sh[i].latency.RateMean() < sh[j].latency.RateMean()
}

func (sh *serverHeap) Push(x interface{}) {
	s := x.(*server)
	s.index = len(*sh)
	*sh = append(*sh, s)
}

func (sh *serverHeap) Pop() interface{} {
	old := *sh
	n := len(old)
	x := old[n-1]
	x.index = -1
	*sh = old[0 : n-1]
	return x
}
