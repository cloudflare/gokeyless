package client

import (
	"net"
	"testing"
)

func TestAddrSet(t *testing.T) {
	as := &AddrSet{}

	as.Add(&net.IPAddr{IP: net.IPv4(0, 0, 0, 0)}, 2407)
	as.Add(&net.IPAddr{IP: net.IPv4(1, 1, 1, 1)}, 2407)
	as.Add(&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)}, 2407)

	if !as.Contains(&net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 2407}) {
		t.Fatal("doesn't contain address that was added explicitly")
	}

	if as.Contains(&net.TCPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 2407}) {
		t.Fatal("contains address that wasn't added")
	} else if as.Contains(&net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 2406}) {
		t.Fatal("contains address with port that wasn't added")
	} else if !as.Contains(&net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 2407}) {
		t.Fatal("doesn't contain address that was added explicitly")
	}

	if as.Contains(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2406}) {
		t.Fatal("contains address with port that wasn't added")
	} else if !as.Contains(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2407}) {
		t.Fatal("doesn't contain address in subnet")
	} else if !as.Contains(&net.TCPAddr{IP: net.IPv4(127, 2, 3, 4), Port: 2407}) {
		t.Fatal("doesn't contain address in subnet")
	}
}
