package kcpraw

import (
	"fmt"
	"net"
	"sync"

	"github.com/ccsexyz/mulcon"
	"github.com/ccsexyz/rawcon"
	"github.com/pkg/errors"
	kcp "github.com/xtaci/kcp-go"
)

var (
	raw rawcon.Raw

	mssCache     map[string]int
	mssCacheLock sync.Mutex

	lisCache     map[string]*rawcon.RAWListener
	lisCacheLock sync.Mutex
)

const (
	mulconMethod = "chacha20-ietf"
)

func init() {
	mssCache = make(map[string]int)
	lisCache = make(map[string]*rawcon.RAWListener)
}

func GetMSSByAddr(laddr net.Addr, raddr net.Addr) int {
	s := laddr.String() + raddr.String()
	mssCacheLock.Lock()
	defer mssCacheLock.Unlock()
	mss, ok := mssCache[s]
	if ok {
		return mss
	}
	return 0
}

func putMSSByAddr(laddr net.Addr, raddr net.Addr, mss int) {
	s := laddr.String() + raddr.String()
	mssCacheLock.Lock()
	defer mssCacheLock.Unlock()
	mssCache[s] = mss
}

func GetListenerByAddr(laddr net.Addr) *rawcon.RAWListener {
	lisCacheLock.Lock()
	defer lisCacheLock.Unlock()
	lis, ok := lisCache[laddr.String()]
	if ok {
		return lis
	}
	return nil
}

func putListenerByAddr(laddr net.Addr, lis *rawcon.RAWListener) {
	lisCacheLock.Lock()
	defer lisCacheLock.Unlock()
	lisCache[laddr.String()] = lis
}

func checkAddr(addr string) (err error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	} else if len(host) == 0 {
		err = fmt.Errorf("You must set the addr to ip:port")
	} else if host == "0.0.0.0" {
		err = fmt.Errorf("You can't set host to 0.0.0.0")
	}
	return
}

// DialWithOptions connects to the remote address "raddr" on the network "udp" with packet encryption
func DialWithOptions(raddr string, block kcp.BlockCrypt, dataShards, parityShards int, password string, mulconn int, udp bool) (*kcp.UDPSession, error) {
	var dialer func() (conn net.Conn, err error)
	var conn net.PacketConn
	var err error

	if udp {
		udpaddr, err := net.ResolveUDPAddr("udp4", raddr)
		if err != nil {
			return nil, err
		}
		dialer = func() (conn net.Conn, err error) {
			rawconn, err := net.DialUDP("udp4", nil, udpaddr)
			conn = rawconn
			return
		}
	} else {
		err := checkAddr(raddr)
		if err != nil {
			return nil, errors.Wrap(err, "checkAddr")
		}
		dialer = func() (conn net.Conn, err error) {
			rawconn, err := raw.DialRAW(raddr)
			conn = rawconn
			putMSSByAddr(rawconn.LocalAddr(), rawconn.RemoteAddr(), rawconn.GetMSS())
			return
		}
	}

	if mulconn > 0 {
		conn, err = mulcon.Dial(dialer, mulconn, mulconMethod, password)
	} else {
		var c net.Conn
		c, err = dialer()
		c2, ok := c.(*net.UDPConn)
		if ok {
			conn = c2
		} else {
			conn = c.(*rawcon.RAWConn)
		}
	}
	if err != nil {
		return nil, err
	}
	return kcp.NewConn(raddr, block, dataShards, parityShards, conn)
}

// ListenWithOptions listens for incoming KCP packets addressed to the local address laddr on the network "udp" with packet encryption,
// dataShards, parityShards defines Reed-Solomon Erasure Coding parameters
func ListenWithOptions(laddr string, block kcp.BlockCrypt, dataShards, parityShards int, password string, usemul bool, udp bool) (*kcp.Listener, error) {
	var conn net.PacketConn
	var err error

	if udp {
		udpaddr, err := net.ResolveUDPAddr("udp4", laddr)
		if err != nil {
			return nil, err
		}
		conn, err = net.ListenUDP("udp4", udpaddr)
		if err != nil {
			return nil, errors.Wrap(err, "net.ListenUDP")
		}
	} else {
		err = checkAddr(laddr)
		if err != nil {
			return nil, errors.Wrap(err, "checkAddr")
		}
		lis, err := raw.ListenRAW(laddr)
		if err != nil {
			return nil, errors.Wrap(err, "net.ListenRAW")
		}
		putListenerByAddr(lis.LocalAddr(), lis)
		conn = lis
	}

	if usemul {
		conn, err = mulcon.Listen(conn, mulconMethod, password)
	}

	return kcp.ServeConn(block, dataShards, parityShards, conn)
}

// SetNoHTTP determines whether to do http obfuscating
func SetNoHTTP(v bool) {
	raw.NoHTTP = v
}

// SetHost set http host
func SetHost(v string) {
	raw.Host = v
}

// SetDSCP set tos number
func SetDSCP(v int) {
	raw.DSCP = v
}

// SetIgnRST if v is true, the tcp rst packet will be ignored
func SetIgnRST(v bool) {
	raw.IgnRST = v
}

// SetMixed if v is true, the server will accept both http request and tcp request
func SetMixed(v bool) {
	raw.Mixed = v
}
