package kcpraw

import (
	"runtime"

	"github.com/pkg/errors"
	kcp "github.com/xtaci/kcp-go"
)

// DialWithOptions connects to the remote address "raddr" on the network "udp" with packet encryption
func DialWithOptions(raddr string, block kcp.BlockCrypt, dataShards, parityShards int) (*kcp.UDPSession, error) {
	if runtime.GOOS == "linux" {
		conn, err := dialRAW(raddr)
		if err != nil {
			return nil, errors.Wrap(err, "net.DialRAW")
		}
		return kcp.NewConn(raddr, block, dataShards, parityShards, conn)
	} else {
		conn, err := dialRAW2(raddr)
		if err != nil {
			return nil, errors.Wrap(err, "net.DialRAW")
		}
		return kcp.NewConn(raddr, block, dataShards, parityShards, conn)
	}
}

// ListenWithOptions listens for incoming KCP packets addressed to the local address laddr on the network "udp" with packet encryption,
// dataShards, parityShards defines Reed-Solomon Erasure Coding parameters
func ListenWithOptions(laddr string, block kcp.BlockCrypt, dataShards, parityShards int) (*kcp.Listener, error) {
	if runtime.GOOS == "linux" {
		conn, err := listenRAW(laddr)
		if err != nil {
			return nil, errors.Wrap(err, "net.ListenRAW")
		}
		return kcp.ServeConn(block, dataShards, parityShards, conn)
	} else {
		conn, err := listenRAW2(laddr)
		if err != nil {
			return nil, errors.Wrap(err, "net.ListenRAW")
		}
		return kcp.ServeConn(block, dataShards, parityShards, conn)
	}
}
