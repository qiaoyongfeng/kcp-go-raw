package kcpraw

import (
	"github.com/ccsexyz/rawcon"
	"github.com/pkg/errors"
	kcp "github.com/xtaci/kcp-go"
)

// DialWithOptions connects to the remote address "raddr" on the network "udp" with packet encryption
func DialWithOptions(raddr string, block kcp.BlockCrypt, dataShards, parityShards int) (*kcp.UDPSession, error) {
	conn, err := rawcon.DialRAW(raddr)
	if err != nil {
		return nil, errors.Wrap(err, "net.DialRAW")
	}
	return kcp.NewConn(raddr, block, dataShards, parityShards, conn)
}

// ListenWithOptions listens for incoming KCP packets addressed to the local address laddr on the network "udp" with packet encryption,
// dataShards, parityShards defines Reed-Solomon Erasure Coding parameters
func ListenWithOptions(laddr string, block kcp.BlockCrypt, dataShards, parityShards int) (*kcp.Listener, error) {
	conn, err := rawcon.ListenRAW(laddr)
	if err != nil {
		return nil, errors.Wrap(err, "net.ListenRAW")
	}
	return kcp.ServeConn(block, dataShards, parityShards, conn)
}

// SetNoHTTP determines whether to do http obfuscating
func SetNoHTTP(v bool) {
	rawcon.SetNoHTTP(v)
}

// SetHost set http host
func SetHost(v string) {
	rawcon.SetHost(v)
}

// SetDSCP set tos number
func SetDSCP(v int) {
	rawcon.SetDSCP(v)
}

// SetIgnRST if v is true, the tcp rst packet will be ignored
func SetIgnRST(v bool) {
	rawcon.SetIgnRST(v)
}
