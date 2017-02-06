package kcpraw

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

type RAWConn struct {
	conn  *net.IPConn
	wconn *net.IPConn
	rconn *ipv4.RawConn
	udp   net.Conn
	layer *pktLayers
	buf   []byte
}

func (raw *RAWConn) Close() (err error) {
	if raw.udp != nil && raw.wconn != nil {
		raw.sendFin()
	}
	if raw.udp != nil {
		err = raw.udp.Close()
	}
	if raw.conn != nil {
		err1 := raw.conn.Close()
		if err1 != nil {
			err = err1
		}
	}
	if raw.wconn != nil {
		err2 := raw.wconn.Close()
		if err2 != nil {
			err = err2
		}
	}
	return
}

func (raw *RAWConn) updateTCP() {
	tcp := raw.layer.tcp
	tcp.Padding = nil
	tcp.FIN = false
	tcp.PSH = false
	tcp.ACK = false
	tcp.RST = false
	tcp.SYN = false
}

func (raw *RAWConn) sendPacket() (err error) {
	layer := raw.layer
	tcp := layer.tcp
	ip4 := layer.ip4
	tcp.SetNetworkLayerForChecksum(ip4)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buf, opts, tcp, gopacket.Payload(tcp.Payload))
	if err != nil {
		return
	}
	_, err = raw.wconn.WriteTo(buf.Bytes(), &net.IPAddr{IP: ip4.DstIP})
	return
}

func (raw *RAWConn) sendSyn() (err error) {
	raw.updateTCP()
	tcp := raw.layer.tcp
	tcp.SYN = true
	options := tcp.Options
	tcp.Options = append(tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x5, 0xb4},
	})
	err = raw.sendPacket()
	tcp.Options = options
	return
}

func (conn *RAWConn) sendSynAck() (err error) {
	conn.updateTCP()
	tcp := conn.layer.tcp
	tcp.SYN = true
	tcp.ACK = true
	options := tcp.Options
	tcp.Options = append(tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x5, 0xb4},
	})
	err = conn.sendPacket()
	tcp.Options = options
	return
}

func (conn *RAWConn) sendAck() (err error) {
	conn.updateTCP()
	conn.layer.tcp.ACK = true
	return conn.sendPacket()
}

func (conn *RAWConn) sendFin() (err error) {
	conn.updateTCP()
	conn.layer.tcp.FIN = true
	return conn.sendPacket()
}

func (conn *RAWConn) sendRst() (err error) {
	conn.updateTCP()
	conn.layer.tcp.RST = true
	return conn.sendPacket()
}

func (raw *RAWConn) Write(b []byte) (n int, err error) {
	n = len(b)
	raw.updateTCP()
	tcp := raw.layer.tcp
	tcp.PSH = true
	tcp.ACK = true
	tcp.Payload = b
	err = raw.sendPacket()
	tcp.Payload = nil
	tcp.Seq += uint32(n)
	return
}

func (raw *RAWConn) ReadTCPLayer() (tcp *layers.TCP, addr *net.UDPAddr, err error) {
	for {
		var n int
		var ipaddr *net.IPAddr
		n, ipaddr, err = raw.conn.ReadFromIP(raw.buf)
		if err != nil {
			e, ok := err.(net.Error)
			if ok && e.Temporary() {
				raw.SetReadDeadline(time.Time{})
			}
			return
		}
		packet := gopacket.NewPacket(raw.buf[:n], layers.LayerTypeTCP, gopacket.Default)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			fmt.Println("bad tcp layer")
			continue
		}
		tcp, _ = tcpLayer.(*layers.TCP)
		addr = &net.UDPAddr{
			IP:   ipaddr.IP,
			Port: int(tcp.SrcPort),
		}
		if tcp.RST {
			err = errors.New("connection reset by peer")
		}
		return
	}
}

func (raw *RAWConn) Read(b []byte) (n int, err error) {
	n, _, err = raw.ReadFrom(b)
	return
}

func (conn *RAWConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   conn.layer.ip4.SrcIP,
		Port: int(conn.layer.tcp.SrcPort),
	}
}

func (conn *RAWConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP:   conn.layer.ip4.DstIP,
		Port: int(conn.layer.tcp.DstPort),
	}
}

func (raw *RAWConn) SetDeadline(t time.Time) error {
	return raw.conn.SetDeadline(t)
}

func (raw *RAWConn) SetReadDeadline(t time.Time) error {
	return raw.conn.SetReadDeadline(t)
}

func (raw *RAWConn) SetWriteDeadline(t time.Time) error {
	return raw.conn.SetWriteDeadline(t)
}

func (raw *RAWConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for {
		var tcp *layers.TCP
		tcp, addr, err = raw.ReadTCPLayer()
		if err != nil {
			return
		}
		if tcp == nil || addr == nil {
			continue
		}
		if tcp.FIN {
			err = errors.New("receive fin")
			return
		}
		if tcp.SYN && tcp.ACK {
			err = raw.sendAck()
			if err != nil {
				return
			} else {
				continue
			}
		}
		if tcp.Payload == nil || len(tcp.Payload) == 0 {
			continue
		}
		n = len(tcp.Payload)
		raw.layer.tcp.Ack += uint32(n)
		copy(b, tcp.Payload)
		return n, addr, err
	}
}

func (raw *RAWConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return raw.Write(b)
}

func dialRAW(address string) (raw *RAWConn, err error) {
	udp, err := net.Dial("udp4", address)
	if err != nil {
		return
	}
	ulocaladdr := udp.LocalAddr().(*net.UDPAddr)
	uremoteaddr := udp.RemoteAddr().(*net.UDPAddr)
	conn, err := net.DialIP("ip4:tcp", &net.IPAddr{IP: ulocaladdr.IP}, &net.IPAddr{IP: uremoteaddr.IP})
	fatalErr(err)
	wconn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: ulocaladdr.IP})
	fatalErr(err)
	if DSCP != 0 {
		ipv4.NewConn(wconn).SetTOS(DSCP)
	}
	rconn, err := ipv4.NewRawConn(conn)
	fatalErr(err)
	// https://www.kernel.org/doc/Documentation/networking/filter.txt
	rconn.SetBPF([]bpf.RawInstruction{
		{0x30, 0, 0, 0x00000009},
		{0x15, 0, 6, 0x00000006},
		{0x28, 0, 0, 0x00000006},
		{0x45, 4, 0, 0x00001fff},
		{0xb1, 0, 0, 0x00000000},
		{0x48, 0, 0, 0x00000002},
		{0x15, 0, 1, uint32(ulocaladdr.Port)},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	})
	raw = &RAWConn{
		conn:  conn,
		wconn: wconn,
		rconn: rconn,
		udp:   udp,
		buf:   make([]byte, 65536),
		layer: &pktLayers{
			eth: nil,
			ip4: &layers.IPv4{
				SrcIP:    ulocaladdr.IP,
				DstIP:    uremoteaddr.IP,
				Protocol: layers.IPProtocolTCP,
			},
			tcp: &layers.TCP{
				SrcPort: layers.TCPPort(ulocaladdr.Port),
				DstPort: layers.TCPPort(uremoteaddr.Port),
				Window:  12580,
				Ack:     0,
			},
		},
	}
	binary.Read(rand.Reader, binary.LittleEndian, &(raw.layer.tcp.Seq))
	defer func() {
		if err != nil {
			raw.Close()
		} else {
			raw.SetReadDeadline(time.Time{})
		}
	}()
	retry := 0
	layer := raw.layer
	var ackn uint32
	var seqn uint32
	for {
		if retry > 5 {
			err = errors.New("retry too many times")
			return
		}
		retry++
		err = raw.sendSyn()
		if err != nil {
			return
		}
		err = raw.SetReadDeadline(time.Now().Add(time.Second * 1))
		if err != nil {
			return
		}
		var tcp *layers.TCP
		tcp, _, err = raw.ReadTCPLayer()
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				return
			} else {
				continue
			}
		}
		if tcp.SYN && tcp.ACK {
			layer.tcp.Ack = tcp.Seq + 1
			layer.tcp.Seq++
			ackn = layer.tcp.Ack
			seqn = layer.tcp.Seq
			err = raw.sendAck()
			if err != nil {
				return
			}
			break
		}
	}
	if NoHTTP {
		return
	}
	retry = 0
	opt := getTCPOptions()
	var headers string
	if len(HTTPHost) != 0 {
		headers += "Host: " + HTTPHost + "\r\n"
		headers += "X-Online-Host: " + HTTPHost + "\r\n"
	}
	req := buildHTTPRequest(headers)
	for {
		if retry > 5 {
			err = errors.New("retry too many times")
			return
		}
		retry++
		layer.tcp.Options = opt
		_, err = raw.Write([]byte(req))
		if err != nil {
			return
		}
		layer.tcp.Options = nil
		err = raw.SetReadDeadline(time.Now().Add(time.Second * 1))
		if err != nil {
			return
		}
		var tcp *layers.TCP
		tcp, _, err = raw.ReadTCPLayer()
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				return
			} else {
				continue
			}
		}
		if tcp.SYN && tcp.ACK {
			// raw.ackn = tcp.Seq + 1
			layer.tcp.Ack = ackn
			layer.tcp.Seq = seqn
			err = raw.sendAck()
			if err != nil {
				return
			}
			continue
		}
		n := len(tcp.Payload)
		if tcp.PSH && tcp.ACK && n >= 20 && checkTCPOtions(tcp.Options) {
			head := string(tcp.Payload[:4])
			tail := string(tcp.Payload[n-4:])
			if head == "HTTP" && tail == "\r\n\r\n" {
				layer.tcp.Ack = tcp.Seq + uint32(n)
				break
			}
		}
	}
	return
}

const (
	SYNRECEIVED = 0
	WAITHTTPREQ = 1
	HTTPREPSENT = 2
	ESTABLISHED = 3
)

type connInfo struct {
	state uint32
	layer *pktLayers
	rep   []byte
}

type RAWListener struct {
	RAWConn
	newcons map[string]*connInfo
	conns   map[string]*connInfo
	mutex   myMutex
	laddr   *net.UDPAddr
}

func listenRAW(address string) (listener *RAWListener, err error) {
	udpaddr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return
	}
	conn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: udpaddr.IP})
	if err != nil {
		return
	}
	wconn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: udpaddr.IP})
	if err != nil {
		return
	}
	if DSCP != 0 {
		ipv4.NewConn(wconn).SetTOS(DSCP)
	}
	rconn, err := ipv4.NewRawConn(conn)
	fatalErr(err)
	// filter: tcp and src port udpaddr.Port
	rconn.SetBPF([]bpf.RawInstruction{
		{0x30, 0, 0, 0x00000009},
		{0x15, 0, 6, 0x00000006},
		{0x28, 0, 0, 0x00000006},
		{0x45, 4, 0, 0x00001fff},
		{0xb1, 0, 0, 0x00000000},
		{0x48, 0, 0, 0x00000002},
		{0x15, 0, 1, uint32(udpaddr.Port)},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	})
	listener = &RAWListener{
		RAWConn: RAWConn{
			conn:  conn,
			wconn: wconn,
			rconn: rconn,
			udp:   nil,
			buf:   make([]byte, 65536),
			layer: nil,
		},
		newcons: make(map[string]*connInfo),
		conns:   make(map[string]*connInfo),
		laddr:   udpaddr,
	}
	return
}

func (listener *RAWListener) doRead(b []byte) (n int, addr *net.UDPAddr, err error) {
	for {
		var tcp *layers.TCP
		var addrstr string
		tcp, addr, err = listener.ReadTCPLayer()
		if addr != nil {
			addrstr = addr.String()
		}
		if tcp != nil && (tcp.RST || tcp.FIN) {
			listener.mutex.run(func() {
				delete(listener.newcons, addrstr)
				delete(listener.conns, addrstr)
			})
			continue
		}
		if err != nil {
			return
		}
		var info *connInfo
		var ok bool
		listener.mutex.run(func() {
			info, ok = listener.conns[addrstr]
		})
		n = len(tcp.Payload)
		if ok && n != 0 {
			t := info.layer.tcp
			t.Ack += uint32(n)
			//fmt.Println("read from ", addrstr, " to ", tcp.DstPort, " with ", n, " bytes")
			if info.state == HTTPREPSENT {
				if tcp.PSH && tcp.ACK {
					info.rep = nil
					info.state = ESTABLISHED
				} else {
					if tcp.PSH && tcp.ACK && checkTCPOtions(tcp.Options) && n > 20 {
						head := string(tcp.Payload[:4])
						tail := string(tcp.Payload[n-4:])
						if head == "POST" && tail == "\r\n\r\n" {
							t.Ack = tcp.Seq + uint32(n)
							listener.layer = info.layer
							t.Options = getTCPOptions()
							_, err = listener.Write(info.rep)
							t.Options = nil
							if err != nil {
								return
							}
						}
					}
					listener.layer = info.layer
					listener.sendFin()
					continue
				}
			}
			if info.state == ESTABLISHED {
				copy(b, tcp.Payload)
				return
			}
			continue
		}
		listener.mutex.run(func() {
			info, ok = listener.newcons[addrstr]
		})
		if ok {
			t := info.layer.tcp
			if info.state == SYNRECEIVED {
				if tcp.ACK && !tcp.PSH && !tcp.FIN && !tcp.SYN {
					t.Seq++
					if NoHTTP {
						info.state = ESTABLISHED
						listener.mutex.run(func() {
							listener.conns[addrstr] = info
							delete(listener.newcons, addrstr)
						})
					} else {
						info.state = WAITHTTPREQ
					}
				} else if tcp.SYN && !tcp.ACK && !tcp.PSH {
					listener.layer = info.layer
					err = listener.sendSynAck()
					if err != nil {
						return
					}
				}
			} else if info.state == WAITHTTPREQ {
				if tcp.PSH && tcp.ACK && checkTCPOtions(tcp.Options) && n > 20 {
					head := string(tcp.Payload[:4])
					tail := string(tcp.Payload[n-4:])
					if head == "POST" && tail == "\r\n\r\n" {
						t.Ack = tcp.Seq + uint32(n)
						listener.layer = info.layer
						if info.rep == nil {
							rep := buildHTTPResponse("")
							info.rep = []byte(rep)
						}
						t.Options = getTCPOptions()
						_, err = listener.Write(info.rep)
						t.Options = nil
						if err != nil {
							return
						}
						info.state = HTTPREPSENT
						listener.mutex.run(func() {
							listener.conns[addrstr] = info
							delete(listener.newcons, addrstr)
						})
					}
				} else if tcp.SYN && !tcp.ACK && !tcp.PSH {
					listener.layer = info.layer
					err = listener.sendSynAck()
					if err != nil {
						return
					}
				}
			}
			continue
		}
		layer := &pktLayers{
			eth: nil,
			ip4: &layers.IPv4{
				SrcIP:    listener.laddr.IP,
				DstIP:    addr.IP,
				Protocol: layers.IPProtocolTCP,
			},
			tcp: &layers.TCP{
				SrcPort: layers.TCPPort(listener.laddr.Port),
				DstPort: layers.TCPPort(addr.Port),
				Window:  12580,
				Ack:     tcp.Seq + 1,
			},
		}
		if tcp.SYN && !tcp.ACK && !tcp.PSH && !tcp.FIN {
			info = &connInfo{
				state: SYNRECEIVED,
				layer: layer,
			}
			binary.Read(rand.Reader, binary.LittleEndian, &(info.layer.tcp.Seq))
			listener.layer = info.layer
			err = listener.sendSynAck()
			if err != nil {
				return
			}
			listener.mutex.run(func() {
				listener.newcons[addrstr] = info
			})
		} else {
			listener.layer = layer
			listener.sendFin()
		}
	}
}

func (listener *RAWListener) LocalAddr() net.Addr {
	return listener.laddr
}

func (listener *RAWListener) RemoteAddr() net.Addr {
	return nil
}

func (listener *RAWListener) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = listener.doRead(b)
	return
}

func (listener *RAWListener) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	listener.mutex.Lock()
	info, ok := listener.conns[addr.String()]
	listener.mutex.Unlock()
	if !ok {
		return 0, errors.New("cannot write to " + addr.String())
	}
	listener.layer = info.layer
	n, err = listener.Write(b)
	return
}

func getTCPOptions() []layers.TCPOption {
	return []layers.TCPOption{
		layers.TCPOption{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
		},
	}
}

func checkTCPOtions(options []layers.TCPOption) (ok bool) {
	for _, v := range options {
		if v.OptionType == layers.TCPOptionKindSACKPermitted {
			ok = true
			break
		}
	}
	return
}
