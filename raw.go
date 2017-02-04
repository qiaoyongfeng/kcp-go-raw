package kcpraw

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	ran "math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type callback func()

type myMutex struct {
	sync.Mutex
}

func (m *myMutex) run(f callback) {
	m.Lock()
	defer m.Unlock()
	f()
}

type RAWConn struct {
	conn  *net.IPConn
	udp   net.Conn
	laddr *net.IPAddr
	raddr *net.IPAddr
	lport int
	rport int
	seqn  uint32
	ackn  uint32
	ip4   *layers.IPv4
	tcp   *layers.TCP
	buf   []byte
}

func NewRAWConn(udp net.Conn) (raw *RAWConn) {
	ulocaladdr := udp.LocalAddr().(*net.UDPAddr)
	localaddr := &net.IPAddr{IP: ulocaladdr.IP}
	uremoteaddr := udp.RemoteAddr().(*net.UDPAddr)
	remoteaddr := &net.IPAddr{IP: uremoteaddr.IP}
	conn, err := net.DialIP("ip4:tcp", localaddr, remoteaddr)
	fatalErr(err)
	raw = &RAWConn{
		conn:  conn,
		udp:   udp,
		laddr: localaddr,
		raddr: remoteaddr,
		lport: ulocaladdr.Port,
		rport: uremoteaddr.Port,
		ackn:  0,
		ip4: &layers.IPv4{
			SrcIP:    localaddr.IP,
			DstIP:    remoteaddr.IP,
			Protocol: layers.IPProtocolTCP,
		},
		tcp: &layers.TCP{
			SrcPort: layers.TCPPort(ulocaladdr.Port),
			DstPort: layers.TCPPort(uremoteaddr.Port),
			Window:  12580,
		},
		buf: make([]byte, 4096),
	}
	binary.Read(rand.Reader, binary.LittleEndian, &(raw.seqn))
	return
}

func NewRAWConnL(conn *net.IPConn, lport int) (raw *RAWConn) {
	laddr := conn.LocalAddr().(*net.IPAddr)
	raw = &RAWConn{
		conn:  conn,
		udp:   nil,
		laddr: laddr,
		lport: lport,
		raddr: nil,
		rport: 0,
		ackn:  0,
		ip4: &layers.IPv4{
			SrcIP:    laddr.IP,
			Protocol: layers.IPProtocolTCP,
		},
		tcp: &layers.TCP{
			SrcPort: layers.TCPPort(lport),
			Window:  12580,
		},
		buf: make([]byte, 4096),
	}
	binary.Read(rand.Reader, binary.LittleEndian, &(raw.seqn))
	return
}

func (raw *RAWConn) Close() (err error) {
	if raw.udp != nil {
		err = raw.udp.Close()
	}
	if raw.conn != nil {
		err1 := raw.conn.Close()
		if err1 != nil {
			err = err1
		}
	}
	return
}

func (raw *RAWConn) updateTCP() {
	tcp := raw.tcp
	tcp.Padding = nil
	tcp.Ack = raw.ackn
	tcp.Seq = raw.seqn
	tcp.FIN = false
	tcp.PSH = false
	tcp.ACK = false
	tcp.RST = false
	tcp.SYN = false
}

func (raw *RAWConn) sendPacket() (err error) {
	tcp := raw.tcp
	tcp.SetNetworkLayerForChecksum(raw.ip4)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if tcp.Payload != nil && len(tcp.Payload) > 0 {
		err = gopacket.SerializeLayers(buf, opts, tcp, gopacket.Payload(tcp.Payload))
	} else {
		err = gopacket.SerializeLayers(buf, opts, tcp)
	}
	if err != nil {
		return
	}
	if raw.udp == nil {
		_, err = raw.conn.WriteToIP(buf.Bytes(), &net.IPAddr{IP: raw.ip4.DstIP})
	} else {
		_, err = raw.conn.Write(buf.Bytes())
	}
	return
}

func (raw *RAWConn) sendSyn() (err error) {
	raw.updateTCP()
	raw.tcp.SYN = true
	options := raw.tcp.Options
	raw.tcp.Options = append(raw.tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x5, 0xb4},
	})
	err = raw.sendPacket()
	raw.tcp.Options = options
	return
}

func (conn *RAWConn) sendSynAck() (err error) {
	conn.updateTCP()
	conn.tcp.SYN = true
	conn.tcp.ACK = true
	options := conn.tcp.Options
	conn.tcp.Options = append(conn.tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x5, 0xb4},
	})
	err = conn.sendPacket()
	conn.tcp.Options = options
	return
}

func (conn *RAWConn) sendAck() (err error) {
	conn.updateTCP()
	conn.tcp.ACK = true
	return conn.sendPacket()
}

func (conn *RAWConn) sendFin() (err error) {
	conn.updateTCP()
	conn.tcp.FIN = true
	return conn.sendPacket()
}

func (conn *RAWConn) sendRst() (err error) {
	conn.updateTCP()
	conn.tcp.RST = true
	return conn.sendPacket()
}

func (raw *RAWConn) Write(b []byte) (n int, err error) {
	n = len(b)
	raw.updateTCP()
	tcp := raw.tcp
	tcp.PSH = true
	tcp.ACK = true
	tcp.Ack = raw.ackn
	tcp.Seq = raw.seqn
	tcp.Payload = b
	err = raw.sendPacket()
	tcp.Payload = nil
	raw.seqn += uint32(n)
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
		if raw.raddr != nil && !compareIPv4(ipaddr.IP, raw.raddr.IP) {
			continue
		}
		packet := gopacket.NewPacket(raw.buf[:n], layers.LayerTypeTCP, gopacket.Default)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			fmt.Println("bad tcp layer")
			continue
		}
		tcp, _ = tcpLayer.(*layers.TCP)
		if int(tcp.DstPort) != raw.lport {
			continue
		}
		if raw.rport != 0 && int(tcp.SrcPort) != raw.rport {
			tcp = nil
			continue
		}
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

func compareIPv4(ip1, ip2 net.IP) bool {
	bytes1 := []byte(ip1)
	bytes2 := []byte(ip2)
	return bytes1[0] == bytes2[0] && bytes1[1] == bytes2[1] && bytes1[2] == bytes2[2] && bytes1[3] == bytes2[3]
}

func (raw *RAWConn) LocalAddr() net.Addr {
	return raw.conn.LocalAddr()
}

func (raw *RAWConn) RemoteAddr() net.Addr {
	return raw.conn.RemoteAddr()
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
		raw.ackn += uint32(n)
		copy(b, tcp.Payload)
		return n, addr, err
	}
}

func (raw *RAWConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return raw.Write(b)
}

func dialRAW(address string) (raw *RAWConn, err error) {
	udp, err := net.Dial("udp4", address)
	// log.Println(address)
	if err != nil {
		return
	}
	raw = NewRAWConn(udp)
	defer func() {
		if err != nil {
			raw.Close()
		} else {
			raw.SetReadDeadline(time.Time{})
		}
	}()
	retry := 0
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
			raw.ackn = tcp.Seq + 1
			raw.seqn++
			ackn = raw.ackn
			seqn = raw.seqn
			err = raw.sendAck()
			if err != nil {
				return
			}
			break
		}
	}
	retry = 0
	opt := getTCPOptions()
	req := buildHTTPRequest("Host: ltetp.tv189.com\r\nX-Online-Host: ltetp.tv189.com\r\n")
	for {
		if retry > 5 {
			err = errors.New("retry too many times")
			return
		}
		retry++
		raw.tcp.Options = opt
		_, err = raw.Write([]byte(req))
		if err != nil {
			return
		}
		raw.tcp.Options = nil
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
			raw.ackn = ackn
			raw.seqn = seqn
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
				raw.ackn = tcp.Seq + uint32(n)
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
	seqn  uint32
	ackn  uint32
	rep   []byte
}

type RAWListener struct {
	raw     *RAWConn
	newcons map[string]*connInfo
	nmutex  myMutex
	conns   map[string]*connInfo
	cmutex  myMutex
}

func (listener *RAWListener) Close() (err error) {
	return listener.raw.Close()
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
	listener = &RAWListener{
		raw:     NewRAWConnL(conn, udpaddr.Port),
		newcons: make(map[string]*connInfo),
		conns:   make(map[string]*connInfo),
	}
	return
}

func (listener *RAWListener) doRead(b []byte) (n int, addr *net.UDPAddr, err error) {
	raw := listener.raw
	for {
		var tcp *layers.TCP
		var addrstr string
		tcp, addr, err = raw.ReadTCPLayer()
		if addr != nil {
			addrstr = addr.String()
		}
		if tcp != nil && (tcp.RST || tcp.FIN) {
			listener.nmutex.run(func() {
				delete(listener.newcons, addrstr)
			})
			listener.cmutex.run(func() {
				delete(listener.conns, addrstr)
			})
			continue
		}
		if err != nil {
			return
		}
		if addr.Port == listener.raw.lport {
			continue
		}
		var info *connInfo
		var ok bool
		listener.cmutex.run(func() {
			info, ok = listener.conns[addrstr]
		})
		n = len(tcp.Payload)
		if ok && n != 0 {
			info.ackn += uint32(n)
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
							info.ackn = tcp.Seq + 1
							listener.raw.tcp.Ack = info.ackn
							listener.raw.tcp.Seq = info.seqn
							listener.raw.tcp.Options = getTCPOptions()
							_, err = listener.raw.Write(info.rep)
							listener.raw.tcp.Options = nil
							if err != nil {
								return
							}
							info.seqn = listener.raw.seqn
						}
					}
					continue
				}
			}
			if info.state == ESTABLISHED {
				copy(b, tcp.Payload)
				return
			}
			continue
		}
		listener.nmutex.run(func() {
			info, ok = listener.newcons[addrstr]
		})
		listener.raw.ip4.DstIP = addr.IP
		listener.raw.tcp.DstPort = layers.TCPPort(addr.Port)
		if ok {
			if info.state == SYNRECEIVED {
				if tcp.ACK && !tcp.PSH && !tcp.FIN && !tcp.SYN {
					info.state = WAITHTTPREQ
					info.ackn = tcp.Seq + 1
					info.seqn++
				} else if tcp.SYN && !tcp.ACK && !tcp.PSH {
					listener.raw.ackn = info.ackn
					listener.raw.seqn = info.seqn
					listener.raw.sendSynAck()
				}
			} else if info.state == WAITHTTPREQ {
				if tcp.PSH && tcp.ACK && checkTCPOtions(tcp.Options) && n > 20 {
					head := string(tcp.Payload[:4])
					tail := string(tcp.Payload[n-4:])
					if head == "POST" && tail == "\r\n\r\n" {
						info.ackn = tcp.Seq + uint32(n)
						listener.raw.ackn = info.ackn
						listener.raw.seqn = info.seqn
						if info.rep == nil {
							rep := buildHTTPResponse("")
							info.rep = []byte(rep)
						}
						// err = listener.raw.sendAck()
						// if err != nil {
						//     return
						// }
						listener.raw.tcp.Options = getTCPOptions()
						_, err = listener.raw.Write(info.rep)
						listener.raw.tcp.Options = nil
						if err != nil {
							return
						}
						info.state = HTTPREPSENT
						info.seqn = listener.raw.seqn
						listener.cmutex.run(func() {
							listener.conns[addrstr] = info
						})
						listener.nmutex.run(func() {
							delete(listener.newcons, addrstr)
						})
					}
				} else if tcp.SYN && !tcp.ACK && !tcp.PSH {
					listener.raw.ackn = info.ackn
					listener.raw.seqn = info.seqn
					listener.raw.sendSynAck()
				}
			}
			continue
		}
		if tcp.SYN && !tcp.ACK && !tcp.PSH && !tcp.FIN {
			info = &connInfo{
				ackn:  tcp.Seq + 1,
				state: SYNRECEIVED,
			}
			binary.Read(rand.Reader, binary.LittleEndian, &(info.seqn))
			listener.raw.ackn = info.ackn
			listener.raw.seqn = info.seqn
			listener.raw.sendSynAck()
			listener.nmutex.run(func() {
				listener.newcons[addrstr] = info
			})
		} else {
			listener.raw.sendFin()
		}
	}
}

func (listener *RAWListener) SetDeadline(t time.Time) error {
	return listener.raw.SetDeadline(t)
}

func (listener *RAWListener) SetReadDeadline(t time.Time) error {
	return listener.raw.SetDeadline(t)
}

func (listener *RAWListener) SetWriteDeadline(t time.Time) error {
	return listener.raw.SetDeadline(t)
}

func (listener *RAWListener) LocalAddr() net.Addr {
	return listener.raw.LocalAddr()
}

func (listener *RAWListener) RemoteAddr() net.Addr {
	return nil
}

func (listener *RAWListener) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = listener.doRead(b)
	return
}

func (listener *RAWListener) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	udpaddr := addr.(*net.UDPAddr)
	var info *connInfo
	var ok bool
	listener.cmutex.run(func() {
		info, ok = listener.conns[udpaddr.String()]
	})
	if !ok {
		return 0, errors.New("cannot write to " + udpaddr.String())
	}
	listener.raw.ip4.DstIP = udpaddr.IP
	listener.raw.tcp.DstPort = layers.TCPPort(udpaddr.Port)
	listener.raw.ackn = info.ackn
	listener.raw.seqn = info.seqn
	n, err = listener.raw.Write(b)
	info.seqn = listener.raw.seqn
	return
}

// copy from stackoverflow

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var src = ran.NewSource(time.Now().UnixNano())

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func randStringBytesMaskImprSrc(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

var requestFormat string
var responseFromat string

func init() {
	var requestBuffer bytes.Buffer
	strs := []string{
		"POST /%s HTTP/1.1\r\n",
		"Accept: */*\r\n",
		"Accept-Encoding: */*\r\n",
		"Accept-Language: zh-CN\r\n",
		"Connection: keep-alive\r\n",
		"%s",
		"Content-Length:%d\r\n\r\n",
	}
	for _, str := range strs {
		requestBuffer.WriteString(str)
	}
	requestFormat = requestBuffer.String()
	var responseBuffer bytes.Buffer
	strs = []string{
		"HTTP/1.1 200 OK\r\n",
		"Cache-Control: private, no-store, max-age=0, no-cache\r\n",
		"Content-Type: text/html; charset=utf-8\r\n",
		"Content-Encoding: gzip\r\n",
		"Server: openresty/1.11.2\r\n",
		"Connection: keep-alive\r\n",
		"%s",
		"Content-Length: %d\r\n\r\n",
	}
	for _, str := range strs {
		responseBuffer.WriteString(str)
	}
	responseFromat = responseBuffer.String()
}

func buildHTTPRequest(headers string) string {
	return fmt.Sprintf(requestFormat, randStringBytesMaskImprSrc(10), headers, (src.Int63()%65536 + 10485760))
	// return fmt.Sprintf(requestFormat, randStringBytesMaskImprSrc(10), headers, 0)
}

func buildHTTPResponse(headers string) string {
	return fmt.Sprintf(responseFromat, headers, (src.Int63()%65536 + 104857600))
	// return fmt.Sprintf(responseFromat, headers, 0)
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

func fatalErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
