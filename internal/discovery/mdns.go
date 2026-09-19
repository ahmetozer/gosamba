// Package discovery provides mDNS/Bonjour service advertisement so Apple
// clients (macOS Finder, iOS) can auto-discover the gosamba SMB server.
package discovery

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

const (
	mdnsAddr           = "224.0.0.251"
	mdnsPort           = 5353
	mdnsAddrPort       = "224.0.0.251:5353"
	smbService         = "_smb._tcp.local."
	adiskService       = "_adisk._tcp.local."
	deviceService      = "_device-info._tcp.local."
	enumerationService = "_services._dns-sd._udp.local."
	mdnsTTL            = 120 // seconds
)

// Options describes additional Bonjour services. An empty Model omits device-info.
type Options struct {
	TimeMachineShares []string
	Model             string
}

type service struct {
	name string
	port uint16
	txt  []string
}

func services(port int, options []Options) []service {
	out := []service{{smbService, uint16(port), []string{""}}}
	if len(options) == 0 {
		return out
	}
	opts := options[0]
	if len(opts.TimeMachineShares) > 0 {
		txt := []string{"sys=waMa=0,adVF=0x100"}
		for i, share := range opts.TimeMachineShares {
			txt = append(txt, fmt.Sprintf("dk%d=adVN=%s,adVF=0x82", i, share))
		}
		out = append(out, service{adiskService, 9, txt})
	}
	if opts.Model != "" {
		out = append(out, service{deviceService, 0, []string{"model=" + opts.Model}})
	}
	return out
}

// advertiser holds the state for the mDNS responder.
type advertiser struct {
	conns  []*net.UDPConn
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Close shuts down the advertiser and all listening sockets.
func (a *advertiser) Close() error {
	a.cancel()
	for _, c := range a.conns {
		c.Close()
	}
	a.wg.Wait()
	return nil
}

// Advertise starts an mDNS responder that announces the SMB service on all
// available multicast-capable IPv4 interfaces. It returns an io.Closer that
// stops the responder. The context cancellation also stops it.
//
// instance is the Bonjour service instance name (e.g. "MyServer").
// hostname is the hostname without the ".local." suffix.
// port is the TCP port the SMB server listens on.
func Advertise(ctx context.Context, instance, hostname string, port int, log *slog.Logger, options ...Options) (io.Closer, error) {
	// Validate DNS names and TXT lengths before opening sockets; builder errors
	// must never result in a partial announcement.
	q := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: mustNewName(smbService), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}}}
	if _, ok := buildResponse(q, instance, hostname, nil, port, options...); !ok {
		return nil, fmt.Errorf("invalid mDNS service name, port or TXT data")
	}
	if len(options) > 0 {
		options[0].TimeMachineShares = append([]string(nil), options[0].TimeMachineShares...)
	}
	if log == nil {
		log = slog.Default()
	}

	ips, err := localIPv4s()
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	}

	group := &net.UDPAddr{IP: net.ParseIP(mdnsAddr), Port: mdnsPort}
	ifaces, err := multicastIfaces()
	if err != nil {
		return nil, err
	}
	if len(ifaces) == 0 {
		return nil, &net.OpError{Op: "join multicast", Net: "udp4", Err: errNoMulticast}
	}

	rctx, cancel := context.WithCancel(ctx)

	a := &advertiser{cancel: cancel}

	for _, iface := range ifaces {
		iface := iface
		conn, err := net.ListenMulticastUDP("udp4", &iface, group)
		if err != nil {
			log.Debug("mDNS: cannot join multicast on interface", "iface", iface.Name, "err", err)
			continue
		}
		packet := ipv4.NewPacketConn(conn)
		if err := packet.SetMulticastInterface(&iface); err != nil {
			conn.Close()
			log.Debug("mDNS: cannot select multicast interface", "iface", iface.Name, "err", err)
			continue
		}
		if err := packet.SetMulticastTTL(255); err != nil {
			conn.Close()
			log.Debug("mDNS: cannot set multicast TTL", "iface", iface.Name, "err", err)
			continue
		}
		a.conns = append(a.conns, conn)

		a.wg.Add(1)
		go func(conn *net.UDPConn, iface net.Interface) {
			defer a.wg.Done()
			serveLoop(rctx, conn, instance, hostname, ips, port, log, options...)
		}(conn, iface)
	}

	if len(a.conns) == 0 {
		cancel()
		return nil, &net.OpError{Op: "join multicast", Net: "udp4", Err: errNoMulticast}
	}

	log.Info("mDNS: advertising SMB service",
		"instance", instance,
		"hostname", hostname+".local.",
		"port", port,
		"interfaces", len(a.conns),
	)

	// Send an initial unsolicited announcement (gratuitous mDNS).
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		t := time.NewTimer(100 * time.Millisecond)
		defer t.Stop()
		select {
		case <-rctx.Done():
			return
		case <-t.C:
		}
		announce(a.conns, instance, hostname, ips, port, log, options...)
	}()

	return a, nil
}

// serveLoop answers queries for the advertised Bonjour services.
func serveLoop(ctx context.Context, conn *net.UDPConn, instance, hostname string, ips []net.IP, port int, log *slog.Logger, options ...Options) {
	buf := make([]byte, 4096)
	multicast := &net.UDPAddr{IP: net.ParseIP(mdnsAddr), Port: mdnsPort}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return
		}

		var msg dnsmessage.Message
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if msg.Header.Response {
			// Ignore responses from others.
			continue
		}

		resp, matched := buildResponse(msg, instance, hostname, ips, port, options...)
		if !matched || len(resp) == 0 {
			continue
		}

		// Honor legacy unicast queries and the mDNS QU bit.
		target := multicast
		if peer.Port != mdnsPort {
			target = peer
		}
		for _, q := range msg.Questions {
			if q.Class&0x8000 != 0 {
				target = peer
			}
		}
		if _, err := conn.WriteToUDP(resp, target); err != nil {
			log.Debug("mDNS: write response error", "err", err)
		}
	}
}

// announce sends an unsolicited PTR+SRV+TXT+A announcement to all open connections.
func announce(conns []*net.UDPConn, instance, hostname string, ips []net.IP, port int, log *slog.Logger, options ...Options) {
	query := dnsmessage.Message{
		Header: dnsmessage.Header{Response: false},
		Questions: []dnsmessage.Question{
			{
				Name:  mustNewName(smbService),
				Type:  dnsmessage.TypePTR,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	resp, _ := buildResponse(query, instance, hostname, ips, port, options...)
	if len(resp) == 0 {
		return
	}

	multicast := &net.UDPAddr{IP: net.ParseIP(mdnsAddr), Port: mdnsPort}
	for _, conn := range conns {
		if _, err := conn.WriteToUDP(resp, multicast); err != nil {
			log.Debug("mDNS: announce error", "err", err)
		}
	}
}

// buildResponse constructs an mDNS response for the advertised services.
// It is a pure function — no network I/O — so it can be unit-tested directly.
// Returns (responseBytes, matched). matched is false if no question matched.
func buildResponse(query dnsmessage.Message, instance, hostname string, ips []net.IP, port int, options ...Options) ([]byte, bool) {
	if port < 1 || port > 65535 {
		return nil, false
	}
	hostName, err := dnsmessage.NewName(hostname + ".local.")
	if err != nil {
		return nil, false
	}
	advertised := services(port, options)
	var answers []dnsmessage.Resource
	matched := false
	for _, svc := range advertised {
		serviceName, err := dnsmessage.NewName(svc.name)
		if err != nil {
			return nil, false
		}
		instanceName, err := dnsmessage.NewName(instance + "." + svc.name)
		if err != nil {
			return nil, false
		}
		for _, txt := range svc.txt {
			if len(txt) > 255 {
				return nil, false
			}
		}
		for _, q := range query.Questions {
			// The high bit requests a unicast response; the underlying class is IN.
			if q.Class&0x7fff != dnsmessage.ClassINET && q.Class&0x7fff != dnsmessage.ClassANY {
				continue
			}
			name := q.Name.String()
			if (strings.EqualFold(name, svc.name) || strings.EqualFold(name, enumerationService)) && (q.Type == dnsmessage.TypePTR || q.Type == dnsmessage.TypeALL) {
				matched = true
			}
			if strings.EqualFold(name, instanceName.String()) && (q.Type == dnsmessage.TypeSRV || q.Type == dnsmessage.TypeTXT || q.Type == dnsmessage.TypeALL) {
				matched = true
			}
			if strings.EqualFold(name, hostName.String()) && (q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeALL) {
				matched = true
			}
		}
		// PTRs are shared records; SRV/TXT/A are unique and flush stale cache entries.
		answers = append(answers,
			dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: serviceName, Class: dnsmessage.ClassINET, TTL: mdnsTTL}, Body: &dnsmessage.PTRResource{PTR: instanceName}},
			dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: instanceName, Class: dnsmessage.ClassINET | 0x8000, TTL: mdnsTTL}, Body: &dnsmessage.SRVResource{Port: svc.port, Target: hostName}},
			dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: instanceName, Class: dnsmessage.ClassINET | 0x8000, TTL: mdnsTTL}, Body: &dnsmessage.TXTResource{TXT: svc.txt}},
		)
	}
	if !matched || query.Header.Response {
		return nil, false
	}
	for _, q := range query.Questions {
		if strings.EqualFold(q.Name.String(), enumerationService) && (q.Type == dnsmessage.TypePTR || q.Type == dnsmessage.TypeALL) {
			for _, svc := range advertised {
				answers = append(answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: mustNewName(enumerationService), Class: dnsmessage.ClassINET, TTL: mdnsTTL}, Body: &dnsmessage.PTRResource{PTR: mustNewName(svc.name)}})
			}
			break
		}
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.Header.ID, Response: true, Authoritative: true}, Answers: answers}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			var addr [4]byte
			copy(addr[:], ip4)
			response.Additionals = append(response.Additionals, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: hostName, Class: dnsmessage.ClassINET | 0x8000, TTL: mdnsTTL}, Body: &dnsmessage.AResource{A: addr}})
		}
	}
	// Pack reports resource encoding errors, including overlong TXT strings.
	msg, err := response.Pack()
	if err != nil {
		return nil, false
	}
	return msg, true
}

// localIPv4s returns the non-loopback IPv4 addresses of this host.
func localIPv4s() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || ip4.IsLoopback() {
			continue
		}
		ips = append(ips, ip4)
	}
	return ips, nil
}

// multicastIfaces returns interfaces that support multicast.
func multicastIfaces() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagMulticast != 0 && iface.Flags&net.FlagUp != 0 {
			out = append(out, iface)
		}
	}
	return out, nil
}

func mustNewName(s string) dnsmessage.Name {
	n, err := dnsmessage.NewName(s)
	if err != nil {
		panic("invalid DNS name: " + s + ": " + err.Error())
	}
	return n
}

func isTimeout(err error) bool {
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

// errNoMulticast is returned when no multicast-capable interface is found.
type noMulticastError struct{}

func (e *noMulticastError) Error() string { return "no multicast-capable interface available" }

var errNoMulticast = &noMulticastError{}
