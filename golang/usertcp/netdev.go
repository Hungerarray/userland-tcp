package usertcp

import (
	"errors"
	"log/slog"
	"net"
)

var (
	ErrParsingAddrFailed = errors.New("failed to parse IP addr")
	ErrInvalidIPv4Addr   = errors.New("invalid IPv4 addr")
	ErrNotImplemented    = errors.New("not implemented yet!")
)

type NetDev struct {
	tap    *NativeTAP
	logger *slog.Logger
	ACache ArpCache
	Addr   net.IP
	HWAddr net.HardwareAddr
}

func (n NetDev) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("IP", n.Addr.String()),
		slog.String("MAC", n.HWAddr.String()),
	)
}

func NewNetDev(name, addr, hwaddr string, cache ArpCache, logger *slog.Logger) (*NetDev, error) {
	tap, err := CreateIfTAP(name, 1500)
	if err != nil {
		return nil, err
	}
	mac, err := tap.SetIfMAC(hwaddr)
	if err != nil {
		return nil, err
	}
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		return nil, err
	}
	_, err = tap.SetIfRoute(addr)
	if err != nil {
		return nil, err
	}
	if err := tap.SetIfUP(); err != nil {
		return nil, err
	}

	resp := NetDev{
		Addr:   ip,
		HWAddr: mac,
		tap:    tap,
		logger: logger,
	}
	return &resp, nil
}

func (nd *NetDev) Read(b []byte) (int, error) {
	return nd.tap.Read(b)
}

func (nd *NetDev) Write(b []byte) (int, error) {
	return nd.tap.Write(b)
}

func (nd *NetDev) HandleArp(arp Arp) error {
	aHdr := arp.Header()
	arpv4 := arp.ArpIPv4Payload()

	if ok := nd.ACache.UpdateArpTable(aHdr, arpv4); !ok {
		nd.ACache.InsertArpTable(aHdr, arpv4)
	}
	nd.logger.Info("ARP table updated")

	if !nd.Addr.Equal(arpv4.DestinationIP()) {
		nd.logger.Info("ARP was not destined for us")
		return nil
	}

	switch aHdr.Opcode() {
	case ArpRequest:
		nd.logger.Info("handling ARP request")
		return nd.ReplyArp(arp)
	default:
		return ErrNotImplemented
	}
}

func (nd *NetDev) ReplyArp(arp Arp) error {
	data := arp.ArpIPv4Payload()
	payload := data.UpdateCopy(nd.HWAddr, data.SourceMAC(), nd.Addr, data.SourceIP())
	nd.logger.Info("ARP reply payload", slog.Any("payload", payload))

	arpH := arp.Header()
	arpH.SetOpcode(ArpReply)
	nd.logger.Info("ARP reply header", slog.Any("Header", arpH))

	reply := NewArp(arpH, payload)
	ethH := NewEthHeader(nd.HWAddr, data.SourceMAC(), EthArp)
	return TrasmitEthFrame(ethH, reply, nd)
}
