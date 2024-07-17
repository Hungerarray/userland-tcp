package usertcp

import (
	"encoding/binary"
	"errors"
	"net"
)

var (
	ErrParsingAddrFailed = errors.New("failed to parse IP addr")
	ErrInvalidIPv4Addr   = errors.New("invalid IPv4 addr")
)

type NetDev struct {
	Addr   uint32
	HWAddr []byte
}

func NewNetDev(addr, hwaddr string) (*NetDev, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, ErrParsingAddrFailed
	}
	b, err := ip.To4().MarshalText()
	if err != nil {
		return nil, ErrInvalidIPv4Addr
	}
	haddr, err := net.ParseMAC(hwaddr)
	if err != nil {
		return nil, err
	}
	resp := NetDev{
		Addr:   binary.BigEndian.Uint32(b),
		HWAddr: haddr,
	}
	return &resp, nil
}

func (nd *NetDev) Transmit(ethHdr *EthHeader, ethType uint16, dst []byte) error {
	panic("not implemented yet")
}
