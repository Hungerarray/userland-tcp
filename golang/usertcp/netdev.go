package usertcp

import (
	"errors"
	"net"
)

var (
	ErrParsingAddrFailed = errors.New("failed to parse IP addr")
	ErrInvalidIPv4Addr   = errors.New("invalid IPv4 addr")
)

type NetDev struct {
	Addr   net.IP
	HWAddr net.HardwareAddr
	tap    *NativeTAP
}

func NewNetDev(name, addr, hwaddr string) (*NetDev, error) {
	tap, err := CreateIfTAP(name, 1500)
	if err != nil {
		return nil, err
	}
	// mac, err := net.ParseMAC(hwaddr)
	mac, err := tap.SetIfMAC(hwaddr)
	if err != nil {
		return nil, err
	}
	// ip := net.ParseIP(addr)
	ip, err := tap.SetIfRoute(addr)
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
	}
	return &resp, nil
}

func (nd *NetDev) Read(b []byte) (int, error) {
	return nd.tap.Read(b)
}

func (nd *NetDev) Write(b []byte) (int, error) {
	return nd.tap.Write(b)
}

// func (nd *NetDev) Transmit(ethFrame EthFrame, ethType []byte, dst []byte) error {
// 	ethFrame.Header.Ethertype = ethType
// 	ethFrame.Header.Smac = nd.HWAddr
// 	ethFrame.Header.Dmac = dst

// 	nd.Write([]byte(ethFrame))
// }
