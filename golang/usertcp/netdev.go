package usertcp

import (
	"errors"
)

var (
	ErrParsingAddrFailed = errors.New("failed to parse IP addr")
	ErrInvalidIPv4Addr   = errors.New("invalid IPv4 addr")
)

type NetDev struct {
	Addr   string
	HWAddr string
	tap    *NativeTAP
}

func NewNetDev(name, addr, hwaddr string) (*NetDev, error) {
	tap, err := CreateIfTAP(name, 1500)
	if err != nil {
		return nil, err
	}
	if err := tap.SetIfMAC(hwaddr); err != nil {
		return nil, err
	}
	if err := tap.SetIfRoute(addr); err != nil {
		return nil, err
	}
	if err := tap.SetIfUP(); err != nil {
		return nil, err
	}

	resp := NetDev{
		Addr:   addr,
		HWAddr: hwaddr,
		tap:    tap,
	}
	return &resp, nil
}

func (nd *NetDev) Transmit() error {
	panic("not implemented yet")
}
