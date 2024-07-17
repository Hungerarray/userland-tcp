package usertcp

import (
	"encoding/binary"
	"errors"
)

var (
	ErrMalformedEthernetFrame = errors.New("malformed Ethernet frame")
)

type EthHeader struct {
	Dmac      string
	Smac      string
	Ethertype uint16
	Payload   []byte
}

func ParseEthHeader(b []byte) (*EthHeader, error) {
	if len(b) < 14 {
		return nil, ErrMalformedEthernetFrame
	}

	return &EthHeader{
		Dmac:      string(b[:6]),
		Smac:      string(b[6:12]),
		Ethertype: binary.BigEndian.Uint16(b[12:14]),
		Payload:   b[14:],
	}, nil
}
