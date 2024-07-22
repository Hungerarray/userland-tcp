package usertcp

import (
	"encoding/binary"
	"net"
)

type (
	IPv4 []byte
)

const (
	// version  | upper 0-3 bits (uint8)
	// Internet Header Length | lower 4-7 bits (uint8)
	verIHLOffset = 0

	// Type of Service | 8 bits (uint8)
	tosOffset = 1

	// Total Length  | 16 bits (uint16)
	totalLenOffset = 2

	// Identification | 16 bits (uint16)
	identOffset = 4

	// Flags | 3 bits (uint16)
	// FragmentOffset | 13 bits (uint16)
	flagsFOOffset = 6

	// Time to live | 8 bits (uint8)
	ttlOffset = 8

	// Protocol | 8 bits (uint8)
	protocolOffset = 9

	// HeaderChecksum | 16 bits (uint16)
	checksumOffset = 10

	// Source Address | 32 bits (uint32)
	saddrOffset = 12

	// Destination Address | 32 bits (uint32)
	daddrOffset = 16

	optOffset = 20
)

func (i IPv4) Version() uint8 {
	return i[verIHLOffset] >> 4
}

func (i IPv4) IHL() uint8 {
	return i[verIHLOffset] & 0x0F
}

func (i IPv4) TotalLength() uint16 {
	return binary.BigEndian.Uint16(i[totalLenOffset:])
}

func (i IPv4) TTL() uint8 {
	return uint8(i[ttlOffset])
}

func (i IPv4) Protocol() uint8 {
	return uint8(i[protocolOffset])
}

func (i IPv4) Checksum() uint16 {
	return binary.BigEndian.Uint16(i[checksumOffset:])
}

func (i IPv4) SourceAddr() net.IP {
	return net.IP(i[saddrOffset:][:IPv4AddrLength]).To4()
}

func (i IPv4) DestinationAddr() net.IP {
	return net.IP(i[daddrOffset:][:IPv4AddrLength]).To4()
}

// in bytes
func (i IPv4) OptionsLength() uint8 {
	return i.IHL()*4 - 20
}

func (i IPv4) Payload() []byte {
	return i[i.IHL():]
}
