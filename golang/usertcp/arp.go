package usertcp

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	ARPHeaderLength = 8
	ARPv4Length     = 20
)

type (
	Arp       []byte
	ArpHeader []byte
	ArpHWType uint16
	ArpProto  uint16
	ArpOpCode uint16
)

// list of ARP Hardware Types still in use
const (
	ArpHWTypeEthernet        ArpHWType = 1
	ArpHWTypeIEEE802Networks ArpHWType = 6
	ArpHWTypeATM             ArpHWType = 16
)

// list of ARP Opcodes still in use
// we most probably won't encounter RARP on
// our test playground
const (
	ArpRequest  ArpOpCode = 1
	ArpReply    ArpOpCode = 2
	RARPRequest ArpOpCode = 3
	RARPReply   ArpOpCode = 4
)

// list of ARP Protocols,
// shared with EthernetType
const (
	ArpIPv4 ArpProto = 0x0800
	ArpARP  ArpProto = 0x0806
	ArpRARP ArpProto = 0x8035
)

// todo: Add further validations
// currently we are only dealing with
// Ethernet headers, Our interface should
// have no way of getting other type of packets
func (a ArpHeader) IsValid() bool {
	return len(a) >= ARPHeaderLength
}

// errors
var (
	ErrMalformedArpHeader      = errors.New("malformed arp header")
	ErrUnsupportedArpHWType    = errors.New("unsupported ARP HW Type")
	ErrUnsupportedArpPrototype = errors.New("unsupported ARP Prototype")

	ErrMalformedArpV4Data = errors.New("malformed arp v4 data")
)

const (
	arpHWTypeOffset    = 0
	arpProtoTypeOffset = 2
	arpHWSizeOffset    = 4
	arpProSizeOffset   = 5
	arpOpCodeOffset    = 6
	arpDataOffset      = 8
)

func (a ArpHeader) HWType() ArpHWType {
	return ArpHWType(binary.BigEndian.Uint16(a[arpHWTypeOffset:]))
}

func (a ArpHeader) Prototype() ArpProto {
	return ArpProto(binary.BigEndian.Uint16(a[arpProtoTypeOffset:]))
}

func (a ArpHeader) HWSize() uint8 {
	return uint8(a[arpHWSizeOffset])
}

func (a ArpHeader) PrototypeSize() uint8 {
	return uint8(a[arpProSizeOffset])
}

func (a ArpHeader) Opcode() ArpOpCode {
	return ArpOpCode(binary.BigEndian.Uint16(a[arpOpCodeOffset:]))
}

func (a ArpHeader) Data() []byte {
	return a[arpDataOffset:]
}

const (
	arpV4SourceMACOffset = 0
	arpV4SourceIP        = arpV4SourceMACOffset + MACAddrLength
	arpV4DestinationMAC  = arpV4SourceIP + IPv4AddrLength
	arpV4DestinationIP   = arpV4DestinationMAC + MACAddrLength
)

type ArpV4 []byte

func (a ArpV4) IsValid() bool {
	return len(a) >= ARPv4Length
}

func (a ArpV4) SourceMAC() net.HardwareAddr {
	return net.HardwareAddr(a[arpV4SourceMACOffset:][:MACAddrLength])
}

func (a ArpV4) SourceIP() net.IP {
	return net.IP(a[arpV4SourceIP:][:IPv4AddrLength]).To4()
}

func (a ArpV4) DestinationMAC() net.HardwareAddr {
	return net.HardwareAddr(a[arpV4SourceMACOffset:][:MACAddrLength])
}

func (a ArpV4) DestinationIP() net.IP {
	return net.IP(a[arpV4DestinationIP:][:IPv4AddrLength])
}
