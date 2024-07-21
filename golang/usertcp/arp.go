package usertcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
)

const (
	arpHeaderOffset = 0
	arpHeaderLength = 8
	arpV4Offset     = arpHeaderOffset + arpHeaderLength
	arpV4Length     = 20
)

type (
	Arp []byte // -

	ArpHeader []byte // --
	ArpHWType uint16 // ---
	ArpProto  uint16 // ---
	ArpOpCode uint16 // ---

	ArpV4 []byte // --
)

func (a Arp) Header() ArpHeader {
	return ArpHeader(a[arpHeaderOffset:][:arpHeaderLength])
}

func (a Arp) ArpIPv4Payload() ArpV4 {
	return ArpV4(a[arpV4Offset:][:arpV4Length])
}

func (a Arp) IsValid() bool {
	return a.Header().IsValid()
}

func NewArp(h ArpHeader, payload []byte) Arp {
	b := append(h[:arpHeaderLength], payload...)
	return Arp(b)
}

// list of ARP Hardware Types still in use
const (
	ArpHWTypeEthernet        ArpHWType = 1
	ArpHWTypeIEEE802Networks ArpHWType = 6
	ArpHWTypeATM             ArpHWType = 16
)

func (a ArpHWType) String() string {
	switch a {
	case ArpHWTypeEthernet:
		return "Ethernet"
	case ArpHWTypeIEEE802Networks:
		return "IEEE 802 Network"
	case ArpHWTypeATM:
		return "ATM"
	default:
		return "N/A"
	}
}

// list of ARP Opcodes still in use
// we most probably won't encounter RARP on
// our test playground
const (
	ArpRequest  ArpOpCode = 1
	ArpReply    ArpOpCode = 2
	RARPRequest ArpOpCode = 3
	RARPReply   ArpOpCode = 4
)

func (a ArpOpCode) String() string {
	switch a {
	case ArpRequest:
		return "ARP Request"
	case ArpReply:
		return "ARP Reply"
	case RARPRequest:
		return "RARP Request"
	case RARPReply:
		return "RARP Reply"
	default:
		return "N/A"
	}
}

// list of ARP Protocols,
// shared with EthernetType
const (
	ArpIPv4 ArpProto = 0x0800
	ArpARP  ArpProto = 0x0806
	ArpRARP ArpProto = 0x8035
)

func (a ArpProto) String() string {
	switch a {
	case ArpIPv4:
		return "IPv4"
	case ArpARP:
		return "Arp"
	case ArpRARP:
		return "RARP"
	default:
		return "N/A"
	}
}

// todo: Add further validations
// currently we are only dealing with
// Ethernet headers, Our interface should
// have no way of getting other type of packets
func (a ArpHeader) IsValid() bool {
	return len(a) >= arpHeaderLength
}

func (a ArpHeader) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("Hardware Type", a.HWType().String()),
		slog.String("Prototype", a.Prototype().String()),
		slog.Int("Hardware Size", int(a.HWSize())),
		slog.Int("Prototype Size", int(a.PrototypeSize())),
		slog.String("Opcode", a.Opcode().String()),
	)
}

// errors
var (
	ErrMalformedArpHeader      = errors.New("malformed arp header")
	ErrUnsupportedArpHWType    = errors.New("unsupported ARP HW Type")
	ErrUnsupportedArpPrototype = errors.New("unsupported ARP Prototype")
	ErrInvalidArpRequestOpcode = errors.New("expected to have ARP request opcode")

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

func (a ArpHeader) SetOpcode(c ArpOpCode) {
	binary.BigEndian.PutUint16(a[arpOpCodeOffset:], uint16(c))
}

const (
	arpV4SourceMACOffset = 0
	arpV4SourceIP        = arpV4SourceMACOffset + MACAddrLength
	arpV4DestinationMAC  = arpV4SourceIP + IPv4AddrLength
	arpV4DestinationIP   = arpV4DestinationMAC + MACAddrLength
)

func (a ArpV4) IsValid() bool {
	return len(a) >= arpV4Length
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

func (a ArpV4) UpdateCopy(smac, dmac net.HardwareAddr, sip, dip net.IP) ArpV4 {
	buf := bytes.Clone(a)

	copy(buf[arpV4SourceMACOffset:], smac)
	copy(buf[arpV4SourceIP:], sip.To4())
	copy(buf[arpV4DestinationMAC:], dmac)
	copy(buf[arpV4DestinationIP:], dip)

	return buf
}

func (a ArpV4) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("Source MAC", a.SourceMAC().String()),
		slog.String("Source IP", a.SourceIP().String()),
		slog.String("Destination MAC", a.DestinationMAC().String()),
		slog.String("Destination IP", a.DestinationIP().String()),
	)
}
