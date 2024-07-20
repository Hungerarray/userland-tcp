package usertcp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
)

const (
	MaxEthFrameSize = 1518
)

const (
	ethHeaderOffset = 0
	// currently don't support trailing ethernet headers
	// primarily as they aren't as widely used
	ethHeaderLen = 14

	ethDmacOffset = 0
	ethSmacOffset = ethDmacOffset + MACAddrLength
	ethTypeOffset = ethSmacOffset + MACAddrLength
)

// list of Ethernet Types
// this is not a complete list and just a selection
// of Ethernet types
const (
	EthIPv4 EthType = 0x0800
	EthArp  EthType = 0x0806
	EthRARP EthType = 0x8035
	EthIPv6 EthType = 0x86dd
	// EthVirtualLan EthType = 0x8100
)

type (
	// Ethernet frame
	EthFrame []byte
	// Ethernet frame header
	EthHeader []byte
	// Ethernet frame type
	EthType uint16
)

func (f EthFrame) Header() EthHeader {
	return EthHeader(f[:ethHeaderLen])
}

func NewEthHeader(smac, dmac net.HardwareAddr, ethType EthType) EthHeader {
	var buf [ethHeaderLen]byte

	copy(buf[ethSmacOffset:], smac)
	copy(buf[ethDmacOffset:], dmac)
	binary.BigEndian.PutUint16(buf[ethTypeOffset:], uint16(ethType))

	return buf[:]
}

func (f EthFrame) Payload() []byte {
	return f[ethHeaderLen:]
}

func (f EthFrame) IsValid() bool {
	return f.Header().IsValid()
}

func (hdr EthHeader) IsValid() bool {
	// check to see if we can add more validations
	return len(hdr) >= ethHeaderLen
}

func (h EthHeader) Dmac() net.HardwareAddr {
	return net.HardwareAddr(h[ethDmacOffset:][:MACAddrLength])
}

func (h EthHeader) SetDmac(hwAddr net.HardwareAddr) {
	copy(h[ethDmacOffset:][:MACAddrLength], EthHeader(hwAddr))
}

func (h EthHeader) Smac() net.HardwareAddr {
	return net.HardwareAddr(h[ethSmacOffset:][:MACAddrLength])
}

func (h EthHeader) SetSmac(hwAddr net.HardwareAddr) {
	copy(h[ethSmacOffset:][:MACAddrLength], EthHeader(hwAddr))
}

func (h EthHeader) EtherType() EthType {
	return EthType(binary.BigEndian.Uint16(h[ethTypeOffset:]))
}

func (h EthHeader) SetEtherType(et EthType) {
	binary.BigEndian.PutUint16(h[ethTypeOffset:], uint16(et))
}

func (e EthType) String() string {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(e))
	return hex.EncodeToString(buf[:])
}

func (ethH EthHeader) String() string {
	var s strings.Builder

	s.WriteString("\n== Eth Header start ===\n")
	s.WriteString(fmt.Sprintf("Destination mac: %s\n", ethH.Dmac()))
	s.WriteString(fmt.Sprintf("Source mac: %s\n", ethH.Smac()))
	s.WriteString(fmt.Sprintf("Ethernet Type: %s\n", ethH.EtherType()))
	s.WriteString("=== Eth Header end ===\n")

	return s.String()
}

func (eth EthHeader) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("Destination MAC", eth.Dmac().String()),
		slog.String("Source MAC", eth.Smac().String()),
		slog.String("Ethernet Type", eth.EtherType().String()),
	)
}

func ReadEthFrame(r io.Reader) (EthFrame, error) {
	var buf [MaxEthFrameSize]byte
	count, err := r.Read(buf[:])
	if err != nil {
		return nil, err
	}

	frame := EthFrame(bytes.Clone(buf[:count]))
	return frame, err
}

func TrasmitEthFrame(ethHeader EthHeader, payload []byte, w io.Writer) error {
	buf := append(ethHeader, payload...)
	_, err := w.Write(buf)
	return err
}
