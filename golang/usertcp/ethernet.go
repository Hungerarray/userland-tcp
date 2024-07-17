package usertcp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
)

var (
	ErrMalformedEthernetFrame = errors.New("malformed Ethernet frame")
)

type EthType []byte

func (e EthType) String() string {
	return hex.EncodeToString(e)
}

type EthFrame struct {
	Header  EthHeader
	payload []byte
}

type EthHeader struct {
	Dmac      net.HardwareAddr
	Smac      net.HardwareAddr
	Ethertype EthType
}

func CreateEthFrame(ethHeader EthHeader, payload []byte) []byte {
	frame := make([]byte, 0)
	frame = append(frame, ethHeader.Dmac...)
	frame = append(frame, ethHeader.Smac...)
	frame = append(frame, ethHeader.Ethertype...)
	frame = append(frame, payload...)
	return frame
}

func CreateEthHeder(dmac, smac net.HardwareAddr, ethType EthType) EthHeader {
	return EthHeader{
		Dmac:      dmac,
		Smac:      smac,
		Ethertype: ethType,
	}
}

func ParseEthFrame(b []byte) (*EthFrame, error) {
	if len(b) < 14 {
		return nil, ErrMalformedEthernetFrame
	}
	return &EthFrame{
		Header:  parseEthHeader(b[:14]),
		payload: b[14:],
	}, nil
}

func parseEthHeader(b []byte) EthHeader {
	return EthHeader{
		Dmac:      b[:6],
		Smac:      b[6:12],
		Ethertype: b[12:14],
	}
}

func (ethH EthHeader) String() string {
	var s strings.Builder

	s.WriteString("\n== Eth Header start ===\n")
	s.WriteString(fmt.Sprintf("Destination mac: %s\n", ethH.Dmac))
	s.WriteString(fmt.Sprintf("Source mac: %s\n", ethH.Smac))
	s.WriteString(fmt.Sprintf("Ethernet Type: %s\n", ethH.Ethertype))
	s.WriteString("=== Eth Header end ===\n")

	return s.String()
}
