package usertcp

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"errors"
	"log"
	"net"
)

const (
	ARP_ETHERNET = 0x0001
	ARP_IPV4     = 0x0800
	ARP_REQUEST  = 0x0001
	ARP_REPLY    = 0x0002

	ARP_FREE     = 0
	ARP_WAITING  = 1
	ARP_RESOLVED = 2
)

// errors
var (
	ErrMalformedArpHeader      = errors.New("malformed arp header")
	ErrUnsupportedArpHWType    = errors.New("unsupported ARP HW Type")
	ErrUnsupportedArpPrototype = errors.New("unsupported ARP Prototype")

	ErrMalformedArpV4Data = errors.New("malformed arp v4 data")
)

type ArpHeader struct {
	HWType  []byte
	ProType []byte
	HWSize  byte
	ProSize byte
	Opcode  []byte
	Data    []byte
}

func parseArpHeader(b []byte) (*ArpHeader, error) {
	if len(b) < 8 {
		return nil, ErrMalformedArpHeader
	}

	return &ArpHeader{
		HWType:  b[0:2],
		ProType: b[2:4],
		HWSize:  b[4],
		ProSize: b[5],
		Opcode:  b[6:8],
		Data:    b[8:],
	}, nil
}

type ArpV4 struct {
	Smac net.HardwareAddr
	Sip  []byte
	Dmac net.HardwareAddr
	Dip  []byte
}

func parseArpV4(b []byte) (*ArpV4, error) {
	if len(b) < 20 {
		return nil, ErrMalformedArpV4Data
	}

	return &ArpV4{
		Smac: b[:6],
		Sip:  b[6:10],
		Dmac: b[10:16],
		Dip:  b[16:20],
	}, nil
}

type ArpCacheEntry struct {
	HWtype []byte
	Sip    []byte
	Smac   net.HardwareAddr
}

type ArpCache struct {
	entries list.List
}

func (a *ArpCache) InsertArpTranslationTable4(hdr ArpHeader, a4 ArpV4) {
	arpEntry := ArpCacheEntry{
		HWtype: hdr.HWType,
		Sip:    a4.Sip,
		Smac:   a4.Smac,
	}
	// need to send in pointer and not the value
	a.entries.PushBack(&arpEntry)
}

func (a *ArpCache) UpdateArpTranslationTable(hdr ArpHeader, a4 ArpV4) bool {
	for e := a.entries.Front(); e != nil; e = e.Next() {
		v, ok := e.Value.(*ArpCacheEntry)
		if !ok {
			panic("corrupted arp cache list")
		}

		if bytes.Equal(v.HWtype, hdr.HWType) && bytes.Equal(v.Sip, a4.Sip) {
			v.Smac = a4.Smac
			return true
		}
	}
	return false
}

func (a *ArpCache) Incoming(n NetDev, frame EthFrame) error {
	hdr, err := parseArpHeader(frame.payload)
	if err != nil {
		return err
	}

	// todo: improve on this
	var buf [2]byte

	binary.BigEndian.PutUint16(buf[:], ARP_ETHERNET)
	if !bytes.Equal(hdr.HWType, buf[:]) {
		return ErrUnsupportedArpHWType
	}

	binary.BigEndian.PutUint16(buf[:], ARP_IPV4)
	if !bytes.Equal(hdr.ProType, buf[:]) {
		return ErrUnsupportedArpPrototype
	}

	data, err := parseArpV4(hdr.Data)
	if err != nil {
		return err
	}

	if !bytes.Equal(n.Addr, data.Dip) {
		log.Print("[warn]: ARP request was not for us\n")
	}

	if ok := a.UpdateArpTranslationTable(*hdr, *data); !ok {
		a.InsertArpTranslationTable4(*hdr, *data)
	}

	switch binary.BigEndian.Uint16(hdr.Opcode) {
	case ARP_REQUEST:
		return a.arp_reply(n, frame.Header, *hdr)
	default:
		log.Print("[warn]: Unsupported OP code\n")
	}
	return nil
}

func (a *ArpCache) arp_reply(n NetDev, ethHdr EthHeader, arpHdr ArpHeader) error {
	data, error := parseArpV4(arpHdr.Data)
	if error != nil {
		return error
	}

	data.Dmac = data.Smac
	data.Dip = data.Sip
	data.Smac = n.HWAddr
	data.Sip = n.Addr
	binary.BigEndian.PutUint16(arpHdr.Opcode, ARP_REPLY)

}
