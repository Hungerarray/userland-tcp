package usertcp

import (
	"container/list"
	"net"
)

type ArpCacheEntry struct {
	HWType    ArpHWType
	SourceIP  net.IP
	SourceMAC net.HardwareAddr
}

type ArpCache struct {
	entries list.List
}

func (a *ArpCache) InsertArpTranslationTable4(hdr ArpHeader, a4 ArpV4) {
	arpEntry := ArpCacheEntry{
		HWType:    hdr.HWType(),
		SourceIP:  a4.SourceIP(),
		SourceMAC: a4.SourceMAC(),
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

		if v.HWType == hdr.HWType() && v.SourceIP.Equal(a4.SourceIP()) {
			v.SourceMAC = a4.SourceMAC()
			return true
		}
	}
	return false
}

// This shouldn't be happening here
//
// func (a *ArpCache) Incoming(n NetDev, frame EthFrame) error {
// 	// hdr, err := parseArpHeader(frame.payload)
// 	hdr, err := parseArpHeader([]byte{})
// 	if err != nil {
// 		return err
// 	}
//
// 	// todo: improve on this
// 	var buf [2]byte
//
// 	binary.BigEndian.PutUint16(buf[:], ARP_ETHERNET)
// 	if !bytes.Equal(hdr.HWType, buf[:]) {
// 		return ErrUnsupportedArpHWType
// 	}
//
// 	binary.BigEndian.PutUint16(buf[:], ARP_IPV4)
// 	if !bytes.Equal(hdr.ProType, buf[:]) {
// 		return ErrUnsupportedArpPrototype
// 	}
//
// 	data, err := parseArpV4(hdr.Data)
// 	if err != nil {
// 		return err
// 	}
//
// 	if !bytes.Equal(n.Addr, data.Dip) {
// 		log.Print("[warn]: ARP request was not for us\n")
// 	}
//
// 	if ok := a.UpdateArpTranslationTable(*hdr, *data); !ok {
// 		a.InsertArpTranslationTable4(*hdr, *data)
// 	}
//
// 	switch binary.BigEndian.Uint16(hdr.Opcode) {
// 	case ARP_REQUEST:
// 		// return a.arp_reply(n, frame.Header, *hdr)
// 	default:
// 		log.Print("[warn]: Unsupported OP code\n")
// 	}
// 	return nil
// }

// func (a *ArpCache) arp_reply(n NetDev, ethHdr EthHeader, arpHdr ArpHeader) error {
// 	data, error := parseArpV4(arpHdr.Data)
// 	if error != nil {
// 		return error
// 	}

// 	data.Dmac = data.Smac
// 	data.Dip = data.Sip
// 	data.Smac = n.HWAddr
// 	data.Sip = n.Addr
// 	binary.BigEndian.PutUint16(arpHdr.Opcode, ARP_REPLY)

// }
