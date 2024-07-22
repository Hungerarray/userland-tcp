package usertcp

import (
	"container/list"
	"net"
)

// Local ARP Cache entry containing
// SourceIP and SourceMAC as well as
// the HWType of the device
//
// (- ? possible addition of timeouts for more
// resillient infra)
type ArpCacheEntry struct {
	SourceIP  net.IP
	SourceMAC net.HardwareAddr
	HWType    ArpHWType
}

// Local ArpCache List
// uses double linked list
// from [container/list] package.
//
// The zero value of this struct is an arp cache ready to use
type ArpCache struct {
	entries list.List
}

// Insert an IPv4 Arp request into ARP table
func (a *ArpCache) InsertArpTable(hdr ArpHeader, a4 ArpV4) {
	arpEntry := ArpCacheEntry{
		HWType:    hdr.HWType(),
		SourceIP:  a4.SourceIP(),
		SourceMAC: a4.SourceMAC(),
	}
	// need to send in pointer and not the value
	a.entries.PushBack(&arpEntry)
}

// Update existing IPv4 ARP table entry
func (a *ArpCache) UpdateArpTable(hdr ArpHeader, a4 ArpV4) bool {
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
