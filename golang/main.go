package main

import (
	"encoding/hex"
	"linux-networking/usertcp"
	"log"
)

const (
	devAddr = "160.84.32.24/24"
	macAddr = "DE:C7:87:CB:A8:5C"
)

func main() {
	netDev, err := usertcp.NewNetDev("tap1", devAddr, macAddr)
	if err != nil {
		log.Fatal(err)
	}

	for {
		var buf [1024]byte
		count, err := netDev.Read(buf[:])
		if err != nil {
			log.Fatalf("[error]: %s\n", err.Error())
		}
		log.Printf("[info]: got %d bytes, %s\n", count, hex.EncodeToString(buf[:count]))
		ethFrame := usertcp.EthFrame(buf[:count])
		if err != nil {
			log.Printf("[warn]: failed to parse ethernet header")
			continue
		}

		log.Printf("[info]: Parsed Ethernet header, %s", ethFrame.Header())
		// replace the src and destination
		// addr, err := net.ParseMAC(macAddr)
		// if err != nil {
		// 	panic("malformed mac address")
		// }
		// h := usertcp.CreateEthHeder(ethFrame.Header.Smac, addr, ethFrame.Header.Ethertype)
		// b := usertcp.CreateEthFrame(h, make([]byte, 0))

		// netDev.Write(b)
	}
}
