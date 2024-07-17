package main

import (
	"encoding/hex"
	"linux-networking/usertcp"
	"log"
)

func main() {
	tap, err := usertcp.CreateIfTAP("tap1", 1500)
	if err != nil {
		log.Fatal(err)
	}

	for {
		var buf [1024]byte
		count, err := tap.Read(buf[:])
		if err != nil {
			log.Fatalf("[error]: %s\n", err.Error())
		}
		log.Printf("[info]: got %d bytes, %s\n", count, hex.EncodeToString(buf[:count]))
		// ethHdr, err := usertcp.ParseEthHeader(buf[:count])
		if err != nil {
			log.Printf("[warn]: failed to parse ethernet header")
			continue
		}

		// log.Printf("[info]: Parsed Ethernet header, %s", ethHdr)
	}
}
