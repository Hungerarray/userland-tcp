package main

import (
	"linux-networking/usertcp"
	"log"
	"log/slog"
	"os"
)

const (
	devAddr = "160.84.32.24/24"
	macAddr = "DE:C7:87:CB:A8:5C"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var ac usertcp.ArpCache
	netDev, err := usertcp.NewNetDev("tap1", devAddr, macAddr, ac, logger)
	if err != nil {
		log.Fatal(err)
	}

	for {
		frame, err := usertcp.ReadEthFrame(netDev)
		if err != nil {
			logger.Warn("failed to parse ethernet header")
			continue
		}

		fHeader := frame.Header()
		logger.Info("parsed Ethernet Header",
			slog.Any("ethHeader", fHeader),
		)

		switch fHeader.EtherType() {
		case usertcp.EthArp:
			arp := usertcp.Arp(frame.Payload())
			if !arp.IsValid() {
				logger.Warn("invalid arp packet, dropped packet")
			}
			aHeader := arp.Header()
			logger.Info("parsed ARP header",
				slog.Any("arpHeader", aHeader),
			)
			netDev.HandleArp(arp)

		case usertcp.EthIPv4:
		case usertcp.EthIPv6:
		case usertcp.EthRARP:
		default:
			logger.Warn("unknown ethernet type, dropped frame")
		}
	}
}
