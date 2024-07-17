package usertcp

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// With reference from https://git.zx2c4.com/wireguard-go/tree/tun/tun_linux.go?id=12269c276173#n551
const (
	cloneDevicePath = "/dev/net/tun"
)

type NativeTAP struct {
	tapFile *os.File
	name    string

	closeOnce sync.Once
}

func (t *NativeTAP) File() *os.File {
	return t.tapFile
}

func (t *NativeTAP) Close() error {
	var err error
	t.closeOnce.Do(func() {
		err = t.tapFile.Close()
	})
	return err
}

func (t *NativeTAP) Name() string {
	return t.name
}

func (t *NativeTAP) Read(b []byte) (int, error) {
	return t.File().Read(b)
}

func (t *NativeTAP) Write(b []byte) (int, error) {
	return t.File().Write(b)
}

func CreateIfTAP(name string, mtu int) (*NativeTAP, error) {
	nfd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CreateTAP failed, %s does not exist", cloneDevicePath)
		}
		return nil, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}

	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr)
	if err != nil {
		return nil, err
	}

	err = unix.SetNonblock(nfd, true)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}

	fd := os.NewFile(uintptr(nfd), cloneDevicePath)

	return &NativeTAP{
		tapFile: fd,
		name:    name,
	}, nil
}

func (t *NativeTAP) SetIfMAC(hwaddr string) error {
	dev, err := netlink.LinkByName(t.name)
	if err != nil {
		return err
	}
	haddr, err := net.ParseMAC(hwaddr)
	if err != nil {
		return err
	}
	return netlink.LinkSetHardwareAddr(dev, haddr)
}

func (t *NativeTAP) SetIfRoute(cidr string) error {
	dev, err := netlink.LinkByName(t.name)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}

	return netlink.AddrAdd(dev, addr)
}

func (t *NativeTAP) SetIfUP() error {
	dev, err := netlink.LinkByName(t.name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(dev)
}
