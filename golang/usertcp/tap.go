package usertcp

import (
	"fmt"
	"os"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// With reference from https://git.zx2c4.com/wireguard-go/tree/tun/tun_linux.go?id=12269c276173#n551
const (
	cloneDevicePath = "/dev/net/tun"
	deviceCIDR      = "169.254.169.215/32"
)

type Device interface {
	File() *os.File
	Close() error
	Name() string

	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
}

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

func CreateTAP(name string, mtu int) (Device, error) {
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

	err = setIfRoute(name, deviceCIDR)
	if err != nil {
		return nil, err
	}

	err = setIfUP(name)
	if err != nil {
		return nil, err
	}

	return &NativeTAP{
		tapFile: fd,
		name:    name,
	}, nil
}

func setIfRoute(name, cidr string) error {
	dev, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}

	return netlink.AddrAdd(dev, addr)
}

func setIfUP(name string) error {
	dev, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(dev)
}
