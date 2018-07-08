// Package tuntap provides a portable interface to create and use
// TUN/TAP virtual network interfaces.
//
// Note that while this package lets you create the interface and pass
// packets to/from it, it does not provide an API to configure the
// interface. Interface configuration is a very large topic and should
// be dealt with separately.
package tuntap

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

type DevKind int

const (
	// Receive/send layer routable 3 packets (IP, IPv6...). Notably,
	// you don't receive link-local multicast with this interface
	// type.
	DevTun DevKind = iota
	// Receive/send Ethernet II frames. You receive all packets that
	// would be visible on an Ethernet link, including broadcast and
	// multicast traffic.
	DevTap
)

type Packet struct {
	// The Ethernet type of the packet. Commonly seen values are
	// 0x0800 for IPv4 and 0x86dd for IPv6.
	Protocol int
	// True if the packet was too large to be read completely.
	Truncated bool
	// The raw bytes of the Ethernet payload (for DevTun) or the full
	// Ethernet frame (for DevTap).
	Packet []byte
}

type Interface struct {
	name string
	//file net.Conn
	file *os.File
	meta bool
}

// Disconnect from the tun/tap interface.
//
// If the interface isn't configured to be persistent, it is
// immediately destroyed by the kernel.
func (t *Interface) Close() error {
	return t.file.Close()
}

// The name of the interface. May be different from the name given to
// Open(), if the latter was a pattern.
func (t *Interface) Name() string {
	return t.name
}

// Read a single packet from the kernel.
func (t *Interface) ReadPacket() (*Packet, error) {
	buf := make([]byte, 10000)

	n, err := t.file.Read(buf)
	if err != nil {
		return nil, err
	}

	var pkt *Packet
	if t.meta {
		pkt = &Packet{Packet: buf[4:n]}
	} else {
		pkt = &Packet{Packet: buf[0:n]}
	}
	pkt.Protocol = int(binary.BigEndian.Uint16(buf[2:4]))
	flags := int(*(*uint16)(unsafe.Pointer(&buf[0])))
	if flags&flagTruncated != 0 {
		pkt.Truncated = true
	}
	return pkt, nil
}

//add by mo
func (t *Interface) Meta() bool {
	return t.meta
}

func (t *Interface) SetNonblock() {
	syscall.SetNonblock(int(t.file.Fd()), true)
	//syscall.Socket()
}

func (t *Interface) ReadPacket2(buf []byte) (*Packet, error) {
	//buf := make([]byte, 10000)

	n, err := t.file.Read(buf)
	if err != nil {
		return nil, err
	}

	var pkt *Packet
	if t.meta {
		pkt = &Packet{Packet: buf[4:n]}
		pkt.Protocol = int(binary.BigEndian.Uint16(buf[2:4]))
		flags := int(*(*uint16)(unsafe.Pointer(&buf[0])))
		if flags&flagTruncated != 0 {
			pkt.Truncated = true
		}
	} else {
		pkt = &Packet{Packet: buf[0:n]}
	}
	return pkt, nil
}

// Send a single packet to the kernel.
func (t *Interface) WritePacket(pkt *Packet) error {
	// If only we had writev(), I could do zero-copy here...
	/* mo jianwei del*/
	/*
		buf := make([]byte, len(pkt.Packet)+4)
		binary.BigEndian.PutUint16(buf[2:4], uint16(pkt.Protocol))
		copy(buf[4:], pkt.Packet)
	*/
	var buf []byte
	/* mo jianwei del end*/
	var n int
	var err error
	if t.meta {
		buf = make([]byte, len(pkt.Packet)+4)
		binary.BigEndian.PutUint16(buf[2:4], uint16(pkt.Protocol))
		copy(buf[4:], pkt.Packet)
		n, err = t.file.Write(buf)
	} else {
		n, err = t.file.Write(pkt.Packet)
	}
	if err != nil {
		return err
	}
	if t.meta {
		if n != len(buf) {
			fmt.Printf("n =%d, len(buf)=%d\n", n, len(buf))
			return io.ErrShortWrite
		}
	} else if n != len(pkt.Packet) {
		fmt.Printf("n =%d, len(buf)=%d\n", n, len(pkt.Packet))
		return io.ErrShortWrite
	}
	return nil
}

// Open connects to the specified tun/tap interface.
//
// If the specified device has been configured as persistent, this
// simply looks like a "cable connected" event to observers of the
// interface. Otherwise, the interface is created out of thin air.
//
// ifPattern can be an exact interface name, e.g. "tun42", or a
// pattern containing one %d format specifier, e.g. "tun%d". In the
// latter case, the kernel will select an available interface name and
// create it.
//
// meta determines whether the tun/tap header fields in Packet will be
// used.
//
// Returns a TunTap object with channels to send/receive packets, or
// nil and an error if connecting to the interface failed.
func Open(ifPattern string, kind DevKind, meta bool) (*Interface, error) {
	file, err := openDevice(ifPattern)
	if err != nil {
		return nil, err
	}

	ifName, err := createInterface(file, ifPattern, kind, meta)
	if err != nil {
		file.Close()
		return nil, err
	}

	return &Interface{ifName, file, meta}, nil
}
