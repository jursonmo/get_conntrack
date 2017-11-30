package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

var filePath string = "/root/unixSocket"

func main() {
	addr, err := net.ResolveUnixAddr("unix", filePath)
	if err != nil {
		panic(err)
	}

	uc, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		panic(err)
	}

	for {
		buf := make([]byte, 36)
		nr, err := uc.Read(buf)
		if err != nil {
			panic(err)
		}
		showDnatInfo(buf[:nr])
	}

}

type tuple struct {
	saddr uint32
	daddr uint32
	sport uint16
	dport uint16
	proto uint8
	pad   [3]uint8
}

type conntrack struct {
	tuple [2]tuple
}

func ipString(ipaddr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ipaddr>>24), byte(ipaddr>>16), byte(ipaddr>>8), byte(ipaddr))
}

func (t tuple) String() string {
	var buf bytes.Buffer
	buf.WriteString(" src=")
	buf.WriteString(ipString(t.saddr))
	buf.WriteString(" dst=")
	buf.WriteString(ipString(t.daddr))
	buf.WriteString(" sport=")
	buf.WriteString(strconv.Itoa(int(t.sport)))
	buf.WriteString(" dport=")
	buf.WriteString(strconv.Itoa(int(t.dport)))
	buf.WriteString(" proto=")
	buf.WriteString(strconv.Itoa(int(t.proto)))
	return buf.String()
	//return fmt.Sprintf("src=%s,dst=%s,sport=%d,dport=%d,proto=%d", ipString(t.saddr), ipString(t.daddr), t.sport, t.dport, t.proto)
}

func showDnatInfo(data []byte) {
	var ct conntrack
	//ct.tuple[0].saddr = binary.BigEndian.Uint32(b[:4])
	b := bytes.NewBuffer(data)
	binary.Read(b, binary.BigEndian, &ct.tuple[0].saddr)
	binary.Read(b, binary.BigEndian, &ct.tuple[0].daddr)
	binary.Read(b, binary.BigEndian, &ct.tuple[0].sport)
	binary.Read(b, binary.BigEndian, &ct.tuple[0].dport)
	binary.Read(b, binary.BigEndian, &ct.tuple[0].proto)
	for i := 0; i < len(ct.tuple[0].pad); i++ {
		b.ReadByte()
	}

	binary.Read(b, binary.BigEndian, &ct.tuple[1].saddr)
	binary.Read(b, binary.BigEndian, &ct.tuple[1].daddr)
	binary.Read(b, binary.BigEndian, &ct.tuple[1].sport)
	binary.Read(b, binary.BigEndian, &ct.tuple[1].dport)
	binary.Read(b, binary.BigEndian, &ct.tuple[1].proto)
	for i := 0; i < len(ct.tuple[1].pad); i++ {
		b.ReadByte()
	}
	fmt.Printf("original:%s, reply:%s \n", ct.tuple[0].String(), ct.tuple[1].String())
}
