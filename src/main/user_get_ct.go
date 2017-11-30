package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"unsafe"

	"github.com/lab11/go-tuntap/tuntap"
)

var (
	CtInfo [2]byte = [2]byte{0x08, 0x01}
)

type MAC [6]byte

type Ether struct {
	DstMac MAC
	SrcMac MAC
	Proto  [2]byte
}

func TranEther(b []byte) *Ether {
	return (*Ether)(unsafe.Pointer(&b[0]))
}
func (e *Ether) IsCtInfo() bool {
	return e.Proto == CtInfo
}

func main() {
	tun_name := "express_tun"
	tund, err := tuntap.Open(tun_name, 1, false)
	if err != nil {
		log.Printf("============== tuntap.Open error:%s==============\n", err.Error())
		return
	}
	out, err := exec.Command("ifconfig", tun_name, "up").CombinedOutput()
	if err != nil {
		log.Printf("open err:%s,out=%s\n", err.Error(), string(out))
		return
	}
	out, err = exec.Command("insmod", "express_ct.ko", fmt.Sprintf("tun_dev_name=%s", tun_name)).CombinedOutput()
	if err != nil {
		log.Printf("open err:%s,out=%s\n", err.Error(), string(out))
		return
	}

	for {
		buf := make([]byte, 1514)
		inpkt, err := tund.ReadPacket2(buf)
		if err != nil {
			log.Printf("==============ReadPacket error:%s==============\n", err.Error())
			log.Panicln(err)
			return
		}
		n := len(inpkt.Packet)
		//log.Printf("==============ReadPacket n:%d==============\n", n)
		ether := TranEther(inpkt.Packet)

		if !ether.IsCtInfo() {
			log.Printf("e.Proto[0]=%d,e.Proto[1]=%d\n", ether.Proto[0], ether.Proto[1])
			continue
		}
		iph := inpkt.Packet[14:]
		iphLen := (iph[0] & 0xf) * 4
		//log.Printf("==============iphLen =%d==============\n", iphLen)

		DnatInfo := iph[iphLen:]
		showDnatInfo(DnatInfo)
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
