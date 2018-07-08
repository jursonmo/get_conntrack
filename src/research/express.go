package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"packet"
	"strconv"
	"time"

	"github.com/lab11/go-tuntap/tuntap"
)

var (
	setNonblock = true
	EWOULDBLOCK = errors.New("read /dev/net/tun: resource temporarily unavailable")
)

func main() {
	tun_name := "express_tun"
	tund, err := tuntap.Open(tun_name, 1, false)
	if err != nil {
		log.Printf("============== tuntap.Open error:%s==============\n", err.Error())
		return
	}
	if setNonblock {
		tund.SetNonblock()
	}
	out, err := exec.Command("ifconfig", tun_name, "up").CombinedOutput()
	if err != nil {
		log.Printf("open err:%s,out=%s\n", err.Error(), string(out))
	}
	http.Post()
	for {
		buf := make([]byte, 1514)
		inpkt, err := tund.ReadPacket2(buf)
		if err != nil {
			log.Printf("==============ReadPacket error:%s==============\n", err.Error())
			//if delete tun dev,  and here print :ReadPacket error:read /dev/net/tun: file descriptor in bad state
			if setNonblock {
				//边缘触发的api时，要注意每次都要读到socket返回EWOULDBLOCK为止
				//src/syscall/zerrors_linux_amd64.go +1392,  EWOULDBLOCK or EAGAIN ==  "resource temporarily unavailable"
				if err.(*os.PathError).Err.Error() == "resource temporarily unavailable" { //EWOULDBLOCK
					log.Printf("EWOULDBLOCK")
					time.Sleep(time.Second)
					continue
				}
			}
			log.Panicln(err)
			return
		}
		n := len(inpkt.Packet)
		log.Printf("==============ReadPacket n:%d==============\n", n)

		ether := packet.TranEther(inpkt.Packet)

		log.Printf("dst mac :%s", ether.DstMac.String())
		log.Printf("src mac :%s", ether.SrcMac.String())

		if !ether.IsIpPtk() {
			log.Printf("==============no ip packet==============\n")
			continue
		}
		iph := inpkt.Packet[14:]
		iphLen := (iph[0] & 0xf) * 4
		log.Printf("==============iphLen =%d==============\n", iphLen)

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
