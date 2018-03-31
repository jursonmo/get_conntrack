package main

/*
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <linux/ioctl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <stddef.h>
#include <errno.h>
//#define KUMAP_IOC_MAGIC	'K'
//#define KUMAP_IOC_SEM_WAIT _IOW(KUMAP_IOC_MAGIC, 1, int)

char* cmmap(int fd){
	return mmap(NULL, 2048, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
}
void cunmap(void *mapBuf){
 	munmap(mapBuf, 2048);//去除映射
}
*/
import "C"
import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// type ringbuffer_header struct {
// 	r, w       uint16
// 	size       uint32
// 	count, pad uint16
// }
// type ringbuffer struct {
// 	hdr   ringbuffer_header
// 	magic uint32
// }

// func (rb *ringbuffer) show() {
// 	fmt.Printf("rb: r=%d, w=%d,size=%d, count=%d,pad=%d, magic=%d\n", rb.hdr.r, rb.hdr.w, rb.hdr.size, rb.hdr.count, rb.hdr.pad, rb.magic)
// }
// func (rb *ringbuffer) encode(mapbuf uintptr) {
// 	rb.hdr.r = *(*uint16)(unsafe.Pointer(mapbuf + 0))
// 	rb.hdr.w = *(*uint16)(unsafe.Pointer(mapbuf + 2))
// 	rb.hdr.size = *(*uint32)(unsafe.Pointer(mapbuf + 4))
// 	rb.hdr.count = *(*uint16)(unsafe.Pointer(mapbuf + 8))
// 	rb.hdr.pad = *(*uint16)(unsafe.Pointer(mapbuf + 10))
// 	rb.magic = *(*uint32)(unsafe.Pointer(mapbuf + 12))
// }

//结构体字段记录的是内存地址
type ringbuffer_header struct {
	r, w       uintptr
	size       uintptr
	count, pad uintptr
}

type ringbuffer struct {
	hdr   ringbuffer_header
	magic uintptr
}

func (rb *ringbuffer) encode(mapbuf uintptr) {
	rb.hdr.r = mapbuf + 0
	rb.hdr.w = mapbuf + 2
	rb.hdr.size = mapbuf + 4
	rb.hdr.count = mapbuf + 8
	rb.hdr.pad = mapbuf + 10
	rb.magic = mapbuf + 12
}

func (rb *ringbuffer) show() {
	fmt.Printf("rb: r=%d, w=%d,size=%d, count=%d,pad=%d, magic=%d\n",
		*(*uint16)(unsafe.Pointer(rb.hdr.r)), *(*uint16)(unsafe.Pointer(rb.hdr.w)),
		*(*uint32)(unsafe.Pointer(rb.hdr.size)), *(*uint16)(unsafe.Pointer(rb.hdr.count)),
		*(*uint16)(unsafe.Pointer(rb.hdr.pad)), *(*uint32)(unsafe.Pointer(rb.magic)))
}

func main() {
	/*KUMAP_IOC_SEM_WAIT:
	1<<30 |
	'k'<<8 |
	1<<0 |
	4<<16
	*/
	KUMAP_IOC_SEM_WAIT := 1<<30 | 75<<8 | 1<<0 | 4<<16
	f, err := os.OpenFile("/dev/kumap/kudev", os.O_RDWR, 0666)
	if err != nil {
		panic(err)
	}
	/*cgo mmap */
	//C.mmap(nil, 2048, C.PROT_READ|C.PROT_WRITE, C.MAP_SHARED, fd, 0)
	//mapbuf := uintptr(unsafe.Pointer((*C.char)(C.cmmap(C.int(f.Fd())))))
	//defer C.cunmap(unsafe.Pointer(mapbuf))
	/*
		kenel printk :
		sizeof(rbf_t)=16, sizeof(rbf_hdr_t)=12, offset, r=0, w=2,size=4,count=8,pad=10,magic=12
		rbf_init mem: ffff880038ff0000 size: 4084,  RBF_NODE_SIZE=32, count: 127
	*/
	// rb := new(ringbuffer)
	// rb.encode(mapbuf)
	// rb.show() //rb: r=0, w=1,size=4084, count=127,pad=0, magic=12345

	/*go mmap */
	//b, err := syscall.Mmap(int(fd), off, len, prot, flags)//b []byte
	mapbuf, err := syscall.Mmap(int(f.Fd()), 0, 2048, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		panic(err)
	}
	fmt.Printf("gomap mapbuf len=%d\n", len(mapbuf)) //output: 2048, equal mmap len
	rb := new(ringbuffer)
	rb.encode(uintptr(unsafe.Pointer(&mapbuf[0])))
	rb.show() //rb: r=0, w=1,size=4084, count=127,pad=0, magic=12345
	var arg int
	for {
		fmt.Println("doing syscall.Syscall ioctl")
		r1, r2, syerr := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(KUMAP_IOC_SEM_WAIT), uintptr(unsafe.Pointer(&arg)))
		if syerr != 0 {
			return //syscall.Errno(syerr)
		}
		_, _ = r1, r2
		fmt.Println("syscall.Syscall ioctl ok")

		//rb.encode(mapbuf)
		rb.show()
	}
}
