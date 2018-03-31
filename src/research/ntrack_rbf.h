#ifndef __NTRACK_RBF_H__
#define __NTRACK_RBF_H__

#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/module.h>
#define print printk
#else /* end kernel */

#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#define print printf

#endif /* __KERNEL__ */

/* 
* ring buffer system defines. 
*/
#define RBF_NODE_SIZE	32 //(1024 * 2)

typedef struct ringbuffer_header {
	/* idx read, write record the idx[N] */
	volatile uint16_t r,w;

	uint32_t size;	//buffer size;
	uint16_t count;	//node count;
	uint16_t pad;
} rbf_hdr_t;

typedef struct ringbuffer {
	rbf_hdr_t hdr;
	uint32_t magic;
	uint8_t buffer[0];
} rbf_t;

static inline rbf_t* rbf_init(void *mem, uint32_t size)
{
	rbf_t *rbp = (rbf_t*)mem;
	//WARN_ON((size % L1_CACHE_BYTES) || (RBF_NODE_SIZE % L1_CACHE_BYTES));
	
	#ifdef __KERNEL__
	printk("sizeof(rbf_t)=%ld, sizeof(rbf_hdr_t)=%ld, offset, r=%ld, w=%ld,size=%ld,count=%ld,pad=%ld,magic=%ld\n", sizeof(rbf_t), sizeof(rbf_hdr_t)
		, offsetof(rbf_hdr_t,r), offsetof(rbf_hdr_t,w), offsetof(rbf_hdr_t,size), offsetof(rbf_hdr_t,count), offsetof(rbf_hdr_t,pad), offsetof(rbf_t,magic));
	printk(" rbf_init : L1_CACHE_BYTES =%d , size yu L1_CACHE_BYTES=%d, RBF_NODE_SIZE yu L1_CACHE_BYTES=%d \n", L1_CACHE_BYTES, size % L1_CACHE_BYTES, RBF_NODE_SIZE % L1_CACHE_BYTES);
	#endif
	memset(rbp, 0, sizeof(rbf_t));
	rbp->hdr.size = size - sizeof(rbf_hdr_t);
	rbp->hdr.count = rbp->hdr.size / RBF_NODE_SIZE;
	rbp->magic = 12345;
	print("\n\trbf_init mem: %p\n"
		"\tsize: %u,  RBF_NODE_SIZE=%d, count: %u\n"
		"\tr: %d, w: %d\n", 
		mem, rbp->hdr.size, RBF_NODE_SIZE, rbp->hdr.count, 
		rbp->hdr.r, rbp->hdr.w);

	return rbp;
}

static inline void rbf_dump(rbf_t *rbp)
{
	print("mem: %p, sz: 0x%x, count: 0x%x\n", 
		rbp, rbp->hdr.size, rbp->hdr.count);

	print("\tr: %d, w: %d\n", rbp->hdr.r, rbp->hdr.w);
}

static inline void *rbf_get_buff(rbf_t* rbp)
{
	volatile uint16_t idx = (rbp->hdr.w + 1) % rbp->hdr.count;

	/* overflow ? */
	if (idx != rbp->hdr.r) {
		return (void *)&rbp->buffer[RBF_NODE_SIZE * rbp->hdr.w];
	}

	return NULL;
}

static inline void rbf_release_buff(rbf_t* rbp)
{
	rbp->hdr.w = (rbp->hdr.w + 1) % rbp->hdr.count;
}

static inline void *rbf_get_data(rbf_t *rbp)
{
	uint16_t idx = rbp->hdr.r;

	if(idx != rbp->hdr.w) {
		return (void*)&rbp->buffer[RBF_NODE_SIZE * idx];
	}

	return NULL;
}

static inline void rbf_release_data(rbf_t *rbp)
{
	rbp->hdr.r = (rbp->hdr.r + 1) % rbp->hdr.count;
}

#endif /* __NTRACK_RBF_H__ */
