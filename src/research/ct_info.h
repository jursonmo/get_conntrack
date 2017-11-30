#ifndef __CT_INFO_H__
#define __CT_INFO_H__

#ifdef __KERNEL__
#include <linux/netfilter.h>
#else 
	#include <sys/types.h>
	#include <unistd.h>
	#include <stdint.h>
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
	

struct tuple {
	unsigned int sip;
	unsigned int dip;
	unsigned short sport;
	unsigned short dport;
	uint8_t proto;
	uint8_t pad[3];
	//unsigned char proto;
};//__attribute__ ((packed));

struct dnat_info {
	//struct tuple tuple_info[IP_CT_DIR_MAX];
	struct tuple tuple_info[2];
};

void dump_dnat_info(struct dnat_info * di) {
	struct tuple *t;
	#ifdef __KERNEL__
	t = &di->tuple_info[IP_CT_DIR_ORIGINAL];
	printk("===di original  : src %u.%u.%u.%u,dst :%u.%u.%u.%u, sport=%u, dport=%u\n", NIPQUAD(t->sip), NIPQUAD(t->dip), ntohs(t->sport), ntohs(t->dport));

	t = &di->tuple_info[IP_CT_DIR_REPLY];
	printk("===di reply  : src %u.%u.%u.%u,dst :%u.%u.%u.%u, sport=%u, dport=%u\n", NIPQUAD(t->sip), NIPQUAD(t->dip), ntohs(t->sport), ntohs(t->dport));
	printk("sizeof(struct dnat_info) =%lu\n", sizeof(struct dnat_info));
	
	#else 

	t = &di->tuple_info[0];
	printf("===di original  : src %u.%u.%u.%u,dst :%u.%u.%u.%u, sport=%u, dport=%u\n", NIPQUAD(t->sip), NIPQUAD(t->dip), ntohs(t->sport), ntohs(t->dport));

	t = &di->tuple_info[1];
	printf("===di reply  : src %u.%u.%u.%u,dst :%u.%u.%u.%u, sport=%u, dport=%u\n", NIPQUAD(t->sip), NIPQUAD(t->dip), ntohs(t->sport), ntohs(t->dport));
	printf("sizeof(struct dnat_info) =%lu\n", sizeof(struct dnat_info));
	#endif
}
#endif
