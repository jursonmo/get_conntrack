#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/moduleparam.h>

#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_nat_helper.h>

#include "ct_info.h"


int get_dnat_info(struct sk_buff *skb, struct nf_conn *ct, struct dnat_info *di) {
	struct nf_conntrack_tuple *t = NULL;
	t = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	di->tuple_info[IP_CT_DIR_ORIGINAL].sip = t->src.u3.ip;
	di->tuple_info[IP_CT_DIR_ORIGINAL].dip = t->dst.u3.ip;
	di->tuple_info[IP_CT_DIR_ORIGINAL].sport = t->src.u.all;
	di->tuple_info[IP_CT_DIR_ORIGINAL].dport = t->dst.u.all;
	di->tuple_info[IP_CT_DIR_ORIGINAL].proto = t->dst.protonum;

	t = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	di->tuple_info[IP_CT_DIR_REPLY].sip = t->src.u3.ip;
	di->tuple_info[IP_CT_DIR_REPLY].dip = t->dst.u3.ip;
	di->tuple_info[IP_CT_DIR_REPLY].sport = t->src.u.all;
	di->tuple_info[IP_CT_DIR_REPLY].dport = t->dst.u.all;
	di->tuple_info[IP_CT_DIR_REPLY].proto = t->dst.protonum;	

	di->skb_hash = skb_get_hash(skb);
	return 0;
}

static unsigned int dnat_conntrack_hook_fn(const struct nf_hook_ops *ops,
					struct sk_buff *skb,
				     const struct net_device *in,
				     const struct net_device *out,
				     int (*okfn)(struct sk_buff *))
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = NULL;		
	struct dnat_info di;
	struct iphdr *ip;
	
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct) {
		return NF_ACCEPT;
	}
	
	if (nf_ct_is_untracked(ct)) {
		return NF_ACCEPT;
	}
	
	if (!(ct->status & IPS_DST_NAT)) {
		return NF_ACCEPT;
	}
	
	ip = ip_hdr(skb);
	if (ip->protocol == IPPROTO_TCP) {
		if (ctinfo == IP_CT_NEW) {
			//prepare for nf_nat_mangle_tcp_packet
			nfct_seqadj_ext_add(ct);
			return NF_ACCEPT;
		}

		//if nf_ct_seqadj_set have set this bit, means have put ct_info to payload,so here return
		if (test_bit(IPS_SEQ_ADJUST_BIT, &ct->status)){
			return NF_ACCEPT;
		}
		// __nf_nat_mangle_tcp_packet want skb is linerize: SKB_LINEAR_ASSERT(skb);, so here do skb_linearize
		if (skb_linearize(skb)) {
			return NF_ACCEPT;
		}
		//dump_ct_info(ct);
		get_dnat_info(skb, ct, &di);
		//dump_dnat_info(&di);
		//mangle_packet ??
		if (!nf_nat_mangle_tcp_packet(skb, ct, ctinfo, 
				ip->ihl * 4, 0, 0, (char *)&di, sizeof(di))){
			//nf_ct_helper_log(skb, ct, "cannot mangle packet");
				printk("nf_nat_mangle_tcp_packet: cannot mangle packet\n");
				return NF_DROP;
		}
	}else if (ip->protocol == IPPROTO_UDP) {
			//check if skb is udp ct first packet
			struct nf_conn_acct *acct = nf_conn_acct_find(ct);
			if (!acct) {
				return NF_ACCEPT;
			}
			
			//udp_packet incread counter
			// only the first packet put ct info to udp paylaod? maybe, should put ct info in every udp packet
			if (acct->counter[IP_CT_DIR_ORIGINAL].packets.counter !=1 ) {
				return NF_ACCEPT;					
			}
			
			if (skb_linearize(skb)) {
				return NF_ACCEPT;
			}
			get_dnat_info(skb, ct, &di);
			if(!nf_nat_mangle_udp_packet(skb, ct, ctinfo, 
				ip->ihl * 4, 0, 0, (char *)&di, sizeof(di))){
				//nf_ct_helper_log(skb, ct, "cannot mangle packet");
				printk("nf_nat_mangle_udp_packet: cannot mangle packet\n");
				return NF_DROP;
			}
	}
	
	return NF_ACCEPT;
}




static struct nf_hook_ops ct_dnat_hooks[] __read_mostly = {
	{
		.hook = (nf_hookfn	*)dnat_conntrack_hook_fn,
		//.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER + 1,
	},
};



static int __init kumap_module_init(void)
{
	int ret;	

	ret = nf_register_hooks(ct_dnat_hooks, ARRAY_SIZE(ct_dnat_hooks));
	if (ret < 0) {
		printk("register hook failed.\n");
		return -1;
	}	
	printk("nf_register_hooks ct_dnat_hooks success\n");
	printk("kmalloc init ok\n");
	return 0;
}

static void __exit kumap_module_fini(void)
{
	nf_unregister_hooks(ct_dnat_hooks, ARRAY_SIZE(ct_dnat_hooks));
	synchronize_net();
	printk("kmmap_module_fini \n");
}


module_init(kumap_module_init);
module_exit(kumap_module_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("MO JIAN WEI");
MODULE_DESCRIPTION("put ct_info to tcp/udp payload");
MODULE_VERSION("0.1");



