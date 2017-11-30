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

struct tuple {
	unsigned int sip;
	unsigned int dip;
	unsigned short sport;
	unsigned short dport;
	uint8_t proto;
	uint8_t pad[3];
};

struct dnat_info {
	struct tuple tuple_info[IP_CT_DIR_MAX];
};

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
	

struct net_device *tun_dev = NULL;
char *tun_dev_name = NULL;

module_param(tun_dev_name, charp, S_IRUSR);


void dump_ct_info(struct nf_conn *ct)
{
	struct nf_conntrack_tuple *t;
	if  (!ct) {
		return;
	}
	t = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	printk("original ct: src=%u.%u.%u.%u, dst=%u.%u.%u.%u,sp=%u,dp=%u, proto=%d \n", NIPQUAD(t->src.u3.ip), NIPQUAD(t->dst.u3.ip), ntohs(t->src.u.all) , ntohs(t->dst.u.all), t->dst.protonum);
	t = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	printk("reply ct: src=%u.%u.%u.%u, dst=%u.%u.%u.%u,sp=%u,dp=%u, proto=%d \n", NIPQUAD(t->src.u3.ip) , NIPQUAD(t->dst.u3.ip), ntohs(t->src.u.all), ntohs(t->dst.u.all), t->dst.protonum);
}

int get_dnat_info(struct nf_conn *ct, struct dnat_info *di) {
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
	return 0;
}

int tun_send(struct sk_buff *skb, struct dnat_info *di)
{
	struct sk_buff *tun_skb = NULL;
	unsigned char *tp = NULL;
	struct ethhdr *eth= NULL;
	tun_skb = skb_copy(skb, GFP_ATOMIC);
	if (!tun_skb) {
		printk("tun_skb  skb_copy fail: \n");
		return NF_ACCEPT;
	}
	eth = eth_hdr(tun_skb);
	eth->h_proto = htons(0x0801);
	tp = skb_transport_header(tun_skb);
	memcpy(tp, di, sizeof(struct dnat_info));
	tun_skb->tail = (sk_buff_data_t)( tp+ sizeof(struct dnat_info));
	tun_skb->data = tun_skb->head + tun_skb->mac_header;
	tun_skb->len = tun_skb->transport_header + sizeof(struct dnat_info)-tun_skb->mac_header;
	tun_skb->dev = tun_dev;
	dev_queue_xmit(tun_skb);
	return NF_ACCEPT;
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
	
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct) {
		return NF_ACCEPT;
	}
	
	if (nf_ct_is_untracked(ct)) {
		return NF_ACCEPT;
	}

	if (!(ct->status & IPS_DST_NAT) || skb->nfctinfo != IP_CT_NEW) {
		return NF_ACCEPT;
	}
	
	//dump_ct_info(ct);
	get_dnat_info(ct, &di);
	//dump_dnat_info(&di);

	if (tun_dev) {
		tun_send(skb, &di);
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
	if (tun_dev_name) {
		tun_dev = dev_get_by_name(&init_net, tun_dev_name);
		if (!tun_dev) {
			printk("get dev %s fail\n", tun_dev_name);
			goto out;
		}
		printk("get dev %s ok\n", tun_dev_name);
	}
	ret = nf_register_hooks(ct_dnat_hooks, ARRAY_SIZE(ct_dnat_hooks));
	if (ret < 0) {
		printk("register hook failed.\n");
		goto  put_dev;
	}	
	printk("nf_register_hooks ct_dnat_hooks success\n");
	printk("kmalloc init ok\n");
	return 0;

put_dev:
	if (tun_dev) {
		dev_put(tun_dev);
	}
out :
	return -1;
}

static void __exit kumap_module_fini(void)
{
	
	nf_unregister_hooks(ct_dnat_hooks, ARRAY_SIZE(ct_dnat_hooks));
	synchronize_net();

	if (tun_dev) {
		dev_put(tun_dev);
	}	
	printk("kmmap_module_fini \n");
}


module_init(kumap_module_init);
module_exit(kumap_module_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("MO JIAN WEI");
MODULE_DESCRIPTION("kmmap : kernel memory map for user space");
MODULE_VERSION("0.1");



