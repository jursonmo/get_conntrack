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

#include <linux/io.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/cdev.h>

#include "ct_info.h"
#include "ntrack_rbf.h"

#define KUMAP_IOC_MAGIC	'K'
#define KUMAP_IOC_SEM_WAIT _IOW(KUMAP_IOC_MAGIC, 1, int)
static DEFINE_SEMAPHORE(kumap_sem_notify);
static int kumem_running = 0;
static int user_waiting = 0;
atomic_t notified;

#define KUMAP_LOG_LEVEL	2
#define KUMAP_LOG(level, fmt, ...) do { \
	if ((level) <= KUMAP_LOG_LEVEL) { \
		printk("*KUMAP* " fmt "\n", ##__VA_ARGS__); \
	} \
} while (0)

#define KUMAP_LOG_IF(level, cond, fmt, ...) do { \
	if ((level) <= KUMAP_LOG_LEVEL) { \
		if (cond) { \
			printk("*KUMAP* " fmt "\n", ##__VA_ARGS__); \
		} \
	} \
} while (0)


#define KUMAP_ASSERT(cond)	BUG_ON(!(cond))

#define KUMAP_ASSERT_MSG(cond, fmt, ...) do { \
	if (unlikely(!(cond))) { \
		printk(fmt "\n", ##__VA_ARGS__); \
		BUG(); \
	} \
} while (0)

#define KUMAP_ERROR(...)			KUMAP_LOG(0, ##__VA_ARGS__)
#define KUMAP_ERROR_IF(cond, ...)	KUMAP_LOG_IF(0, cond, ##__VA_ARGS__)

#define KUMAP_WARN(...)			KUMAP_LOG(1, ##__VA_ARGS__)
#define KUMAP_WARN_IF(cond, ...)	KUMAP_LOG_IF(1, cond, ##__VA_ARGS__)

#define KUMAP_INFO(...)			KUMAP_LOG(2, ##__VA_ARGS__)
#define KUMAP_INFO_IF(cond, ...)	KUMAP_LOG_IF(2, cond, ##__VA_ARGS__)

#define KUMAP_DEBUG(...)			KUMAP_LOG(3, ##__VA_ARGS__)
#define KUMAP_DEBUG_IF(cond, ...)	KUMAP_LOG_IF(3, cond, ##__VA_ARGS__)


rbf_t *RBF; 
spinlock_t rbf_lock;

#define default_kmszie 4//128,  default 4096 =4k
char *KUMEM = NULL;
int kmsize = 0;
struct net_device *tun_dev = NULL;
//char tun_dev_name[20];
char *tun_dev_name = NULL;

module_param(kmsize, int, 0);//S_IRUSR
module_param(tun_dev_name, charp, S_IRUSR);


int map_test(void) {
        char *mem;
        int *p;
        if (kmsize == 0) {
            printk("kmsize not set, default %dk\n", default_kmszie);
            kmsize = default_kmszie;
        }
        printk("kmsize = %dk \n", kmsize);
        mem = kmalloc(kmsize*1024, GFP_ATOMIC);//GFP_KERNEL
        if (!mem){
                printk("kmalloc fail \n");
                return 0;
        }
        p = (int*)(mem);
        p[0] = 0;
        p[1] = 1;
        p[1] = 2;
        printk("kmalloc succes \n");
        return 0;
}

char* init_kumem(int size)
{
	char *mem = NULL;	
	
        if (size == 0) {
            printk("kmsize not set, default %dk\n", default_kmszie);
            size = default_kmszie;
        }
        printk("kmsize = %dk \n", size);
        mem = kmalloc(size*1024, GFP_KERNEL);//GFP_ATOMIC
        if (!mem){
                printk("kmalloc KUMEM fail \n");
                return NULL;
        }
	memset(mem, 0, size*1024);
	printk("kmalloc success: MEM %p ,size=%dk\n", mem, size);
	//strcpy(mem, "mjwmap123");	
	RBF = rbf_init(mem, size*1024);
	rbf_dump(RBF);
	spin_lock_init(&rbf_lock);
	return mem;
}

void kumap_device_notify(void)
{
	static unsigned long long jiffies_last = 0;
	int nt;
	//notify only when userspace listenning 
	if  (!kumem_running) {
		return;
	}

	nt = atomic_read(&notified);
	if (nt > 10) {
		//only up(&kumap_sem_notify) 10 times
		return;
	}
	if(user_waiting || jiffies != jiffies_last) {
		printk("up  sem,  user_waiting=%d\n", user_waiting);
		up(&kumap_sem_notify);
		jiffies_last = jiffies;
		atomic_inc(&notified);
	}
}

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
	char *tp = NULL;
	//__alloc_skb(size, priority, 0, NUMA_NO_NODE);
	tun_skb = skb_copy(skb, GFP_ATOMIC);
	if (!tun_skb) {
		printk("tun_skb  skb_copy fail: \n");
		//dump_ct_info(ct);
		return NF_ACCEPT;
	}

	//check mac, network, transport header
	printk("old skb mac=%u,network=%u,transport=%u, data offset=%ld\n", skb->mac_header, skb->network_header, skb->transport_header, skb->data-skb->head);
	printk("tun_skb  mac=%u,network=%u,transport=%u, data offset=%ld\n", tun_skb->mac_header, tun_skb->network_header, tun_skb->transport_header, tun_skb->data-tun_skb->head);

	tp = skb_transport_header(tun_skb);
	memcpy(tp, di, sizeof(struct dnat_info));
	if (!tun_dev) {
		kfree_skb(tun_skb);
		return NF_ACCEPT;
	}
/*
#ifdef NET_SKBUFF_DATA_USES_OFFSET
typedef unsigned int sk_buff_data_t;
#else
typedef unsigned char *sk_buff_data_t;
#endif
*/
	//reset tun_skb->len
	tun_skb->tail = (sk_buff_data_t)( (unsigned long)tp+ sizeof(struct dnat_info));//(sk_buff_data_t)(tun_skb->head + tun_skb->transport_header + sizeof(struct dnat_info));
	tun_skb->data = tun_skb->head + tun_skb->mac_header;
	tun_skb->len = tun_skb->transport_header + sizeof(struct dnat_info)-tun_skb->mac_header;//tun_skb->tail - tun_skb->data;
	tun_skb->dev = tun_dev;
	tun_skb->ip_summed = CHECKSUM_NONE;
	dev_queue_xmit(tun_skb);
	return NF_ACCEPT;
}
static unsigned int dnat_conntrack_hook_fn(/*unsigned int hook*/const struct nf_hook_ops *ops,
					struct sk_buff *skb,
				     const struct net_device *in,
				     const struct net_device *out,
				     int (*okfn)(struct sk_buff *))
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = NULL;
	struct iphdr *iph;	
	struct dnat_info di ;
	char *buf = NULL;
	
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
	iph = ip_hdr(skb);
	printk("skb iph: %u.%u.%u.%u -->%u.%u.%u.%u\n", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));

	dump_ct_info(ct);
	//get dnat info from ct
	get_dnat_info(ct, &di);

	dump_dnat_info(&di);

	if (tun_dev) {
		return tun_send(skb, &di);
	}

	spin_lock(&rbf_lock);
	buf = rbf_get_buff(RBF);
	if (!buf) {
		printk("rbf_get_buff fail\n");
		spin_unlock(&rbf_lock);
		return NF_ACCEPT;
	}
	memcpy(buf, &di, sizeof(struct dnat_info));
	rbf_release_buff(RBF);
	spin_unlock(&rbf_lock);
	
	kumap_device_notify();
	return NF_ACCEPT;
}



static int kumem_open(struct inode *inode, struct file *filp)
{
	printk("kumap chrdev open ,running now\n");
	kumem_running = 1;
	filp->private_data = KUMEM;
	return 0;
}
static ssize_t kumem_read(struct file *filp, char *buf, size_t count, loff_t *off)
{
	return 0;
}
static ssize_t kumem_write(struct file *filp, const char *buffer, size_t count, loff_t *off)
{
	return 0;
}
static int  kumem_release(struct inode *inode, struct file *filp){
	printk("kumap chrdev close ,stop running now\n");
	kumem_running = 0;
	filp->private_data = NULL;
	return 0;
}



static long kumem_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int res = 0;
	switch(cmd) {
		case KUMAP_IOC_SEM_WAIT:
			user_waiting= 1;
			res = down_interruptible(&kumap_sem_notify);
			if(res) {
				KUMAP_ERROR("wait dsp down interruptable return :%d\n", res);
			}
			atomic_set(&notified, 0);
			user_waiting = 0;
			break;
		default:
			KUMAP_ERROR("unknow ioctl cmd: %d, %lu\n", cmd, arg);
			break;
	}
	return 0;
}

int kumem_map (struct file *filp, struct vm_area_struct *vma)
{
	int res;
	char *mem =NULL;
	size_t mapped_size = vma->vm_end - vma->vm_start;
	mem = (char *)filp->private_data;
	if (!mem) {
		printk("kumap fail  mem=NULL \n");
		return -ENOMEM;
	}
	//mapped_size = n * 4096, at lease 4096
	if ((mapped_size + vma->vm_pgoff * PAGE_SIZE) > kmsize*1024) {
		printk("shm: shm get mem size failed.\n"
				"mapsize: %ld, pgoff: %lu, memsize: %ldk.\n",
				(unsigned long)mapped_size, (unsigned long)vma->vm_pgoff, (unsigned long)kmsize);

		return -ENOMEM;
	}

	vma->vm_flags |= VM_IO;
	//vma->vm_flags |= VM_RESERVED;
	
	res = remap_pfn_range(vma,
		vma->vm_start,
		virt_to_phys(mem) >> PAGE_SHIFT,
		 mapped_size,
		vma->vm_page_prot);
	
	if (res){
		printk("kumap fail  res=%d \n", res);
		return -ENOMEM;
	}
	printk("kumem_map  success \n");
	return 0;
}

struct ku_dev {
	dev_t dev_id;
	struct cdev dev;
	struct class *cls;
};

static struct ku_dev tdev;

static struct file_operations kumap_fops = {
      open: kumem_open,
      read: kumem_read,
      write: kumem_write,
      release: kumem_release,
      unlocked_ioctl: kumem_ioctl,
      mmap : kumem_map,
      //owner: THIS_MODULE
};

static int kumap_register_chrdev(const struct file_operations *fops)
{
	const char *name = "/kumap/kudev";
	struct device *dev;
	int res;

	res = alloc_chrdev_region(&tdev.dev_id, 0, 1, name);
	if (res != 0) {
		KUMAP_ERROR("register chr dev region failed. %d\n", res);
		return -EINVAL;
	}

	cdev_init(&tdev.dev, fops);
	res = cdev_add(&tdev.dev, tdev.dev_id, 1);
	if (res < 0) {
		goto __free_region;
	}

	tdev.cls = class_create(THIS_MODULE, name);
	if (IS_ERR_OR_NULL(tdev.cls)) {
		goto __free_cdev;
	}

	dev = device_create(tdev.cls, NULL, tdev.dev_id, NULL, name);
	if (IS_ERR_OR_NULL(dev)) {
		goto __free_cls;
	}

	return 0;

__free_cls:
	class_destroy(tdev.cls);
__free_cdev:
	cdev_del(&tdev.dev);
__free_region:
	unregister_chrdev_region(tdev.dev_id, 1);
	return -EINVAL;
}

static void kumap_unregister_chrdev(void)
{
	device_destroy(tdev.cls, tdev.dev_id);
	class_destroy(tdev.cls);
	cdev_del(&tdev.dev);
	unregister_chrdev_region(tdev.dev_id, 1);
}


static struct nf_hook_ops ct_dnat_hooks[] __read_mostly = {
	{
		.hook = (nf_hookfn*)dnat_conntrack_hook_fn,
		//.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER + 1,
	},
};



static int __init kumap_module_init(void)
{
	int ret;	
	//map_test();
	
	//char *default_tun_dev_name =  "express_tun";
	//memset(tun_dev_name, 0, sizeof(tun_dev_name));
	//strcpy(tun_dev_name, default_tun_dev_name);
	if (tun_dev_name) {
		tun_dev = dev_get_by_name(&init_net, tun_dev_name);
		if (!tun_dev) {
			KUMAP_ERROR("get dev %s fail\n", tun_dev_name);
			goto out;
		}
		KUMAP_INFO("get dev %s ok\n", tun_dev_name);
	}

	ret = kumap_register_chrdev(&kumap_fops);
	if (ret ){
		goto put_dev;
	}

	if (!kmsize) {
		kmsize = default_kmszie;
	}
	if (!(KUMEM = init_kumem(kmsize))){
		KUMAP_ERROR( "kmalloc kumem error \n");
		goto  unregister_dev;
	}
	ret = nf_register_hooks(ct_dnat_hooks, ARRAY_SIZE(ct_dnat_hooks));
	if (ret < 0) {
		KUMAP_ERROR("register hook failed.\n");
		goto  free_kumem;
	}	
	KUMAP_INFO("nf_register_hooks ct_dnat_hooks success\n");
	KUMAP_INFO("kmalloc init ok\n");
	return 0;


free_kumem:
	kfree(KUMEM);
	KUMEM =  NULL;		
unregister_dev:
	kumap_unregister_chrdev();	
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
	kumap_unregister_chrdev();
	if (KUMEM) {
		kfree(KUMEM);
		KUMEM = NULL;
	}	
	if (tun_dev) {
		dev_put(tun_dev);
	}	
	KUMAP_INFO("kmmap_module_fini \n");
}


module_init(kumap_module_init);
module_exit(kumap_module_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("MO JIAN WEI");
MODULE_DESCRIPTION("kmmap : kernel memory map for user space");
MODULE_VERSION("0.1");



