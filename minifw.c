#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>

#include <linux/vmalloc.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/netfilter.h>
#include <asm/uaccess.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>		// has the netfilter hook's structure

#define DBTAG "F-WALL"
#define IPADDRESS(addr) \
	((unsigned char *)&addr)[0],\
	((unsigned char *)&addr)[1],\
	((unsigned char *)&addr)[2],\
	((unsigned char *)&addr)[3]\


static int atouc(const char **str)
{
	long n = 0;
	int i = 0;

	while (i < 3 &&  '0' <= **str && **str <= '9')
	{
		n = n * 10 + (**str - '0');
		++*str;
		i++;
	}
	if (n >= (unsigned char)-1)
		return -1;
	return n;
}

static int str_to_ip(const char *s)
{
	int x;
	int i = 0;
	unsigned char ip[4];
	
	for (; i < 3; i++)
	{
		if ((x = atouc(&s)) < 0)
			goto exit_invalid;
		ip[i] = (unsigned char )x;
		s++;
	}
	if ((x = atouc(&s)) < 0 || *s)
			goto exit_invalid;
	ip[i] = (unsigned char )x;	
	return *((unsigned int *)&ip);

exit_invalid:
	return -1;
}

typedef struct 
{
	uint32_t *arr;
	int now;
	int size;
} ip_table;

static struct nf_hook_ops *nfho_in = NULL;
static ip_table *ipt = NULL;

static int alloc_ip_table(int size)
{
	ipt = vmalloc(sizeof(ip_table));
	if (ipt == NULL)
		goto alloc_error;
	ipt->arr = vmalloc(sizeof(int) * size);
	if (ipt->arr == NULL)
		goto alloc_error;
	for (int i = 0; i < size; i++)
		ipt->arr[i] = 0;
	ipt->now = 0;
	ipt->size = size;
	return 0;

alloc_error:
	if (ipt != NULL)
	{
		if (ipt->arr)
			vfree(ipt->arr);
		vfree(ipt);
	}
	return -1;
}

static void register_ip(uint32_t ip)
{
	if (ipt->now > ipt->size)
		return ;
	ipt->arr[ipt->now++] = ip;
}

static int is_in_iptable(uint32_t ip)
{
	for (int i = 0; i < ipt->now; i++)
	{
		if (ipt->arr[i] == ip)
			return (1);
	}
	return (0);
}

static unsigned int block_ip_handler(void *priv, struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	struct iphdr *iph;
	uint32_t saddr = 0;
	
	if (!skb)
		goto exit_accpet;
	if (!(iph = ip_hdr(skb)))
		goto exit_drop;
	saddr = ntohl(iph->saddr);
	if (is_in_iptable(saddr))
	{
		printk(KERN_INFO "%s: blocked ==> %u.%u.%u.%u\n", DBTAG,
					IPADDRESS(saddr));
		goto exit_drop;
	}
	goto exit_accpet;	

exit_drop:
	return NF_DROP;	
exit_accpet:
	return NF_ACCEPT;
}

static int register_ip_filter(const char *ip)
{
	int ip_;

	if ((ip_ = str_to_ip(ip)) < 0)
		return (-1);
	register_ip((uint32_t)ip_);
	pr_info("%s: entry block list %s\n", DBTAG, ip);

	return (0);
}

static int __init minifw_init(void)
{
	pr_info("%s: init \n", DBTAG);
	
nfho_in = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops),
						GFP_KERNEL);
	if (nfho_in == NULL)
		goto exit_error;
	nfho_in->hook = (nf_hookfn *)block_ip_handler;
	nfho_in->hooknum = NF_INET_PRE_ROUTING;
	nfho_in->pf = PF_INET;
	nfho_in->priority = NF_IP_PRI_CONNTRACK + 1;
	
	if (alloc_ip_table(4))
		goto exit_error;

	register_ip_filter("8.8.8.8");
	nf_register_net_hook(&init_net, nfho_in);
	return (0);
	
exit_error:
	printk(KERN_INFO "%s: ERROR init kernel module\n", DBTAG);
	return -1;
}

static void __exit minifw_exit(void)
{
	pr_info("%s: exit\n", DBTAG);
	if (nfho_in)
	{
		nf_unregister_net_hook(&init_net, nfho_in);
		kfree(nfho_in);
	}
}

module_init(minifw_init);
module_exit(minifw_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("mini-fw");
