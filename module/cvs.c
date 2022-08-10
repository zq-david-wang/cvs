#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/namei.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_nat.h>
#include <linux/netfilter/x_tables.h>
#include <linux/random.h>
#include <net/ip.h>
#include <net/netfilter/nf_conntrack_core.h>

#include "../include/common.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("lddlinan <00107082@163.com>");
MODULE_DESCRIPTION("DNAT support");

static struct bpf_map *entry_map = NULL;

static int cvs_init(void) {
    struct path path;
    int rc;
    int error = 0;
    if (entry_map != NULL) return error;
    rc = kern_path(root_vip, LOOKUP_FOLLOW, &path);
    if (rc!=0) {
        printk(KERN_INFO "kern path error %d\n", rc);
        error = -1;
    } else {
        struct inode *inode;
        struct dentry *d;
        d = path.dentry;
        inode = d->d_inode;
        if (inode == NULL || IS_ERR(inode)) {
            printk(KERN_INFO "inode error %p\n", inode);
            error = -2;
        } else {
            struct bpf_map *m;
            m = inode->i_private;
            if (m == NULL || IS_ERR(m) || m->ops == NULL) {
                printk(KERN_INFO "bpf map error %p\n", m);
                error = -3;
            } else {
                // pin the map
                bpf_map_inc(m);
                entry_map = m;
            }
        }
        path_put(&path);
    }
    return error;
}

#define NOVIP 1
#define NORIP 2
static int random_real_ip(unsigned int vip, unsigned int n, unsigned int *out_ip) {
    char map_path[64];
    struct path path;
    int rc;
    build_path(map_path, vip);
    rc = kern_path(map_path, LOOKUP_FOLLOW, &path);
    if (rc!=0) {
        return -1;
    } else {
        struct inode *inode;
        struct dentry *d;
        d = path.dentry;
        inode = d->d_inode;
        if (inode == NULL || IS_ERR(inode)) {
            return -2;
        } else {
            struct bpf_map *m;
            m = inode->i_private;
            if (m == NULL || IS_ERR(m) || m->ops == NULL) {
                return -3;
            } else {
                // lookup something
                int i = get_random_u32()%n;
                RIPNode* rip = m->ops->map_lookup_elem(m, &i);
                if (rip==NULL || IS_ERR(rip)) return -4; 
                *out_ip = rip->ip;
            }
        }
        path_put(&path);
    }
    return 0;
}
static int cvs_get_endpoints(unsigned int vip, unsigned int *out_ip) {
    VIPKNode key;
    VIPVNode *value = NULL;
    int error = 0;
    struct bpf_map *m;
    error = cvs_init();
    if (error) return error;
    key.ip = vip;
    key._ = 0;
    m = entry_map;
    value = m->ops->map_lookup_elem(m, &key);
    if (value==NULL||IS_ERR(value)) error = NOVIP; 
    else if (value->n==0) error = NORIP;
    else {
        if (random_real_ip(vip, value->n, out_ip)) error = NORIP;
    }
    return error;
}


static unsigned int cvs_dnat_any(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    unsigned int sip = ip_hdr(skb)->daddr;
    unsigned int ip, rc;
    struct nf_conn *ct;
    enum ip_conntrack_info ctinfo;
    struct nf_nat_range2 range;
    union nf_inet_addr addr;
    rc = cvs_get_endpoints(sip, &ip);
    if (rc==NOVIP) return NF_ACCEPT; // not registered ip
    if (rc==NORIP) return NF_DROP; // registered vip, but no rip
    // printk(KERN_INFO "vip match %x --> %x\n", sip, ip);
    ct = nf_ct_get(skb, &ctinfo); // IP_CT_NEW
    if (ct == NULL) return NF_DROP;
    range.flags  = NF_NAT_RANGE_MAP_IPS;
    addr.ip = ip;
    range.min_addr    = addr;
    range.max_addr    = addr;
    rc = nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
    if (rc != NF_ACCEPT) return rc;
    return nf_nat_packet(ct, ctinfo, state->hook, skb);
}


static const struct nf_hook_ops nf_nat_ipv4_ops[] = {
    {
        .hook        = cvs_dnat_any,
        .pf        = NFPROTO_IPV4,
        .hooknum    = NF_INET_PRE_ROUTING,
        .priority    = NF_IP_PRI_NAT_DST,
    },
    {
        .hook        = cvs_dnat_any,
        .pf        = NFPROTO_IPV4,
        .hooknum    = NF_INET_LOCAL_OUT,
        .priority   = NF_IP_PRI_NAT_DST,
    },
};

static int cvs_nat_table_init(struct net *net)
{
    int rc, i;
    if (!net_eq(net, &init_net)) return 0;
    printk(KERN_INFO "register for host net\n");
    for (i=0; i<ARRAY_SIZE(nf_nat_ipv4_ops); i++) {
        rc = nf_nat_ipv4_register_fn(net, &nf_nat_ipv4_ops[i]);
        if (rc) {
            while(i) nf_nat_ipv4_unregister_fn(net, &nf_nat_ipv4_ops[--i]);
            return rc;
        }
    }
    return 0;
}

static void __net_exit cvs_nat_net_exit(struct net *net)
{
    int i;
    if (!net_eq(net, &init_net)) return;
    for (i=0; i<ARRAY_SIZE(nf_nat_ipv4_ops); i++) {
        nf_nat_ipv4_unregister_fn(net, &nf_nat_ipv4_ops[i]);
    }
}


static int __init cvs_module_init(void) {
    int rc = cvs_nat_table_init(&init_net);
    if (rc < 0) return rc;
    return 0;
}

static void __exit cvs_module_exit(void) {
    if (entry_map != NULL) {
        bpf_map_put(entry_map);
    }
    cvs_nat_net_exit(&init_net);
    printk(KERN_INFO "Container virtual service offline\n");
}


module_init(cvs_module_init);
module_exit(cvs_module_exit);
