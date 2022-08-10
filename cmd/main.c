#include <stdio.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <string.h>
#include "../include/common.h"


static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

const char *help = "POC for vip loadbalance via bpf maps and netfilter.\n\
To add new entry: cvsadm push [vip] [rip]\n\
To remove last entry: cvsadm pop [vip]\n\
To list rip: cvsadm list [vip]\n";

int get_vip_fd(unsigned int vip) {
    char path[64];
    union bpf_attr attr_create, attr_pin;
    int fd, rc;
    memset(&attr_pin, 0, sizeof(attr_pin));
    memset(&attr_create, 0, sizeof(attr_create));
    build_path(path, vip);
    attr_pin.pathname = ptr_to_u64(path);
    fd = sys_bpf(BPF_OBJ_GET, &attr_pin, sizeof(attr_pin));
    if (fd<0) {
        attr_create.map_type = BPF_MAP_TYPE_ARRAY;
        attr_create.key_size    = 4;
        attr_create.value_size  = sizeof(RIPNode);
        attr_create.max_entries = 1024;
        printf("vip bpf map not initialized, create it now\n");
        fd = sys_bpf(BPF_MAP_CREATE, &attr_create, sizeof(attr_create));
        if (fd<0) {
            perror("fail to create bpf map for vip:");
            return -1;
        }
        attr_pin.bpf_fd = fd;
        rc = sys_bpf(BPF_OBJ_PIN, &attr_pin, sizeof(attr_pin));
        if (rc != 0) {
            perror("fail to pin root bpf map:");
            return -1;
        }
    }
    return fd;
}

int get_root_fd() {
    union bpf_attr attr_create, attr_pin;
    int fd, rc;
    memset(&attr_pin, 0, sizeof(attr_pin));
    memset(&attr_create, 0, sizeof(attr_create));
    attr_pin.pathname = ptr_to_u64(root_vip);
    fd = sys_bpf(BPF_OBJ_GET, &attr_pin, sizeof(attr_pin));
    if (fd<0) {
        attr_create.map_type = BPF_MAP_TYPE_HASH;
        attr_create.key_size    = sizeof(VIPKNode);
        attr_create.value_size  = sizeof(VIPVNode);
        attr_create.max_entries = 1024;
        printf("root bpf map not initialized, create it now\n");
        fd = sys_bpf(BPF_MAP_CREATE, &attr_create, sizeof(attr_create));
        if (fd<0) {
            perror("fail to create bpf map:");
            return -1;
        }
        attr_pin.bpf_fd = fd;
        rc = sys_bpf(BPF_OBJ_PIN, &attr_pin, sizeof(attr_pin));
        if (rc != 0) {
            perror("fail to pin root bpf map:");
            return -1;
        }
    }
    return fd;
}

unsigned int parse_ip(char *p) {
    int k, i=0, b;
    unsigned int ip=0;
    for (k=0; k<4; k++) {
        b=0;
        if (p[i]<'0'||p[i]>'9') return 0;
        while(p[i]>='0'&&p[i]<='9') {
            b=b*10+p[i++]-'0';
            if (b>256) return 0;
        }
        if (p[i]!=0&&p[i]!='.') return 0;
        ip |= b<<(k*8);
        if (k==3) break;
        i++;
    }
    if (p[i]!=0) return 0;
    return ip;
}

void print_ip(unsigned int ip) {
    int k;
    int bs[4];
    for (k=0; k<4; k++) {
        bs[k] = ip&0xff;
        ip>>=8;
    }
    printf("%d.%d.%d.%d\n", bs[0], bs[1], bs[2], bs[3]);
}

int main(int argc, char *argv[]) {
    unsigned int vip, ip;
    int i, rc, fd;
    union bpf_attr attr_elem;
    VIPKNode key;
    VIPVNode value;
    RIPNode rip;
    int root_fd = get_root_fd();
    if (root_fd < 0) return -1;
    memset(&attr_elem, 0, sizeof(attr_elem));
    attr_elem.flags = BPF_ANY;

    
    if (argc==3&&strcmp(argv[1], "list")==0) {
        vip = parse_ip(argv[2]);
        if (vip==0) {
            printf("invalid ip: %s\n", argv[2]);
            return -1;
        }
        key.ip = vip; key._ = 0;
        attr_elem.map_fd = root_fd;
        attr_elem.key    = ptr_to_u64(&key);
        attr_elem.value    = ptr_to_u64(&value);
        rc = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("vip not found\n");
            return 0;
        }
        fd = get_vip_fd(vip);
        if (fd<0) return -1;
        printf("vip: %s\n", argv[2]);
        attr_elem.map_fd = fd;
        for (i=0; i<value.n; i++) {
            attr_elem.key    = ptr_to_u64(&i);
            attr_elem.value    = ptr_to_u64(&rip);
            rc = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr_elem, sizeof(attr_elem));
            if (rc<0) {
                perror("lookup failed\n");
                return -1;
            }
            print_ip(rip.ip);
        }
    } else if (argc==3&&strcmp(argv[1], "pop")==0) {
        vip = parse_ip(argv[2]);
        if (vip==0) {
            printf("invalid ip: %s\n", argv[2]);
            return -1;
        }
        key.ip = vip; key._ = 0;
        attr_elem.map_fd = root_fd;
        attr_elem.key    = ptr_to_u64(&key);
        attr_elem.value    = ptr_to_u64(&value);
        rc = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("vip not found\n");
            return 0;
        }
        if (value.n==0) {
            printf("no real ip to pop\n");
            return 0;
        }
        // remove index value.n-1
        /* array, no need to delete, just bookmark the length
        fd = get_vip_fd(vip);
        if (fd<0) return -1;
        i = value.n-1;
        attr_elem.map_fd = fd;
        attr_elem.key    = ptr_to_u64(&i);
        attr_elem.value    = ptr_to_u64(&rip);
        // attr_elem.value  = 0;
        rc = sys_bpf(BPF_MAP_DELETE_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            perror("fail to pop vip");
            return -1;
        }
        */
        value.n-=1;
        attr_elem.map_fd = root_fd;
        attr_elem.key    = ptr_to_u64(&key);
        attr_elem.value  = ptr_to_u64(&value);
        rc = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("fail to sync count\n");
            return -1;
        }
    } else if (argc==4&&strcmp(argv[1], "push")==0) {
        vip = parse_ip(argv[2]);
        if (vip==0) {
            printf("invalid ip: %s\n", argv[2]);
            return -1;
        }
        key.ip = vip; key._ = 0;
        attr_elem.map_fd = root_fd;
        attr_elem.key    = ptr_to_u64(&key);
        attr_elem.value    = ptr_to_u64(&value);
        rc = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("vip not found, adding new entry now\n");
            value.n=0;
            rc = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr_elem, sizeof(attr_elem));
            if (rc!=0) {
                perror("fail to register new vip\n");
                return -1;
            }
        }
        ip = parse_ip(argv[3]);
        if (ip==0) {
            printf("invalid ip: %s\n", argv[3]);
            return -1;
        }
        fd = get_vip_fd(vip);
        if (fd<0) return -1;
        i = value.n;
        rip.ip = ip;
        attr_elem.map_fd = fd;
        attr_elem.key    = ptr_to_u64(&i);
        attr_elem.value  = ptr_to_u64(&rip);
        rc = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("fail to add new rip\n");
            return -1;
        }
        value.n+=1;
        attr_elem.map_fd = root_fd;
        attr_elem.key    = ptr_to_u64(&key);
        attr_elem.value  = ptr_to_u64(&value);
        rc = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("fail to sync count\n");
            return -1;
        }
        
    } else {
        printf(help);
        return -1;
    }

    return 0;
}
