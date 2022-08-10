
typedef struct { unsigned int ip, _; } VIPKNode;
typedef struct { unsigned int n, _; } VIPVNode;
typedef struct { unsigned int ip, _; } RIPNode;

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static const char *root =  "/sys/fs/bpf/cvs/";
static const char *root_vip =  "/sys/fs/bpf/cvs/s";


static void build_path(char *outpath, unsigned int ip) {
    int k, v, i=0;
    while(root[i]) {
        outpath[i]=root[i];
        i++;
    }
    for (k=0; k<8; k++) {
        v = ip&0xf; ip>>=4;
        if (v<10) outpath[i++]=v+'0';
        else outpath[i++]=v-10+'A';
    }
    outpath[i]=0;
}
