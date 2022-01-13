#include <linux/bpf.h>
#include <linux/in.h>
#include "helpers.h"

#define MAX_OPS_BUFF_LENGTH 4096

struct bpf_map __section("maps") pair_original_dst = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(struct pair),
	.value_size     = sizeof(struct origin_info),
	.max_entries    = 65535,
	.map_flags      = 0,
};

__section("cgroup/getsockopt")
int get_sockopt(struct bpf_sockopt *ctx)
{
    // char comm[80];
	// __u64 ptg = bpf_get_current_pid_tgid();
    // bpf_get_current_comm(comm, sizeof(comm));
	// __u64 ptg = bpf_get_current_pid_tgid();
    if (ctx->optlen > MAX_OPS_BUFF_LENGTH) {
        printk("optname: %d, unexpected optlen %d, reset to %d", ctx->optname, ctx->optlen, MAX_OPS_BUFF_LENGTH);
        ctx->optlen = MAX_OPS_BUFF_LENGTH;
    }
    if (ctx->optname == 80) {
        struct pair p;
        p.sip = ctx->sk->src_ip4;
        p.sport = bpf_htons(ctx->sk->src_port);
        p.dip = ctx->sk->dst_ip4;
        p.dport = bpf_htons(ctx->sk->dst_port);
        struct origin_info *origin;
        origin = bpf_map_lookup_elem(&pair_original_dst, &p);
        if (!origin) {
            printk("get sockopt1 origin error: %d -> %d", p.sip, p.dip);
            printk("get sockopt1 origin port error: %d -> %d", p.sport, p.dport);
            p.dip = ctx->sk->src_ip4;
            p.dport = bpf_htons(ctx->sk->src_port);
            p.sip = ctx->sk->dst_ip4;
            p.sport = bpf_htons(ctx->sk->dst_port);
            origin = bpf_map_lookup_elem(&pair_original_dst, &p);
        }
        if (origin) {
            printk("get sockopt origin: %d:%d", origin->ip, origin->port);
            // rewrite original_dst
            ctx->optlen = (__s32)sizeof(struct sockaddr_in);
            if ((void*)((struct sockaddr_in*)ctx->optval+1) > ctx->optval_end) {
                return 1;
            }
            ctx->retval = 0;
            struct sockaddr_in sa;
            sa.sin_family = ctx->sk->family;
            sa.sin_addr.s_addr = origin->ip;
            sa.sin_port = origin->port;
            *(struct sockaddr_in*)ctx->optval = sa;
        } else {
            printk("get sockopt2 origin error: %d -> %d", p.sip, p.dip);
            printk("get sockopt2 origin port error: %d -> %d", p.sport, p.dport);
        }
    }
	return 1;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
