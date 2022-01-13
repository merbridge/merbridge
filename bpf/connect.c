#include <linux/bpf.h>
#include <linux/in.h>
#include "helpers.h"
#include "istio.h"

struct bpf_map __section("maps") cookie_original_dst = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(struct origin_info),
	.max_entries    = 65535,
	.map_flags      = 0,
};

// local_pods stores Pods' ips in current node.
// which can be set by controller.
// only contains injected pods.
struct bpf_map __section("maps") local_pod_ips = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(__u32),
	.max_entries    = 65535,
	.map_flags      = 0,
};

// process_ip stores envoy's ip address.
struct bpf_map __section("maps") process_ip = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(__u32),
	.max_entries    = 65535,
	.map_flags      = 0,
};

static __u32 outip = 1;

__section("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx)
{
    // init
    if (ctx->protocol != IPPROTO_TCP) {
        return 1;
    }
    __u32 flag = 0;
    if (!bpf_map_lookup_elem(&local_pod_ips, &flag)) {
        printk("init ip tables");
        __u32 ip1 = 50394122;
        __u32 ip2 = 117502986;
        __u32 v1 = 0;
        __u32 v2 = 0;
        __u32 v3 = 0;
        bpf_map_update_elem(&local_pod_ips, &ip1, &v1, BPF_NOEXIST);
        bpf_map_update_elem(&local_pod_ips, &ip2, &v2, BPF_NOEXIST);
        bpf_map_update_elem(&local_pod_ips, &flag, &v3, BPF_NOEXIST);
    }
    char comm[80];
	// __u64 ptg = bpf_get_current_pid_tgid() & 0xffffffff;
    __u32 pid = bpf_get_current_pid_tgid() & 0xffffffff;
    bpf_get_current_comm(comm, sizeof(comm));
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    // printk("comm: %s, tgid: %d, pid: %d", comm, ptg >> 32, ptg & 0xffffffff);
    // printk("cookie: %d, connect to: ip: %x  port: %d", cookie, bpf_htonl(ctx->user_ip4), bpf_htons(ctx->user_port));

    if (is_port_listen_current_ns(ctx, ISTIO_OUT_PORT)) {
        if (uid != 1337) {
            if (bpf_htonl(ctx->user_ip4) >> 24 == 0x7f) {
                return 1;
            }
            // app -> others
            // we need redirect it to envoy.
            printk("connect app -> others: %x %d", bpf_htonl(ctx->user_ip4), bpf_htons(ctx->user_port));
            __u64 cookie = bpf_get_socket_cookie_addr(ctx);
            printk("updated cookie %d with %d:%d", cookie, ctx->user_ip4, ctx->user_port);
            struct origin_info origin;
            origin.ip = ctx->user_ip4;
            origin.port = ctx->user_port;
            origin.pid = pid;
            origin.re_dport = bpf_htons(ISTIO_OUT_PORT);
            if(bpf_map_update_elem(&cookie_original_dst, &cookie, &origin, BPF_ANY)) 
            {
                // printk("write cookie_original_dst failed");
                return 0;
            }
            ctx->user_ip4 = bpf_htonl(0x7f800000 | (outip++));
            if (outip >> 20) {
                outip = 1;
            }
            ctx->user_port = bpf_htons(ISTIO_OUT_PORT);
        }
        else {
            // from envoy to others
            printk("call from envoy");
            __u32 ip = ctx->user_ip4;
            if (!bpf_map_lookup_elem(&local_pod_ips, &ip)) {
                // dst ip is not in this node, bypass
                printk("dst ip is not in this node: %d", ip);
                return 1;
            }
            // dst ip is in this node, but not the current pod, 
            // it is envoy to envoy connecting.
            printk("connect envoy -> other envoy: %d %d", ctx->user_ip4, ctx->user_port);
            __u64 cookie = bpf_get_socket_cookie_addr(ctx);
            struct origin_info origin;
            origin.ip = ctx->user_ip4;
            origin.port = ctx->user_port;
            origin.pid = pid;
            origin.re_dport = bpf_htons(ISTIO_IN_PORT);
            if(bpf_map_update_elem(&cookie_original_dst, &cookie, &origin, BPF_NOEXIST)) {
                printk("update cookie origin failed");
                return 0;
            }
            void* curr_ip = bpf_map_lookup_elem(&process_ip, &pid);
            if (!curr_ip || *(__u32*)curr_ip != ctx->user_ip4) {
                // try redirect to 15006
                // but it may cause error if it is envoy call self pod,
                // in this case, we can read src and dst ip in sockops,
                // if src is equals dst, it means envoy call self pod,
                // we should reject this traffic in sockops,
                // envoy will create a new connection to self pod.
                ctx->user_port = bpf_htons(ISTIO_IN_PORT);
                printk("rewrite envoy to envoy port: pid: %d", pid);
            }
        }
    }

	return 1;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
