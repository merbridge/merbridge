#include "headers/helpers.h"
#include "headers/maps.h"
#include "headers/mesh.h"
#include <linux/bpf.h>
#include <linux/in.h>

static inline int sockops_ipv4(struct bpf_sock_ops *skops)
{
    __u64 cookie = bpf_get_socket_cookie_ops(skops);

    void *dst = bpf_map_lookup_elem(&cookie_original_dst, &cookie);
    if (dst) {
        struct origin_info dd = *(struct origin_info *)dst;
        if (bpf_htons(dd.re_dport) == IN_REDIRECT_PORT &&
            (skops->local_ip4 == 100663423 ||
             skops->local_ip4 == skops->remote_ip4)) {
            // the is an incorrrct connection,
            // envoy want to call self container port,
            // but we send it to wrong port(15006).
            // we should reject this connection.
            // and alse update process_ip table.
            printk("incorrect connection: cookie=%d", cookie);
            __u32 pid = dd.pid;
            __u32 ip = skops->remote_ip4;
            bpf_map_update_elem(&process_ip, &pid, &ip, BPF_ANY);
            return 1;
        }
        // get_sockopts can read pid and cookie,
        // we should write a new map named pair_original_dst
        struct pair p = {
            .sip = skops->local_ip4,
            .sport = skops->local_port,
            .dip = skops->remote_ip4,
            .dport = skops->remote_port >> 16,
        };
        bpf_map_update_elem(&pair_original_dst, &p, &dd, BPF_NOEXIST);
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    }
    return 0;
}

__section("sockops") int mb_sockops(struct bpf_sock_ops *skops)
{
    __u32 family, op;
    family = skops->family;
    op = skops->op;

    switch (op) {
    // case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        if (family == 2) { // AFI_NET, we dont include socket.h, because it may
                           // cause an import error.
            if (sockops_ipv4(skops))
                return 1;
            else
                return 0;
        }
        break;
    default:
        break;
    }
    return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
