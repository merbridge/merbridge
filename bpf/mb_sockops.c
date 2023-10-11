/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "headers/helpers.h"
#include "headers/maps.h"
#include "headers/mesh.h"
#include <linux/bpf.h>
#include <linux/in.h>

#if ENABLE_IPV4
static inline int sockops_ipv4(struct bpf_sock_ops *skops)
{
    __u64 cookie = bpf_get_socket_cookie_ops(skops);

    struct pair p;
    set_ipv4(p.sip, skops->local_ip4);
    p.sport = bpf_htons(skops->local_port);
    set_ipv4(p.dip, skops->remote_ip4);
    p.dport = skops->remote_port >> 16;

    struct origin_info *dst =
        bpf_map_lookup_elem(&cookie_original_dst, &cookie);
    if (dst) {
        struct origin_info dd = *dst;
        if (!(dd.flags & 1)) {
            __u32 pid = dd.pid;
            // process ip not detected
            if (skops->local_ip4 == envoy_ip ||
                skops->local_ip4 == skops->remote_ip4) {
                // envoy to local
                __u32 ip = skops->remote_ip4;
                debugf("detected process %d's ip is %pI4", pid, &ip);
                bpf_map_update_elem(&process_ip, &pid, &ip, BPF_ANY);
#ifdef USE_RECONNECT
                if (skops->remote_port >> 16 == bpf_htons(IN_REDIRECT_PORT)) {
                    printk("incorrect connection: cookie=%d", cookie);
                    return 1;
                }
#endif
            } else {
                // envoy to envoy
                __u32 ip = skops->local_ip4;
                bpf_map_update_elem(&process_ip, &pid, &ip, BPF_ANY);
                debugf("detected process %d's ip is %pI4", pid, &ip);
            }
        }
        // get_sockopts can read pid and cookie,
        // we should write a new map named pair_original_dst
        bpf_map_update_elem(&pair_original_dst, &p, &dd, BPF_ANY);
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    } else if (skops->local_port == OUT_REDIRECT_PORT ||
               skops->local_port == IN_REDIRECT_PORT ||
               skops->remote_ip4 == envoy_ip) {
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    } else {
        // ztunnel use zero copy, which may be conflict with
        // bpf_msg_redirect_hash, so we ignore it now.
        // __u32 *ztunnel_ip = get_ztunnel_ip();
    }
    return 0;
}
#endif

#if ENABLE_IPV6
static inline int sockops_ipv6(struct bpf_sock_ops *skops)
{
    __u64 cookie = bpf_get_socket_cookie_ops(skops);
    struct pair p;
    memset(&p, 0, sizeof(p));
    p.sport = bpf_htons(skops->local_port);
    p.dport = skops->remote_port >> 16;
    set_ipv6(p.sip, skops->local_ip6);
    set_ipv6(p.dip, skops->remote_ip6);

    struct origin_info *dst =
        bpf_map_lookup_elem(&cookie_original_dst, &cookie);
    if (dst) {
        struct origin_info dd = *dst;
        // get_sockopts can read pid and cookie,
        // we should write a new map named pair_original_dst
        bpf_map_update_elem(&pair_original_dst, &p, &dd, BPF_ANY);
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    } else if (skops->local_port == OUT_REDIRECT_PORT ||
               skops->local_port == IN_REDIRECT_PORT ||
               ipv6_equal(skops->remote_ip6, envoy_ip6)) {
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    }
    return 0;
}
#endif

__section("sockops") int mb_sockops(struct bpf_sock_ops *skops)
{
    switch (skops->op) {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        switch (skops->family) {
#if ENABLE_IPV4
        case 2:
            // AF_INET, we don't include socket.h, because it may
            // cause an import error.
            return sockops_ipv4(skops);
#endif
#if ENABLE_IPV6
        case 10:
            // AF_INET6
            return sockops_ipv6(skops);
#endif
        }
        return 0;
    }
    return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
