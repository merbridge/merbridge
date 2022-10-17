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
#include "headers/cgroup.h"
#include "headers/helpers.h"
#include "headers/maps.h"
#include "headers/mesh.h"
#include <linux/bpf.h>
#include <linux/in.h>

#if ENABLE_IPV4
__section("cgroup/sendmsg4") int mb_sendmsg4(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio and kuma
    return 1;
#endif
    if (bpf_htons(ctx->user_port) != 53) {
        return 1;
    }
    if (!is_port_listen_in_cgroup(ctx, 0, localhost, DNS_CAPTURE_PORT, DNS_CAPTURE_PORT_FLAG)) {
        // this query is not from mesh injected pod, or DNS CAPTURE not enabled.
        // we do nothing.
        return 1;
    }
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != SIDECAR_USER_ID) {
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        // needs rewrite
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, ctx->user_ip4);
        origin.port = ctx->user_port;
        // save original dst
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("update origin cookie failed: %d", cookie);
        }
        ctx->user_port = bpf_htons(DNS_CAPTURE_PORT);
        ctx->user_ip4 = localhost;
    }
    return 1;
}
#endif

#if ENABLE_IPV6
__section("cgroup/sendmsg6") int mb_sendmsg6(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio
    return 1;
#endif
    if (bpf_htons(ctx->user_port) != 53) {
        return 1;
    }
    if (!(is_port_listen_current_ns6(ctx, ip_zero6, OUT_REDIRECT_PORT) &&
          is_port_listen_udp_current_ns6(ctx, localhost6, DNS_CAPTURE_PORT))) {
        // this query is not from mesh injected pod, or DNS CAPTURE not enabled.
        // we do nothing.
        return 1;
    }
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != SIDECAR_USER_ID) {
        // needs rewrite
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        origin.port = ctx->user_port;
        set_ipv6(origin.ip, ctx->user_ip6);
        // save original dst
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("update origin cookie failed: %d", cookie);
        }
        ctx->user_port = bpf_htons(DNS_CAPTURE_PORT);
        set_ipv6(ctx->user_ip6, localhost6);
    }
    return 1;
}
#endif

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
