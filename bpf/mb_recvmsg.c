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
__section("cgroup/recvmsg4") int mb_recvmsg4(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio and kuma
    return 1;
#endif
    if (bpf_htons(ctx->user_port) != DNS_CAPTURE_PORT) {
        return 1;
    }
    if (!(is_port_listen_current_ns(ctx, ip_zero, OUT_REDIRECT_PORT) &&
          is_port_listen_udp_current_ns(ctx, localhost, DNS_CAPTURE_PORT))) {
        // printk("not from pod");
        return 1;
    }
    __u64 cookie = bpf_get_socket_cookie_addr(ctx);
    struct origin_info *origin = (struct origin_info *)bpf_map_lookup_elem(
        &cookie_original_dst, &cookie);
    if (origin) {
        ctx->user_port = origin->port;
        ctx->user_ip4 = get_ipv4(origin->ip);
        debugf("successfully deal DNS redirect query");
    } else {
        printk("failed to get origin");
    }
    return 1;
}
#endif

#if ENABLE_IPV6
__section("cgroup/recvmsg6") int mb_recvmsg6(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio
    return 1;
#endif
    if (bpf_htons(ctx->user_port) != DNS_CAPTURE_PORT) {
        return 1;
    }
    if (!(is_port_listen_current_ns6(ctx, ip_zero6, OUT_REDIRECT_PORT) &&
          is_port_listen_udp_current_ns6(ctx, localhost6, DNS_CAPTURE_PORT))) {
        // printk("not from pod");
        return 1;
    }

    __u64 cookie = bpf_get_socket_cookie_addr(ctx);
    struct origin_info *origin = (struct origin_info *)bpf_map_lookup_elem(
        &cookie_original_dst, &cookie);
    if (origin) {
        ctx->user_port = origin->port;
        set_ipv6(ctx->user_ip6, origin->ip);
        debugf("successfully deal DNS redirect query");
    } else {
        printk("failed to get origin");
    }
    return 1;
}
#endif

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
