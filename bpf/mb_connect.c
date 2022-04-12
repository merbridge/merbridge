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

static __u32 outip = 1;
#if ENABLE_IPV4
static inline int udp_connect4(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO
    // only works on istio
    return 1;
#endif
    if (!(is_port_listen_current_ns(ctx, ip_zero, OUT_REDIRECT_PORT) &&
          is_port_listen_udp_current_ns(ctx, localhost, DNS_CAPTURE_PORT))) {
        // this query is not from mesh injected pod, or DNS CAPTURE not enabled.
        // we do nothing.
        return 1;
    }
    __u64 cookie = bpf_get_socket_cookie_addr(ctx);
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (bpf_htons(ctx->user_port) == 53 && uid != SIDECAR_USER_ID) {
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

static inline int tcp_connect4(struct bpf_sock_addr *ctx)
{
    // u64 bpf_get_current_pid_tgid(void)
    // Return A 64-bit integer containing the current tgid and
    //                 pid, and created as such: current_task->tgid << 32
    //                | current_task->pid.
    // pid may be thread id, we should use tgid
    __u32 pid = bpf_get_current_pid_tgid() >> 32; // tgid
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;

    // todo(kebe7jun) more reliable way to verify,
    if (!is_port_listen_current_ns(ctx, ip_zero, OUT_REDIRECT_PORT)) {
        // bypass normal traffic.
        // we only deal pod's traffic managed by istio.
        return 1;
    }
    if (uid != SIDECAR_USER_ID) {
        if ((ctx->user_ip4 & 0xff) == 0x7f) {
            // app call local, bypass.
            return 1;
        }
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        // app call others
        debugf("call from user container: cookie: %d, ip: 0x%x, port: %d",
               cookie, ctx->user_ip4, bpf_htons(ctx->user_port));
        // we need redirect it to envoy.
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, ctx->user_ip4);
        origin.port = ctx->user_port;
        origin.pid = pid;
        origin.flags = 1;
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("write cookie_original_dst failed");
            return 0;
        }
        // The reason we try the IP of the 127.128.0.0/20 segment instead of
        // using 127.0.0.1 directly is to avoid conflicts between the
        // quaternions of different Pods when the quaternions are subsequently
        // processed.
        ctx->user_ip4 = bpf_htonl(0x7f800000 | (outip++));
        if (outip >> 20) {
            outip = 1;
        }
        ctx->user_port = bpf_htons(OUT_REDIRECT_PORT);
    } else {
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        // from envoy to others
        debugf("call from sidecar container: cookie: %d, ip: 0x%x, port: %d",
               cookie, ctx->user_ip4, bpf_htons(ctx->user_port));
        __u32 ip[4];
        set_ipv4(ip, ctx->user_ip4);
        if (!bpf_map_lookup_elem(&local_pod_ips, ip)) {
            // dst ip is not in this node, bypass
            debugf("dest ip: 0x%x not in this node, bypass", ctx->user_ip4);
            return 1;
        }
        // dst ip is in this node, but not the current pod,
        // it is envoy to envoy connecting.
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, ctx->user_ip4);
        origin.port = ctx->user_port;
        origin.pid = pid;
        __u32 *curr_ip = bpf_map_lookup_elem(&process_ip, &pid);
        if (curr_ip) {
            // envoy to other envoy
            if (!ipv4_equal(curr_ip, ctx->user_ip4)) {
                debugf("enovy to other, rewrite dst port from %d to %d",
                       bpf_htons(ctx->user_port), IN_REDIRECT_PORT);
                ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
            }
            origin.flags |= 1;
            // envoy to app, no rewrite
        } else {
            origin.flags = 0;
#ifdef USE_RECONNECT
            // envoy to envoy
            // try redirect to 15006
            // but it may cause error if it is envoy call self pod,
            // in this case, we can read src and dst ip in sockops,
            // if src is equals dst, it means envoy call self pod,
            // we should reject this traffic in sockops,
            // envoy will create a new connection to self pod.
            ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
#endif
        }
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_NOEXIST)) {
            printk("update cookie origin failed");
            return 0;
        }
    }

    return 1;
}

__section("cgroup/connect4") int mb_sock_connect4(struct bpf_sock_addr *ctx)
{
    switch (ctx->protocol) {
    case IPPROTO_TCP:
        return tcp_connect4(ctx);
    case IPPROTO_UDP:
        return udp_connect4(ctx);
    default:
        return 1;
    }
}
#endif

#if ENABLE_IPV6
static inline int udp_connect6(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO
    // only works on istio
    return 1;
#endif
    if (!(is_port_listen_current_ns6(ctx, ip_zero6, OUT_REDIRECT_PORT) &&
          is_port_listen_udp_current_ns6(ctx, localhost6, DNS_CAPTURE_PORT))) {
        // this query is not from mesh injected pod, or DNS CAPTURE not enabled.
        // we do nothing.
        return 1;
    }
    __u64 cookie = bpf_get_socket_cookie_addr(ctx);
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (bpf_htons(ctx->user_port) == 53 && uid != SIDECAR_USER_ID) {
        // needs rewrite
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        origin.port = ctx->user_port;
        set_ipv6(origin.ip, ctx->user_ip6);
        // save original dst
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("update origin cookie failed: %d", cookie);
        }
        ctx->user_port = bpf_htons(DNS_CAPTURE_PORT);
        set_ipv6(ctx->user_ip6, localhost6);
    }
    return 1;
}

static inline int tcp_connect6(struct bpf_sock_addr *ctx)
{
    // u64 bpf_get_current_pid_tgid(void)
    // Return A 64-bit integer containing the current tgid and
    //                 pid, and created as such: current_task->tgid << 32
    //                | current_task->pid.
    // pid may be thread id, we should use tgid
    __u32 pid = bpf_get_current_pid_tgid() >> 32; // tgid
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;

    // todo(kebe7jun) more reliable way to verify,
    if (!is_port_listen_current_ns6(ctx, ip_zero6, OUT_REDIRECT_PORT)) {
        // bypass normal traffic.
        // we only deal pod's traffic managed by istio.
        return 1;
    }
    __u32 ip[4];
    set_ipv6(ip, ctx->user_ip6);
    if (uid != SIDECAR_USER_ID) {
        if (ipv6_equal(ip, localhost6)) {
            // app call local, bypass.
            return 1;
        }
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        // app call others
        debugf("call from user container: cookie: %d, ip: %pI6c, port: %d",
               cookie, ip, bpf_htons(ctx->user_port));
        // we need redirect it to envoy.
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        origin.port = ctx->user_port;
        origin.pid = pid;
        origin.flags = 1;
        set_ipv6(origin.ip, ip);
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("write cookie_original_dst failed");
            return 0;
        }
        // ::1 is the only loopback addr
        set_ipv6(ctx->user_ip6, localhost6);
        ctx->user_port = bpf_htons(OUT_REDIRECT_PORT);
    } else {
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        // from envoy to others
        debugf("call from sidecar container: cookie: %d, ip: %pI6c, port: %d",
               cookie, ip, bpf_htons(ctx->user_port));
        if (!bpf_map_lookup_elem(&local_pod_ips, ip)) {
            // dst ip is not in this node, bypass
            debugf("dest ip: %pI6c not in this node, bypass", ip);
            return 1;
        }
        // dst ip is in this node, but not the current pod,
        // it is envoy to envoy connecting.
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        origin.port = ctx->user_port;
        origin.pid = pid;
        set_ipv6(origin.ip, ip);
        __u32 *curr_ip = bpf_map_lookup_elem(&process_ip, &pid);
        if (curr_ip) {
            // envoy to other envoy
            if (!ipv6_equal(curr_ip, ip)) {
                debugf("enovy to other, rewrite dst port from %d to %d",
                       bpf_htons(ctx->user_port), IN_REDIRECT_PORT);
                ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
            }
            origin.flags |= 1;
            // envoy to app, no rewrite
        } else {
            origin.flags = 0;
#ifdef USE_RECONNECT
            // envoy to envoy
            // try redirect to 15006
            // but it may cause error if it is envoy call self pod,
            // in this case, we can read src and dst ip in sockops,
            // if src is equals dst, it means envoy call self pod,
            // we should reject this traffic in sockops,
            // envoy will create a new connection to self pod.
            ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
#endif
        }
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_NOEXIST)) {
            printk("update cookie origin failed");
            return 0;
        }
    }

    return 1;
}

__section("cgroup/connect6") int mb_sock_connect6(struct bpf_sock_addr *ctx)
{
    switch (ctx->protocol) {
    case IPPROTO_TCP:
        return tcp_connect6(ctx);
    case IPPROTO_UDP:
        return udp_connect6(ctx);
    default:
        return 1;
    }
}
#endif

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
