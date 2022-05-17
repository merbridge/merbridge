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

static inline int udp4_connect(struct bpf_sock_addr *ctx)
{

#if MESH != ISTIO
    // only works on istio
    return 1;
#endif
    if (!(is_port_listen_current_ns(ctx, 0, OUT_REDIRECT_PORT) &&
          is_port_listen_udp_current_ns(ctx, 0x7f000001, DNS_CAPTURE_PORT))) {
        // this query is not from mesh injected pod, or DNS CAPTURE not enabled.
        // we do nothing.
        return 1;
    }
    __u64 cookie = bpf_get_socket_cookie_addr(ctx);
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (bpf_htons(ctx->user_port) == 53 && uid != SIDECAR_USER_ID) {
        // needs rewrite
        struct origin_info origin = {.ip = ctx->user_ip4,
                                     .port = ctx->user_port};
        // save original dst
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("update origin cookie failed: %d", cookie);
        }
        ctx->user_port = bpf_htons(DNS_CAPTURE_PORT);
        ctx->user_ip4 = 0x100007f;
    }
    return 1;
}

static inline int tcp4_connect(struct bpf_sock_addr *ctx)
{
    // todo(kebe7jun) more reliable way to verify,
    if (!is_port_listen_current_ns(ctx, 0, OUT_REDIRECT_PORT)) {
        // bypass normal traffic.
        // we only deal pod's traffic managed by istio.
        return 1;
    }
    __u32 curr_pod_ip = 0;
    {
        // get ip addresses of current pod/ns.
        __u32 curr_ip_mark = 0;
        struct bpf_sock_tuple tuple = {};
        tuple.ipv4.dport = bpf_htons(SOCK_IP_MARK_PORT);
        tuple.ipv4.daddr = 0;
        struct bpf_sock *s = bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4),
                                               BPF_F_CURRENT_NETNS, 0);
        if (s) {
            curr_ip_mark = s->mark;
            bpf_sk_release(s);
            __u32 *ip = bpf_map_lookup_elem(&mark_pod_ips_map, &curr_ip_mark);
            if (ip) {
                curr_pod_ip = *ip; // network order
            } else {
                debugf("get ip for mark %x error", curr_ip_mark);
            }
        }
    }
    if (curr_pod_ip == 0) {
        debugf("get current pod ip error");
    }
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    __u32 pid;
    if (uid != SIDECAR_USER_ID) {
        if ((ctx->user_ip4 & 0xff) == 0x7f) {
            // app call local, bypass.
            return 1;
        }
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        // app call others
        debugf("call from user container: cookie: %d, ip: 0x%x, port: %d",
               cookie, ctx->user_ip4, bpf_htons(ctx->user_port));
        // u64 bpf_get_current_pid_tgid(void)
        // Return A 64-bit integer containing the current tgid and
        //                 pid, and created as such: current_task->tgid << 32
        //                | current_task->pid.
        // pid may be thread id, we should use tgid
        pid = bpf_get_current_pid_tgid() >> 32; // tgid
        // we need redirect it to envoy.
        struct origin_info origin = {
            .ip = ctx->user_ip4,
            .port = ctx->user_port,
            .pid = pid,
            .flags = 1,
        };
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("write cookie_original_dst failed");
            return 0;
        }
        if (curr_pod_ip) {
            __u32 ip = curr_pod_ip;
            struct pod_config *pod = bpf_map_lookup_elem(&local_pod_ips, &ip);
            if (pod) {
                int exclude = 0;
                IS_EXCLUDE_PORT(pod->exclude_out_ports, ctx->user_port,
                                &exclude);
                if (exclude) {
                    debugf("ignored dest port by exclude_out_ports, ip: "
                           "%x, port: %d",
                           ip, bpf_htons(ctx->user_port));
                    return 1;
                }
                IS_EXCLUDE_IPRANGES(pod->exclude_out_ranges, ctx->user_ip4,
                                    &exclude);
                debugf("exclude ipranges: %x, exclude: %d",
                       pod->exclude_out_ranges[0].net, exclude);
                if (exclude) {
                    debugf("ignored dest ranges by exclude_out_ranges, ip: %x",
                           ctx->user_ip4);
                    return 1;
                }
                int include = 0;
                IS_INCLUDE_PORT(pod->include_out_ports, ctx->user_port,
                                &include);
                if (!include) {
                    debugf("dest port %d not in pod(%x)'s include_out_ports, "
                           "ignored.",
                           bpf_htons(ctx->user_port), ip);
                    return 1;
                }

                IS_INCLUDE_IPRANGES(pod->include_out_ranges, ctx->user_ip4,
                                    &include);
                if (!include) {
                    debugf(
                        "dest %x not in pod(%x)'s include_out_ranges, ignored.",
                        ctx->user_ip4, ip);
                    return 1;
                }
            } else {
                debugf("current pod ip found(%x), but can not find pod_info "
                       "from local_pod_ips",
                       curr_pod_ip);
            }
            // todo port or ipranges ignore.
            // if we can get the pod ip, we use bind func to bind the pod's ip
            // as the source ip to avoid quaternions conflict of different pods.
            struct sockaddr_in addr;
            addr.sin_addr.s_addr = curr_pod_ip;
            addr.sin_port = 0;
            addr.sin_family = 2;
            if (bpf_bind(ctx, &addr, sizeof(struct sockaddr_in))) {
                printk("bind %x error", curr_pod_ip);
            }
            ctx->user_ip4 = bpf_htonl(0x7f000001);
        } else {
            // if we can not get the pod ip, we rewrite the dest address.
            // The reason we try the IP of the 127.128.0.0/20 segment instead of
            // using 127.0.0.1 directly is to avoid conflicts between the
            // quaternions of different Pods when the quaternions are
            // subsequently processed.
            ctx->user_ip4 = bpf_htonl(0x7f800000 | (outip++));
            if (outip >> 20) {
                outip = 1;
            }
        }
        ctx->user_port = bpf_htons(OUT_REDIRECT_PORT);
    } else {
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        // from envoy to others
        debugf("call from sidecar container: cookie: %d, ip: 0x%x, port: %d",
               cookie, ctx->user_ip4, bpf_htons(ctx->user_port));
        __u32 ip = ctx->user_ip4;
        if (!bpf_map_lookup_elem(&local_pod_ips, &ip)) {
            // dst ip is not in this node, bypass
            debugf("dest ip: 0x%x not in this node, bypass", ctx->user_ip4);
            return 1;
        }
        pid = bpf_get_current_pid_tgid() >> 32;
        // dst ip is in this node, but not the current pod,
        // it is envoy to envoy connecting.
        struct origin_info origin = {
            .ip = ctx->user_ip4,
            .port = ctx->user_port,
            .pid = pid,
        };
        if (curr_pod_ip) {
            origin.flags |= 1;
            if (curr_pod_ip != ip) {
                // call other pod, need redirect port.
                struct pod_config *pod =
                    bpf_map_lookup_elem(&local_pod_ips, &ip);
                if (pod) {
                    int exclude = 0;
                    IS_EXCLUDE_PORT(pod->exclude_in_ports, ctx->user_port,
                                    &exclude);
                    if (exclude) {
                        debugf("ignored dest port by exclude_in_ports, ip: %x, "
                               "port: %d",
                               ip, bpf_htons(ctx->user_port));
                        return 1;
                    }
                    int include = 0;
                    IS_INCLUDE_PORT(pod->include_in_ports, ctx->user_port,
                                    &include);
                    if (!include) {
                        debugf("ignored dest port by include_in_ports, ip: %x, "
                               "port: %d",
                               ip, bpf_htons(ctx->user_port));
                        return 1;
                    }
                }
                ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
            }
        } else {
            // can not get current pod ip, we use the lagecy mode.
            void *curr_ip = bpf_map_lookup_elem(&process_ip, &pid);
            if (curr_ip) {
                // envoy to other envoy
                if (*(__u32 *)curr_ip != ctx->user_ip4) {
                    debugf("enovy to other, rewrite dst port from %d to %d",
                           ctx->user_port, IN_REDIRECT_PORT);
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
        }
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_NOEXIST)) {
            printk("update cookie origin failed");
            return 0;
        }
    }

    return 1;
}

__section("cgroup/connect4") int mb_sock4_connect(struct bpf_sock_addr *ctx)
{
    switch (ctx->protocol) {
    case IPPROTO_TCP:
        return tcp4_connect(ctx);
    case IPPROTO_UDP:
        return udp4_connect(ctx);
    default:
        return 1;
    }
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
