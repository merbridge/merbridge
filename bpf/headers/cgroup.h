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

#pragma once
#include "helpers.h"
#include "maps.h"
#include "mesh.h"
#include <linux/bpf.h>

#define DNS_CAPTURE_PORT_FLAG (1 << 1)

// get_current_cgroup_info return cgroup_id if succeed, 0 for error
static inline int get_current_cgroup_info(void *ctx,
                                          struct cgroup_info *cg_info)
{
    if (!cg_info) {
        printk("cg_info can not be NULL");
        return 0;
    }
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    void *info = bpf_map_lookup_elem(&cgroup_info_map, &cgroup_id);
    if (!info) {
        struct cgroup_info _default = {
            .is_in_mesh = 0,
            .cgroup_ip = {0, 0, 0, 0},
            .flags = 0,
            .detected_flags = 0,
        };
        // not checked ever
        if (!is_port_listen_current_ns(ctx, ip_zero, OUT_REDIRECT_PORT)) {
            // not in mesh
            _default.is_in_mesh = 0;
            debugf("can not get port listen for cgroup(%ld)", cgroup_id);
        } else {
            _default.is_in_mesh = 1;
            // get ip addresses of current pod/ns.
            struct bpf_sock_tuple tuple = {};
            tuple.ipv4.dport = bpf_htons(SOCK_IP_MARK_PORT);
            tuple.ipv4.daddr = 0;
            struct bpf_sock *s = bpf_sk_lookup_tcp(
                ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
            if (s) {
                __u32 curr_ip_mark = s->mark;
                bpf_sk_release(s);
                __u32 *ip = (__u32 *)bpf_map_lookup_elem(&mark_pod_ips_map,
                                                         &curr_ip_mark);
                if (!ip) {
                    debugf("get ip for mark 0x%x error", curr_ip_mark);
                } else {
                    set_ipv6(_default.cgroup_ip, ip); // network order
                }
            }
        }
        if (bpf_map_update_elem(&cgroup_info_map, &cgroup_id, &_default,
                                BPF_ANY)) {
            printk("update cgroup_info_map of cgroup(%ld) error", cgroup_id);
            return 0;
        }
        *cg_info = _default;
    } else {
        *cg_info = *(struct cgroup_info *)info;
    }
    return cgroup_id;
}

// is_port_listen_in_cgroup is used to detect whether a port is listened to in
// the current cgroup, using cgroup_info_map for caching.
static inline int is_port_listen_in_cgroup(void *ctx, __u16 is_tcp, __u32 ip,
                                           __u16 port, __u16 port_flag)
{
    struct cgroup_info cg_info;
    __u64 cgroup_id = get_current_cgroup_info(ctx, &cg_info);
    if (!cgroup_id) {
        return 0;
    }
    if (!cg_info.is_in_mesh) {
        return 0;
    }
    if (cg_info.detected_flags & port_flag) {
        if (cg_info.flags & port_flag) {
            return 1;
        }
        return 0;
    }
    // need detect
    int listen;
    if (is_tcp) {
        listen = is_port_listen_current_ns(ctx, ip, port);
    } else {
        listen = is_port_listen_udp_current_ns(ctx, ip, port);
    }
    cg_info.detected_flags |= port_flag;
    if (listen)
        cg_info.flags |= port_flag;
    bpf_map_update_elem(&cgroup_info_map, &cgroup_id, &cg_info, BPF_ANY);
    return listen;
}
