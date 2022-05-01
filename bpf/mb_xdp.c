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
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static __always_inline __u32 csum_add(__u32 addend, __u32 csum)
{
    __u32 res = csum;
    res += addend;
    return (res + (res < addend));
}

static __always_inline __u32 csum_sub(__u32 addend, __u32 csum)
{
    return csum_add(csum, ~addend);
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    __u32 r = csum << 16 | csum >> 16;
    csum = ~csum;
    csum -= r;
    return (__u16)(csum >> 16);
}

static __always_inline __u16 csum_diff4(__u32 from, __u32 to, __u16 csum)
{
    __u32 tmp = csum_sub(from, ~((__u32)csum));
    return csum_fold_helper(csum_add(to, tmp));
}

__section("xdp") int mb_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }
    if (bpf_htons(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_DROP;
    }

    if (iph->protocol == IPPROTO_IPIP) {
        iph = ((void *)iph + iph->ihl * 4);
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }
    }

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if ((void *)(tcph + 1) > data_end) {
        return XDP_DROP;
    }
    if (tcph->syn && !tcph->ack) {
        // first packet
        if (tcph->dest == bpf_htons(IN_REDIRECT_PORT)) {
            // same node, already rewrite dest port by connect.
            // bypass.
            return XDP_PASS;
        }
        // ingress without mb_connect
        __u32 ip = iph->daddr;
        struct pod_config *pod = bpf_map_lookup_elem(&local_pod_ips, &ip);
        if (!pod) {
            // dest ip is not on this node or not injected sidecar.
            return XDP_PASS;
        }
        if (bpf_htons(tcph->dest) == pod->status_port) {
            return XDP_PASS;
        }
        int exclude = 0;
        IS_EXCLUDE_PORT(pod->exclude_in_ports, tcph->dest, &exclude);
        if (exclude) {
            debugf("ignored dest port by exclude_in_ports, ip: %x, port: %d",
                   iph->daddr, bpf_htons(tcph->dest));
            return XDP_PASS;
        }
        int include = 0;
        IS_INCLUDE_PORT(pod->include_in_ports, tcph->dest, &include);
        if (!include) {
            debugf("ignored dest port by include_in_ports, ip: %x, port: %d",
                   iph->daddr, bpf_htons(tcph->dest));
            return XDP_PASS;
        }

        // like from 10.0.0.1:23456 => 172.31.0.123:80
        // we will rewrite the dest port from 80 to 15006
        // which will be: 10.0.0.1:23456 => 172.31.0.123:15006
        struct pair p = {
            .sip = iph->saddr,
            .sport = tcph->source,
            .dip = iph->daddr,
            .dport = bpf_htons(IN_REDIRECT_PORT),
        };
        struct origin_info origin = {
            .ip = iph->daddr,
            .port = tcph->dest,
            .flags = XDP_ORIGIN_FLAG,
        };
        bpf_map_update_elem(&pair_original_dst, &p, &origin, BPF_NOEXIST);
        __u16 oldd = tcph->dest;
        tcph->dest = bpf_htons(IN_REDIRECT_PORT); // rewrite dest port.
        tcph->check = csum_diff4(oldd, tcph->dest, tcph->check);
    } else if (tcph->source == bpf_htons(IN_REDIRECT_PORT)) {
        // response
        // like from 172.31.0.123:15006 => 10.0.0.1:23456
        // to avoid the client drop packet, we must reset the source port from
        // 15006 to 80.
        struct pair p = {
            .dip = iph->saddr,
            .dport = tcph->source,
            .sip = iph->daddr,
            .sport = tcph->dest,
        };
        struct origin_info *origin =
            bpf_map_lookup_elem(&pair_original_dst, &p);
        if (!origin) {
            // not exists
            debugf("resp origin not found");
            return XDP_PASS;
        }
        if (!(origin->flags & XDP_ORIGIN_FLAG)) {
            // not xdp origin
            printk("resp origin flags %x error", origin->flags);
            return XDP_PASS;
        }
        __u16 olds = tcph->source;
        tcph->source = origin->port; // rewrite source port.
        tcph->check = csum_diff4(olds, tcph->source, tcph->check);
    } else {
        // request
        struct pair p = {
            .sip = iph->saddr,
            .sport = tcph->source,
            .dip = iph->daddr,
            .dport = bpf_htons(IN_REDIRECT_PORT),
        };
        struct origin_info *origin =
            bpf_map_lookup_elem(&pair_original_dst, &p);
        if (!origin) {
            // not exists
            // char srcip[16];
            // ipstr(iph->saddr, srcip);
            // char dip[16];
            // ipstr(iph->daddr, dip);
            // debugf("request origin not found %s -> %s", srcip, dip);
            // debugf("request origin not found port %d -> %d",
            //        bpf_htons(tcph->source), bpf_htons(tcph->dest));
            return XDP_PASS;
        }
        if (!(origin->flags & XDP_ORIGIN_FLAG)) {
            // not xdp origin
            return XDP_PASS;
        }
        __u16 oldd = tcph->dest;
        tcph->dest = bpf_htons(IN_REDIRECT_PORT); // rewrite dest port.
        tcph->check = csum_diff4(oldd, tcph->dest, tcph->check);
    }
    if (tcph->fin && tcph->ack) {
        // todo delete key
        struct pair p = {
            .dip = iph->saddr,
            .dport = tcph->source,
            .sip = iph->daddr,
            .sport = bpf_htons(IN_REDIRECT_PORT),
        };
        bpf_map_delete_elem(&pair_original_dst, &p);
    }
    return XDP_PASS;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
