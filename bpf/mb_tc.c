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
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#import <stddef.h>

#define TCP_CSUM_OFF                                                           \
    (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))

#define TCP_SPORT_OFF                                                          \
    (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))

#define TCP_DPORT_OFF                                                          \
    (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))

__section("classifier_ingress") int mb_tc_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }
    if (bpf_htons(eth->h_proto) != ETH_P_IP) {
        return TC_ACT_OK;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    if (iph->protocol == IPPROTO_IPIP) {
        iph = ((void *)iph + iph->ihl * 4);
        if ((void *)(iph + 1) > data_end) {
            return TC_ACT_OK;
        }
    }

    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if ((void *)(tcph + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    __u16 in_port = bpf_htons(IN_REDIRECT_PORT);
    if (tcph->syn && !tcph->ack) {
        // first packet
        if (tcph->dest == in_port) {
            // same node, already rewrite dest port by connect.
            // bypass.
            debugf("tc ingress: already rewrited");
            return TC_ACT_OK;
        }
        // ingress without mb_connect
        __u32 ip = iph->daddr;
        struct pod_config *pod = bpf_map_lookup_elem(&local_pod_ips, &ip);
        if (!pod) {
            // dest ip is not on this node or not injected sidecar.
            debugf("tc ingress: pod not found, bypassed");
            return TC_ACT_OK;
        }
        if (bpf_htons(tcph->dest) == pod->status_port) {
            return TC_ACT_OK;
        }
        int exclude = 0;
        IS_EXCLUDE_PORT(pod->exclude_in_ports, tcph->dest, &exclude);
        if (exclude) {
            debugf("ignored dest port by exclude_in_ports, ip: %x, port: %d",
                   iph->daddr, bpf_htons(tcph->dest));
            return TC_ACT_OK;
        }
        int include = 0;
        IS_INCLUDE_PORT(pod->include_in_ports, tcph->dest, &include);
        if (!include) {
            debugf("ignored dest port by include_in_ports, ip: %x, port: %d",
                   iph->daddr, bpf_htons(tcph->dest));
            return TC_ACT_OK;
        }

        // like from 10.0.0.1:23456 => 172.31.0.123:80
        // we will rewrite the dest port from 80 to 15006
        // which will be: 10.0.0.1:23456 => 172.31.0.123:15006
        struct pair p = {
            .sip = iph->saddr,
            .sport = tcph->source,
            .dip = iph->daddr,
            .dport = in_port,
        };
        struct origin_info origin = {
            .ip = iph->daddr,
            .port = tcph->dest,
            .flags = TC_ORIGIN_FLAG,
        };
        bpf_map_update_elem(&pair_original_dst, &p, &origin, BPF_NOEXIST);
        __u16 dst_port = tcph->dest;
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, dst_port, in_port,
                            sizeof(dst_port));
        bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &in_port, sizeof(in_port), 0);
        debugf("tc ingress: first rewrited");
    } else {
        // request
        struct pair p = {
            .sip = iph->saddr,
            .sport = tcph->source,
            .dip = iph->daddr,
            .dport = in_port,
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
            debugf("tc ingress: no origin");
            return TC_ACT_OK;
        }
        if (!(origin->flags & TC_ORIGIN_FLAG)) {
            // not tc origin
            debugf("tc ingress: no tc origin flag");
            return TC_ACT_OK;
        }
        __u16 dst_port = tcph->dest;
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, dst_port, in_port,
                            sizeof(dst_port));
        bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &in_port, sizeof(in_port), 0);
        debugf("tc ingress: rewrited");
    }
    return TC_ACT_OK;
}

__section("classifier_egress") int mb_tc_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }
    if (bpf_htons(eth->h_proto) != ETH_P_IP) {
        return TC_ACT_OK;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    if (iph->protocol == IPPROTO_IPIP) {
        iph = ((void *)iph + iph->ihl * 4);
        if ((void *)(iph + 1) > data_end) {
            return TC_ACT_OK;
        }
    }

    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if ((void *)(tcph + 1) > data_end) {
        return TC_ACT_SHOT;
    }
    __u16 in_port = bpf_htons(IN_REDIRECT_PORT);
    if (tcph->source != in_port) {
        debugf("tc egress: no need to rewrite src port, bypassed");
        return TC_ACT_OK;
    }
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
    struct origin_info *origin = bpf_map_lookup_elem(&pair_original_dst, &p);
    if (!origin) {
        // not exists
        debugf("resp origin not found");
        return TC_ACT_OK;
    }
    if (!(origin->flags & TC_ORIGIN_FLAG)) {
        // not tc origin
        printk("resp origin flags %x error", origin->flags);
        return TC_ACT_OK;
    }
    if (tcph->fin && tcph->ack) {
        // todo delete key
        debugf("tc egress: original deleted");
        bpf_map_delete_elem(&pair_original_dst, &p);
    }
    __u16 src_port = origin->port;
    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, in_port, src_port, sizeof(src_port));
    bpf_skb_store_bytes(skb, TCP_SPORT_OFF, &src_port, sizeof(src_port), 0);
    debugf("tc egress: rewrited");
    return TC_ACT_OK;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
