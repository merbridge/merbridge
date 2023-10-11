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
#include <linux/bpf.h>
#include <linux/in.h>

__section("sk_msg") int mb_msg_redir(struct sk_msg_md *msg)
{
    struct pair p;
    memset(&p, 0, sizeof(p));
    p.dport = bpf_htons(msg->local_port);
    p.sport = msg->remote_port >> 16;

    switch (msg->family) {
#if ENABLE_IPV4
    case 2:
        // ipv4
        set_ipv4(p.dip, msg->local_ip4);
        set_ipv4(p.sip, msg->remote_ip4);
        break;
#endif
#if ENABLE_IPV6
    case 10:
        // ipv6
        set_ipv6(p.dip, msg->local_ip6);
        set_ipv6(p.sip, msg->remote_ip6);
        break;
#endif
    }

    long ret = bpf_msg_redirect_hash(msg, &sock_pair_map, &p, BPF_F_INGRESS);
    if (ret)
        debugf("redirect %d bytes with eBPF successfully, src: %pI4, dst: %pI4",
               msg->size, &p.dip[3], &p.sip[3]);
    return 1;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
