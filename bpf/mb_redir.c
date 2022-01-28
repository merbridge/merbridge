#include "headers/helpers.h"
#include "headers/maps.h"
#include <linux/bpf.h>
#include <linux/in.h>

__section("sk_msg") int mb_msg_redir(struct sk_msg_md *msg)
{
    struct pair p = {
        .sip = msg->local_ip4,
        .sport = msg->local_port,
        .dip = msg->remote_ip4,
        .dport = msg->remote_port >> 16,
    };
    long ret = bpf_msg_redirect_hash(msg, &sock_pair_map, &p, 0);
    if (ret)
        debugf("redirect %d bytes with eBPF successfully", msg->size);
    return 1;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
