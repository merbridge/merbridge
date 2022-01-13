#include <linux/bpf.h>
#include <linux/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include "helpers.h"
#include "istio.h"


struct bpf_map __section("maps") sock_pair_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.key_size       = sizeof(struct pair),
	.value_size     = sizeof(__u32),
	.max_entries    = 65535,
	.map_flags      = 0,
};


__section("sk_msg")
int msg_redir(struct sk_msg_md *msg)
{
    struct pair p;
    p.sip = msg->local_ip4;
    p.sport = msg->local_port;
    p.dip = msg->remote_ip4;
    p.dport = msg->remote_port;
    // printk("redirect from ip %d -> %d", p.sip, p.dip);
    // printk("redirect from port %d -> %d", p.sport, p.dport);
	long res = bpf_msg_redirect_hash(msg, &sock_pair_map, &p, 0);
	if (res == 1) {
		printk("success redir msg: %s", msg->data);
	}
	return 1;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
