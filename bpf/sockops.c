#include <linux/bpf.h>
#include <linux/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include "helpers.h"
#include "istio.h"


struct bpf_map __section("maps") cookie_original_dst = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(struct origin_info),
	.max_entries    = 65535,
	.map_flags      = 0,
};

// process_ip stores envoy's ip address.
struct bpf_map __section("maps") process_ip = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(__u32),
	.max_entries    = 65535,
	.map_flags      = 0,
};

struct bpf_map __section("maps") pair_original_dst = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(struct pair),
	.value_size     = sizeof(struct origin_info),
	.max_entries    = 65535,
	.map_flags      = 0,
};

struct bpf_map __section("maps") sock_ops_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.key_size       = sizeof(struct pair),
	.value_size     = sizeof(int),
	.max_entries    = 65535,
	.map_flags      = 0,
};


__section("sockops")
int sockopts(struct bpf_sock_ops *skops)
{
	__u32 family, op;
	family = skops->family;
	op = skops->op;

	switch (op) {
        // case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			if (family == AF_INET){
				// skops->sk->priority = 0;
				__u64 cookie = bpf_get_socket_cookie_ops(skops);
				void * dst = bpf_map_lookup_elem(&cookie_original_dst, &cookie);
				if (dst != NULL) {
					struct origin_info dd = *(struct origin_info*)dst;
					printk("sockops trace: %d, %d -> %d", dd.re_dport, skops->local_ip4, skops->remote_ip4);
					if ((bpf_htons(dd.re_dport) == ISTIO_IN_PORT && skops->local_ip4 == skops->remote_ip4) || skops->local_ip4 == 100663423) {
						// the is an incorrrct connection,
						// envoy want to call self container port,
						// but we send it to wrong port(15006).
						// we should reject this connection.
						// and alse update process_ip table.
						printk("incorrect connection");
						__u32 pid = dd.pid;
						__u32 ip = skops->remote_ip4;
						bpf_map_update_elem(&process_ip, &pid, &ip, BPF_ANY);
						return 1;
					}
					// get_sockopts can read pid and cookie, 
					// we should write a new map named pair_original_dst 
					struct pair p;
					p.sip = skops->local_ip4;
					p.sport = skops->local_port;
					p.dip = skops->remote_ip4;
					p.dport = skops->remote_port;
					if (!p.dport)
					 	p.dport = dd.re_dport;
					printk("update pair: %d -> %d", p.sip, p.dip);
					printk("update pair port: %d -> %d", p.sport, p.dport);
					printk("update pair origin: %d:%d", dd.ip, dd.port);
					bpf_map_update_elem(&pair_original_dst, &p, &dd, BPF_NOEXIST);
					struct pair pp = p;
					bpf_sock_hash_update(skops, &sock_ops_map, &pp, BPF_NOEXIST);
				} else {
					// printk("cookie origin get error: %d", cookie);
				}
			}
            break;
        default:
            break;
        }
	return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
