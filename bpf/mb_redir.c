#include "headers/helpers.h"
#include "headers/istio.h"
#include <linux/bpf.h>
#include <linux/in.h>

struct bpf_map __section("maps") sock_pair_map = {
    .type = BPF_MAP_TYPE_SOCKHASH,
    .key_size = sizeof(struct pair),
    .value_size = sizeof(__u32),
    .max_entries = 65535,
    .map_flags = 0,
};

__section("sk_msg") int mb_msg_redir(struct sk_msg_md *msg) {
  struct pair p = {
      .sip = msg->local_ip4,
      .sport = msg->local_port,
      .dip = msg->remote_ip4,
      .dport = msg->remote_port,
  };
  long res = bpf_msg_redirect_hash(msg, &sock_pair_map, &p, 0);
  if (res == 1) {
    printk("success redir msg.");
  }
  return 1;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
