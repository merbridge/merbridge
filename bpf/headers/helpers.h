#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/swab.h>
#include <linux/types.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_htons(x) (x)
#define bpf_htonl(x) (x)
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#ifndef __section
#define __section(NAME) __attribute__((section(NAME), used))
#endif

struct bpf_map {
  __u32 type;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
  __u32 map_flags;
};

static __u64 (*bpf_get_current_pid_tgid)() = (void *)
    BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_uid_gid)() = (void *)
    BPF_FUNC_get_current_uid_gid;
static void (*bpf_trace_printk)(const char *fmt, int fmt_size,
                                ...) = (void *)BPF_FUNC_trace_printk;
static __u64 (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)
    BPF_FUNC_get_current_comm;

static __u64 (*bpf_get_socket_cookie_ops)(struct bpf_sock_ops *skops) = (void *)
    BPF_FUNC_get_socket_cookie;
static __u64 (*bpf_get_socket_cookie_addr)(struct bpf_sock_addr *ctx) = (void *)
    BPF_FUNC_get_socket_cookie;
static void *(*bpf_map_lookup_elem)(struct bpf_map *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_map_update_elem)(struct bpf_map *map, const void *key,
                                    const void *value, __u64 flags) = (void *)
    BPF_FUNC_map_update_elem;
static struct bpf_sock *(*bpf_sk_lookup_tcp)(
    void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns,
    __u64 flags) = (void *)BPF_FUNC_sk_lookup_tcp;
static long (*bpf_sk_release)(struct bpf_sock *sock) = (void *)
    BPF_FUNC_sk_release;
static long (*bpf_sock_hash_update)(
    struct bpf_sock_ops *skops, struct bpf_map *map, void *key,
    __u64 flags) = (void *)BPF_FUNC_sock_hash_update;
static long (*bpf_msg_redirect_hash)(struct sk_msg_md *md, struct bpf_map *map,
                                     void *key, __u64 flags) = (void *)
    BPF_FUNC_msg_redirect_hash;

#ifndef printk
#define printk(fmt, ...)                                                       \
  ({                                                                           \
    char ____fmt[] = fmt;                                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })
#endif

static inline int is_port_listen_current_ns(void *ctx, __u16 port) {

  struct bpf_sock_tuple tuple = {};
  // memset(&tuple.ipv4.sport, 0, sizeof(tuple.ipv4.sport));
  // tuple.ipv4.saddr = 0;
  // tuple.ipv4.sport = 0;
  // tuple.ipv4.daddr = 0;
  tuple.ipv4.dport = bpf_htons(port);
  struct bpf_sock *s = bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4),
                                         BPF_F_CURRENT_NETNS, 0);
  if (s) {
    bpf_sk_release(s);
    return 1;
  }
  return 0;
}

struct origin_info {
  __u32 pid;
  __u32 ip;
  __u16 port;
  __u16 re_dport;
};

struct pair {
  __u32 sip;
  __u32 dip;
  __u16 sport;
  __u16 dport;
};
