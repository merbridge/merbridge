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
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/swab.h>
#include <linux/types.h>

#ifndef ENABLE_IPV4
#define ENABLE_IPV4 1
#endif

#ifndef ENABLE_IPV6
#define ENABLE_IPV6 0
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_htons(x) (x)
#define bpf_htonl(x) (x)
#else
#error "__BYTE_ORDER__ error"
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
// see https://github.com/libbpf/libbpf/blob/v0.7.0/src/bpf_helper_defs.h#L2943
// only works if kernel version >= 5.15
static __u64 (*bpf_get_netns_cookie)(void *ctx) = (void *)122;

static void *(*bpf_map_lookup_elem)(struct bpf_map *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_map_update_elem)(struct bpf_map *map, const void *key,
                                    const void *value, __u64 flags) = (void *)
    BPF_FUNC_map_update_elem;
static struct bpf_sock *(*bpf_sk_lookup_tcp)(
    void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns,
    __u64 flags) = (void *)BPF_FUNC_sk_lookup_tcp;
static struct bpf_sock *(*bpf_sk_lookup_udp)(
    void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns,
    __u64 flags) = (void *)BPF_FUNC_sk_lookup_udp;
static long (*bpf_sk_release)(struct bpf_sock *sock) = (void *)
    BPF_FUNC_sk_release;
static long (*bpf_sock_hash_update)(
    struct bpf_sock_ops *skops, struct bpf_map *map, void *key,
    __u64 flags) = (void *)BPF_FUNC_sock_hash_update;
static long (*bpf_msg_redirect_hash)(struct sk_msg_md *md, struct bpf_map *map,
                                     void *key, __u64 flags) = (void *)
    BPF_FUNC_msg_redirect_hash;

#ifdef PRINTNL
#define PRINT_SUFFIX "\n"
#else
#define PRINT_SUFFIX ""
#endif

#ifndef printk
#define printk(fmt, ...)                                                       \
    ({                                                                         \
        char ____fmt[] = fmt PRINT_SUFFIX;                                     \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);             \
    })
#endif

#ifndef DEBUG
// do nothing
#define debugf(fmt, ...) ({})
#else
// only print traceing in debug mode
#ifndef debugf
#define debugf(fmt, ...)                                                       \
    ({                                                                         \
        char ____fmt[] = "[debug] " fmt PRINT_SUFFIX;                          \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);             \
    })
#endif

#endif

#ifndef memset
#define memset(x, y, z) __builtin_memset(x, y, z)
#endif

#if ENABLE_IPV4
static __u32 ip_zero = 0;
// 127.0.0.1 (network order)
static __u32 localhost = 16777343;

static inline __u32 get_ipv4(__u32 *ip) { return ip[3]; }

static inline void set_ipv4(__u32 *dst, __u32 src)
{
    dst[0] = 0;
    dst[1] = 0;
    dst[2] = 0;
    dst[3] = src;
}

static inline int ipv4_equal(__u32 *a, __u32 b) { return get_ipv4(a) == b; }

static inline int is_port_listen_current_ns(void *ctx, __u32 ip, __u16 port)
{
    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.dport = bpf_htons(port);
    tuple.ipv4.daddr = ip;
    struct bpf_sock *s = bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4),
                                           BPF_F_CURRENT_NETNS, 0);
    if (s) {
        bpf_sk_release(s);
        return 1;
    }
    return 0;
}

static inline int is_port_listen_udp_current_ns(void *ctx, __u32 ip, __u16 port)
{
    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.dport = bpf_htons(port);
    tuple.ipv4.daddr = ip;
    struct bpf_sock *s = bpf_sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4),
                                           BPF_F_CURRENT_NETNS, 0);
    if (s) {
        bpf_sk_release(s);
        return 1;
    }
    return 0;
}
#endif

#if ENABLE_IPV6
static __u32 ip_zero6[4] = {0, 0, 0, 0};
// ::1 (network order)
static __u32 localhost6[4] = {0, 0, 0, 1 << 24};

static inline void set_ipv6(__u32 *dst, __u32 *src)
{
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

static inline int ipv6_equal(__u32 *a, __u32 *b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static inline int is_port_listen_current_ns6(void *ctx, __u32 *ip, __u16 port)
{
    struct bpf_sock_tuple tuple = {};
    tuple.ipv6.dport = bpf_htons(port);
    set_ipv6(tuple.ipv6.daddr, ip);
    struct bpf_sock *s = bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv6),
                                           BPF_F_CURRENT_NETNS, 0);
    if (s) {
        bpf_sk_release(s);
        return 1;
    }
    return 0;
}

static inline int is_port_listen_udp_current_ns6(void *ctx, __u32 *ip,
                                                 __u16 port)
{
    struct bpf_sock_tuple tuple = {};
    tuple.ipv6.dport = bpf_htons(port);
    set_ipv6(tuple.ipv6.daddr, ip);
    struct bpf_sock *s = bpf_sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv6),
                                           BPF_F_CURRENT_NETNS, 0);
    if (s) {
        bpf_sk_release(s);
        return 1;
    }
    return 0;
}
#endif

struct origin_info {
    __u32 pid;
    __u32 ip[4];
    __u16 port;
    // last bit means that ip of process is detected.
    __u16 flags;
};

struct pair {
    __u32 sip[4];
    __u32 dip[4];
    __u16 sport;
    __u16 dport;
    __u64 ns_cookie;
};
