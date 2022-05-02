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
#include <linux/in.h>
#include <linux/swab.h>
#include <linux/types.h>

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
static void *(*bpf_map_lookup_elem)(struct bpf_map *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_map_update_elem)(struct bpf_map *map, const void *key,
                                    const void *value, __u64 flags) = (void *)
    BPF_FUNC_map_update_elem;
static __u64 (*bpf_map_delete_elem)(struct bpf_map *map, const void *key) =
    (void *)BPF_FUNC_map_delete_elem;
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
static long (*bpf_bind)(struct bpf_sock_addr *ctx, struct sockaddr_in *addr,
                        int addr_len) = (void *)BPF_FUNC_bind;

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

static inline int is_port_listen_current_ns(void *ctx, __u32 ip, __u16 port)
{

    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.dport = bpf_htons(port);
    tuple.ipv4.daddr = bpf_htonl(ip);
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
    tuple.ipv4.daddr = bpf_htonl(ip);
    struct bpf_sock *s = bpf_sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4),
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
    // last bit means that ip of process is detected.
    __u16 flags;
};

struct pair {
    __u32 sip;
    __u32 dip;
    __u16 sport;
    __u16 dport;
};

#define MAX_ITEM_LEN 10

struct cidr {
    __u32 net; // network order
    __u8 mask;
    __u8 __pad[3];
};

static inline int is_in_cidr(struct cidr *c, __u32 ip)
{
    return (bpf_htonl(c->net) >> c->mask) == bpf_htonl(ip) >> c->mask;
}

struct pod_config {
    __u16 status_port;
    __u16 __pad;
    struct cidr exclude_out_ranges[MAX_ITEM_LEN];
    struct cidr include_out_ranges[MAX_ITEM_LEN];
    __u16 include_in_ports[MAX_ITEM_LEN];
    __u16 include_out_ports[MAX_ITEM_LEN];
    __u16 exclude_in_ports[MAX_ITEM_LEN];
    __u16 exclude_out_ports[MAX_ITEM_LEN];
};

#define IS_EXCLUDE_PORT(ITEM, PORT, RET)                                       \
    do {                                                                       \
        *RET = 0;                                                              \
        for (int i = 0; i < MAX_ITEM_LEN && ITEM[i] != 0; i++) {               \
            if (bpf_htons(PORT) == ITEM[i]) {                                  \
                *RET = 1;                                                      \
                break;                                                         \
            }                                                                  \
        }                                                                      \
    } while (0);

#define IS_EXCLUDE_IPRANGES(ITEM, IP, RET)                                     \
    do {                                                                       \
        *RET = 0;                                                              \
        for (int i = 0; i < MAX_ITEM_LEN && ITEM[i].net != 0; i++) {           \
            if (is_in_cidr(&ITEM[i], IP)) {                                    \
                *RET = 1;                                                      \
                break;                                                         \
            }                                                                  \
        }                                                                      \
    } while (0);

#define IS_INCLUDE_PORT(ITEM, PORT, RET)                                       \
    do {                                                                       \
        *RET = 0;                                                              \
        if (ITEM[0] != 0) {                                                    \
            for (int i = 0; i < MAX_ITEM_LEN && ITEM[i] != 0; i++) {           \
                if (bpf_htons(PORT) == ITEM[i]) {                              \
                    *RET = 1;                                                  \
                    break;                                                     \
                }                                                              \
            }                                                                  \
        } else {                                                               \
            *RET = 1;                                                          \
        }                                                                      \
    } while (0);

#define IS_INCLUDE_IPRANGES(ITEM, IP, RET)                                     \
    do {                                                                       \
        *RET = 0;                                                              \
        if (ITEM[0].net != 0) {                                                \
            for (int i = 0; i < MAX_ITEM_LEN && ITEM[i].net != 0; i++) {       \
                if (is_in_cidr(&ITEM[i], IP)) {                                \
                    *RET = 1;                                                  \
                    break;                                                     \
                }                                                              \
            }                                                                  \
        } else {                                                               \
            *RET = 1;                                                          \
        }                                                                      \
    } while (0);
