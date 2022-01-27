#pragma once
#include "helpers.h"

struct bpf_map __section("maps") cookie_original_dst = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct origin_info),
    .max_entries = 65535,
    .map_flags = 0,
};

// local_pods stores Pods' ips in current node.
// which can be set by controller.
// only contains injected pods.
struct bpf_map __section("maps") local_pod_ips = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
    .map_flags = 0,
};

// process_ip stores envoy's ip address.
struct bpf_map __section("maps") process_ip = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
    .map_flags = 0,
};

struct bpf_map __section("maps") pair_original_dst = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct pair),
    .value_size = sizeof(struct origin_info),
    .max_entries = 65535,
    .map_flags = 0,
};

struct bpf_map __section("maps") sock_pair_map = {
    .type = BPF_MAP_TYPE_SOCKHASH,
    .key_size = sizeof(struct pair),
    .value_size = sizeof(__u32),
    .max_entries = 65535,
    .map_flags = 0,
};
