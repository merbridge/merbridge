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
