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
#include <linux/ptrace.h>

struct xupid {
    int nr;
    long *ns;
};

/*
for 5.7 and after
struct pid
{
        refcount_t count;  // 4
        unsigned int level; // 4
        spinlock_t lock; // 4
        // __pad 4 for align
        struct hlist_head tasks[PIDTYPE_MAX]; // 8 * 4
        struct hlist_head inodes; // 8
        wait_queue_head_t wait_pidfd; // 24
        struct rcu_head rcu; // 16
        struct upid numbers[1]; // 16
};

#define XPID_OFFSET 88

5.4-5.6
struct pid
{
        refcount_t count; // 4
        unsigned int level; // 4
        struct hlist_head tasks[PIDTYPE_MAX]; // 8 * 4
        wait_queue_head_t wait_pidfd; // 24
        struct rcu_head rcu; // 16
        struct upid numbers[1]; // 16
};

#define XPID_OFFSET 72

*/

#ifndef XPID_OFFSET
#define XPID_OFFSET 88
#endif

struct xpid {
    int __pad1;
    int level;
    char __pad2[XPID_OFFSET];
    struct xupid numbers[1];
};

struct process_event {
    int op; // 0 - fork, 1 - exit
    int hostpid;
    int level;
    int levelpid;
    int exitcode;
};

__section("kretprobe/alloc_pid") int mb_alloc_pid(struct pt_regs *ctx)
{
    struct xpid *p = (struct xpid *)ctx->rax; // todo support arm64
    int level = 0;
    if (bpf_probe_read(&level, sizeof(level), &p->level)) {
        printk("read level of pid error");
        return 0;
    }
    if (level < WATCH_LEVEL) {
        // we don't care about this
        return 0;
    }
    int levelpid = 0;
    if (bpf_probe_read(&levelpid, sizeof(levelpid),
                       &p->numbers[WATCH_LEVEL].nr)) {
        printk("read levelpid error");
        return 0;
    }
    int hostpid = levelpid;
    if (WATCH_LEVEL > 0) {
        bpf_probe_read(&hostpid, sizeof(hostpid), &p->numbers[0].nr);
    }
    struct process_event e = {
        .op = 0,
        .hostpid = hostpid,
        .level = WATCH_LEVEL,
        .levelpid = levelpid,
        .exitcode = 0,
    };
#if WATCH_LEVEL != 0
    bpf_map_update_elem(&process_level_pid, &hostpid, &levelpid, BPF_ANY);
#endif
    int ret = bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, &e,
                                    sizeof(e));
    if (ret) {
        printk("error out perf event: %d", ret);
    }
    return 0;
}

__section("kprobe/do_exit") int mb_do_exit(struct pt_regs *ctx)
{
    int exitcode = ctx->rdi;                        // todo support arm64
    int hostpid = bpf_get_current_pid_tgid() >> 32; // tgid
    int levelpid = hostpid;
#if WATCH_LEVEL != 0
    void *p = bpf_map_lookup_elem(&process_level_pid, &hostpid);
    if (p) {
        levelpid = *(int *)p;
        debugf("find level pid %d for hostpid: %d", levelpid, hostpid);
    }
    if (bpf_map_delete_elem(&process_level_pid, &hostpid)) {
        printk("error delete hostpid: %d", hostpid);
    }
#endif
    struct process_event e = {
        .op = 1,
        .hostpid = hostpid,
        .level = WATCH_LEVEL,
        .levelpid = levelpid,
        .exitcode = exitcode,
    };
    int ret = bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, &e,
                                    sizeof(e));
    if (ret) {
        printk("error out perf event: %d", ret);
    }
    return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
