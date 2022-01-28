#include "headers/helpers.h"
#include "headers/maps.h"
#include "headers/mesh.h"
#include <linux/bpf.h>
#include <linux/in.h>

static __u32 outip = 1;

__section("cgroup/connect4") int mb_sock4_connect(struct bpf_sock_addr *ctx)
{
    // init
    if (ctx->protocol != IPPROTO_TCP) {
        return 1;
    }
    __u32 pid = bpf_get_current_pid_tgid() & 0xffffffff;
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;

    // todo(kebe7jun) more reliable way to verify,
    if (!is_port_listen_current_ns(ctx, OUT_REDIRECT_PORT)) {
        // bypass normal traffic.
        // we only deal pod's traffic managed by istio.
        return 1;
    }
    if (uid != SIDECAR_USER_ID) {
        if ((ctx->user_ip4 & 0xff) == 0x7f) {
            // app call local, bypass.
            return 1;
        }
        // app call others
        debugf("call from user container: ip: 0x%x, port: %d", ctx->user_ip4,
               bpf_htons(ctx->user_port));
        // we need redirect it to envoy.
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        struct origin_info origin = {
            .ip = ctx->user_ip4,
            .port = ctx->user_port,
            .pid = pid,
            .re_dport = bpf_htons(OUT_REDIRECT_PORT),
        };
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("write cookie_original_dst failed");
            return 0;
        }
        // The reason we try the IP of the 127.128.0.0/20 segment instead of
        // using 127.0.0.1 directly is to avoid conflicts between the
        // quaternions of different Pods when the quaternions are subsequently
        // processed.
        ctx->user_ip4 = bpf_htonl(0x7f800000 | (outip++));
        if (outip >> 20) {
            outip = 1;
        }
        ctx->user_port = bpf_htons(OUT_REDIRECT_PORT);
    } else {
        // from envoy to others
        debugf("call from sidecar container: ip: 0x%x, port: %d", ctx->user_ip4,
               bpf_htons(ctx->user_port));
        __u32 ip = ctx->user_ip4;
        if (!bpf_map_lookup_elem(&local_pod_ips, &ip)) {
            // dst ip is not in this node, bypass
            printk("dest ip: 0x%x not in this node, bypass", ctx->user_ip4);
            return 1;
        }
        // dst ip is in this node, but not the current pod,
        // it is envoy to envoy connecting.
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        struct origin_info origin = {
            .ip = ctx->user_ip4,
            .port = ctx->user_port,
            .pid = pid,
        };
        void *curr_ip = bpf_map_lookup_elem(&process_ip, &pid);
        if (curr_ip) {
            // envoy to other envoy
            if (*(__u32 *)curr_ip != ctx->user_ip4) {
                ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
                // debugf("enovy to other");
            }
            // envoy to app, no rewrite
        } else {
            // envoy to envoy
            // try redirect to 15006
            // but it may cause error if it is envoy call self pod,
            // in this case, we can read src and dst ip in sockops,
            // if src is equals dst, it means envoy call self pod,
            // we should reject this traffic in sockops,
            // envoy will create a new connection to self pod.
            ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
        }
        origin.re_dport = ctx->user_port;
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_NOEXIST)) {
            printk("update cookie origin failed");
            return 0;
        }
    }

    return 1;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
