
CC=clang
CFLAGS=-O2 -g  -Wall -target bpf -I/usr/include/$(shell uname -m)-linux-gnu
PROG_MOUNT_PATH=/sys/fs/bpf

MACROS:=
DEBUG ?=

MESH_MODE ?= istio

ifeq ($(MESH_MODE),istio)
    MACROS:= $(MACROS) -DMESH=1
else ifeq ($(MESH_MODE),linkerd)
    MACROS:= $(MACROS) -DMESH=2
else
$(error MESH_MODE $(MESH_MODE) isn't supported)
endif

# see https://stackoverflow.com/questions/15063298/how-to-check-kernel-version-in-makefile
KVER = $(shell uname -r)
KMAJ = $(shell echo $(KVER) | \
sed -e 's/^\([0-9][0-9]*\)\.[0-9][0-9]*\.[0-9][0-9]*.*/\1/')
KMIN = $(shell echo $(KVER) | \
sed -e 's/^[0-9][0-9]*\.\([0-9][0-9]*\)\.[0-9][0-9]*.*/\1/')
KREV = $(shell echo $(KVER) | \
sed -e 's/^[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*/\1/')

kver_ge = $(shell \
echo test | awk '{if($(KMAJ) < $(1)) {print 0} else { \
if($(KMAJ) > $(1)) {print 1} else { \
if($(KMIN) < $(2)) {print 0} else { \
if($(KMIN) > $(2)) {print 1} else { \
if($(KREV) < $(3)) {print 0} else { print 1 } \
}}}}}' \
)

# See https://nakryiko.com/posts/bpf-tips-printk/, kernel will auto print newline if version greater than 5.9.0
ifneq ($(call kver_ge,5,8,999),1)
MACROS:= $(MACROS) -DPRINTNL # kernel version less
endif

ifeq ($(DEBUG),1)
    MACROS:= $(MACROS) -DDEBUG
endif

ifeq ($(USE_RECONNECT),1)
    MACROS:= $(MACROS) -DUSE_RECONNECT
endif

CGROUP2_PATH ?= $(shell mount | grep cgroup2 | awk '{print $$3}' | grep -v "^/host" | head -n 1)
ifeq ($(CGROUP2_PATH),)
$(error It looks like your system does not have cgroupv2 enabled, or the automatic recognition fails. Please enable cgroupv2, or specify the path of cgroupv2 manually via CGROUP2_PATH parameter.)
endif

TARGETS=mb_connect.o mb_get_sockopts.o mb_redir.o mb_sockops.o mb_bind.o mb_sendmsg.o mb_recvmsg.o mb_xdp.o

init-cgroup:
	[ -d $(PROG_MOUNT_PATH)/ ] || sudo mount -t bpf bpf $(PROG_MOUNT_PATH)

%.o: %.c
	$(CC) $(CFLAGS) $(MACROS) -c $< -o $@

generate-compilation-database:
	CC="$(CC)" CFLAGS="$(CFLAGS)" MACROS="$(MACROS)" scripts/generate-compilation-database.sh | tee compile_commands.json

compile: $(TARGETS)

compile-clean:
	[ -f mb_connect.c ] && sudo rm -f $(TARGETS)

# Map
load-map-cookie_original_dst:
	[ -f $(PROG_MOUNT_PATH)/cookie_original_dst ] || sudo bpftool map create $(PROG_MOUNT_PATH)/cookie_original_dst type lru_hash key 8 value 12 entries 65535 name cookie_original_dst

load-map-local_pod_ips:
	[ -f $(PROG_MOUNT_PATH)/local_pod_ips ] || sudo bpftool map create $(PROG_MOUNT_PATH)/local_pod_ips type hash key 4 value 244 entries 1024 name local_pod_ips

load-map-process_ip:
	[ -f $(PROG_MOUNT_PATH)/process_ip ] || sudo bpftool map create $(PROG_MOUNT_PATH)/process_ip type lru_hash key 4 value 4 entries 1024 name process_ip

load-map-mark_pod_ips_map:
	[ -f $(PROG_MOUNT_PATH)/mark_pod_ips_map ] || sudo bpftool map create $(PROG_MOUNT_PATH)/mark_pod_ips_map type hash key 4 value 4 entries 65535 name mark_pod_ips_map

load-map-pair_original_dst:
	[ -f $(PROG_MOUNT_PATH)/pair_original_dst ] || sudo bpftool map create $(PROG_MOUNT_PATH)/pair_original_dst type lru_hash key 12 value 12 entries 65535 name pair_original_dst

load-map-sock_pair_map:
	[ -f $(PROG_MOUNT_PATH)/sock_pair_map ] || sudo bpftool map create $(PROG_MOUNT_PATH)/sock_pair_map type sockhash key 12 value 4 entries 65535 name sock_pair_map


clean-maps:
	sudo rm -f \
		$(PROG_MOUNT_PATH)/sock_pair_map \
		$(PROG_MOUNT_PATH)/pair_original_dst \
		$(PROG_MOUNT_PATH)/process_ip \
		$(PROG_MOUNT_PATH)/local_pod_ips \
		$(PROG_MOUNT_PATH)/cookie_original_dst \
		$(PROG_MOUNT_PATH)/mark_pod_ips_map

load-getsock: load-map-pair_original_dst
	sudo bpftool prog load mb_get_sockopts.o $(PROG_MOUNT_PATH)/get_sockopts \
		map name pair_original_dst pinned $(PROG_MOUNT_PATH)/pair_original_dst

attach-getsock:
	sudo bpftool cgroup attach $(CGROUP2_PATH) getsockopt pinned $(PROG_MOUNT_PATH)/get_sockopts

clean-getsock:
	sudo bpftool cgroup detach $(CGROUP2_PATH) getsockopt pinned $(PROG_MOUNT_PATH)/get_sockopts
	sudo rm $(PROG_MOUNT_PATH)/get_sockopts

load-redir: load-map-sock_pair_map
	sudo bpftool prog load mb_redir.o $(PROG_MOUNT_PATH)/redir \
		map name sock_pair_map pinned $(PROG_MOUNT_PATH)/sock_pair_map

attach-redir:
	sudo bpftool prog attach pinned $(PROG_MOUNT_PATH)/redir msg_verdict pinned $(PROG_MOUNT_PATH)/sock_pair_map

clean-redir:
	sudo bpftool prog detach pinned $(PROG_MOUNT_PATH)/redir msg_verdict pinned $(PROG_MOUNT_PATH)/sock_pair_map
	sudo rm $(PROG_MOUNT_PATH)/redir

load-connect: load-map-cookie_original_dst load-map-local_pod_ips load-map-process_ip load-map-mark_pod_ips_map
	sudo bpftool prog load mb_connect.o $(PROG_MOUNT_PATH)/connect \
		map name cookie_original_dst pinned $(PROG_MOUNT_PATH)/cookie_original_dst \
		map name local_pod_ips pinned $(PROG_MOUNT_PATH)/local_pod_ips \
		map name mark_pod_ips_map pinned $(PROG_MOUNT_PATH)/mark_pod_ips_map \
		map name process_ip pinned $(PROG_MOUNT_PATH)/process_ip

attach-connect:
	sudo bpftool cgroup attach $(CGROUP2_PATH) connect4 pinned $(PROG_MOUNT_PATH)/connect

clean-connect:
	sudo bpftool cgroup detach $(CGROUP2_PATH) connect4 pinned $(PROG_MOUNT_PATH)/connect
	sudo rm $(PROG_MOUNT_PATH)/connect

load-sockops: load-map-cookie_original_dst load-map-process_ip load-map-pair_original_dst load-map-sock_pair_map
	sudo bpftool prog load mb_sockops.o $(PROG_MOUNT_PATH)/sockops \
		map name cookie_original_dst pinned $(PROG_MOUNT_PATH)/cookie_original_dst \
		map name process_ip pinned $(PROG_MOUNT_PATH)/process_ip \
		map name pair_original_dst pinned $(PROG_MOUNT_PATH)/pair_original_dst \
		map name sock_pair_map pinned $(PROG_MOUNT_PATH)/sock_pair_map

attach-sockops:
	sudo bpftool cgroup attach $(CGROUP2_PATH) sock_ops pinned $(PROG_MOUNT_PATH)/sockops

clean-sockops:
	sudo bpftool cgroup detach $(CGROUP2_PATH) sock_ops pinned $(PROG_MOUNT_PATH)/sockops
	sudo rm -rf $(PROG_MOUNT_PATH)/sockops

load-bind:
	sudo bpftool prog load mb_bind.o $(PROG_MOUNT_PATH)/bind

attach-bind:
	sudo bpftool cgroup attach $(CGROUP2_PATH) bind4 pinned $(PROG_MOUNT_PATH)/bind

clean-bind:
	sudo bpftool cgroup detach $(CGROUP2_PATH) bind4 pinned $(PROG_MOUNT_PATH)/bind
	sudo rm -rf $(PROG_MOUNT_PATH)/bind

load-sendmsg: load-map-cookie_original_dst
	sudo bpftool prog load mb_sendmsg.o $(PROG_MOUNT_PATH)/sendmsg \
		map name cookie_original_dst pinned $(PROG_MOUNT_PATH)/cookie_original_dst

attach-sendmsg:
	sudo bpftool cgroup attach $(CGROUP2_PATH) sendmsg4 pinned $(PROG_MOUNT_PATH)/sendmsg

clean-sendmsg:
	sudo bpftool cgroup detach $(CGROUP2_PATH) sendmsg4 pinned $(PROG_MOUNT_PATH)/sendmsg
	sudo rm -rf $(PROG_MOUNT_PATH)/sendmsg

load-recvmsg: load-map-cookie_original_dst
	sudo bpftool prog load mb_recvmsg.o $(PROG_MOUNT_PATH)/recvmsg \
		map name cookie_original_dst pinned $(PROG_MOUNT_PATH)/cookie_original_dst

attach-recvmsg:
	sudo bpftool cgroup attach $(CGROUP2_PATH) recvmsg4 pinned $(PROG_MOUNT_PATH)/recvmsg

clean-recvmsg:
	sudo bpftool cgroup detach $(CGROUP2_PATH) recvmsg4 pinned $(PROG_MOUNT_PATH)/recvmsg
	sudo rm -rf $(PROG_MOUNT_PATH)/recvmsg

load-xdp: mb_xdp.o load-map-pair_original_dst
	sudo bpftool prog load mb_xdp.o $(PROG_MOUNT_PATH)/mb_xdp \
		map name pair_original_dst pinned $(PROG_MOUNT_PATH)/pair_original_dst \
		map name local_pod_ips pinned $(PROG_MOUNT_PATH)/local_pod_ips

clean-xdp:
	sudo rm $(PROG_MOUNT_PATH)/mb_xdp

load: compile load-from-obj

load-from-obj: load-connect load-sockops load-getsock load-redir load-bind load-sendmsg load-recvmsg load-xdp

attach: attach-connect attach-sockops attach-getsock attach-redir attach-bind attach-sendmsg attach-recvmsg

clean: clean-connect clean-sockops clean-getsock clean-redir clean-maps compile-clean clean-bind clean-sendmsg clean-recvmsg clean-xdp
