
CC=clang
CFLAGS=-O2 -g  -Wall -target bpf
CGROUP_PATH=/sys/fs/bpf

TARGETS=mb_connect.o mb_get_sockopts.o mb_redir.o mb_sockops.o

init-cgroup:
	[ -d $(CGROUP_PATH)/ ] || sudo mount -t bpf bpf $(CGROUP_PATH)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

compile: $(TARGETS)

compile-clean:
	sudo rm -f $(TARGETS)

# Map
load-map-cookie_original_dst:
	[ -f $(CGROUP_PATH)/cookie_original_dst ] || sudo bpftool map create $(CGROUP_PATH)/cookie_original_dst type lru_hash key 4 value 12 entries 65535 name cookie_original_dst

load-map-local_pod_ips:
	[ -f $(CGROUP_PATH)/local_pod_ips ] || sudo bpftool map create $(CGROUP_PATH)/local_pod_ips type hash key 4 value 4 entries 1024 name local_pod_ips

load-map-process_ip:
	[ -f $(CGROUP_PATH)/process_ip ] || sudo bpftool map create $(CGROUP_PATH)/process_ip type hash key 4 value 4 entries 1024 name process_ip

load-map-pair_original_dst:
	[ -f $(CGROUP_PATH)/pair_original_dst ] || sudo bpftool map create $(CGROUP_PATH)/pair_original_dst type lru_hash key 12 value 12 entries 1024 name pair_original_dst

load-map-sock_pair_map:
	[ -f $(CGROUP_PATH)/sock_pair_map ] || sudo bpftool map create $(CGROUP_PATH)/sock_pair_map type sockhash key 12 value 4 entries 1024 name sock_pair_map


clean-maps:
	sudo rm -f \
		$(CGROUP_PATH)/sock_pair_map \
		$(CGROUP_PATH)/pair_original_dst \
		$(CGROUP_PATH)/process_ip \
		$(CGROUP_PATH)/local_pod_ips \
		$(CGROUP_PATH)/cookie_original_dst

load-getsock: load-map-pair_original_dst
	sudo bpftool prog load mb_get_sockopts.o $(CGROUP_PATH)/get_sockopts \
		map name pair_original_dst pinned $(CGROUP_PATH)/pair_original_dst
	sudo bpftool cgroup attach /sys/fs/cgroup/unified/ getsockopt pinned $(CGROUP_PATH)/get_sockopts

clean-getsock:
	sudo bpftool cgroup detach /sys/fs/cgroup/unified/ getsockopt pinned $(CGROUP_PATH)/get_sockopts
	sudo rm $(CGROUP_PATH)/get_sockopts

load-redir: load-map-sock_pair_map
	sudo bpftool prog load mb_redir.o $(CGROUP_PATH)/redir \
		map name sock_pair_map pinned $(CGROUP_PATH)/sock_pair_map
	sudo bpftool prog attach pinned $(CGROUP_PATH)/redir msg_verdict pinned $(CGROUP_PATH)/sock_pair_map

clean-redir:
	sudo bpftool prog detach pinned $(CGROUP_PATH)/redir msg_verdict pinned $(CGROUP_PATH)/sock_pair_map
	sudo rm $(CGROUP_PATH)/redir

load-connect: load-map-cookie_original_dst load-map-local_pod_ips load-map-process_ip
	sudo bpftool prog load mb_connect.o $(CGROUP_PATH)/connect \
		map name cookie_original_dst pinned $(CGROUP_PATH)/cookie_original_dst \
		map name local_pod_ips pinned $(CGROUP_PATH)/local_pod_ips \
		map name process_ip pinned $(CGROUP_PATH)/process_ip
	sudo bpftool cgroup attach /sys/fs/cgroup/unified/ connect4 pinned $(CGROUP_PATH)/connect

clean-connect: 
	sudo bpftool cgroup detach /sys/fs/cgroup/unified/ connect4 pinned $(CGROUP_PATH)/connect
	sudo rm $(CGROUP_PATH)/connect

load-sockops: load-map-cookie_original_dst load-map-process_ip load-map-pair_original_dst load-map-sock_pair_map
	sudo bpftool prog load mb_sockops.o $(CGROUP_PATH)/sockops \
		map name cookie_original_dst pinned $(CGROUP_PATH)/cookie_original_dst \
		map name process_ip pinned $(CGROUP_PATH)/process_ip \
		map name pair_original_dst pinned $(CGROUP_PATH)/pair_original_dst \
		map name sock_pair_map pinned $(CGROUP_PATH)/sock_pair_map
	sudo bpftool cgroup attach /sys/fs/cgroup/unified/ sock_ops pinned $(CGROUP_PATH)/sockops

clean-sockops:
	sudo bpftool cgroup detach /sys/fs/cgroup/unified/ sock_ops pinned $(CGROUP_PATH)/sockops
	sudo rm -rf $(CGROUP_PATH)/sockops

load: compile load-from-obj

load-from-obj: load-connect load-sockops load-getsock load-redir

clean: clean-connect clean-sockops clean-getsock clean-redir clean-maps compile-clean
