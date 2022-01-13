
load-getsock: load-map-pair_original_dst
	# clang \
	# 	-I/usr/src/linux-headers-5.15.13-051513/include \
	# 	-I/usr/src/linux-headers-5.15.13-051513/arch/x86/include \
	# 	-I/usr/src/linux-headers-5.15.13-051513/arch/x86/include/generated \
	# 	-O2 -g  -Wall -target bpf  -c get_sockopts.c -o get_sockopts.o

	clang -O2 -g  -Wall -target bpf  -c get_sockopts.c -o get_sockopts.o
	sudo bpftool prog load get_sockopts.o "/sys/fs/bpf/get_sockopts" \
		map name pair_original_dst pinned "/sys/fs/bpf/pair_original_dst"
	sudo bpftool cgroup attach "/sys/fs/cgroup/unified/" getsockopt pinned "/sys/fs/bpf/get_sockopts"

clean-getsock:
	sudo bpftool cgroup detach "/sys/fs/cgroup/unified/" getsockopt pinned "/sys/fs/bpf/get_sockopts"
	sudo rm "/sys/fs/bpf/get_sockopts"

load-map-cookie_original_dst:
	[ -f /sys/fs/bpf/cookie_original_dst ] || sudo bpftool map create /sys/fs/bpf/cookie_original_dst type hash key 4 value 12 entries 65535 name cookie_original_dst

load-map-local_pod_ips:
	[ -f /sys/fs/bpf/local_pod_ips ] || sudo bpftool map create /sys/fs/bpf/local_pod_ips type hash key 4 value 4 entries 65535 name local_pod_ips

load-map-process_ip:
	[ -f /sys/fs/bpf/process_ip ] || sudo bpftool map create /sys/fs/bpf/process_ip type hash key 4 value 4 entries 65535 name process_ip

load-map-pair_original_dst:
	[ -f /sys/fs/bpf/pair_original_dst ] || sudo bpftool map create /sys/fs/bpf/pair_original_dst type hash key 12 value 12 entries 65535 name pair_original_dst

load-map-sock_ops_map:
	[ -f /sys/fs/bpf/sock_ops_map ] || sudo bpftool map create /sys/fs/bpf/sock_ops_map type sockhash key 12 value 4 entries 65535 name sock_ops_map

load-connect: load-map-cookie_original_dst load-map-local_pod_ips load-map-process_ip
	clang -O2 -g  -Wall -target bpf  -c connect.c -o connect.o
	sudo bpftool prog load connect.o "/sys/fs/bpf/connect" \
		map name cookie_original_dst pinned "/sys/fs/bpf/cookie_original_dst" \
		map name local_pod_ips pinned "/sys/fs/bpf/local_pod_ips" \
		map name process_ip pinned "/sys/fs/bpf/process_ip"
	sudo bpftool cgroup attach "/sys/fs/cgroup/unified/" connect4 pinned "/sys/fs/bpf/connect"

clean-connect:
	sudo bpftool cgroup detach "/sys/fs/cgroup/unified/" connect4 pinned "/sys/fs/bpf/connect"
	sudo rm "/sys/fs/bpf/connect"

load-sockops: load-map-cookie_original_dst load-map-process_ip load-map-pair_original_dst load-map-sock_ops_map
	clang -O2 -g  -Wall -target bpf  -c sockops.c -o sockops.o
	sudo bpftool prog load sockops.o "/sys/fs/bpf/sockops" \
		map name cookie_original_dst pinned "/sys/fs/bpf/cookie_original_dst" \
		map name process_ip pinned "/sys/fs/bpf/process_ip" \
		map name pair_original_dst pinned "/sys/fs/bpf/pair_original_dst" \
		map name sock_ops_map pinned "/sys/fs/bpf/sock_ops_map"
	sudo bpftool cgroup attach /sys/fs/cgroup/unified/ sock_ops pinned "/sys/fs/bpf/sockops"

clean-sockops:
	sudo bpftool cgroup detach /sys/fs/cgroup/unified/ sock_ops pinned "/sys/fs/bpf/sockops"
	sudo rm -rf "/sys/fs/bpf/sockops"

load: load-connect load-sockops load-getsock

clean: clean-connect clean-sockops clean-getsock  
