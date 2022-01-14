
load:
	[ -f bpf/mb_connect.c ] && make -C bpf load || make -C bpf load-from-obj
clean:
	make -C bpf clean
compile:
	make -C bpf compile
