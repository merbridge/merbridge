
load:
	make -C bpf load
clean:
	make -C bpf clean

load-from-obj: 
	make -C bpf load-from-source
