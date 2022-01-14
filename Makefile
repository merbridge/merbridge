
load:
	make -C bpf load
clean:
	make -C bpf clean
compile:
	make -C bpf compile

load-from-obj: 
	make -C bpf load-from-source
