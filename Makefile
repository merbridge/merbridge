
load:
	[ -f bpf/mb_connect.c ] && make -C bpf load || make -C bpf load-from-obj
clean:
	make -C bpf clean
compile:
	make -C bpf compile

lint-c:
	clang-format --Werror -n bpf/*.c bpf/headers/*.h

format-c:
	find . -regex '.*\.\(c\|h\)' -exec clang-format -style=file -i {} \;

lint: lint-c

format: format-c
