
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

lint-go:
	golangci-lint run

format-go:
	goimports -w -local github.com/merbridge/merbridge/ .
	gofmt -l -d -w .

lint: lint-c lint-go

format: format-c format-go
