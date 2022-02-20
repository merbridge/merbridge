# some makefile commands used by merbridge
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

helm: helm-linkerd helm-istio

helm-linkerd:
	helm template --set-string "merbridge.namespace=linkerd,merbridge.mode=linkerd" merbridge helm > deploy/all-in-one-linkerd.yaml

helm-istio:
	helm template merbridge helm > deploy/all-in-one.yaml

helm-package:
	helm package helm
