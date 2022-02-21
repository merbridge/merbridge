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
	helm template --set-string "mode=linkerd" -n "linkerd" merbridge helm > deploy/all-in-one-linkerd.yaml

helm-istio:
	helm template -n "istio-system" merbridge helm > deploy/all-in-one.yaml

helm-package:
	helm package helm

helm-install:
	curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# check helm templates in Github Workflow
# check if the generated yaml has been updated
helm-ci: helm-install
	@echo "start to check deploy/all-in-one.yaml"
	@helm template -n "istio-system" merbridge helm > deploy/all-in-one-g.yaml
	@cmp -s deploy/all-in-one-g.yaml deploy/all-in-one.yaml; \
	RETVAL=$$?; \
	if [ $$RETVAL -ne 0 ]; then \
	  echo "deploy/all-in-one.yaml is incorrect, remember to run make make helm-istio to update all-in-one.yaml"; rm -rf deploy/all-in-one-g.yaml; exit 1; \
	fi

	@rm -rf deploy/all-in-one-g.yaml

	@echo "start to check deploy/all-in-one-linkerd.yaml"
	@helm template --set-string "mode=linkerd" -n "linkerd" merbridge helm > deploy/all-in-one-linkerd-g.yaml
	@cmp -s deploy/all-in-one-linkerd.yaml deploy/all-in-one-linkerd-g.yaml; \
	RETVAL=$$?; \
	if [ $$RETVAL -ne 0 ]; then \
	  echo "deploy/all-in-one-linkerd.yaml is incorrect, remember to run make make helm-linkerd to update all-in-one-linkerd.yaml"; rm -rf deploy/all-in-one-linkerd-g.yaml; exit 1; \
	fi

	@rm -rf deploy/all-in-one-linkerd-g.yaml