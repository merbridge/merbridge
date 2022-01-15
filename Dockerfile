
FROM ubuntu:20.04 as compiler

WORKDIR /app

# ENV TZ=Asia/Shanghai
ARG DEBIAN_FRONTEND=noninteractive

RUN apt update &&\
    apt install -y git cmake make gcc python3 libncurses-dev gawk flex bison openssl \
    libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf

RUN git clone -b v5.4 https://github.com/torvalds/linux.git --depth 1

RUN cd /app/linux/tools/bpf/bpftool && \
    make && make install

RUN apt install -y clang
# /usr/local/sbin/bpftool

ADD . .

RUN cd /app && make compile

FROM golang:1.17 as mbctl

WORKDIR /app

ADD go.mod .
ADD go.sum .

RUN go mod download

ADD . .

RUN go build -ldflags "-s -w" -o ./dist/mbctl ./cmd/mbctl/main.go

FROM ubuntu:20.04

WORKDIR /app

RUN apt update && apt install -y libelf-dev make sudo

COPY --from=compiler /usr/local/sbin/bpftool /usr/local/sbin/bpftool
COPY --from=compiler /app/bpf/*.o bpf/
COPY --from=compiler /app/bpf/Makefile bpf/
COPY --from=compiler /app/Makefile Makefile
COPY --from=mbctl /app/dist/mbctl mbctl

CMD /app/mbctl
