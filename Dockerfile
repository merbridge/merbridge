
FROM ubuntu:20.04 as compiler

WORKDIR /app

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update &&\
    apt-get install -y git cmake make gcc python3 libncurses-dev gawk flex bison openssl \
    libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf

RUN git clone -b v5.4 https://github.com/torvalds/linux.git --depth 1

RUN cd /app/linux/tools/bpf/bpftool && \
    make && make install

FROM golang:1.18.0 as mbctl

WORKDIR /app

ADD go.mod .
ADD go.sum .

RUN go mod download

ADD . .

RUN go build -ldflags "-s -w" -o ./dist/mbctl ./app/main.go

FROM ubuntu:20.04

WORKDIR /app

RUN apt-get update && apt-get install -y libelf-dev make sudo clang iproute2
COPY --from=compiler /usr/local/sbin/bpftool /usr/local/sbin/bpftool
COPY bpf bpf
COPY Makefile Makefile
COPY --from=mbctl /app/dist/mbctl mbctl

CMD /app/mbctl
