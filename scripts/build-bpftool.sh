#!/usr/bin/env bash

set -ex

if [ -z "$KERNEL_VERSION" ]; then
    KERNEL_VERSION=v5.4
fi
if [ -z "$SKIP_INSTALL" ]; then
sudo apt update
sudo apt install -y git cmake make gcc python3 libncurses-dev gawk flex bison openssl \
    libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf
fi

tmp=$(mktemp -d)

git clone -b ${KERNEL_VERSION} https://github.com/torvalds/linux.git --depth 1 ${tmp}/linux

pushd ${tmp}/linux/tools/bpf/bpftool

sudo make && sudo make install

sudo rm -rf "${tmp}"

popd
