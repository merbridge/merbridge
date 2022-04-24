# Copyright © 2022 Merbridge Authors

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#!/usr/bin/env bash

set -ex

if [ -z "$KERNEL_VERSION" ]; then
    KERNEL_VERSION=v5.4
fi
if [ -z "$SKIP_INSTALL" ]; then
    apt update
    apt install -y git cmake make gcc python3 libncurses-dev gawk flex bison openssl \
        libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf
fi

tmp=$(mktemp -d)

git clone -b ${KERNEL_VERSION} https://github.com/torvalds/linux.git --depth 1 ${tmp}/linux

pushd ${tmp}/linux/tools/bpf/bpftool

make && sudo make install

rm -rf "${tmp}"

popd
