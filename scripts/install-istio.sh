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

ISTIO_VERSION=${ISTIO_VERSION:-1.12.3}
if [ -z "$SKIP_INSTALL" ]; then
    tmp=$(mktemp -d)
    pushd ${tmp}
    wget https://github.com/istio/istio/releases/download/${ISTIO_VERSION}/istio-${ISTIO_VERSION}-linux-amd64.tar.gz
    tar -zxf istio-${ISTIO_VERSION}-linux-amd64.tar.gz
    sudo cp -rf istio-${ISTIO_VERSION}/bin/istioctl /usr/local/bin
    popd
    rm -rf "${tmp}"
fi

istioctl install -y $@
