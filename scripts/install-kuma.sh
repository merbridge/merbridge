#!/usr/bin/env bash

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

set -ex

KUMA_VERSION=${KUMA_VERSION:-1.7.0}
if [ -z "$SKIP_INSTALL" ]; then
    tmp=$(mktemp -d)
    pushd "${tmp}"
    VERSION=$KUMA_VERSION curl -L https://kuma.io/installer.sh | bash -
    sudo cp -rf "kuma-${KUMA_VERSION}/bin/kumactl" /usr/local/bin
    popd
    rm -rf "${tmp}"
fi

kumactl install control-plane | kubectl apply -f -
kubectl rollout status deployment -n kuma-system kuma-control-plane
