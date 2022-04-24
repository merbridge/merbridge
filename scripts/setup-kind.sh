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

NAME=${1:-merbridge}
KIND_VERSION=${KIND_VERSION:-v0.11.1}
if [ -z "$SKIP_INSTALL" ]; then
    curl -Lo ./kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-$(uname)-amd64"
    chmod +x ./kind
    sudo mv kind /usr/local/bin
fi
kind create cluster --name ${NAME}
sudo mkdir -p /root/.kube/
sudo cp ~/.kube/config /root/.kube/config
