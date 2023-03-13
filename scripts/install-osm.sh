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

OSM_VERSION=${OSM_VERSION:-v1.2.3}
if [ -z "$SKIP_INSTALL" ]; then
    tmp=$(mktemp -d)
    pushd ${tmp}
    wget -c https://github.com/openservicemesh/osm/releases/download/${OSM_VERSION}/osm-${OSM_VERSION}-linux-amd64.tar.gz
    tar -zxf osm-${OSM_VERSION}-linux-amd64.tar.gz
    sudo cp -rf linux-amd64/osm /usr/local/bin
    popd
    rm -rf "${tmp}"
fi

osm_namespace=osm-system
osm_mesh_name=osm

osm install \
    --mesh-name "$osm_mesh_name" \
    --osm-namespace "$osm_namespace" \
    --set=osm.certificateProvider.kind=tresor \
    --set=osm.image.pullPolicy=Always \
    --set=osm.enablePermissiveTrafficPolicy=true \
    --verbose

kubectl wait --for=condition=ready pod -n $osm_namespace -l app=osm-bootstrap --timeout=180s

kubectl wait --for=condition=ready pod -n $osm_namespace -l app=osm-injector --timeout=180s

kubectl wait --for=condition=ready pod -n $osm_namespace -l app=osm-controller --timeout=180s