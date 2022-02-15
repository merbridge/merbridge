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

sudo istioctl install -y
