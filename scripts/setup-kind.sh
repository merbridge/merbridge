#!/usr/bin/env bash

set -ex

NAME=${1:-merbridge}
KIND_VERSION=${KIND_VERSION:-v0.11.1}
if [ -z "$SKIP_INSTALL" ]; then
    curl -Lo ./kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-$(uname)-amd64"
    sudo chmod +x ./kind
    sudo mv kind /usr/local/bin
fi
sudo kind create cluster --name ${NAME}
