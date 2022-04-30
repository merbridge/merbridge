# merbridge

Use eBPF to speed up your Service Mesh like crossing an Einstein-Rosen Bridge.

## Usage

### Install

You just only need to run the following command to your Istio cluster to get eBPF to speed up Istio:

```bash
kubectl apply -f https://raw.githubusercontent.com/merbridge/merbridge/main/deploy/all-in-one.yaml
```

Or on Linkerd cluster:

```bash
kubectl apply -f https://raw.githubusercontent.com/merbridge/merbridge/main/deploy/all-in-one-linkerd.yaml
```

> Note: currently only works on Linux kernel >= 5.7, run `uname -r` check your kernel version before install merbridge.

If you want to install Merbridge by `Helm`, read the guidelines: [Deploy Merbridge with Helm](deploy/).

### Uninstall

- Istio:
```bash
kubectl delete -f https://raw.githubusercontent.com/merbridge/merbridge/main/deploy/all-in-one.yaml
```

- Linkerd:
```bash
kubectl delete -f https://raw.githubusercontent.com/merbridge/merbridge/main/deploy/all-in-one-linkerd.yaml
```

## Get involved

Join the [Merbridge slack](https://join.slack.com/t/merbridge/shared_invite/zt-11uc3z0w7-DMyv42eQ6s5YUxO5mZ5hwQ).

## Contributors

<a href="https://github.com/merbridge/merbridge/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=merbridge/merbridge" />
</a>

Made with [contrib.rocks](https://contrib.rocks).

## License
Copyright 2022 the Merbridge Authors. All rights reserved.

Licensed under the Apache License, Version 2.0.

## Landscapes

<p align="center">
<img src="https://landscape.cncf.io/images/left-logo.svg" width="150"/>&nbsp;&nbsp;<img src="https://landscape.cncf.io/images/right-logo.svg" width="200"/>
<br/><br/>
Merbridge enriches the <a href="https://landscape.cncf.io/?selected=merbridge">CNCF CLOUD NATIVE Landscape.</a>
</p>
