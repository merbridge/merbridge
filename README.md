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

> Note: currently only works on Linux kernel >= 5.15, run `uname -r` check your kernel version before install merbridge.

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

## License
Copyright 2022 the Merbridge Authors. All rights reserved.

Licensed under the Apache License, Version 2.0.
