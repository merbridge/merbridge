# merbridge

Use eBPF to speed up your Service Mesh like crossing an Einstein-Rosen Bridge.

## Usage

### Install

You just only need to run the following command to your Istio cluster to get eBPF to speed up Istio:

```bash
kubectl apply -f https://raw.githubusercontent.com/merbridge/merbridge/main/deploy/all-in-one.yaml
```

### Uninstall

```bash
kubectl delete -f https://raw.githubusercontent.com/merbridge/merbridge/main/deploy/all-in-one.yaml
```

> Note: currently only works on Linux kernel >= 5.15, run `uname -r` check your kernel version before install merbridge.
