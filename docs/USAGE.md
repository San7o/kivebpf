# Usage

This document explains how to interact with the operator. You should
have the operator deployed first: to use a local development build
please read the [DEVELOPMENT](./DEVELOPMENT.md) document for
instructions, otherwise you can fetch the operator from the
[official docker registry](https://hub.docker.com/repository/docker/giovann103/kivebpf/general).

To install the operator from the online docker registry, first make
sure your system is supported by reading the `Suppoted Environments`
section in the official
[README](https://github.com/San7o/kivebpf/tree/main), then simply run:

```bash
kubectl apply -f https://raw.githubusercontent.com/San7o/kivebpf/refs/heads/main/dist/install-remote.yaml
```

Once you have the operator deployed, you can instruct It to log
accesses to files via **KivePolicies**. An `KivePolicy` is a custom
kubernetes resource that contains information about which file[s] to
trace and in which pods.  The operator will parse this policy every
time one is added / removed / updated and It will configure the eBPF
program to monitor the right files.

An example `KivePolicy` is located in
[config/samples/kive_v2alpha1_kivepolicy.yaml](../config/samples/kive_v2alpha1_kivepolicy.yaml).
More examples can be found in the same directory. Check out the
reference for [APIv1](./APIv1.md).


```yaml
apiVersion: kivebpf.san7o.github.io/v1
kind: KivePolicy
metadata:
  labels:
    app.kubernetes.io/name: kivebpf
  finalizers:
    - kivepolicy.kivebpf.san7o.github.io/finalizer
  name: kive-sample-policy
  namespace: kivebpf-system
spec:
  alertVersion: v1
  traps:
    - path: /secret.txt
      create: true
      mode: 444
      matchAny:
      - pod: nginx-pod
        namespace: default
        matchLabels:
          security-level: high
      metadata:
          severity: medium
```

This sample policy will trace the file `/secret.txt` in the pods with
name `nginx-pod` in the namespace `default` and with the label
`security-level=high`. If the file did not exist in the pod, It will
create It with `mode` permissions since `create` is set to true.

You can load it to the kubernetes cluster using the **apply** command
of [kubectl](https://kubernetes.io/docs/reference/kubectl/):

```bash
kubectl apply -f config/samples/kive_v2alpha1_kivepolicy.yaml
```

The operator will log some information when a policy is created /
deleted / updated.

It it now time to test this policy. First, we need to create a pod
that matches the `match` fields in the `KivePolicy`. This repository
provides an nginx pod in
[hack/k8s-manifests/sample-nginx-pod.yaml](../hack/k8s-manifests/sample-nginx-pod.yaml)
with the right characteristics, you can load it with kubectl:

```bash
kubectl apply -f hack/k8s-manifests/sample-nginx-pod.yaml
```

After the pod has started, you can try to access the `/secret.txt` file
by executing a command inside it:

```bash
kubectl exec -it nginx-pod -- cat /secret.txt
```

You should expect to see some logging information on the standard
output of one of the kive pods, like this (prettified):

```json
2025-08-02T16:51:19Z    INFO    Access Detected
{
  "KiveAlert": {
    "kive-alert-version": "v1",
    "kive-policy-name": "kive-sample-policy",
    "timestamp": "2025-08-02T16:51:19Z",
    "metadata": {
      "path": "/secret.txt",
      "inode": 16256084,
      "mask": 36,
      "kernel-id": "2c147a95-23e5-4f99-a2de-67d5e9fdb502"
    },
    "pod": {
      "name": "nginx-pod",
      "namespace": "default",
      "container": {
        "id": "containerd://0c37512624823392d71e99a12011148db30ba7ea2a74fc7ff8bd5f85bc7b499c",
        "name": "nginx"
      }
    },
    "node": {
      "name": "kive-worker"
    },
    "process": {
      "pid": 176928,
      "tgid": 176928,
      "uid": 0,
      "gid": 0,
      "binary": "cat",
      "cwd": ""
    }
  }
}
```

Note that only the leader pod in the kernel where the file resides
will output the information, so you may need to check the standard
output of all the kive pods. This happens because the data is logged
in the same node where the eBPF program noticed the access (to
understand how the operator works under the hood, read the
[DESIGN](./DESIGN.md) document), we will later see how you can easily
gather all the logs in a single place using [callbacks](#callback).

You may have seen a message like this just above the alert:

```txt
Could not read /host/proc/176917/cwd while generating an KiveAlert, this can happen if the process terminated too quickly for the operator to react or the node is running in a container and procfs is not mounted in /host/real/proc
```

If you setup the cluster correctly, the problem here is that the `cat`
process died before the operator could read the information associated
with the process. Those missing informations will simply be empty
values in the output and do not cause the operator to break. Try to
keep the process alive and see that the warning does not appear and
you get additional information such as the current working directory
(cwd) and the arguments to the binary:

```bash
kubectl exec -it nginx-pod -- cat /secret.txt -
```

Support for getting the process information is in the work.

<a name="callback"></a>

## Callback

You can ask the operator to use send data to an endpoint by setting
the `callback` filed in a trap like this:

```yaml
apiVersion: kivebpf.san7o.github.io/v1
kind: KivePolicy
metadata:
  labels:
    app.kubernetes.io/name: kivebpf
  finalizers:
    - kivepolicy.kivebpf.san7o.github.io/finalizer
  name: kive-sample-policy
  namespace: kivebpf-system
spec:
  alertVersion: v1
  traps:
    - path: /secret.txt
      create: true
      mode: 444
      callback: "http://callback-service.kivebpf-system.svc.cluster.local:9376/ingest"  # HERE
      matchAny:
      - pod: nginx-pod
        namespace: default
        matchLabels:
          security-level: high
```

If a callback is set on a trap, then the operator will make an HTTP
POST request to that endpoint with the `KiveAlert` as json data and
will stop logging to the standard output.
