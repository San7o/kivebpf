# kivebpf

Kivebpf is a free and open source eBPF-powered file access monitoring
Kubernetes operator.

Kivebpf is used by [Koney](https://github.com/dynatrace-oss/koney/) to
place deception policies on kubernetes clusters.

Note that Kivebpf is not yet ready for production use.

# Basic Usage

You can specify a path to monitor and in which containers by
creating a `KivePolicy`. The following is an example policy:

```yaml
apiVersion: kivebpf.san7o.github.io/v1
kind: KivePolicy
metadata:
  labels:
    app.kubernetes.io/name: kivebpf
  name: kive-sample-policy
  namespace: kivebpf-system
spec:
  alertVersion: v1
  traps:
  - path: /secret.txt
    create: true
    mode: 444
    callback: "http://my-callback.com/alerts"
    matchAny:
    - pod: nginx-pod
      namespace: default
      containerName: "regex:nginx-.*"
      matchLabels:
        security-level: high
    metadata:
      alert-level: critical
```

This sets up a trap on the path `/secret.txt` in the matched
containers, creating it with `mode` permissions if it does not
exist. The match groups under the `matchAny` field will be matched via
a logical OR, and each field in a match group is matched with a
logical AND. All the match fields are optional, but there must be at
least one match group under `matchAny`.

When a file gets accessed, the operator will generate an `KiveAlert`
and print the information to standard output in json format. The
following is an example alert:

```json
{
  "kive-alert-version": "v1",
  "kive-policy-name": "kive-sample-policy",
  "timestamp": "2025-08-02T16:51:19Z",
  "metadata": {
    "path": "/secret.txt",
    "inode": 16256084,
    "mask": 36,
    "kernel-id": "2c147a95-23e5-4f99-a2de-67d5e9fdb502"
  },
  "custom-metadata": {
    "alert-level": "critical"
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
    "binary": "/usr/bin/cat",
    "cwd": "/",
    "arguments": "/secret.txt -"
  }
}
```

- `cwd` and `arguments` are currently disabled

If you specify a `callback` in the `KivePolicy`, then the data will be
sent to the URL of the callback through an HTTP POST request.

Please, read the [USAGE](./docs/USAGE.md) document to learn how to use
the operator in more detail. You can find more examples in
[config/samples](./config/samples/).

## Quick deploy

Simply install the operator from the [official docker
repository](https://hub.docker.com/repository/docker/giovann103/kivebpf/general):

```bash
kubectl apply -f https://raw.githubusercontent.com/San7o/kivebpf/refs/heads/main/dist/install-remote.yaml
```

## Supported Environments

| Component          | Supported Version(s)     | Notes                                                               |
| ------------------ | ------------------------ | ------------------------------------------------------------------- |
| Kubernetes         | v1.33.x minikube or kind |                                                                     |
| Container Runtime  | containerd               | Only `containerd` is supported at the moment.                       |
| Go (for dev build) | 1.24                     | Required for building the operator.                                 |
| Linux Version      | >= 5.10                  | All kernels from 5.10 are supported. Tested on 5.10, 6.6, and 6.14. |
| Architectures      | x86_64                   | The eBPF program works only on x86_64.                              |

# Development

The [DESIGN](./docs/DESIGN.md) document contains all the information
about the internals of the operator.

Please read the [DEVELOPMENT](./docs/DEVELOPMENT.md) document to build
and get started with Kive's
development. [EBPF-TESTING](./docs/EBPF-TESTING.md) has instructions
to build and test the eBPF program without running the kubernetes
operator. To run a local cluster, take a look at
[k8s-lab](./k8s-lab/README.md) or simply use the script
[registry-cluster.sh](./hack/registry-cluster.sh).

The [status](./docs/status.org) contains information about the current
status of development and future work.
