# Developement

This document contains useful information to build the operator
yourself. It explains how to create a local test cluster and build
both the eBPF program and the kubernetes operator. For regular usage,
please read the [USAGE](./USAGE.md) document.

## Setup a local cluster

To use an operator, you need a kubernetes cluster. In the [official
repository](https://github.com/San7o/kivebpf) you can find the
script [hack/registry-cluster.sh](../hack/registry-cluster.sh) which will
create a local cluster using
[kind](https://github.com/kubernetes-sigs/kind) with one control node
and one worker node. Additionally, It sets up a local docker registry
to push the operator image during development.

Run the following command to create the cluster (needs to be run only
once):

```bash
make create-cluster-local
```

You can delete the cluster with `delete-cluster.sh` or with
`make delete-cluster-local` when you do not need It anymore.

On minikube:

```bash
minikube start --container-runtime=containerd
```

## Dev Environments

For convenience, this project uses different environments to manage
building and deploying. By default, there are two different
environments: `local` and `remote`.

You can easily add a custom environment by creating a file called
`.env-<ENV-NAME>` where `<ENV-NAME>` is a name of your choice. This
file will be included in the Makefile before running any command, so
you can change the variables used by the Makefile from the env file
without changing the Makefile.

For example, the `IMG` variable tells the Makefile where to push
images and tells the operator where to pull them. You can add an entry
to your custom environment `.env-custom` like so:

```bash
IMG=registry/my-bautiful-name:latest
```

To select which environment to use, append `ENV=<ENV-NAME>` to your
make commands, for example:

```bash
make deploy ENV=custom
```

The default environment is `local`, in this case you can omit the `ENV`
from the make command to use the local environment. You can use
environments on all make commands.

## Generate files

The operator uses generators to create various config files such as
RBAC policies, CRD manifests and the eBPF program. Those need to be
regenerated every time they are updated.

To generate the RBAC policies, run:

```bash
make generate
```

To create the CRD manifests, run:

```bash
make manifests
```

To generate the eBPF program, you need to have the following
dependencies in your system:

- Linux kernel version 5.7 or later, with ebpf support enabled
- LLVM 11 or later (clang and llvm-strip)
- libbpf headers
- Linux kernel headers
- a recent go compiler

On Ubuntu, you can run the following command to install the required
dependencies:

```bash
apt-get install make clang llvm libbpf-dev golang linux-headers-$(uname -r)
```

Once you have the dependencies, run:

```bash
make generate-ebpf
```

If you just want to test the eBPF program without building / deploying
the entire operator, please refer to the
[BPF-TESTING](./EBPF-TESTING.md) document.

Now, if you simply want to check if the operator compiles, you can run
`make` and the operator will be compiled locally. This is not enough
to use or test the operator since it neds to be running in a
kubernetes cluster in a pod, we will now see how to do this.

## Build the docker container

Note that you may need sudo privileges for the following commands
depending on your permissions.

To build the docker image, first **make sure that generated files are
updated** (section above), then build the image with:

```bash
make docker-build
```

If you generated the cluster with `registry-cluster.sh`, you can push
it to a test local docker repository:

```bash
make docker-push
```

Or specify how to tag / push the image by modifying the `IMG` env
variable in your environment.

To do both `docker-build` and `docker-push` in a single command, you
can run:

```bash
make docker
```

## Deploy the operator

If you just want to load *only* the custom resources, run:

```bash
make install
```

If you want to deploy the full operator (including resources), run:

```bash
make deploy
```

You can now proceed by reading the [USAGE](./USAGE.md) document which
will explain how to use the operator.

Important note: if you are using Kind, or any other cluster where the
nodes run inside a container, the `cwd` and `arguments` in the
`KiveAlert` will be empty or incorrect. This happens because the
`/proc` filesystem inside a node in a Kind cluster is not the real
host procfs. For this reason, if you want to read `cwd` and
`arguments` you need to mount `/proc` inside the node in
`/host/real/proc` (done by default if you used the script to generate
the cluster provided by this project). Then, after deploying the
operator, you need to patch it by applying the config in
`hack/kind-mount-procfs.yaml`.

## Testing

To run end to end tests, first make sure that you have a cluster
running with the operator deployed, and that there is not `KivePolicy`
present. Then, simply run:

```bash
make test
```

## Useful commands

When building a new docker image, you want the kive pods to update to
the new version. The pods are already configured to fetch the latest
version of the image in the local test docker repository, to do so you
just need to kill them. You can use the following command:

```bash
make kill-pods
```

This will also remove all the `KiveData` resources so that you start
with a clean configuration, as if you just applied the `KivePolicies`.

To completely remove the operator from the cluster, run:

```bash
make undeploy
```

Other commands can be found via `make help`.

```bash
make help
```
