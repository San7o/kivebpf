/*
                    GNU GENERAL PUBLIC LICENSE
                       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/

// SPDX-License-Identifier: GPL-2.0-only

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	kivev2alpha1 "github.com/San7o/kivebpf/api/v2alpha1"
	comm "github.com/San7o/kivebpf/internal/controller/comm"
)

const (
	MapMaxEntries = 1024
	KprobedFunc   = "inode_permission"
)

var (
	RingbuffReader *ringbuf.Reader = nil
	Objs           bpfObjects      = bpfObjects{}
	Kprobe         link.Link       = nil
	Loaded         bool            = false
)

type BpfMapKey = bpfMapKey

/*
 *  Loads the eBPF objects, the eBPF program and opens the ring
 *  buffer.
 */
func LoadEbpf(ctx context.Context) error {

	// Remove resource limits for kernels <5.11.
	err := rlimit.RemoveMemlock()
	if err != nil {
		return fmt.Errorf("LoadEbpf Error Remove memlock: %w", err)
	}

	if err = loadBpfObjects(&Objs, nil); err != nil {
		return fmt.Errorf("LoadEbpf Error Load eBPF objects: %w", err)
	}

	kernelIsOld, err := isKernelOld()
	if err != nil {
		return fmt.Errorf("LoadEbpf Error Check kernel version: %w", err)
	}

	if kernelIsOld {
		Kprobe, err = link.Kprobe(KprobedFunc, Objs.KprobeInodePermissionOld, nil)
		if err != nil {
			return fmt.Errorf("LoadEbpf Error Open kprobe (old kernel): %w", err)
		}
	} else {
		Kprobe, err = link.Kprobe(KprobedFunc, Objs.KprobeInodePermissionNew, nil)
		if err != nil {
			return fmt.Errorf("LoadEbpf Error Open kprobe: %w", err)
		}
	}

	RingbuffReader, err = ringbuf.NewReader(Objs.Rb)
	if err != nil {
		return fmt.Errorf("LoadEbpf Error Open ringbuf reader: %w", err)
	}

	Loaded = true
	return nil
}

/*
 *  Unload the eBPF program, objects and ringbuffer.
 */
func UnloadEbpf(ctx context.Context) error {

	if Kprobe != nil {

		if err := Kprobe.Close(); err != nil {
			return fmt.Errorf("UnloadEbpf Error Failed to close ebpf program: %w", err)
		}

		if err := Objs.TracedInodes.Close(); err != nil {
			return fmt.Errorf("UnloadEbpf Error Failed to close eBPF map: %w", err)
		}

		if err := Objs.Close(); err != nil {
			return fmt.Errorf("UnloadEbpf Error Failed to close eBPF objects: %w", err)
		}

		if RingbuffReader != nil {
			if err := RingbuffReader.Close(); err != nil {
				return fmt.Errorf("UnloadEbpf Error failed to close the Rinbuffer Reader: %w", err)
			}
		}

		Loaded = false
	}

	return nil
}

/*
 *  Read the data from the Ringbuffer, hangs until data is received or
 *  returns an error. This function can be used without a running
 *  kubernetes cluster.
 */
func ReadEbpfData() (bpfLogData, error) {

	var data bpfLogData
	record, err := RingbuffReader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return bpfLogData{}, fmt.Errorf("ReadAlert Error Buffer closed.")
		}
	}

	err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &data)
	if err != nil {
		return bpfLogData{}, fmt.Errorf("ReadAlert Error Parse ringbuf data")
	}

	return data, nil
}

func ReadAlert(ctx context.Context, cli client.Reader) (kivev2alpha1.KiveAlert, error) {

	if RingbuffReader == nil {
		return kivev2alpha1.KiveAlert{}, fmt.Errorf("ReadAlert Error Ringbuffer not inizialized")
	}

	log := log.FromContext(ctx)
	data, err := ReadEbpfData() // Hangs
	if err != nil {
		return kivev2alpha1.KiveAlert{}, fmt.Errorf("ReadAlert Error Reading Ebpf Data: %w", err)
	}

	kiveDataList := &kivev2alpha1.KiveDataList{}
	err = cli.List(ctx, kiveDataList)
	if err != nil {
		return kivev2alpha1.KiveAlert{}, fmt.Errorf("ReadAlert Error Failed to get Kive Data resource: %w", err)
	}

	for _, kiveData := range kiveDataList.Items {
		if kiveData.Spec.InodeNo == data.Ino {

			cwd := ""
			args := ""
			binary := ""

			// If the node is a container on some host, then we need to read
			// the host's procfs which is assumed to be mounted in
			// /host/real/proc. If this does not exist, either the cluster
			// is misconfigured or it is non containerized, then we check
			// the regualr procfs of the node. This workaround is needed
			// since procfs of a node is not the same as the host if the
			// node is a container on the host (for example, for clusters
			// created using Kind)
			//
			// TODO: this is a hack and has been disabled until a better
			//       solution is ound
			/*
				cmdLine := ""
				readSuccess := true
				cwd, err = os.Readlink(fmt.Sprintf("%s/%d/cwd", container.RealHostProcMountpoint, data.Pid))
				if err != nil {
					cwd, err = os.Readlink(fmt.Sprintf("%s/%d/cwd", container.ProcMountpoint, data.Pid))
					if err != nil {
						readSuccess = false
						// error is handled gracefully
						log.Info(fmt.Sprintf("Could not read %s/%d/cwd while generating an KiveAlert, this can happen if the process terminated too quickly for the operator to react or the node is running in a container and procfs is not mounted in %s", container.ProcMountpoint, data.Pid, container.RealHostProcMountpoint))
					}
				}

				if readSuccess {

					cmdlinePath := fmt.Sprintf("%s/%d/cmdline", container.RealHostProcMountpoint, data.Pid)
					cmdlineBytes, err := os.ReadFile(cmdlinePath)
					if err != nil {
						cmdlinePath = fmt.Sprintf("%s/%d/cmdline", container.ProcMountpoint, data.Pid)
						cmdlineBytes, err = os.ReadFile(cmdlinePath)
						if err != nil {
							// error is handled gracefully
							log.Info(fmt.Sprintf("Could not read %s/%d/cmdline while generating an KiveAlert, this can happen if the process terminated too quickly for the operator to react or the node is running in a container and procfs is not mounted in %s", container.ProcMountpoint, data.Pid, container.RealHostProcMountpoint))
						}
					}
					cmdLine = string(cmdlineBytes)
				}
			*/

			binary = int8ArrayToString(data.Comm[:])

			// TODO: see above
			/*
				if cmdLine != "" {
					binary, args = parseCmdline(cmdLine)
				}
			*/

			kiveAlertVersion := kiveData.Annotations["kive-alert-version"]
			if kiveAlertVersion == "" {
				kiveAlertVersion = "v1"
			} else if !slices.Contains(kivev2alpha1.SupportedKiveAlertVersions, kiveAlertVersion) {
				log.Info(fmt.Sprintf("Generate KiveAlert for KivePolicy %s: version %s is not supported, defaulting to v1",
					kiveData.Annotations["kive-policy-name"], kiveData.Annotations["version"]))
				kiveAlertVersion = "v1"
			}

			out := kivev2alpha1.KiveAlert{
				AlertVersion: kiveAlertVersion,
				PolicyName:   kiveData.Annotations["kive-policy-name"],
				Timestamp:    time.Now().UTC().Format(time.RFC3339),
				Metadata: kivev2alpha1.KiveAlertMetadata{
					Path:     kiveData.Annotations["path"],
					Inode:    data.Ino,
					Mask:     data.Mask,
					KernelID: kiveData.ObjectMeta.Labels[comm.KernelIDLabel],
					Callback: kiveData.ObjectMeta.Annotations["callback"],
				},
				CustomMetadata: map[string]string{},
				Pod: kivev2alpha1.PodMetadata{
					Name:      kiveData.Annotations["pod-name"],
					Namespace: kiveData.Annotations["namespace"],
					Container: kivev2alpha1.ContainerMetadata{
						Id:   kiveData.Annotations["container-id"],
						Name: kiveData.Annotations["container-name"],
					},
					Ip: kiveData.Annotations["ip"],
				},
				Node: kivev2alpha1.NodeMetadata{
					Name: kiveData.Annotations["node-name"],
				},
				Process: kivev2alpha1.ProcessMetadata{
					Pid:       data.Pid,
					Tgid:      data.Tgid,
					Uid:       data.Uid,
					Gid:       data.Gid,
					Binary:    binary,
					Cwd:       cwd,
					Arguments: args,
				},
			}

			for key, val := range kiveData.Spec.Metadata {
				out.CustomMetadata[key] = val
			}

			return out, nil
		}
	}

	return kivev2alpha1.KiveAlert{}, fmt.Errorf("ReadAlert Error eBPF data received but no corresponsing kiveData was found")
}
