/*
                    GNU GENERAL PUBLIC LICENSE
                       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/

// SPDX-License-Identifier: GPL-2.0-only

package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logger "sigs.k8s.io/controller-runtime/pkg/log"

	kivev2alpha1 "github.com/San7o/kivebpf/api/v2alpha1"
	comm "github.com/San7o/kivebpf/internal/controller/comm"
	ebpf "github.com/San7o/kivebpf/internal/controller/ebpf"
)

type KiveDataReconciler struct {
	client.Client
	UncachedClient client.Reader
	Scheme         *runtime.Scheme
}

const (
	KiveDataFinalizerName = "kivedata.kivebpf.san7o.github.io/finalizer"
)

// +kubebuilder:rbac:groups=kivebpf.san7o.github.io,resources=kivedata,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kivebpf.san7o.github.io,resources=kivedata/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kivebpf.san7o.github.io,resources=kivedata/finalizers,verbs=update

func (r *KiveDataReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	log := logger.FromContext(ctx)
	log.Info("KiveData reconcile triggered.")

	if !ebpf.Loaded {
		log.Info("Loading eBPF program")
		if err := ebpf.LoadEbpf(ctx); err != nil { // Fatal
			return ctrl.Result{}, fmt.Errorf("Reconcile Error Load eBPF program: %w", err)
		}
		go Output(r.UncachedClient)
	}

	kiveDataLabels := client.MatchingLabels{
		comm.KernelIDLabel: KernelID,
	}
	kiveDataList := &kivev2alpha1.KiveDataList{}
	err := r.Client.List(ctx, kiveDataList, kiveDataLabels)
	if err != nil { // Fatal
		return ctrl.Result{}, fmt.Errorf("Reconcile Error Failed to get Kive Data resource: %w", err)
	}

	kivePolicyList := &kivev2alpha1.KivePolicyList{}
	err = r.Client.List(ctx, kivePolicyList)
	if err != nil { // Fatal
		return ctrl.Result{}, fmt.Errorf("Reconcile Error Failed to get KivePolicy resource: %w", err)
	}

	// Check if each KiveData (referring to this kernel id) does have a
	// corresponding KivePolicy. If it does, then we update the eBPF
	// map with the information from the KiveData. If it doesn't, then
	// the KivePolicy has been eliminated and the KiveData should be
	// deleted.
Data:
	for _, kiveData := range kiveDataList.Items {

		// Check if this KiveData is being deleted
		if !kiveData.ObjectMeta.DeletionTimestamp.IsZero() {

			if controllerutil.ContainsFinalizer(&kiveData, KiveDataFinalizerName) {

				kiveDataCopy := kiveData.DeepCopy()

				err := ebpf.RemoveInode(ebpf.BpfMapKey{Inode: kiveData.Spec.InodeNo, Dev: kiveData.Spec.DevID})
				if err != nil {
					log.Info("Reconcile Error Remove Inode during deletion of KiveData %s: %w", kiveData.Name, err)
				}

				controllerutil.RemoveFinalizer(kiveDataCopy, KiveDataFinalizerName)

				err = r.Client.Patch(ctx, kiveDataCopy, client.MergeFrom(&kiveData))
				if err != nil {

					// Try again
					log.Info("Reconcile Error Update finalizer for KiveData,, trying again", "name", kiveData.Name, "error", err)
					return ctrl.Result{Requeue: true}, nil
				}

				// Patch causes reconciliation, so we return from this one
				log.Info("Successfully deleted KiveData", "name", kiveDataCopy.Name)
				return ctrl.Result{}, nil

			}
			continue Data
		}

		// Check if there is a finalizer
		if !controllerutil.ContainsFinalizer(&kiveData, KiveDataFinalizerName) {

			kiveDataCopy := kiveData.DeepCopy()
			controllerutil.AddFinalizer(kiveDataCopy, KiveDataFinalizerName)
			err := r.Client.Patch(ctx, kiveDataCopy, client.MergeFrom(&kiveData))
			if err != nil {

				// Try again
				log.Info("Reconcile Could not add finalizer to KiveData, trying again", "name", kiveData.Name, "error", err)
				return ctrl.Result{Requeue: true}, nil
			} else {

				// Patch causes reconciliation, so we return from this one
				log.Info("Successfully added finalizer to KiveData", "name", kiveData.Name)
				return ctrl.Result{}, nil
			}
		}

		found := false
	Policy:
		for _, kivePolicy := range kivePolicyList.Items {

			if !kivePolicy.ObjectMeta.DeletionTimestamp.IsZero() {
				continue Policy
			}

		Trap:
			for _, kiveTrap := range kivePolicy.Spec.Traps {

				found, err = KiveDataTrapCmp(kiveData, kiveTrap)
				if err != nil {
					log.Error(err, fmt.Sprintf("Reconcile Error Failed compare KiveData %s and Trap with path %s", kiveData.Name, kiveTrap.Path))
					continue Trap
				}

				if !found {
					continue Trap
				}

				// Check that container exists
				matchingFields := client.MatchingFields{}
				matchingFields["metadata.name"] = kiveData.Annotations["pod-name"]
				matchingFields["metadata.namespace"] = kiveData.Annotations["namespace"]
				matchingFields["spec.nodeName"] = kiveData.Annotations["node-name"]
				podList := &corev1.PodList{}
				err = r.UncachedClient.List(ctx, podList, matchingFields)
				if err != nil {
					log.Error(err, "Reconcile Error Failed to list pods")
					continue Trap
				}

				found = false
				for _, pod := range podList.Items {
					for _, containerStatus := range pod.Status.ContainerStatuses {
						if KiveDataContainerCmp(kiveData, pod, containerStatus) {
							found = true
							break Policy
						}
					}
				}
			}
		}

		if !found {
			err := r.Client.Delete(ctx, &kiveData)
			if err != nil {
				log.Error(err, fmt.Sprintf("Reconciler Error Delete KiveData %s", kiveData.Name))
				continue Data
			}

			log.Info("Deleting KiveData")
			continue Data
		}

		err = ebpf.AddInode(ebpf.BpfMapKey{Inode: kiveData.Spec.InodeNo, Dev: kiveData.Spec.DevID})
		if err != nil {
			log.Error(err, fmt.Sprintf("Reconcile Error Update map with inode %d for KiveData %s", kiveData.Spec.InodeNo, kiveData.Name))
			continue Data
		}
	}

	return ctrl.Result{}, nil
}

func (r *KiveDataReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// Index pod name, namespace and ip so we can query a pod
	fieldIndexer := mgr.GetFieldIndexer()
	err := fieldIndexer.IndexField(context.Background(), &corev1.Pod{}, "metadata.name",
		func(rawObj client.Object) []string {
			return []string{rawObj.GetName()}
		})
	if err != nil {
		return fmt.Errorf("SetupWithManager Error Index Pod Name: %w", err)
	}

	err = fieldIndexer.IndexField(context.Background(), &corev1.Pod{}, "metadata.namespace",
		func(rawObj client.Object) []string {
			return []string{rawObj.GetNamespace()}
		})
	if err != nil {
		return fmt.Errorf("SetupWithManager Error Index Pod Namespace: %w", err)
	}

	err = fieldIndexer.IndexField(context.Background(), &corev1.Pod{}, "spec.nodeName",
		func(rawObj client.Object) []string {
			return []string{rawObj.GetNamespace()}
		})
	if err != nil {
		return fmt.Errorf("SetupWithManager Error Index Pod NodeName: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&kivev2alpha1.KiveData{}).
		Complete(r)
}
