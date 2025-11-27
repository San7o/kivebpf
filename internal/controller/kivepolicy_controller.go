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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	kivev2alpha1 "github.com/San7o/kivebpf/api/v2alpha1"
	comm "github.com/San7o/kivebpf/internal/controller/comm"
	container "github.com/San7o/kivebpf/internal/controller/container"
)

const (
	KivePolicyFinalizerName = "kivepolicy.kivebpf.san7o.github.io/finalizer"
)

var (
	KernelID string = ""
)

type KivePolicyReconciler struct {
	client.Client
	UncachedClient client.Reader
	Scheme         *runtime.Scheme
}

// +kubebuilder:rbac:groups=kivebpf.san7o.github.io,resources=kivepolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kivebpf.san7o.github.io,resources=kivepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kivebpf.san7o.github.io,resources=kivepolicies/finalizers,verbs=update

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods/status,verbs=get
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=deployments/status,verbs=get

// The KivePolicy reconciliation is responsible for the following:
//   - For each KivePolicy, fetch files' information such as the inode
//     number from the matched container.
//   - create KiveData resources with the previously fetched information
//     if not already present.
func (r *KivePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	log := log.FromContext(ctx)
	var err error = nil
	log.Info("KivePolicy reconcile triggered.")

	kivePolicyList := &kivev2alpha1.KivePolicyList{}
	err = r.UncachedClient.List(ctx, kivePolicyList)
	if err != nil { // Fatal
		return ctrl.Result{}, fmt.Errorf("Reconcile Error Failed to get KivePolicy resource: %w", err)
	}

	// Loop over the KivePolicies and check if all the corresponsing
	// KiveData exist. In case they does not, a new KiveData is created.
Policy:
	for _, kivePolicy := range kivePolicyList.Items {

		// Check if this policy is being deleted
		if !kivePolicy.ObjectMeta.DeletionTimestamp.IsZero() {

			if controllerutil.ContainsFinalizer(&kivePolicy, KivePolicyFinalizerName) {

				kivePolicyCopy := kivePolicy.DeepCopy()
				controllerutil.RemoveFinalizer(kivePolicyCopy, KivePolicyFinalizerName)
				err := r.Client.Patch(ctx, kivePolicyCopy, client.MergeFrom(&kivePolicy))
				if err != nil {

					// Try again
					log.Info("Reconcile Error Update finalizer for KivePolicy, trying again", "name", kivePolicy.Name, "error", err)
					return ctrl.Result{Requeue: true}, nil
				}

				// Patch causes reconciliation, so we return from this one
				log.Info("Successfully deleted KivePolicy", "name", kivePolicy.Name)
				return ctrl.Result{}, nil
			}
			continue Policy
		}

		// Check if there is a finalizer
		if !controllerutil.ContainsFinalizer(&kivePolicy, KivePolicyFinalizerName) {

			kivePolicyCopy := kivePolicy.DeepCopy()
			controllerutil.AddFinalizer(kivePolicyCopy, KivePolicyFinalizerName)
			err := r.Client.Patch(ctx, kivePolicyCopy, client.MergeFrom(&kivePolicy))
			if err != nil {

				// Try again
				log.Info("Reconcile Could not add finalizer for KivePolicy, trying again", "name", kivePolicy.Name, "error", err)
				return ctrl.Result{Requeue: true}, nil
			} else {

				// Patch causes reconciliation, so we return from this one
				log.Info("Successfully added finalizer to KivePolicy", "name", kivePolicy.Name)
				return ctrl.Result{}, nil
			}
		}

	Trap:
		for _, kiveTrap := range kivePolicy.Spec.Traps {

			// Saves which containers are already matched by this trap so
			// that they do not get matched twice and have two different
			// KiveAlerts from the same trap
			matchedContainers := map[string]bool{}

			trapID, err := KiveTrapHashID(kiveTrap, kivePolicy.Spec.AlertVersion)
			if err != nil {
				log.Error(err, fmt.Sprintf("Reconcile Error Generate TrapID for Trap at path %s in KivePolicy %s", kiveTrap.Path, kivePolicy.Name))
				continue Trap
			}

		Match:
			for _, kiveTrapMatch := range kiveTrap.MatchAny {

				// Get Pods that match this KiveTrap
				labelMap := make(client.MatchingLabels)
				labelMap = kiveTrapMatch.MatchLabels

				matchingFields := client.MatchingFields{}
				if kiveTrapMatch.PodName != "" {
					matchingFields["metadata.name"] = kiveTrapMatch.PodName
				}
				if kiveTrapMatch.Namespace != "" {
					matchingFields["metadata.namespace"] = kiveTrapMatch.Namespace
				}
				if kiveTrapMatch.IP != "" {
					matchingFields["metadata.podIP"] = kiveTrapMatch.IP
				}
				podList := &corev1.PodList{}
				err = r.UncachedClient.List(ctx, podList, labelMap, matchingFields)
				if err != nil {
					log.Error(err, "Reconcile Error Failed to list pods")
					continue Match
				}

				for _, pod := range podList.Items {

				Container:
					for _, containerStatus := range pod.Status.ContainerStatuses {

						match, err := RegexMatch(kiveTrapMatch.ContainerName, containerStatus.Name)
						if err != nil {
							log.Error(err, fmt.Sprintf("Reconcile error matching regex %s with container %s", kiveTrapMatch.ContainerName, containerStatus.Name))
							continue Container
						}
						if !match {
							continue Container
						}

						if pod.Status.Phase != corev1.PodRunning {
							return ctrl.Result{Requeue: true}, nil
						}

						matchID := pod.Name + pod.Namespace + containerStatus.Name
						if _, ok := matchedContainers[matchID]; ok {
							// This container was already registered
							continue Container
						}
						matchedContainers[matchID] = true

						containerData, err := container.GetContainerData(ctx, containerStatus, kiveTrap)
						if err != nil {
							log.Error(err, fmt.Sprintf("Reconcile Error Get contianer data for container %s", containerStatus.Name))
							continue Container
						}
						if containerData.ShouldRequeue {
							return ctrl.Result{Requeue: true}, nil
						}
						if !containerData.IsFound { // Inode was not found
							continue Container
						}
						inode := containerData.Ino
						dev := containerData.DevID

						// Here we are crating a new KiveData since an already existing
						// one for this Pod and this KivePolicy has not been found
						kiveData := &kivev2alpha1.KiveData{
							TypeMeta: metav1.TypeMeta{
								Kind:       "KiveData",
								APIVersion: "kivebpf.san7o.github.io/v2alpha1",
							},
							ObjectMeta: metav1.ObjectMeta{
								// Give it an unique name
								Name:      NewKiveDataName(inode, dev, pod, containerStatus),
								Namespace: kivev2alpha1.Namespace,
								// Annotations are used as information for the KiveAlert
								Annotations: map[string]string{
									"kive-alert-version": kivePolicy.Spec.AlertVersion,
									"kive-policy-name":   kivePolicy.Name,
									"callback":           kiveTrap.Callback,
									"pod-name":           pod.Name,
									"namespace":          pod.Namespace,
									"pod-ip":             pod.Status.PodIP,
									"path":               kiveTrap.Path,
									"container-id":       containerData.ID,
									"container-name":     containerData.Name,
									"node-name":          pod.Spec.NodeName,
								},
								Labels: map[string]string{
									// The trap-id is used to link this KiveData to this trap
									TrapIDLabel:        trapID,
									comm.KernelIDLabel: KernelID,
								},
								Finalizers: []string{KiveDataFinalizerName},
							},
							Spec: kivev2alpha1.KiveDataSpec{
								InodeNo:  inode,
								DevID:    dev,
								Metadata: map[string]string{},
							},
						}

						for key, val := range kiveTrap.Metadata {
							kiveData.Spec.Metadata[key] = val
						}

						err = r.Client.Patch(ctx, kiveData, client.Apply, client.ForceOwnership, client.FieldOwner(FieldOwnerKiveController))
						if err != nil {
							log.Error(err, fmt.Sprintf("Reconcile Error patch KiveData resource %s", kiveData.Name))
							continue Container
						}
						log.Info("Created / Updated KiveData resource.")
					}
				}
			}
		}
	}

	// Force a reconciliation for KiveData, which will delete any
	// KiveData that does not belong anymore to a KivePolicy.
	// We trigger a reconciliation by updating an annotation with the
	// current time.
	kiveDataList := &kivev2alpha1.KiveDataList{}
	err = r.UncachedClient.List(ctx, kiveDataList)
	if err != nil { // Fatal
		return ctrl.Result{}, fmt.Errorf("Reconcile Error Failed to get KiveData resource: %w", err)
	}

	if len(kiveDataList.Items) == 0 {
		return ctrl.Result{}, nil
	}
	kiveData := kiveDataList.Items[0]
	orig := kiveData.DeepCopy()
	if kiveData.Annotations == nil {
		kiveData.Annotations = map[string]string{}
	}
	kiveData.Annotations["force-reconcile"] = time.Now().UTC().Format(time.RFC3339)
	err = r.Patch(ctx, &kiveData, client.MergeFrom(orig))
	if err != nil {
		log.Error(err, fmt.Sprintf("Reconcile Error Patch KiveData %s", kiveData.Name))
	}
	return ctrl.Result{}, nil
}

func (r *KivePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {

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

	err = fieldIndexer.IndexField(context.Background(), &corev1.Pod{}, "metadata.podIP",
		func(rawObj client.Object) []string {
			pod := rawObj.(*corev1.Pod)
			return []string{pod.Status.PodIP}
		})
	if err != nil {
		return fmt.Errorf("SetupWithManager Error Index Pod Ip: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&kivev2alpha1.KivePolicy{}).
		Complete(r)
}
