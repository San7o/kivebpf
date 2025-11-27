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
	ctrl "sigs.k8s.io/controller-runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	kivev2alpha1 "github.com/San7o/kivebpf/api/v2alpha1"
	comm "github.com/San7o/kivebpf/internal/controller/comm"
)

type KivePodReconciler struct {
	client.Client
	UncachedClient client.Reader
}

// There are two main operations we are concearned about with
// pods: pod creation and pod termination.
//   - creation: upon creation, the controller should send a
//     reconcile request for KivePolicy so that new KiveData will
//     be generated for the new pod.
//   - termination: upon termination, the controller should check if
//     each KiveData refers to an existing pod. If it doesn't, then
//     that resource should be eliminated.
//
// Failures are treated as terminations.
func (r *KivePodReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {

	log := log.FromContext(ctx)
	shouldRequeue := false
	log.Info("Pod watch event triggered.")

	kiveDataLabels := client.MatchingLabels{
		comm.KernelIDLabel: KernelID,
	}
	kiveDataList := &kivev2alpha1.KiveDataList{}
	err := r.UncachedClient.List(ctx, kiveDataList, kiveDataLabels)
	if err != nil { // Fatal
		return reconcile.Result{}, fmt.Errorf("Reconcile Error Failed to get KiveData resource: %w", err)
	}
	podList := &corev1.PodList{}
	err = r.UncachedClient.List(ctx, podList)
	if err != nil { // Fatal
		return reconcile.Result{}, fmt.Errorf("Reconcile Error Failed to get PodList resource: %w", err)
	}

Data:
	for _, kiveData := range kiveDataList.Items {

		found := false
	Pod:
		for _, pod := range podList.Items {
			if kiveData.Annotations["pod-name"] == pod.Name &&
				kiveData.Annotations["namespace"] == pod.Namespace &&
				kiveData.Annotations["pod-ip"] == pod.Status.PodIP {

				if pod.Status.Phase != corev1.PodSucceeded &&
					pod.Status.Phase != corev1.PodFailed {
					shouldRequeue = true
				}
				found = true
				break Pod
			}
		}

		if !found {

			log.Info("Deleting KiveData")
			err := r.Client.Delete(ctx, &kiveData)
			if err != nil {
				log.Error(err, fmt.Sprintf("Reconcile Error Deleting KiveData %s after pod event", kiveData.Name))
				continue Data
			}
		}
	}

	// Trigger a KivePolicy reconciliation event to handle pod
	// creation. If a pod is not yet ready, the reconciliation should
	// loop until all the pods are ready.
	kivePolicyList := &kivev2alpha1.KivePolicyList{}
	err = r.UncachedClient.List(ctx, kivePolicyList)
	if err != nil { // Fatal
		return reconcile.Result{Requeue: shouldRequeue}, fmt.Errorf("Reconcile Error Failed to get Kive Policy resource: %w", err)
	}

	if len(kivePolicyList.Items) == 0 {
		return ctrl.Result{Requeue: shouldRequeue}, nil
	}

	kivePolicy := kivePolicyList.Items[0]
	orig := kivePolicy.DeepCopy()
	if kivePolicy.Annotations == nil {
		kivePolicy.Annotations = map[string]string{}
	}
	kivePolicy.Annotations["force-reconcile"] = time.Now().UTC().Format(time.RFC3339)
	if err = r.Patch(ctx, &kivePolicy, client.MergeFrom(orig)); err != nil {
		log.Error(err, fmt.Sprintf("Reconcile Error Patch KivePolicy %s", kivePolicy.Name))
	}

	return reconcile.Result{Requeue: shouldRequeue}, nil
}

func (r *KivePodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}
