/*
                    GNU GENERAL PUBLIC LICENSE
                       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/

// SPDX-License-Identifier: GPL-2.0-only

package certmanager

import (
	"context"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	admissionregistrationv1apply "k8s.io/client-go/applyconfigurations/admissionregistration/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CreateOrUpdateWebhookConfigurations creates or updates both mutating and validating webhook configurations,
// and updates CRD conversion webhooks with the CA bundle
func CreateOrUpdateWebhookConfigurations(ctx context.Context, config *WebhookConfig, caBundle []byte) error {
	kubeConfig := ctrl.GetConfigOrDie()
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	// Create or update mutating webhook configuration
	if err := createOrUpdateMutatingWebhookConfig(ctx, kubeClient, config, caBundle); err != nil {
		return fmt.Errorf("failed to create or update mutating webhook configuration: %w", err)
	}

	// Create or update validating webhook configuration
	if err := createOrUpdateValidatingWebhookConfig(ctx, kubeClient, config, caBundle); err != nil {
		return fmt.Errorf("failed to create or update validating webhook configuration: %w", err)
	}

	// Update CRD conversion webhooks with CA bundle
	if err := updateCRDConversionWebhooks(ctx, caBundle, config.CrdNames); err != nil {
		return fmt.Errorf("failed to update CRD conversion webhooks: %w", err)
	}

	return nil
}

// createOrUpdateMutatingWebhookConfig creates or updates the mutating webhook configuration
func createOrUpdateMutatingWebhookConfig(ctx context.Context, client *kubernetes.Clientset, config *WebhookConfig, caBundle []byte) error {
	failPolicy := admissionregistrationv1.Fail
	sideEffects := admissionregistrationv1.SideEffectClassNone

	mutateConfig := admissionregistrationv1apply.MutatingWebhookConfiguration(config.MutateConfig.MetadataName).
		WithKind("MutatingWebhookConfiguration").
		WithAPIVersion("admissionregistration.k8s.io/v1").
		WithWebhooks(
			admissionregistrationv1apply.MutatingWebhook().
				WithName(config.MutateConfig.KiveData.WebhookName).
				WithAdmissionReviewVersions(config.ReviewVersions...).
				WithRules(
					admissionregistrationv1apply.RuleWithOperations().
						WithOperations(
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
						).
						WithAPIGroups(config.APIGroups...).
						WithAPIVersions(config.APIVersions...).
						WithResources(config.MutateConfig.KiveData.Resources...),
				).
				WithClientConfig(
					admissionregistrationv1apply.WebhookClientConfig().
						WithCABundle(caBundle...).
						WithService(
							admissionregistrationv1apply.ServiceReference().
								WithName(config.ServiceName).
								WithNamespace(config.ServiceNamespace).
								WithPath(config.MutateConfig.KiveData.ServicePath),
						),
				).
				WithFailurePolicy(failPolicy).
				WithSideEffects(sideEffects),
			admissionregistrationv1apply.MutatingWebhook().
				WithName(config.MutateConfig.KivePolicy.WebhookName).
				WithAdmissionReviewVersions(config.ReviewVersions...).
				WithRules(
					admissionregistrationv1apply.RuleWithOperations().
						WithOperations(
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
						).
						WithAPIGroups(config.APIGroups...).
						WithAPIVersions(config.APIVersions...).
						WithResources(config.MutateConfig.KivePolicy.Resources...),
				).
				WithClientConfig(
					admissionregistrationv1apply.WebhookClientConfig().
						WithCABundle(caBundle...).
						WithService(
							admissionregistrationv1apply.ServiceReference().
								WithName(config.ServiceName).
								WithNamespace(config.ServiceNamespace).
								WithPath(config.MutateConfig.KivePolicy.ServicePath),
						),
				).
				WithFailurePolicy(failPolicy).
				WithSideEffects(sideEffects),
		)

	// Create or update configuration using Server-Side Apply
	_, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Apply(ctx, mutateConfig, metav1.ApplyOptions{FieldManager: "kivebpf", Force: true})
	if err != nil {
		return fmt.Errorf("failed to apply mutating webhook configuration: %w", err)
	}

	return nil
}

// createOrUpdateValidatingWebhookConfig creates or updates the validating webhook configuration
func createOrUpdateValidatingWebhookConfig(ctx context.Context, client *kubernetes.Clientset, config *WebhookConfig, caBundle []byte) error {
	failPolicy := admissionregistrationv1.Fail
	sideEffects := admissionregistrationv1.SideEffectClassNone

	validateConfig := admissionregistrationv1apply.ValidatingWebhookConfiguration(config.ValidateConfig.MetadataName).
		WithKind("ValidatingWebhookConfiguration").
		WithAPIVersion("admissionregistration.k8s.io/v1").
		WithWebhooks(
			admissionregistrationv1apply.ValidatingWebhook().
				WithName(config.ValidateConfig.KiveData.WebhookName).
				WithAdmissionReviewVersions(config.ReviewVersions...).
				WithRules(
					admissionregistrationv1apply.RuleWithOperations().
						WithOperations(
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
						).
						WithAPIGroups(config.APIGroups...).
						WithAPIVersions(config.APIVersions...).
						WithResources(config.ValidateConfig.KiveData.Resources...),
				).
				WithClientConfig(
					admissionregistrationv1apply.WebhookClientConfig().
						WithCABundle(caBundle...).
						WithService(
							admissionregistrationv1apply.ServiceReference().
								WithName(config.ServiceName).
								WithNamespace(config.ServiceNamespace).
								WithPath(config.ValidateConfig.KiveData.ServicePath),
						),
				).
				WithFailurePolicy(failPolicy).
				WithSideEffects(sideEffects),
			admissionregistrationv1apply.ValidatingWebhook().
				WithName(config.ValidateConfig.KivePolicy.WebhookName).
				WithAdmissionReviewVersions(config.ReviewVersions...).
				WithRules(
					admissionregistrationv1apply.RuleWithOperations().
						WithOperations(
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
						).
						WithAPIGroups(config.APIGroups...).
						WithAPIVersions(config.APIVersions...).
						WithResources(config.ValidateConfig.KivePolicy.Resources...),
				).
				WithClientConfig(
					admissionregistrationv1apply.WebhookClientConfig().
						WithCABundle(caBundle...).
						WithService(
							admissionregistrationv1apply.ServiceReference().
								WithName(config.ServiceName).
								WithNamespace(config.ServiceNamespace).
								WithPath(config.ValidateConfig.KivePolicy.ServicePath),
						),
				).
				WithFailurePolicy(failPolicy).
				WithSideEffects(sideEffects),
		)

	// Create or update configuration using Server-Side Apply
	_, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Apply(ctx, validateConfig, metav1.ApplyOptions{FieldManager: "kivebpf", Force: true})
	if err != nil {
		return fmt.Errorf("failed to apply validating webhook configuration: %w", err)
	}

	return nil
}

// updateCRDConversionWebhooks updates the CA bundle in CRD conversion webhooks.
// This function only updates existing CRDs and never creates them.
func updateCRDConversionWebhooks(ctx context.Context, caBundle []byte, crdNames []string) error {
	kubeConfig := ctrl.GetConfigOrDie()

	// Create a scheme with apiextensions types registered
	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("failed to add apiextensions to scheme: %w", err)
	}

	k8sClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("failed to create controller-runtime client: %w", err)
	}

	for _, crdName := range crdNames {
		if err := updateCRDConversionWebhook(ctx, k8sClient, crdName, caBundle); err != nil {
			return fmt.Errorf("failed to update CRD %s: %w", crdName, err)
		}
	}

	return nil
}

// updateCRDConversionWebhook updates a single CRD's conversion webhook with the CA bundle
func updateCRDConversionWebhook(ctx context.Context, k8sClient client.Client, crdName string, caBundle []byte) error {
	// Get the existing CRD
	crd := &apiextensionsv1.CustomResourceDefinition{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: crdName}, crd); err != nil {
		if apierrors.IsNotFound(err) {
			// CRD doesn't exist yet, skip it
			return nil
		}
		return fmt.Errorf("failed to get CRD: %w", err)
	}

	// Check if the CRD has a conversion webhook configured
	if crd.Spec.Conversion == nil ||
		crd.Spec.Conversion.Strategy != apiextensionsv1.WebhookConverter ||
		crd.Spec.Conversion.Webhook == nil {
		// CRD doesn't have a conversion webhook, skip it
		return nil
	}

	// Update the CA bundle
	if crd.Spec.Conversion.Webhook.ClientConfig == nil {
		crd.Spec.Conversion.Webhook.ClientConfig = &apiextensionsv1.WebhookClientConfig{}
	}
	crd.Spec.Conversion.Webhook.ClientConfig.CABundle = caBundle

	// Update the CRD
	if err := k8sClient.Update(ctx, crd); err != nil {
		return fmt.Errorf("failed to update CRD: %w", err)
	}

	return nil
}
