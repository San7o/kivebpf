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

	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	initLog = ctrl.Log.WithName("cert-init")
)

// InitWebhookCertificates is the main entry point for the init container mode.
// It generates certificates, writes them to disk, and creates/updates webhook configurations.
func InitWebhookCertificates(serviceName, namespace, organizationName string) error {
	ctx := context.Background()

	initLog.Info("starting webhook certificate initialization.",
		"service", serviceName,
		"namespace", namespace,
		"organization", organizationName)

	// Step 1: Generate self-signed CA
	initLog.Info("generating certificate authority ... (this might take up to 2 minutes)")
	ca, err := GenerateCA(organizationName, CertificateAuthorityCommonName)
	if err != nil {
		return fmt.Errorf("failed to generate certificate authority: %w", err)
	}
	initLog.Info("certificate authority generated successfully.")

	// Step 2: Generate server certificate signed by CA
	initLog.Info("generating server certificate ... (this might take up to 2 minutes)")
	serverCert, err := GenerateServerCert(ca, serviceName, namespace, organizationName)
	if err != nil {
		return fmt.Errorf("failed to generate server certificate: %w", err)
	}
	initLog.Info("server certificate generated successfully.",
		"dnsNames", serverCert.Cert.DNSNames)

	// Step 3: Write certificates to disk (emptyDir volume)
	initLog.Info("writing certificates to disk ...", "certDir", CertDirectory)
	if err := WriteCertificates(CertDirectory, serverCert); err != nil {
		return fmt.Errorf("failed to write certificates to disk: %w", err)
	}
	initLog.Info("certificates written to disk successfully.")

	// Step 4: Create or update webhook configurations with CA bundle
	initLog.Info("refreshing webhook configurations ...")
	config := &WebhookConfig{
		CertDir:          CertDirectory,
		ServiceName:      serviceName,
		ServiceNamespace: namespace,
		ReviewVersions:   []string{"v1"},
		APIGroups:        []string{"kivebpf.san7o.github.io"},
		// APIVersions must be supported by the current webhook server
		// (however, note that conversion webhooks can handle multiple versions)
		APIVersions: []string{"v2alpha1"},
		MutateConfig: WebhookConfigValues{
			MetadataName: "kivebpf-mutating-webhook-configuration",
			KiveData: WebhookConfigEntry{
				WebhookName: "mutate.kivedata.kivebpf.san7o.github.io",
				ServicePath: "/mutate-kive-kivedata",
				Resources:   []string{"kivedata"},
			},
			KivePolicy: WebhookConfigEntry{
				WebhookName: "mutate.kivepolicy.kivebpf.san7o.github.io",
				ServicePath: "/mutate-kive-kivepolicy",
				Resources:   []string{"kivepolicies"},
			},
		},
		ValidateConfig: WebhookConfigValues{
			MetadataName: "kivebpf-validating-webhook-configuration",
			KiveData: WebhookConfigEntry{
				WebhookName: "validate.kivedata.kivebpf.san7o.github.io",
				ServicePath: "/validate-kive-kivedata",
				Resources:   []string{"kivedata"},
			},
			KivePolicy: WebhookConfigEntry{
				WebhookName: "validate.kivepolicy.kivebpf.san7o.github.io",
				ServicePath: "/validate-kive-kivepolicy",
				Resources:   []string{"kivepolicies"},
			},
		},
		// CRDs with conversion webhooks that must be patched
		CrdNames: []string{
			"kivedata.kivebpf.san7o.github.io",
			"kivepolicies.kivebpf.san7o.github.io",
		},
	}

	if err := CreateOrUpdateWebhookConfigurations(ctx, config, ca.CertPEM.Bytes()); err != nil {
		return fmt.Errorf("failed to refresh webhook configurations: %w", err)
	}
	initLog.Info("webhook configurations refreshed successfully.")

	initLog.Info("webhook certificate initialization completed successfully.")
	return nil
}
