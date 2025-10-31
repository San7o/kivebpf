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
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"time"
)

// CertificateAuthority represents a Certificate Authority with its certificate and private key
type CertificateAuthority struct {
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
	CertPEM    *bytes.Buffer
}

// ServerCertificate represents a server certificate with its certificate and private key
type ServerCertificate struct {
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
	CertPEM    *bytes.Buffer
	KeyPEM     *bytes.Buffer
}

// WebhookConfig contains configuration for webhook setup
type WebhookConfig struct {
	ServiceName      string   // webhooks[].clientConfig.service.name
	ServiceNamespace string   // webhooks[].clientConfig.service.namespace
	ReviewVersions   []string // webhooks[].admissionReviewVersions
	APIGroups        []string // webhooks[].rules[].apiGroups
	APIVersions      []string // webhooks[].rules[].apiVersions
	CrdNames         []string // customresourcedefinitions to be patched
	MutateConfig     WebhookConfigValues
	ValidateConfig   WebhookConfigValues
}

// WebhookConfigValues holds configuration values specific to a webhook type (mutate / validate)
type WebhookConfigValues struct {
	MetadataName string // metadata.name
	KiveData     WebhookConfigEntry
	KivePolicy   WebhookConfigEntry
}

// WebhookConfigEntry holds configuration specific to a webhook type and resource (e.g., KiveData, KivePolicy)
type WebhookConfigEntry struct {
	WebhookName string   // webhooks[].name
	ServicePath string   // webhooks[].clientConfig.service.path
	Resources   []string // webhooks[].rules[].resources
}

const (
	// CertificateAuthorityCommonName is the common name used for the Certificate Authority
	CertificateAuthorityCommonName = "kivebpf-ca"

	// CertDirectory is the default directory where certificates are stored
	CertDirectory = "/tmp/k8s-webhook-server/serving-certs"

	// WebhookSecretName is the name of the secret that stores webhook certificates
	WebhookSecretName = "kivebpf-webhook-server-cert"

	// SecretKeyTLSCert is the key for the TLS certificate in the secret
	SecretKeyTLSCert = "tls.crt"

	// SecretKeyTLSKey is the key for the TLS private key in the secret
	SecretKeyTLSKey = "tls.key"

	// SecretKeyCABundle is the key for the CA bundle in the secret
	SecretKeyCABundle = "ca.crt"

	// CertificateRenewalThreshold is how long before expiry we should renew
	CertificateRenewalThreshold = 30 * 24 * time.Hour // 30 days
)
