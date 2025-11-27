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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

// GetOrCreateWebhookSecret gets the existing webhook secret or creates a new one with fresh certificates
func GetOrCreateWebhookSecret(ctx context.Context, namespace, serviceName, organizationName string) (*corev1.Secret, []byte, error) {
	kubeConfig := ctrl.GetConfigOrDie()
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	// Try to get existing secret
	existingSecret, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, WebhookSecretName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// If secret exists, check if certificate is still valid
	if err == nil && existingSecret != nil {
		valid, caBundle, err := isCertificateValid(existingSecret)
		if err != nil {
			initLog.Info("existing certificate validation failed, will regenerate", "error", err)
		} else if valid {
			initLog.Info("existing certificate is still valid, reusing it")
			return existingSecret, caBundle, nil
		} else {
			initLog.Info("existing certificate is expired or will expire soon, regenerating")
		}
	}

	// Generate new certificates
	initLog.Info("generating new certificates ... (this might take a few minutes)")
	ca, serverCert, err := generateCertificates(serviceName, namespace, organizationName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate certificates: %w", err)
	}

	// Create or update secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      WebhookSecretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyTLSCert:  serverCert.CertPEM.Bytes(),
			SecretKeyTLSKey:   serverCert.KeyPEM.Bytes(),
			SecretKeyCABundle: ca.CertPEM.Bytes(),
		},
	}

	if existingSecret != nil {
		// Update existing secret
		secret.ResourceVersion = existingSecret.ResourceVersion
		updatedSecret, err := kubeClient.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to update secret: %w", err)
		}
		return updatedSecret, ca.CertPEM.Bytes(), nil
	}

	// Create new secret
	createdSecret, err := kubeClient.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create secret: %w", err)
	}

	return createdSecret, ca.CertPEM.Bytes(), nil
}

// isCertificateValid checks if the certificate in the secret is still valid
func isCertificateValid(secret *corev1.Secret) (bool, []byte, error) {
	// Check if all required keys exist
	certPEM, hasCert := secret.Data[SecretKeyTLSCert]
	keyPEM, hasKey := secret.Data[SecretKeyTLSKey]
	caBundle, hasCA := secret.Data[SecretKeyCABundle]

	if !hasCert || !hasKey || !hasCA {
		return false, nil, fmt.Errorf("secret missing required keys")
	}

	// Check if values are empty (placeholder secret)
	if len(certPEM) == 0 || len(keyPEM) == 0 || len(caBundle) == 0 {
		return false, nil, fmt.Errorf("secret contains empty values - likely not initialized yet")
	}

	// Parse the certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired or will expire soon
	now := time.Now().UTC()
	if now.After(cert.NotAfter) {
		return false, caBundle, fmt.Errorf("certificate has expired")
	}

	// Check if certificate will expire within the renewal threshold
	if now.Add(CertificateRenewalThreshold).After(cert.NotAfter) {
		return false, caBundle, fmt.Errorf("certificate will expire soon (within %v)", CertificateRenewalThreshold)
	}

	// Certificate is valid
	return true, caBundle, nil
}

// generateCertificates generates both CA and server certificates
func generateCertificates(serviceName, namespace, organizationName string) (*CertificateAuthority, *ServerCertificate, error) {
	// Generate CA
	ca, err := GenerateCA(organizationName, CertificateAuthorityCommonName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	// Generate server certificate
	serverCert, err := GenerateServerCert(ca, serviceName, namespace, organizationName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	return ca, serverCert, nil
}
