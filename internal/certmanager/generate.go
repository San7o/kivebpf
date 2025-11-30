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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// GenerateCA generates a self-signed Certificate Authority
func GenerateCA(organizationName, commonName string) (*CertificateAuthority, error) {
	// Generate unique serial number for CA certificate
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	// Create CA configuration
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organizationName},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().AddDate(1, 0, 0), // 1 year
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Generate CA private key
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create self-signed CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPrivateKey.Public(), caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// PEM encode CA certificate
	caPEM := new(bytes.Buffer)
	if err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return nil, fmt.Errorf("failed to PEM encode CA certificate: %w", err)
	}

	return &CertificateAuthority{
		Cert:       ca,
		PrivateKey: caPrivateKey,
		CertPEM:    caPEM,
	}, nil
}

// GenerateServerCert generates a server certificate signed by the provided CA
func GenerateServerCert(ca *CertificateAuthority, serviceName, namespace, organizationName string) (*ServerCertificate, error) {
	// Build DNS names for the webhook service
	// The API server needs to be able to resolve these names
	dnsNames := []string{
		serviceName,
		fmt.Sprintf("%s.%s", serviceName, namespace),
		fmt.Sprintf("%s.%s.svc", serviceName, namespace),
		fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, namespace),
	}
	commonName := fmt.Sprintf("%s.%s.svc", serviceName, namespace)

	// Generate server private key
	serverPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server private key: %w", err)
	}

	// Generate SubjectKeyId from the public key
	// This follows RFC 5280 Section 4.2.1.2 method (1)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&serverPrivateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyHash := sha1.Sum(publicKeyBytes)

	// Generate unique serial number for server certificate
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	// Create server certificate configuration
	cert := &x509.Certificate{
		DNSNames:     dnsNames,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organizationName},
		},
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().AddDate(1, 0, 0), // 1 year
		SubjectKeyId: publicKeyHash[:],
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Create server certificate signed by CA
	serverCertBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.Cert, &serverPrivateKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	// PEM encode server certificate
	serverCertPEM := new(bytes.Buffer)
	if err := pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	}); err != nil {
		return nil, fmt.Errorf("failed to PEM encode server certificate: %w", err)
	}

	// Marshal server private key to PKCS8 format (which works for both RSA and ECDSA)
	serverPrivateKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(serverPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal server private key: %w", err)
	}

	// PEM encode server private key
	serverPrivateKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(serverPrivateKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: serverPrivateKeyPKCS8,
	}); err != nil {
		return nil, fmt.Errorf("failed to PEM encode server private key: %w", err)
	}

	return &ServerCertificate{
		Cert:       cert,
		PrivateKey: serverPrivateKey,
		CertPEM:    serverCertPEM,
		KeyPEM:     serverPrivateKeyPEM,
	}, nil
}

// generateSerialNumber generates a random serial number for certificates
func generateSerialNumber() (*big.Int, error) {
	// Serial numbers are positive integers not exceeding 20 octets (RFC 5280, §4.1.2.2)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}
