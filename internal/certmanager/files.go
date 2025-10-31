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
	"fmt"
	"os"
	"path/filepath"
)

// WriteCertificates writes the server certificate and key to the specified directory
func WriteCertificates(certDir string, serverCert *ServerCertificate) error {
	// Create the certificate directory if it doesn't exist
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory %s: %w", certDir, err)
	}

	// Write server certificate
	certPath := filepath.Join(certDir, CrtFileName)
	if err := writeFile(certPath, serverCert.CertPEM); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	// Write server private key
	keyPath := filepath.Join(certDir, KeyFileName)
	if err := writeFile(keyPath, serverCert.KeyPEM); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// writeFile writes data from a buffer to a file
func writeFile(filepath string, data *bytes.Buffer) error {
	f, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filepath, err)
	}
	defer f.Close()

	if _, err := f.Write(data.Bytes()); err != nil {
		return fmt.Errorf("failed to write data to file %s: %w", filepath, err)
	}

	return nil
}
