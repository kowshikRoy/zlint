package ocsp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/zmap/zlint/v3/lint"
	"golang.org/x/crypto/ocsp"
)

func TestOcspResponseSignatureValid(t *testing.T) {
	// Helper function to create a self-signed certificate
	createTestCertificate := func() (*x509.Certificate, *rsa.PrivateKey, error) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "Test Certificate",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		if err != nil {
			return nil, nil, err
		}

		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, nil, err
		}

		return cert, priv, nil
	}

	// Helper function to create an OCSP response
	createTestOCSPResponse := func(cert *x509.Certificate, responderCert *x509.Certificate, responderKey *rsa.PrivateKey, status int) ([]byte, error) {
		var revocationEntry *ocsp.RevocationEntry
		if status == ocsp.Revoked {
			revocationEntry = &ocsp.RevocationEntry{
				RevocationTime: time.Now(),
				Reason:         ocsp.Unspecified,
			}
		}

		response := ocsp.Response{
			Status: status,
			Single: []*ocsp.SingleResponse{
				{
					ThisUpdate:      time.Now(),
					NextUpdate:      time.Now().Add(time.Hour),
					RevocationEntry: revocationEntry,
				},
			},
		}

		respBytes, err := response.CreateResponse(cert, responderCert, responderKey)
		if err != nil {
			return nil, err
		}

		return respBytes, nil
	}

	// Create a test certificate and responder certificate
	cert, _, err := createTestCertificate()
	if err != nil {
		t.Fatalf("Error creating test certificate: %v", err)
	}

	responderCert, responderKey, err := createTestCertificate()
	if err != nil {
		t.Fatalf("Error creating responder certificate: %v", err)
	}

	// Create a valid OCSP response
	validRespBytes, err := createTestOCSPResponse(cert, responderCert, responderKey, ocsp.Good)
	if err != nil {
		t.Fatalf("Error creating valid OCSP response: %v", err)
	}

	// Create an invalid OCSP response (signed by a different key)
	invalidKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error creating invalid key: %v", err)
	}

	invalidRespBytes, err := createTestOCSPResponse(cert, responderCert, invalidKey, ocsp.Good)
	if err != nil {
		t.Fatalf("Error creating invalid OCSP response: %v", err)
	}

	// Create a revoked OCSP response
	revokedRespBytes, err := createTestOCSPResponse(cert, responderCert, responderKey, ocsp.Revoked)
	if err != nil {
		t.Fatalf("Error creating revoked OCSP response: %v", err)
	}

	// Test cases
	tests := []struct {
		name             string
		responseBytes    []byte
		responderCert    *x509.Certificate
		expectedStatus   lint.LintStatus
		expectedDetails  string
		responderCertPEM string
	}{
		{
			name:           "Valid signature - Good",
			responseBytes:  validRespBytes,
			responderCert:  responderCert,
			expectedStatus: lint.Pass,
		},
		{
			name:           "Valid signature - Revoked",
			responseBytes:  revokedRespBytes,
			responderCert:  responderCert,
			expectedStatus: lint.Pass,
		},
		{
			name:           "Invalid signature",
			responseBytes:  invalidRespBytes,
			responderCert:  responderCert,
			expectedStatus: lint.Error,
		},
		{
			name:             "Missing responder certificate",
			responseBytes:    validRespBytes,
			expectedStatus:   lint.Error,
			expectedDetails:  "Responder certificate not provided in configuration",
			responderCertPEM: "",
		},
		{
			name:            "Invalid responder certificate",
			responseBytes:   validRespBytes,
			expectedStatus:  lint.Error,
			expectedDetails: "Invalid PEM format for responder certificate",
			responderCertPEM: "invalid pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *ocsp.Response
			if tt.responseBytes != nil {
				var err error
				resp, err = ocsp.ParseResponse(tt.responseBytes, nil)
				if err != nil {
					t.Fatalf("Error parsing OCSP response: %v", err)
				}
			}

			var result *lint.LintResult
			if tt.responderCertPEM != "" || tt.responderCert != nil {
				var certPEM string
				if tt.responderCertPEM != "" {
					certPEM = tt.responderCertPEM
				} else {
					certPEMBytes := pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: tt.responderCert.Raw,
					})
					certPEM = string(certPEMBytes)
				}

				l := &ocspResponseSignatureValid{}
				l.Configure()
				l.config.ResponderCertificate = certPEM
				result = l.RunTest(resp)
			} else {
				l := &ocspResponseSignatureValid{}
				l.Configure()
				result = l.RunTest(resp)
			}

			if result.Status != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, result.Status)
			}

			if tt.expectedDetails != "" && result.Details != tt.expectedDetails {
				t.Errorf("Expected details '%s', got '%s'", tt.expectedDetails, result.Details)
			}
		})
	}
}
