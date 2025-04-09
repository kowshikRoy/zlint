package ocsp

import (
        "crypto/x509"
        "encoding/pem"
        "fmt"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/crypto/ocsp"
)

/*************************************************************************
 * RFC 6960, Section 4.2.1:
 * The signature on an OCSP response MUST be valid.
 *************************************************************************/

type ocspResponseSignatureValid struct {
        config *OcspResponseSignatureValidConfig
}

type OcspResponseSignatureValidConfig struct {
        ResponderCertificate string `toml:"responder_certificate"`
}

func (l *ocspResponseSignatureValid) Configure() interface{} {
        l.config = &OcspResponseSignatureValidConfig{}
        return l.config
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_ocsp_response_signature_valid",
		Description:   "The signature on an OCSP response MUST be valid",
		Citation:      "RFC 6960, Section 4.2.1",
		Source:        lint.RFC6960,
		EffectiveDate: util.RFC6960Date,
		Lint:          &ocspResponseSignatureValid{},
	})
}

func (l *ocspResponseSignatureValid) CheckApplies(resp *ocsp.Response) bool {
	return resp != nil
}

func (l *ocspResponseSignatureValid) RunTest(resp *ocsp.Response) *lint.LintResult {
	if resp.Signature == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "OCSP response is not signed",
		}
	}

        if l.config == nil || l.config.ResponderCertificate == "" {
                return &lint.LintResult{
                        Status:  lint.Error,
                        Details: "Responder certificate not provided in configuration",
                }
	}

        block, _ := pem.Decode([]byte(l.config.ResponderCertificate))
        if block == nil {
                return &lint.LintResult{
                        Status:  lint.Error,
                        Details: "Invalid PEM format for responder certificate",
                }
        }

        responderCert, err := x509.ParseCertificate(block.Bytes)
        if err != nil {
                return &lint.LintResult{
                        Status:  lint.Error,
                        Details: fmt.Sprintf("Error parsing responder certificate: %v", err),
                }
        }

        err = resp.VerifySignature(responderCert)
        if err != nil {
                return &lint.LintResult{
                        Status:  lint.Error,
                        Details: fmt.Sprintf("OCSP response signature verification failed: %v", err),
                }
        }

        return &lint.LintResult{Status: lint.Pass}
}
