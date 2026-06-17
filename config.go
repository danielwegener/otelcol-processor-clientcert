// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clientcertprocessor // import "github.com/danielwegener/otelcol-processor-clientcert"

import (
	"fmt"

	"go.opentelemetry.io/collector/component"
)

// CertField names a field to extract from an X.509 peer certificate.
type CertField string

const (
	SubjectCN         CertField = "subject_cn"
	SubjectAltNames   CertField = "subject_alt_names"
	IssuerCN          CertField = "issuer_cn"
	IssuerOrg         CertField = "issuer_org"
	SHA256Fingerprint CertField = "sha256_fingerprint"
	SerialNumber      CertField = "serial_number"
	NotAfter          CertField = "not_after"
)

// MissingCertBehavior controls what happens when a signal arrives without a peer certificate.
type MissingCertBehavior string

const (
	// Passthrough passes the signal through unchanged (default).
	Passthrough MissingCertBehavior = "passthrough"
	// Drop silently discards the signal.
	Drop MissingCertBehavior = "drop"
	// ReturnError returns an error to the sender; the signal is not forwarded.
	ReturnError MissingCertBehavior = "error"
)

// AttributeMapping pairs a resource attribute key with a certificate field.
type AttributeMapping struct {
	// TargetKey is the resource attribute key to write to.
	TargetKey string `mapstructure:"target_key"`
	// Source is the certificate field to read.
	Source CertField `mapstructure:"source"`

	_ struct{}
}

// Config is the configuration for the clientcert processor.
type Config struct {
	// Attributes lists the certificate fields to extract. Writes use upsert
	// semantics: a client-asserted value with the same key is always overwritten
	// by the server-verified cert value.
	Attributes []AttributeMapping `mapstructure:"attributes"`

	// OnMissingCert controls behaviour when no peer certificate is present on the
	// connection (plaintext or server-only TLS). Defaults to "passthrough".
	OnMissingCert MissingCertBehavior `mapstructure:"on_missing_cert"`

	_ struct{}
}

var _ component.Config = (*Config)(nil)

// Validate checks the processor configuration for correctness.
func (c *Config) Validate() error {
	for i, a := range c.Attributes {
		if a.TargetKey == "" {
			return fmt.Errorf("attributes[%d]: target_key must not be empty", i)
		}
		switch a.Source {
		case SubjectCN, SubjectAltNames, IssuerCN, IssuerOrg, SHA256Fingerprint, SerialNumber, NotAfter:
		default:
			return fmt.Errorf("attributes[%d]: unknown source %q (valid: subject_cn, subject_alt_names, issuer_cn, issuer_org, sha256_fingerprint, serial_number, not_after)", i, a.Source)
		}
	}
	switch c.OnMissingCert {
	case Passthrough, Drop, ReturnError, "":
	default:
		return fmt.Errorf("unknown on_missing_cert %q (valid: passthrough, drop, error)", c.OnMissingCert)
	}
	return nil
}

func createDefaultConfig() component.Config {
	return &Config{
		Attributes: []AttributeMapping{
			{TargetKey: "tls.client.cn", Source: SubjectCN},
		},
		OnMissingCert: Passthrough,
	}
}
