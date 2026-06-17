// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clientcertprocessor // import "github.com/danielwegener/otelcol-processor-clientcert"

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name: "valid defaults",
			cfg:  *createDefaultConfig().(*Config),
		},
		{
			name: "multiple valid sources",
			cfg: Config{
				Attributes: []AttributeMapping{
					{TargetKey: "tls.client.cn", Source: SubjectCN},
					{TargetKey: "tls.client.fp", Source: SHA256Fingerprint},
					{TargetKey: "tls.client.exp", Source: NotAfter},
				},
				OnMissingCert: Drop,
			},
		},
		{
			name:    "empty target_key",
			cfg:     Config{Attributes: []AttributeMapping{{Source: SubjectCN}}},
			wantErr: "target_key must not be empty",
		},
		{
			name:    "unknown source",
			cfg:     Config{Attributes: []AttributeMapping{{TargetKey: "foo", Source: "bogus"}}},
			wantErr: "unknown source",
		},
		{
			name:    "unknown on_missing_cert",
			cfg:     Config{OnMissingCert: "ignore"},
			wantErr: "unknown on_missing_cert",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfig_DefaultIsValid(t *testing.T) {
	require.NoError(t, componenttest.CheckConfigStruct(createDefaultConfig()))
}
