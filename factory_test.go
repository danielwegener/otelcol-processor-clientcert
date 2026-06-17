// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clientcertprocessor // import "github.com/danielwegener/otelcol-processor-clientcert"

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/processor/processortest"

	"github.com/danielwegener/otelcol-processor-clientcert/internal/metadata"
)

func TestFactory_Type(t *testing.T) {
	assert.Equal(t, metadata.Type, NewFactory().Type())
}

func TestFactory_CreateTracesProcessor(t *testing.T) {
	f := NewFactory()
	p, err := f.CreateTraces(context.Background(), processortest.NewNopSettings(metadata.Type), f.CreateDefaultConfig(), consumertest.NewNop())
	require.NoError(t, err)
	assert.NotNil(t, p)
}

func TestFactory_CreateMetricsProcessor(t *testing.T) {
	f := NewFactory()
	p, err := f.CreateMetrics(context.Background(), processortest.NewNopSettings(metadata.Type), f.CreateDefaultConfig(), consumertest.NewNop())
	require.NoError(t, err)
	assert.NotNil(t, p)
}

func TestFactory_CreateLogsProcessor(t *testing.T) {
	f := NewFactory()
	p, err := f.CreateLogs(context.Background(), processortest.NewNopSettings(metadata.Type), f.CreateDefaultConfig(), consumertest.NewNop())
	require.NoError(t, err)
	assert.NotNil(t, p)
}
