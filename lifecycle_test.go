// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clientcertprocessor // import "github.com/danielwegener/otelcol-processor-clientcert"

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.opentelemetry.io/collector/processor/xprocessor"

	"github.com/danielwegener/otelcol-processor-clientcert/internal/metadata"
)

func TestComponentFactoryType(t *testing.T) {
	require.Equal(t, metadata.Type, NewFactory().Type())
}

func TestComponentConfigStruct(t *testing.T) {
	require.NoError(t, componenttest.CheckConfigStruct(NewFactory().CreateDefaultConfig()))
}

func TestComponentLifecycle(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()

	tests := []struct {
		name     string
		createFn func(ctx context.Context, set processor.Settings, cfg component.Config) (component.Component, error)
	}{
		{
			name: "traces",
			createFn: func(ctx context.Context, set processor.Settings, cfg component.Config) (component.Component, error) {
				return factory.CreateTraces(ctx, set, cfg, consumertest.NewNop())
			},
		},
		{
			name: "metrics",
			createFn: func(ctx context.Context, set processor.Settings, cfg component.Config) (component.Component, error) {
				return factory.CreateMetrics(ctx, set, cfg, consumertest.NewNop())
			},
		},
		{
			name: "logs",
			createFn: func(ctx context.Context, set processor.Settings, cfg component.Config) (component.Component, error) {
				return factory.CreateLogs(ctx, set, cfg, consumertest.NewNop())
			},
		},
		{
			name: "profiles",
			createFn: func(ctx context.Context, set processor.Settings, cfg component.Config) (component.Component, error) {
				return factory.(xprocessor.Factory).CreateProfiles(ctx, set, cfg, consumertest.NewNop())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"-shutdown", func(t *testing.T) {
			c, err := tt.createFn(context.Background(), processortest.NewNopSettings(metadata.Type), cfg)
			require.NoError(t, err)
			require.NoError(t, c.Shutdown(context.Background()))
		})
		t.Run(tt.name+"-lifecycle", func(t *testing.T) {
			c, err := tt.createFn(context.Background(), processortest.NewNopSettings(metadata.Type), cfg)
			require.NoError(t, err)
			require.NoError(t, c.Start(context.Background(), componenttest.NewNopHost()))
			require.NotPanics(t, func() {
				switch tt.name {
				case "traces":
					e := c.(processor.Traces)
					td := generateTestTraces()
					if !e.Capabilities().MutatesData {
						td.MarkReadOnly()
					}
					require.NoError(t, e.ConsumeTraces(context.Background(), td))
				case "metrics":
					e := c.(processor.Metrics)
					md := generateTestMetrics()
					if !e.Capabilities().MutatesData {
						md.MarkReadOnly()
					}
					require.NoError(t, e.ConsumeMetrics(context.Background(), md))
				case "logs":
					e := c.(processor.Logs)
					ld := generateTestLogs()
					if !e.Capabilities().MutatesData {
						ld.MarkReadOnly()
					}
					require.NoError(t, e.ConsumeLogs(context.Background(), ld))
				}
			})
			require.NoError(t, c.Shutdown(context.Background()))
		})
	}
}

func generateTestTraces() ptrace.Traces {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("resource", "R1")
	span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("test_span")
	span.SetStartTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-time.Second)))
	span.SetEndTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	return td
}

func generateTestMetrics() pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("resource", "R1")
	m := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	m.SetName("test_metric")
	dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetIntValue(1)
	dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	return md
}

func generateTestLogs() plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("resource", "R1")
	lr := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.Body().SetStr("test log")
	lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	return ld
}
