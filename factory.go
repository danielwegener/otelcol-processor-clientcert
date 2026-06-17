// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clientcertprocessor // import "github.com/danielwegener/otelcol-processor-clientcert"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
	"go.opentelemetry.io/collector/processor/processorhelper/xprocessorhelper"
	"go.opentelemetry.io/collector/processor/xprocessor"
	"go.uber.org/zap"

	"github.com/danielwegener/otelcol-processor-clientcert/internal/metadata"
)

var processorCapabilities = consumer.Capabilities{MutatesData: true}

// NewFactory returns a new factory for the clientcert processor.
func NewFactory() processor.Factory {
	return xprocessor.NewFactory(
		metadata.Type,
		createDefaultConfig,
		xprocessor.WithTraces(createTracesProcessor, metadata.TracesStability),
		xprocessor.WithMetrics(createMetricsProcessor, metadata.MetricsStability),
		xprocessor.WithLogs(createLogsProcessor, metadata.LogsStability),
		xprocessor.WithProfiles(createProfilesProcessor, metadata.ProfilesStability),
	)
}

func createTracesProcessor(ctx context.Context, set processor.Settings, cfg component.Config, next consumer.Traces) (processor.Traces, error) {
	p := newCertProcessor(set.Logger, cfg.(*Config))
	return processorhelper.NewTraces(ctx, set, cfg, next, p.processTraces,
		processorhelper.WithCapabilities(processorCapabilities))
}

func createMetricsProcessor(ctx context.Context, set processor.Settings, cfg component.Config, next consumer.Metrics) (processor.Metrics, error) {
	p := newCertProcessor(set.Logger, cfg.(*Config))
	return processorhelper.NewMetrics(ctx, set, cfg, next, p.processMetrics,
		processorhelper.WithCapabilities(processorCapabilities))
}

func createLogsProcessor(ctx context.Context, set processor.Settings, cfg component.Config, next consumer.Logs) (processor.Logs, error) {
	p := newCertProcessor(set.Logger, cfg.(*Config))
	return processorhelper.NewLogs(ctx, set, cfg, next, p.processLogs,
		processorhelper.WithCapabilities(processorCapabilities))
}

func createProfilesProcessor(ctx context.Context, set processor.Settings, cfg component.Config, next xconsumer.Profiles) (xprocessor.Profiles, error) {
	p := newCertProcessor(set.Logger, cfg.(*Config))
	return xprocessorhelper.NewProfiles(ctx, set, cfg, next, p.processProfiles,
		xprocessorhelper.WithCapabilities(processorCapabilities))
}

func newCertProcessor(logger *zap.Logger, cfg *Config) *certProcessor {
	return &certProcessor{logger: logger, cfg: cfg}
}
