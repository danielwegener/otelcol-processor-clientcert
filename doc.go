// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate make mdatagen

// Package clientcertprocessor extracts mTLS peer certificate fields from the
// gRPC connection context and writes them as resource attributes on every
// telemetry signal passing through the pipeline.
package clientcertprocessor // import "github.com/danielwegener/otelcol-processor-clientcert"
