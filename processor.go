// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clientcertprocessor // import "github.com/danielwegener/otelcol-processor-clientcert"

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var errNoPeerCert = errors.New("clientcert: no peer certificate on connection")

type certProcessor struct {
	logger *zap.Logger
	cfg    *Config
}

func (p *certProcessor) processTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	attrs, err := p.attrsFromCtx(ctx)
	if err != nil {
		return td, err
	}
	if attrs == nil {
		return td, nil
	}
	for i := 0; i < td.ResourceSpans().Len(); i++ {
		applyAttrs(td.ResourceSpans().At(i).Resource().Attributes(), attrs)
	}
	return td, nil
}

func (p *certProcessor) processMetrics(ctx context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
	attrs, err := p.attrsFromCtx(ctx)
	if err != nil {
		return md, err
	}
	if attrs == nil {
		return md, nil
	}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		applyAttrs(md.ResourceMetrics().At(i).Resource().Attributes(), attrs)
	}
	return md, nil
}

func (p *certProcessor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	attrs, err := p.attrsFromCtx(ctx)
	if err != nil {
		return ld, err
	}
	if attrs == nil {
		return ld, nil
	}
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		applyAttrs(ld.ResourceLogs().At(i).Resource().Attributes(), attrs)
	}
	return ld, nil
}

func (p *certProcessor) processProfiles(ctx context.Context, pd pprofile.Profiles) (pprofile.Profiles, error) {
	attrs, err := p.attrsFromCtx(ctx)
	if err != nil {
		return pd, err
	}
	if attrs == nil {
		return pd, nil
	}
	for i := 0; i < pd.ResourceProfiles().Len(); i++ {
		applyAttrs(pd.ResourceProfiles().At(i).Resource().Attributes(), attrs)
	}
	return pd, nil
}

// attrsFromCtx extracts the configured certificate fields from the gRPC peer
// on ctx. Returns nil, nil when no cert is present and OnMissingCert is Passthrough.
func (p *certProcessor) attrsFromCtx(ctx context.Context) (map[string]string, error) {
	cert, ok := peerCert(ctx)
	if !ok {
		switch p.cfg.OnMissingCert {
		case Drop:
			p.logger.Debug("dropping signal: no peer certificate on connection")
			return nil, errNoPeerCert
		case ReturnError:
			return nil, errNoPeerCert
		default: // Passthrough
			return nil, nil
		}
	}

	out := make(map[string]string, len(p.cfg.Attributes))
	for _, a := range p.cfg.Attributes {
		if v := extractField(cert, a.Source); v != "" {
			out[a.TargetKey] = v
		}
	}
	return out, nil
}

func applyAttrs(m pcommon.Map, attrs map[string]string) {
	for k, v := range attrs {
		m.PutStr(k, v)
	}
}

// peerCert returns the first peer certificate from the gRPC context, if present.
func peerCert(ctx context.Context) (*x509.Certificate, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, false
	}
	return tlsInfo.State.PeerCertificates[0], true
}

func extractField(cert *x509.Certificate, source CertField) string {
	switch source {
	case SubjectCN:
		return cert.Subject.CommonName
	case SubjectAltNames:
		names := append(cert.DNSNames, cert.EmailAddresses...)
		for _, ip := range cert.IPAddresses {
			names = append(names, ip.String())
		}
		return strings.Join(names, ",")
	case IssuerCN:
		return cert.Issuer.CommonName
	case IssuerOrg:
		if len(cert.Issuer.Organization) > 0 {
			return cert.Issuer.Organization[0]
		}
	case SHA256Fingerprint:
		h := sha256.Sum256(cert.Raw)
		return hex.EncodeToString(h[:])
	case SerialNumber:
		return cert.SerialNumber.String()
	case NotAfter:
		return cert.NotAfter.UTC().Format(time.RFC3339)
	}
	return ""
}
