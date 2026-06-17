// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clientcertprocessor // import "github.com/danielwegener/otelcol-processor-clientcert"

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestExtractField(t *testing.T) {
	cert := selfSignedCert(t, "device-001", []string{"device-001.example.com"})

	assert.Equal(t, "device-001", extractField(cert, SubjectCN))
	assert.Equal(t, "device-001.example.com", extractField(cert, SubjectAltNames))
	assert.NotEmpty(t, extractField(cert, SHA256Fingerprint))
	assert.NotEmpty(t, extractField(cert, SerialNumber))
	assert.NotEmpty(t, extractField(cert, NotAfter))
	assert.Empty(t, extractField(cert, IssuerOrg)) // self-signed, no org
}

func TestProcessTraces_WithCert(t *testing.T) {
	p := newCertProcessor(zaptest.NewLogger(t), &Config{
		Attributes:    []AttributeMapping{{TargetKey: "tls.client.cn", Source: SubjectCN}},
		OnMissingCert: Passthrough,
	})

	td := ptrace.NewTraces()
	td.ResourceSpans().AppendEmpty()

	got, err := p.processTraces(ctxWithCert(t, "my-device"), td)
	require.NoError(t, err)

	val, ok := got.ResourceSpans().At(0).Resource().Attributes().Get("tls.client.cn")
	require.True(t, ok)
	assert.Equal(t, "my-device", val.Str())
}

func TestProcessMetrics_WithCert(t *testing.T) {
	p := newCertProcessor(zaptest.NewLogger(t), &Config{
		Attributes:    []AttributeMapping{{TargetKey: "tls.client.cn", Source: SubjectCN}},
		OnMissingCert: Passthrough,
	})

	md := pmetric.NewMetrics()
	md.ResourceMetrics().AppendEmpty()

	got, err := p.processMetrics(ctxWithCert(t, "my-device"), md)
	require.NoError(t, err)

	val, ok := got.ResourceMetrics().At(0).Resource().Attributes().Get("tls.client.cn")
	require.True(t, ok)
	assert.Equal(t, "my-device", val.Str())
}

func TestProcessLogs_WithCert(t *testing.T) {
	p := newCertProcessor(zaptest.NewLogger(t), &Config{
		Attributes:    []AttributeMapping{{TargetKey: "tls.client.cn", Source: SubjectCN}},
		OnMissingCert: Passthrough,
	})

	ld := plog.NewLogs()
	ld.ResourceLogs().AppendEmpty()

	got, err := p.processLogs(ctxWithCert(t, "my-device"), ld)
	require.NoError(t, err)

	val, ok := got.ResourceLogs().At(0).Resource().Attributes().Get("tls.client.cn")
	require.True(t, ok)
	assert.Equal(t, "my-device", val.Str())
}

func TestProcessProfiles_WithCert(t *testing.T) {
	p := newCertProcessor(zaptest.NewLogger(t), &Config{
		Attributes:    []AttributeMapping{{TargetKey: "tls.client.cn", Source: SubjectCN}},
		OnMissingCert: Passthrough,
	})

	pd := pprofile.NewProfiles()
	pd.ResourceProfiles().AppendEmpty()

	got, err := p.processProfiles(ctxWithCert(t, "my-device"), pd)
	require.NoError(t, err)

	val, ok := got.ResourceProfiles().At(0).Resource().Attributes().Get("tls.client.cn")
	require.True(t, ok)
	assert.Equal(t, "my-device", val.Str())
}

func TestProcessTraces_NoCert_Passthrough(t *testing.T) {
	p := newCertProcessor(zaptest.NewLogger(t), &Config{OnMissingCert: Passthrough})

	td := ptrace.NewTraces()
	td.ResourceSpans().AppendEmpty()

	got, err := p.processTraces(context.Background(), td)
	require.NoError(t, err)
	assert.Equal(t, 1, got.ResourceSpans().Len())
}

func TestProcessTraces_NoCert_Drop(t *testing.T) {
	p := newCertProcessor(zaptest.NewLogger(t), &Config{OnMissingCert: Drop})

	_, err := p.processTraces(context.Background(), ptrace.NewTraces())
	assert.ErrorIs(t, err, errNoPeerCert)
}

func TestProcessTraces_NoCert_Error(t *testing.T) {
	p := newCertProcessor(zaptest.NewLogger(t), &Config{OnMissingCert: ReturnError})

	_, err := p.processTraces(context.Background(), ptrace.NewTraces())
	assert.ErrorIs(t, err, errNoPeerCert)
}

func TestUpsertOverwritesClientAssertedValue(t *testing.T) {
	p := newCertProcessor(zaptest.NewLogger(t), &Config{
		Attributes:    []AttributeMapping{{TargetKey: "tls.client.cn", Source: SubjectCN}},
		OnMissingCert: Passthrough,
	})

	td := ptrace.NewTraces()
	td.ResourceSpans().AppendEmpty().Resource().Attributes().PutStr("tls.client.cn", "forged-device")

	got, err := p.processTraces(ctxWithCert(t, "real-device"), td)
	require.NoError(t, err)

	val, _ := got.ResourceSpans().At(0).Resource().Attributes().Get("tls.client.cn")
	assert.Equal(t, "real-device", val.Str(), "cert CN must overwrite client-asserted value")
}

// ctxWithCert returns a context that looks like a gRPC peer context carrying
// an mTLS client certificate with the given CN.
func ctxWithCert(t *testing.T, cn string) context.Context {
	t.Helper()
	cert := selfSignedCert(t, cn, nil)
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		},
	})
}

// selfSignedCert generates a minimal self-signed certificate for testing.
func selfSignedCert(t *testing.T, cn string, dnsNames []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
