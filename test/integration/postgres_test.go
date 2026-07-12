//go:build integration

package integration_test

import (
	"testing"
	"time"

	"github.com/spiffe/spiffe-helper/test/integration/postgres"
	"github.com/spiffe/spiffe-helper/test/integration/spire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	postgresSPIFFEID       = "spiffe://example.org/postgres-db"
	postgresDNSName        = "postgres-db"
	updatedPostgresDNSName = "postgres-db-updated"
)

func TestPostgresQueries(t *testing.T) {
	spireEnv, postgresDB := sharedPostgresDB(t)
	requirePostgresServerDNSName(t, spireEnv, postgresDB, postgresDNSName)

	tests := []struct {
		name              string
		sslMode           string
		wantErrorContains string
		wantOutput        string
	}{
		{
			name:       "tls connection succeeds",
			sslMode:    "verify-full",
			wantOutput: "test@user.com",
		},
		{
			name:              "plaintext connection fails",
			sslMode:           "disable",
			wantErrorContains: "pg_hba.conf",
			wantOutput:        "pg_hba.conf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := postgresDB.Query(t, "SELECT mail FROM public.mail", postgres.QueryOptions{
				SSLMode: tt.sslMode,
			})

			require.Contains(t, result.Output, tt.wantOutput)
			if tt.wantErrorContains == "" {
				require.NoError(t, result.Error)
				return
			}

			require.ErrorContains(t, result.Error, tt.wantErrorContains)
		})
	}
}

func TestPostgresServerCertificateUpdatesAfterRegistrationEntryChange(t *testing.T) {
	spireEnv, postgresDB := sharedPostgresDB(t)
	requirePostgresServerDNSName(t, spireEnv, postgresDB, postgresDNSName)

	updatePostgresServerDNSName(t, spireEnv, updatedPostgresDNSName)

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		cert, err := postgresDB.ServerX509SVID()
		require.NoError(collect, err)
		require.Equal(collect, []string{updatedPostgresDNSName}, cert.DNSNames)
	}, 2*time.Minute, time.Second)
}

func requirePostgresServerDNSName(t *testing.T, spireEnv *spire.Environment, postgresDB *postgres.Database, dnsName string) {
	t.Helper()

	updatePostgresServerDNSName(t, spireEnv, dnsName)
	requirePostgresServerCertificate(t, postgresDB, dnsName)
}

func updatePostgresServerDNSName(t *testing.T, spireEnv *spire.Environment, dnsName string) {
	t.Helper()

	spireEnv.UpdateEntry(t, spire.Entry{
		SPIFFEID:  postgresSPIFFEID,
		Selectors: postgres.Selectors(),
		DNSNames:  []string{dnsName},
		TTL:       time.Minute,
	})
}

func requirePostgresServerCertificate(t *testing.T, postgresDB *postgres.Database, dnsName string) {
	t.Helper()

	cert, err := postgresDB.ServerX509SVID()
	require.NoError(t, err)
	require.Len(t, cert.URIs, 1)
	require.Equal(t, postgresSPIFFEID, cert.URIs[0].String())
	require.Equal(t, []string{dnsName}, cert.DNSNames)
}
