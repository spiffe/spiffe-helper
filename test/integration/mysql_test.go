//go:build integration

package integration_test

import (
	"testing"
	"time"

	"github.com/spiffe/spiffe-helper/test/integration/mysql"
	"github.com/spiffe/spiffe-helper/test/integration/spire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	mysqlSPIFFEID       = "spiffe://example.org/mysql-db"
	mysqlDNSName        = "mysql-db"
	updatedMySQLDNSName = "mysql-db-updated"
)

func TestMySQLQueries(t *testing.T) {
	spireEnv, mysqlDB := sharedMySQLDB(t)
	requireMySQLServerDNSName(t, spireEnv, mysqlDB, mysqlDNSName)

	tests := []struct {
		name              string
		sslMode           string
		wantErrorContains string
		wantOutput        string
	}{
		{
			name:       "tls connection succeeds",
			sslMode:    "VERIFY_CA",
			wantOutput: "test@user.com",
		},
		{
			name:              "plaintext connection fails",
			sslMode:           "DISABLED",
			wantErrorContains: "secure transport",
			wantOutput:        "secure transport",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mysqlDB.Query(t, "SELECT mail FROM test_db.mail", mysql.QueryOptions{
				SSLMode: tt.sslMode,
			})

			requireErrorContains(t, result.Error, tt.wantErrorContains)
			require.Contains(t, result.Output, tt.wantOutput)
		})
	}
}

func TestMySQLServerCertificateUpdatesAfterRegistrationEntryChange(t *testing.T) {
	spireEnv, mysqlDB := sharedMySQLDB(t)
	requireMySQLServerDNSName(t, spireEnv, mysqlDB, mysqlDNSName)

	updateMySQLServerDNSName(t, spireEnv, updatedMySQLDNSName)

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		cert, err := mysqlDB.ServerX509SVID()
		require.NoError(collect, err)
		require.Equal(collect, []string{updatedMySQLDNSName}, cert.DNSNames)
	}, 2*time.Minute, time.Second)
}

func requireMySQLServerDNSName(t *testing.T, spireEnv *spire.Environment, mysqlDB *mysql.Database, dnsName string) {
	t.Helper()

	updateMySQLServerDNSName(t, spireEnv, dnsName)
	requireMySQLServerCertificate(t, mysqlDB, dnsName)
}

func updateMySQLServerDNSName(t *testing.T, spireEnv *spire.Environment, dnsName string) {
	t.Helper()

	spireEnv.UpdateEntry(t, spire.Entry{
		SPIFFEID:  mysqlSPIFFEID,
		Selectors: mysql.Selectors(),
		DNSNames:  []string{dnsName},
		TTL:       time.Minute,
	})
}

func requireMySQLServerCertificate(t *testing.T, mysqlDB *mysql.Database, dnsName string) {
	t.Helper()

	cert, err := mysqlDB.ServerX509SVID()
	require.NoError(t, err)
	require.Len(t, cert.URIs, 1)
	require.Equal(t, mysqlSPIFFEID, cert.URIs[0].String())
	require.Equal(t, []string{dnsName}, cert.DNSNames)
}
