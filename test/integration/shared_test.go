//go:build integration

package integration_test

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spiffe-helper/test/integration/internal/dockercompose"
	"github.com/spiffe/spiffe-helper/test/integration/mysql"
	"github.com/spiffe/spiffe-helper/test/integration/postgres"
	"github.com/spiffe/spiffe-helper/test/integration/spire"
	"github.com/stretchr/testify/require"
)

type integrationEnvironment struct {
	dockerCompose *dockercompose.Project
	spire         *spire.Environment
}

var sharedIntegration struct {
	once sync.Once
	env  *integrationEnvironment
}

var sharedMySQL struct {
	once sync.Once
	db   *mysql.Database
}

var sharedPostgres struct {
	once sync.Once
	db   *postgres.Database
}

func TestMain(m *testing.M) {
	code := m.Run()

	if sharedIntegration.env != nil {
		logf := func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		}
		sharedIntegration.env.dockerCompose.Close(code != 0, logf)
		if sharedIntegration.env.spire != nil {
			sharedIntegration.env.spire.Cleanup(logf)
		}
	}

	os.Exit(code)
}

func integrationEnv(t *testing.T) *integrationEnvironment {
	t.Helper()

	sharedIntegration.once.Do(func() {
		dockerCompose := dockercompose.New()
		sharedIntegration.env = &integrationEnvironment{
			dockerCompose: dockerCompose,
		}
		sharedIntegration.env.spire = spire.Start(t, dockerCompose)
	})

	require.NotNil(t, sharedIntegration.env, "shared integration environment is required")
	require.NotNil(t, sharedIntegration.env.spire, "shared SPIRE environment is required")
	return sharedIntegration.env
}

func sharedMySQLDB(t *testing.T) (*spire.Environment, *mysql.Database) {
	t.Helper()

	env := integrationEnv(t)
	sharedMySQL.once.Do(func() {
		env.spire.RegisterEntry(t, spire.Entry{
			SPIFFEID:  mysqlSPIFFEID,
			Selectors: mysql.Selectors(),
			DNSNames:  []string{mysqlDNSName},
			TTL:       time.Minute,
		})
		sharedMySQL.db = mysql.Start(t, env.dockerCompose)
	})

	require.NotNil(t, sharedMySQL.db, "shared MySQL database is required")
	return env.spire, sharedMySQL.db
}

func sharedPostgresDB(t *testing.T) (*spire.Environment, *postgres.Database) {
	t.Helper()

	env := integrationEnv(t)
	sharedPostgres.once.Do(func() {
		env.spire.RegisterEntry(t, spire.Entry{
			SPIFFEID:  postgresSPIFFEID,
			Selectors: postgres.Selectors(),
			DNSNames:  []string{postgresDNSName},
			TTL:       time.Minute,
		})
		sharedPostgres.db = postgres.Start(t, env.dockerCompose)
	})

	require.NotNil(t, sharedPostgres.db, "shared Postgres database is required")
	return env.spire, sharedPostgres.db
}

func requireErrorContains(t *testing.T, err error, expected string) {
	t.Helper()

	if expected == "" {
		require.NoError(t, err)
		return
	}

	require.ErrorContains(t, err, expected)
}
