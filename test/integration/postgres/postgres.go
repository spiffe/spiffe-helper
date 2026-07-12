package postgres

import (
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/spiffe-helper/test/integration/internal/dockercompose"
	"github.com/spiffe/spiffe-helper/test/util"
	"github.com/stretchr/testify/require"
)

const (
	postgresUID  = "7001"
	databaseName = "test_db"
)

type Database struct {
	dockerCompose *dockercompose.Project
}

type QueryOptions struct {
	SSLMode string
}

type QueryResult struct {
	Output string
	Error  error
}

func Start(tb testing.TB, dockerCompose *dockercompose.Project) *Database {
	tb.Helper()
	require.NotNil(tb, dockerCompose, "Docker Compose project is required")

	dockerCompose.Load(tb, "postgres/compose.yaml", map[string]string{
		"POSTGRES_UID": postgresUID,
	})

	dockerCompose.Up(tb, "postgres-db", "postgres-client")
	dockerCompose.WaitForExec(
		tb,
		"postgres-db",
		time.Minute,
		"pg_isready", "-h", "/run/postgresql", "-U", "postgres",
	)

	createDatabase(tb, dockerCompose, databaseName)
	createMailTable(tb, dockerCompose)
	insertEmailAddress(tb, dockerCompose, "test@user.com")

	return &Database{dockerCompose: dockerCompose}
}

func Selectors() []string {
	return []string{"unix:uid:" + postgresUID}
}

func (db *Database) ServerX509SVID() (*x509.Certificate, error) {
	result := db.dockerCompose.TryExec(
		"postgres-client",
		"sh", "-c",
		"true | openssl s_client -starttls postgres -connect postgres-db:5432 -servername postgres-db -showcerts",
	)
	if result.Err != nil {
		return nil, fmt.Errorf("read Postgres server certificate: %w\n%s", result.Err, result.Stderr)
	}

	cert, err := util.ParseCertificate([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("parse Postgres server certificate: %w", err)
	}

	return cert, nil
}

func (db *Database) Query(tb testing.TB, query string, options QueryOptions) QueryResult {
	tb.Helper()

	sslMode := options.SSLMode
	if sslMode == "" {
		sslMode = "verify-full"
	}

	connectionString := "postgres://postgres@postgres-db:5432/" + databaseName + "?sslmode=" + sslMode +
		"&sslrootcert=/run/postgresql/certs/root.crt"

	result := db.dockerCompose.TryExec(
		"postgres-client",
		"psql",
		connectionString,
		"-tA",
		"-c", query,
	)

	return QueryResult{
		Output: result.Stdout + result.Stderr,
		Error:  queryError(result),
	}
}

func queryError(result dockercompose.Result) error {
	if result.Err == nil {
		return nil
	}

	return fmt.Errorf("%w: %s", result.Err, strings.TrimSpace(result.Stdout+result.Stderr))
}

func createDatabase(tb testing.TB, dockerCompose *dockercompose.Project, name string) {
	tb.Helper()

	dockerCompose.Exec(
		tb,
		"postgres-db",
		"psql", "-h", "/run/postgresql", "-U", "postgres", "-d", "postgres",
		"-v", "ON_ERROR_STOP=1",
		"-c", "CREATE DATABASE "+name,
	)
}

func createMailTable(tb testing.TB, dockerCompose *dockercompose.Project) {
	tb.Helper()

	dockerCompose.Exec(
		tb,
		"postgres-db",
		"psql", "-h", "/run/postgresql", "-U", "postgres", "-d", databaseName,
		"-v", "ON_ERROR_STOP=1",
		"-c", "CREATE TABLE IF NOT EXISTS public.mail (id BIGSERIAL PRIMARY KEY, mail VARCHAR(256))",
	)
}

func insertEmailAddress(tb testing.TB, dockerCompose *dockercompose.Project, emailAddress string) {
	tb.Helper()

	dockerCompose.Exec(
		tb,
		"postgres-db",
		"psql", "-h", "/run/postgresql", "-U", "postgres", "-d", databaseName,
		"-v", "ON_ERROR_STOP=1",
		"-c", "INSERT INTO public.mail(mail) VALUES ("+sqlStringLiteral(emailAddress)+")",
	)
}

func sqlStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
