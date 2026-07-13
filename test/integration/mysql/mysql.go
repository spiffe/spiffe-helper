package mysql

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
	mysqlUID     = "0"
	databaseName = "test_db"
	testUsername = "testuser"
	testPassword = "password"
)

// Database manages the MySQL integration test database.
type Database struct {
	dockerCompose *dockercompose.Project
}

// QueryOptions contains options for querying the MySQL test database.
type QueryOptions struct {
	SSLMode string
}

// QueryResult contains the output and error from a MySQL query.
type QueryResult struct {
	Output string
	Error  error
}

// Start starts the MySQL integration test database.
func Start(tb testing.TB, dockerCompose *dockercompose.Project) *Database {
	tb.Helper()
	require.NotNil(tb, dockerCompose, "Docker Compose project is required")

	dockerCompose.AddFile(tb, "mysql/compose.yaml", nil)

	dockerCompose.Up(tb, "mysql-db", "mysql-helper", "mysql-client")
	dockerCompose.WaitForExec(
		tb,
		"mysql-db",
		time.Minute,
		"mysqladmin", "--protocol=socket", "-uroot", "ping",
	)

	createDatabase(tb, dockerCompose, databaseName)
	createMailTable(tb, dockerCompose, databaseName)
	insertEmailAddress(tb, dockerCompose, databaseName, "test@user.com")
	createUser(tb, dockerCompose, databaseName, testUsername, testPassword)

	db := &Database{dockerCompose: dockerCompose}
	waitForServerCertificate(tb, db)
	return db
}

// Selectors returns the SPIRE selectors for the MySQL test database.
func Selectors() []string {
	return []string{"unix:uid:" + mysqlUID}
}

// ServerX509SVID returns the X509-SVID served by the MySQL test database.
func (db *Database) ServerX509SVID() (*x509.Certificate, error) {
	result := db.dockerCompose.TryExec(
		"mysql-client",
		"sh", "-c",
		"true | openssl s_client -starttls mysql -connect mysql-db:3306 -servername mysql-db -showcerts",
	)
	if result.Err != nil {
		return nil, fmt.Errorf("read MySQL server certificate: %w\n%s", result.Err, result.Stderr)
	}

	cert, err := util.ParseCertificate([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("parse MySQL server certificate: %w", err)
	}

	return cert, nil
}

// Query runs the passed in query and its options on the MySQL container.
func (db *Database) Query(tb testing.TB, query string, options QueryOptions) QueryResult {
	tb.Helper()

	sslMode := options.SSLMode
	if sslMode == "" {
		sslMode = "VERIFY_CA"
	}

	result := db.dockerCompose.TryExec(
		"mysql-client",
		"mysql",
		"-hmysql-db",
		"-u"+testUsername,
		"-p"+testPassword,
		"--batch",
		"--skip-column-names",
		"--ssl-mode="+sslMode,
		"--ssl-ca=/var/lib/mysql/certs/ca.pem",
		"-e", query,
	)

	return QueryResult{
		Output: strings.TrimSpace(result.Stdout + result.Stderr),
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
		"mysql-db",
		"mysql", "--protocol=socket", "-uroot",
		"-e", "CREATE DATABASE IF NOT EXISTS "+name,
	)
}

func createMailTable(tb testing.TB, dockerCompose *dockercompose.Project, databaseName string) {
	tb.Helper()

	dockerCompose.Exec(
		tb,
		"mysql-db",
		"mysql", "--protocol=socket", "-uroot",
		"-e", "CREATE TABLE IF NOT EXISTS "+databaseName+".mail (id BIGINT AUTO_INCREMENT PRIMARY KEY, mail VARCHAR(256))",
	)
}

func insertEmailAddress(tb testing.TB, dockerCompose *dockercompose.Project, databaseName string, emailAddress string) {
	tb.Helper()

	dockerCompose.Exec(
		tb,
		"mysql-db",
		"mysql", "--protocol=socket", "-uroot",
		"-e", "INSERT INTO "+databaseName+".mail(mail) VALUES ("+sqlStringLiteral(emailAddress)+")",
	)
}

func createUser(tb testing.TB, dockerCompose *dockercompose.Project, databaseName string, username string, password string) {
	tb.Helper()

	dockerCompose.Exec(
		tb,
		"mysql-db",
		"mysql", "--protocol=socket", "-uroot",
		"-e", strings.Join([]string{
			"CREATE USER IF NOT EXISTS " + sqlStringLiteral(username) + "@'%' IDENTIFIED BY " + sqlStringLiteral(password),
			"GRANT SELECT ON " + databaseName + ".* TO " + sqlStringLiteral(username) + "@'%'",
			"FLUSH PRIVILEGES",
		}, "; "),
	)
}

func sqlStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func waitForServerCertificate(tb testing.TB, db *Database) {
	tb.Helper()

	require.Eventually(tb, func() bool {
		cert, err := db.ServerX509SVID()
		return err == nil && len(cert.URIs) > 0
	}, time.Minute, time.Second, "wait for MySQL server SPIFFE certificate")
}
