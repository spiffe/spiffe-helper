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

const mysqlUID = "0"

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

	dockerCompose.Load(tb, "mysql/compose.yaml", nil)

	dockerCompose.Up(tb, "mysql-db", "mysql-helper", "mysql-client")
	dockerCompose.WaitForExec(
		tb,
		"mysql-db",
		time.Minute,
		"mysqladmin", "--protocol=socket", "-uroot", "ping",
	)

	createDatabase(tb, dockerCompose)

	db := &Database{dockerCompose: dockerCompose}
	waitForServerCertificate(tb, db)
	return db
}

func Selectors() []string {
	return []string{"unix:uid:" + mysqlUID}
}

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
		"-utestuser",
		"-ppassword",
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

func createDatabase(tb testing.TB, dockerCompose *dockercompose.Project) {
	tb.Helper()

	dockerCompose.Exec(
		tb,
		"mysql-db",
		"mysql", "--protocol=socket", "-uroot",
		"-e", strings.Join([]string{
			"CREATE USER IF NOT EXISTS 'testuser'@'%' IDENTIFIED BY 'password'",
			"CREATE DATABASE IF NOT EXISTS test_db",
			"CREATE TABLE IF NOT EXISTS test_db.mail (id BIGINT AUTO_INCREMENT PRIMARY KEY, mail VARCHAR(256))",
			"INSERT INTO test_db.mail(mail) VALUES ('test@user.com')",
			"GRANT SELECT ON test_db.* TO 'testuser'@'%'",
			"FLUSH PRIVILEGES",
		}, "; "),
	)
}

func waitForServerCertificate(tb testing.TB, db *Database) {
	tb.Helper()

	require.Eventually(tb, func() bool {
		cert, err := db.ServerX509SVID()
		return err == nil && len(cert.URIs) > 0
	}, time.Minute, time.Second, "wait for MySQL server SPIFFE certificate")
}
