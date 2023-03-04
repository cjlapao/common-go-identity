package sql_migrations

import (
	"github.com/cjlapao/common-go-database/sql"
	log "github.com/cjlapao/common-go-logger"
)

type ClaimsTableMigration struct{}

func (m ClaimsTableMigration) Name() string {
	return "Create Identity Claims Table"
}

func (m ClaimsTableMigration) Order() int {
	return 2
}

func (m ClaimsTableMigration) Up() bool {
	logger := log.Get()
	dbService := sql.Get()

	tenantDb := dbService.TenantDatabase().Connect()

	if tenantDb == nil {
		logger.Error("Error connecting to apply  %v", m.Name())
		return false
	}

	defer tenantDb.Close()

	_, err := tenantDb.Query(`
CREATE TABLE IF NOT EXISTS identity_claims(  
    id CHAR(50) NOT NULL COMMENT 'Primary Key',
    claimName CHAR(100) NOT NULL COMMENT 'Claim Name',
    PRIMARY KEY (id, claimName)
) DEFAULT CHARSET UTF8 COMMENT '';
`)

	if err != nil {
		logger.Exception(err, "Error applying Up to  %v", m.Name())
		return false
	}

	return true
}

func (m ClaimsTableMigration) Down() bool {
	logger := log.Get()
	dbService := sql.Get()

	globalDb := dbService.GlobalDatabase()

	if globalDb == nil {
		logger.Error("Error connecting to apply  %v", m.Name())
		return false
	}

	defer globalDb.Database.Close()

	_, err := globalDb.Database.Query(`
  DROP TABLE IF EXISTS identity_claims;
`)

	if err != nil {
		logger.Exception(err, "Error Applying Down to %v", m.Name())
		return false
	}
	return true
}
