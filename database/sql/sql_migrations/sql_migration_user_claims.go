package sql_migrations

import (
	"github.com/cjlapao/common-go-database/sql"
	"github.com/cjlapao/common-go/log"
)

type UserClaimsTableMigration struct{}

func (m UserClaimsTableMigration) Name() string {
	return "Create Identity User Claims Table"
}

func (m UserClaimsTableMigration) Order() int {
	return 4
}

func (m UserClaimsTableMigration) Up() bool {
	logger := log.Get()
	dbService := sql.Get()

	tenantDb := dbService.TenantDatabase().Connect()

	if tenantDb == nil {
		logger.Error("Error connecting to apply  %v", m.Name())
		return false
	}

	defer tenantDb.Close()

	_, err := tenantDb.Query(`
CREATE TABLE IF NOT EXISTS identity_user_claims(  
    userId CHAR(50) NOT NULL COMMENT 'User Id',
    claimId CHAR(50) NOT NULL COMMENT 'Claim Id',
    Index user_id_index (userId),
    Index claim_id_index (claimId),
    FOREIGN KEY (userId)
      REFERENCES identity_users(id)
      ON DELETE CASCADE,
    FOREIGN KEY (claimId)
      REFERENCES identity_claims(id)
      ON DELETE CASCADE
) DEFAULT CHARSET UTF8 COMMENT '';
`)

	if err != nil {
		logger.Exception(err, "Error applying Up to  %v", m.Name())
		return false
	}
	return true
}

func (m UserClaimsTableMigration) Down() bool {
	logger := log.Get()
	dbService := sql.Get()

	globalDb := dbService.GlobalDatabase()

	if globalDb == nil {
		logger.Error("Error connecting to apply  %v", m.Name())
		return false
	}

	defer globalDb.Database.Close()

	_, err := globalDb.Database.Query(`
  DROP TABLE IF EXISTS identity_user_claims;
`)

	if err != nil {
		logger.Exception(err, "Error Applying Down to %v", m.Name())
		return false
	}
	return true
}
