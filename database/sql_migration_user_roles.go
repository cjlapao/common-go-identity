package database

import (
	"github.com/cjlapao/common-go-database/sql"
	"github.com/cjlapao/common-go/log"
)

type UserRolesTableMigration struct{}

func (m UserRolesTableMigration) Name() string {
	return "Create Identity User Roles Table"
}

func (m UserRolesTableMigration) Order() int {
	return 5
}

func (m UserRolesTableMigration) Up() bool {
	logger := log.Get()
	dbService := sql.Get()

	tenantDb := dbService.TenantDatabase().Connect()

	if tenantDb == nil {
		logger.Error("Error connecting to apply  %v", m.Name())
		return false
	}

	defer tenantDb.Close()

	_, err := tenantDb.Query(`
  CREATE TABLE IF NOT EXISTS identity_user_roles(  
    userId CHAR(50) NOT NULL COMMENT 'User Id',
    roleId CHAR(50) NOT NULL COMMENT 'Claim Id',
    Index user_id_index (userId),
    Index role_id_index (roleId),
    FOREIGN KEY (userId)
      REFERENCES identity_users(id)
      ON DELETE CASCADE,
    FOREIGN KEY (roleId)
      REFERENCES identity_roles(id)
      ON DELETE CASCADE
) DEFAULT CHARSET UTF8 COMMENT '';
`)

	if err != nil {
		logger.Exception(err, "Error applying Up to  %v", m.Name())
		return false
	}
	return true
}

func (m UserRolesTableMigration) Down() bool {
	logger := log.Get()
	dbService := sql.Get()

	globalDb := dbService.GlobalDatabase()

	if globalDb == nil {
		logger.Error("Error connecting to apply  %v", m.Name())
		return false
	}

	defer globalDb.Database.Close()

	_, err := globalDb.Database.Query(`
  DROP TABLE IF EXISTS identity_user_roles;
`)

	if err != nil {
		logger.Exception(err, "Error Applying Down to %v", m.Name())
		return false
	}
	return true
}
