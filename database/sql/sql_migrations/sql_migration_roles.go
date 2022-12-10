package sql_migrations

import (
	"github.com/cjlapao/common-go-database/sql"
	"github.com/cjlapao/common-go/log"
)

type RoleTableMigration struct{}

func (m RoleTableMigration) Name() string {
	return "Create Identity Roles Table"
}

func (m RoleTableMigration) Order() int {
	return 1
}

func (m RoleTableMigration) Up() bool {
	logger := log.Get()
	dbService := sql.Get()

	tenantDb := dbService.TenantDatabase().Connect()

	if tenantDb == nil {
		logger.Error("Error connecting to apply  %v", m.Name())
		return false
	}

	defer tenantDb.Close()

	_, err := tenantDb.Query(`
CREATE TABLE IF NOT EXISTS identity_roles(  
    id CHAR(50) NOT NULL COMMENT 'Primary Key',
    roleName CHAR(100) NOT NULL COMMENT 'Role Name',
    PRIMARY KEY (id, roleName)
) DEFAULT CHARSET UTF8 COMMENT '';
`)

	if err != nil {
		logger.Exception(err, "Error applying Up to  %v", m.Name())
		return false
	}
	return true
}

func (m RoleTableMigration) Down() bool {
	logger := log.Get()
	dbService := sql.Get()

	globalDb := dbService.GlobalDatabase()

	if globalDb == nil {
		logger.Error("Error connecting to apply  %v", m.Name())
		return false
	}

	defer globalDb.Database.Close()

	_, err := globalDb.Database.Query(`
  DROP TABLE IF EXISTS identity_roles;
`)

	if err != nil {
		logger.Exception(err, "Error Applying Down to %v", m.Name())
		return false
	}
	return true
}
