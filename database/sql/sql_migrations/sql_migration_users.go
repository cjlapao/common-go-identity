package sql_migrations

import (
	"github.com/cjlapao/common-go-database/sql"
	log "github.com/cjlapao/common-go-logger"
)

type UserTableMigration struct{}

func (m UserTableMigration) Name() string {
	return "Create Identity Users Table"
}

func (m UserTableMigration) Order() int {
	return 0
}

func (m UserTableMigration) Up() bool {
	logger := log.Get()
	dbService := sql.Get()

	tenantDb := dbService.TenantDatabase().Connect()

	if tenantDb == nil {
		logger.Error("Error connecting to apply  %v", m.Name())
		return false
	}

	defer tenantDb.Close()

	_, err := tenantDb.Query(`
  CREATE TABLE IF NOT EXISTS identity_users(  
    id CHAR(50) NOT NULL COMMENT 'Primary Key',
    email CHAR(100) NOT NULL COMMENT 'Email Address',
    emailVerified BOOLEAN COMMENT 'Is Email Address Verified',
    username CHAR(100) NOT NULL COMMENT 'User Name',
    firstName CHAR(100) NOT NULL COMMENT 'First Name',
    lastName CHAR(100) NOT NULL COMMENT 'Last Name',
    displayName CHAR(200) NOT NULL COMMENT 'Display Name',
    password CHAR(200) NOT NULL COMMENT 'User Password',
    refreshToken TEXT COMMENT 'User Refresh Token',
    recoveryToken TEXT COMMENT 'Recovery Token',
    emailVerifyToken TEXT COMMENT 'Email Verification Token',
    invalidAttempts INT COMMENT 'Invalid attempts to login',
    blocked BOOLEAN COMMENT 'Is User Blocked?',
    blockedUntil CHAR(200) COMMENT 'User blocked until', 
    create_time DATETIME COMMENT 'Create Time',
    update_time DATETIME COMMENT 'Update Time',
    PRIMARY KEY (id, email, username)
) DEFAULT CHARSET UTF8 COMMENT '';
`)

	if err != nil {
		logger.Exception(err, "Error applying Up to  %v", m.Name())
		return false
	}
	return true
}

func (m UserTableMigration) Down() bool {
	logger := log.Get()
	dbService := sql.Get()

	globalDb := dbService.GlobalDatabase()

	if globalDb == nil {
		logger.Error("Error connecting to apply  %v", m.Name())
		return false
	}

	defer globalDb.Database.Close()

	_, err := globalDb.Database.Query(`
  DROP TABLE IF EXISTS identity_users;
`)

	if err != nil {
		logger.Exception(err, "Error applying Down to  %v", m.Name())
		return false
	}
	return true
}
