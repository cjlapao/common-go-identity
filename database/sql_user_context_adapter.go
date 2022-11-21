package database

import (
	"github.com/cjlapao/common-go-database/migrations"
	"github.com/cjlapao/common-go-database/sql"
	"github.com/cjlapao/common-go-identity/models"
)

type SqlDBUserContextAdapter struct{}

func (u SqlDBUserContextAdapter) ApplyMigrations() error {
	sqlRepo := sql.NewSqlMigrationRepo()
	migrationService := migrations.NewMigrationService(sqlRepo)

	migrationService.Register(UserTableMigration{})
	migrationService.Register(RoleTableMigration{})
	migrationService.Register(UserRolesTableMigration{})
	migrationService.Register(ClaimsTableMigration{})
	migrationService.Register(UserClaimsTableMigration{})

	return migrationService.Run()
}

func (u SqlDBUserContextAdapter) GetUserById(id string) *models.User {
	var result models.User
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
SELECT 
  * 
FROM
  identity_users
WHERE
  id = ?
`, id)

	if row.Err() != nil {
		return nil
	}
	row.Scan(
		&result.ID,
		&result.Email,
		&result.EmailVerified,
		&result.Username,
		&result.FirstName,
		&result.LastName,
		&result.DisplayName,
		&result.Password,
		&result.RefreshToken,
		&result.EmailVerifyToken,
		&result.InvalidAttempts,
		&result.Blocked,
	)

	if result.ID == "" {
		return nil
	}

	result.Claims = u.GetUserClaimsById(id)
	result.Roles = u.GetUserRolesById(id)
	db.Close()

	return &result
}

func (u SqlDBUserContextAdapter) GetUserByEmail(email string) *models.User {
	var result models.User
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
SELECT 
  * 
FROM
  identity_users
WHERE
  email = '?'
`, email)

	if row.Err() != nil {
		return nil
	}
	row.Scan(
		&result.ID,
		&result.Email,
		&result.EmailVerified,
		&result.Username,
		&result.FirstName,
		&result.LastName,
		&result.DisplayName,
		&result.Password,
		&result.RefreshToken,
		&result.EmailVerifyToken,
		&result.InvalidAttempts,
		&result.Blocked,
	)

	if result.ID == "" {
		return nil
	}

	result.Claims = u.GetUserClaimsById(result.ID)
	result.Roles = u.GetUserRolesById(result.ID)
	db.Close()

	return &result
}

func (u SqlDBUserContextAdapter) GetUserByUsername(username string) *models.User {
	var result models.User
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
SELECT 
  * 
FROM
  identity_users
WHERE
  username = '?'
`, username)

	if row.Err() != nil {
		return nil
	}

	row.Scan(
		&result.ID,
		&result.Email,
		&result.EmailVerified,
		&result.Username,
		&result.FirstName,
		&result.LastName,
		&result.DisplayName,
		&result.Password,
		&result.RefreshToken,
		&result.EmailVerifyToken,
		&result.InvalidAttempts,
		&result.Blocked,
	)

	if result.ID == "" {
		return nil
	}

	result.Claims = u.GetUserClaimsById(result.ID)
	result.Roles = u.GetUserRolesById(result.ID)
	db.Close()

	return &result
}

func (u SqlDBUserContextAdapter) UpsertUser(user models.User) error {
	db := u.getTenantRepository().Connect()
	var existingUser models.User

	row := db.QueryRowContext(`
SELECT
  id
FROM
  identity_users
WHERE
  id = '?'
  `, user.ID)

	row.Scan(&existingUser.ID)

	if existingUser.ID == "" {
		row := db.QueryRowContext(`
INSERT INTO 
identity_users(
  id,
  email,
  emailVerified,
  username,
  firstName,
  lastName,
  displayName,
  password,
  refreshToken,
  emailVerifyToken,
  invalidAttempts,
  blocked,
  blockedUntil)
VALUES
(
  '?',
  '?',
  ?,
  '?',
  '?',
  '?',
  '?',
  '?',
  ?,
  ?,
  ?,
  ?,
  ?
);`, user.ID, user.Email, user.EmailVerified, user.Username, user.FirstName,
			user.LastName, user.DisplayName, user.Password, user.RefreshToken, user.EmailVerifyToken,
			user.InvalidAttempts, user.Blocked, user.BlockedUntil)

		return row.Err()
	} else {
		row := db.QueryRowContext(`
UPDATE
  identity_users
SET
  email = '?',
  emailVerified = ?,
  username ='?',
  firstName = '?',
  lastName = '?',
  displayName = '?',
  password = '?',
  refreshToken = '?',
  emailVerifyToken = '?',
  invalidAttempts = ?,
  blocked = ?,
  blockedUntil = '?'
WHERE
  id = '?'
;`, user.Email, user.EmailVerified, user.Username, user.FirstName,
			user.LastName, user.DisplayName, user.Password, user.RefreshToken, user.EmailVerifyToken,
			user.InvalidAttempts, user.Blocked, user.BlockedUntil, user.ID)
		return row.Err()
	}
}

func (u SqlDBUserContextAdapter) RemoveUser(id string) bool {
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
DELETE
FROM
  identity_users
WHERE
  id = '?'
`, id)

	db.Close()
	return row.Err() != nil
}

func (u SqlDBUserContextAdapter) GetUserRefreshToken(id string) *string {
	var result models.User
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
SELECT 
  refreshToken
FROM
  identity_users
WHERE
  id = '?'
`, id)

	if row.Err() != nil {
		return nil
	}

	row.Scan(
		&result.RefreshToken,
	)

	db.Close()

	if result.RefreshToken == "" {
		return nil
	}

	return &result.RefreshToken
}

func (u SqlDBUserContextAdapter) UpdateUserRefreshToken(id string, token string) bool {
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
UPDATE
  identity_users
SET 
  refreshToken = '?'
WHERE
  id = '?'
`, token, id)

	return row.Err() != nil
}

func (u SqlDBUserContextAdapter) GetUserEmailVerifyToken(id string) *string {
	var result models.User
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
SELECT 
  verifyEmailToken
FROM
  identity_users
WHERE
  id = '?'
`, id)

	if row.Err() != nil {
		return nil
	}

	row.Scan(
		&result.EmailVerifyToken,
	)

	db.Close()

	if result.EmailVerifyToken == "" {
		return nil
	}

	return &result.EmailVerifyToken
}

func (u SqlDBUserContextAdapter) UpdateUserEmailVerifyToken(id string, token string) bool {
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
UPDATE
  identity_users
SET 
  emailVerifyToken = '?'
WHERE
  id = '?'
`, token, id)

	db.Close()
	return row.Err() != nil
}

func (u SqlDBUserContextAdapter) getTenantRepository() *sql.SqlFactory {
	return sql.Get().TenantDatabase()
}

func (u SqlDBUserContextAdapter) GetUserClaimsById(id string) []models.UserClaim {
	result := make([]models.UserClaim, 0)

	db := u.getTenantRepository().Connect()

	userClaimsRows, err := db.QueryContext(`
SELECT * FROM identity_user_claims
RIGHT JOIN identity_claims 
  ON identity_claims.id = identity_user_claims.claimId
WHERE identity_user_claims.userId = '?'
`, id)

	if err != nil {
		return nil
	}

	for userClaimsRows.Next() {
		var claim models.UserClaim
		userClaimsRows.Scan(&claim.ID, &claim.Name)
		result = append(result, claim)
	}

	db.Close()

	return result
}

func (u SqlDBUserContextAdapter) GetUserRolesById(id string) []models.UserRole {
	result := make([]models.UserRole, 0)

	db := u.getTenantRepository().Connect()

	userRolesRows, err := db.QueryContext(`
SELECT * FROM identity_user_roles
RIGHT JOIN identity_roles
  ON identity_roles.id = identity_user_roles.roleId
WHERE identity_user_roles.userId = '?'
`, id)

	if err != nil {
		return nil
	}

	for userRolesRows.Next() {
		var role models.UserRole
		userRolesRows.Scan(&role.ID, &role.Name)
		result = append(result, models.UserRole(role))
	}

	db.Close()

	return result
}
