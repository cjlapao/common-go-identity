package sql

import (
	"strings"
	"time"

	"github.com/cjlapao/common-go-database/migrations"
	"github.com/cjlapao/common-go-database/sql"
	"github.com/cjlapao/common-go-identity/database/dto"
	"github.com/cjlapao/common-go-identity/database/sql/sql_migrations"
)

type SqlDBUserContextAdapter struct{}

func (u SqlDBUserContextAdapter) ApplyMigrations() error {
	sqlRepo := sql.NewSqlMigrationRepo()
	migrationService := migrations.NewMigrationService(sqlRepo)

	migrationService.Register(sql_migrations.UserTableMigration{})
	migrationService.Register(sql_migrations.RoleTableMigration{})
	migrationService.Register(sql_migrations.UserRolesTableMigration{})
	migrationService.Register(sql_migrations.ClaimsTableMigration{})
	migrationService.Register(sql_migrations.UserClaimsTableMigration{})

	return migrationService.Run()
}

func (u SqlDBUserContextAdapter) GetUserById(id string) *dto.UserDTO {
	var result dto.UserDTO
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
SELECT 
  id, email, emailVerified, username, firstName, 
  lastName, displayName, password, refreshToken,
  recoveryToken, emailVerifyToken, invalidAttempts,
  blocked, blockedUntil
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
		&result.RecoveryToken,
		&result.EmailVerifyToken,
		&result.InvalidAttempts,
		&result.Blocked,
		&result.BlockedUntil,
	)

	if result.ID == "" {
		return nil
	}

	result.Claims = u.GetUserClaimsById(id)
	result.Roles = u.GetUserRolesById(id)
	db.Close()

	return &result
}

func (u SqlDBUserContextAdapter) GetUserByEmail(email string) *dto.UserDTO {
	var result dto.UserDTO
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
SELECT 
  id, email, emailVerified, username, firstName, 
  lastName, displayName, password, refreshToken,
  recoveryToken, emailVerifyToken, invalidAttempts,
  blocked, blockedUntil
FROM
  identity_users
WHERE
  email = ?
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
		&result.RecoveryToken,
		&result.EmailVerifyToken,
		&result.InvalidAttempts,
		&result.Blocked,
		&result.BlockedUntil,
	)

	if result.ID == "" {
		return nil
	}

	result.Claims = u.GetUserClaimsById(result.ID)
	result.Roles = u.GetUserRolesById(result.ID)
	db.Close()

	return &result
}

func (u SqlDBUserContextAdapter) GetUserByUsername(username string) *dto.UserDTO {
	var result dto.UserDTO
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
SELECT 
  id, email, emailVerified, username, firstName, 
  lastName, displayName, password, refreshToken,
  recoveryToken, emailVerifyToken, invalidAttempts,
  blocked, blockedUntil
FROM
  identity_users
WHERE
  username = ?
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
		&result.RecoveryToken,
		&result.EmailVerifyToken,
		&result.InvalidAttempts,
		&result.Blocked,
		&result.BlockedUntil,
	)

	if result.ID == "" {
		return nil
	}

	result.Claims = u.GetUserClaimsById(result.ID)
	result.Roles = u.GetUserRolesById(result.ID)
	db.Close()

	return &result
}

func (u SqlDBUserContextAdapter) UpsertUser(user dto.UserDTO) error {
	db := u.getTenantRepository().Connect()
	var existingUser dto.UserDTO

	row := db.QueryRowContext(`
SELECT
  id
FROM
  identity_users
WHERE
  username = ?
  `, user.Username)

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
  recoveryToken,
  emailVerifyToken,
  invalidAttempts,
  blocked,
  blockedUntil,
  create_time)
VALUES
(
  ?,
  ?,
  ?,
  ?,
  ?,
  ?,
  ?,
  ?,
  ?,
  ?,
  ?,
  ?,
  ?,
  ?,
  ?
);`,
			user.ID, user.Email, user.EmailVerified, user.Username, user.FirstName,
			user.LastName, user.DisplayName, user.Password, user.RefreshToken, user.RecoveryToken,
			user.EmailVerifyToken, user.InvalidAttempts, user.Blocked, user.BlockedUntil, time.Now())

		if row.Err() != nil {
			return row.Err()
		}
	} else {
		user.ID = existingUser.ID
		row := db.QueryRowContext(`
UPDATE
  identity_users
SET
  email = ?,
  emailVerified = ?,
  username =?,
  firstName = ?,
  lastName = ?,
  displayName = ?,
  refreshToken = ?,
  recoveryToken = ?
  emailVerifyToken = ?,
  invalidAttempts = ?,
  blocked = ?,
  blockedUntil = ?,
  update_time = ?
WHERE
  id = ?
;`,
			user.Email, user.EmailVerified, user.Username, user.FirstName,
			user.LastName, user.DisplayName, user.RefreshToken, user.RecoveryToken,
			user.EmailVerifyToken, user.InvalidAttempts, user.Blocked, user.BlockedUntil,
			time.Now(), existingUser.ID)
		if row.Err() != nil {
			return row.Err()
		}
	}

	if err := u.UpsertUserRoles(user); err != nil {
		return err
	}

	if err := u.UpsertUserClaims(user); err != nil {
		return err
	}

	return nil
}

func (u SqlDBUserContextAdapter) RemoveUser(id string) bool {
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
DELETE
FROM
  identity_users
WHERE
  id = ?
`, id)

	db.Close()
	return row.Err() != nil
}

func (u SqlDBUserContextAdapter) UpdateUserPassword(id string, password string) error {
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
UPDATE
  identity_users
SET
  password = ?
WHERE
  id = ?
`, password, id)

	db.Close()
	return row.Err()
}

func (u SqlDBUserContextAdapter) GetUserRefreshToken(id string) *string {
	var result dto.UserDTO
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
SELECT 
  refreshToken
FROM
  identity_users
WHERE
  id = ?
`, id)

	if row.Err() != nil {
		return nil
	}

	row.Scan(
		&result.RefreshToken,
	)

	db.Close()

	if result.RefreshToken == nil {
		return nil
	}

	return result.RefreshToken
}

func (u SqlDBUserContextAdapter) UpdateUserRefreshToken(id string, token string) bool {
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
UPDATE
  identity_users
SET 
  refreshToken = ?
WHERE
  id = ?
`, token, id)

	return row.Err() != nil
}

func (u SqlDBUserContextAdapter) CleanUserEmailVerificationToken(id string) error {
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
UPDATE 
  identity_users
SET
  emailVerifyToken = NULL,
  update_time = ?
WHERE
  id = ?
`, time.Now(), id)

	if row.Err() != nil {
		return nil
	}

	db.Close()

	return nil
}

func (u SqlDBUserContextAdapter) GetUserEmailVerificationToken(id string) *string {
	var result dto.UserDTO
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
SELECT 
  emailVerifyToken
FROM
  identity_users
WHERE
  id = ?
`, id)

	if row.Err() != nil {
		return nil
	}

	row.Scan(
		&result.EmailVerifyToken,
	)

	db.Close()

	if result.EmailVerifyToken == nil {
		return nil
	}

	return result.EmailVerifyToken
}

func (u SqlDBUserContextAdapter) UpdateUserEmailVerificationToken(id string, token string) bool {
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
UPDATE
  identity_users
SET 
  emailVerifyToken = ?,
  update_time = ?
WHERE
  id = ?
`, token, time.Now(), id)

	db.Close()
	return row.Err() == nil
}

func (u SqlDBUserContextAdapter) SetEmailVerificationState(id string, state bool) bool {
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
UPDATE
  identity_users
SET 
  emailVerified = ?,
  update_time = ?
WHERE
  id = ?
`, state, time.Now(), id)

	db.Close()
	return row.Err() == nil
}

func (u SqlDBUserContextAdapter) UpdateUserRecoveryToken(id string, token string) bool {
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
UPDATE
  identity_users
SET 
  recoveryToken = ?,
  update_time = ?
WHERE
  id = ?
`, token, time.Now(), id)

	db.Close()
	return row.Err() == nil
}

func (u SqlDBUserContextAdapter) GetUserRecoveryToken(id string) *string {
	var result dto.UserDTO
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
SELECT 
  recoveryToken
FROM
  identity_users
WHERE
  id = ?
`, id)

	if row.Err() != nil {
		return nil
	}

	row.Scan(
		&result.RecoveryToken,
	)

	db.Close()

	if result.RecoveryToken == nil {
		return nil
	}

	return result.RecoveryToken
}

func (u SqlDBUserContextAdapter) CleanUserRecoveryToken(id string) error {
	db := u.getTenantRepository().Connect()

	row := db.QueryRowContext(`
UPDATE 
  identity_users
SET
  recoveryToken = NULL,
  update_time = ?
WHERE
  id = ?
`, time.Now(), id)

	if row.Err() != nil {
		return nil
	}

	db.Close()

	return nil
}

func (u SqlDBUserContextAdapter) GetUserClaimsById(id string) []dto.UserClaimDTO {
	result := make([]dto.UserClaimDTO, 0)

	db := u.getTenantRepository().Connect()

	userClaimsRows, err := db.QueryContext(`
SELECT 
  id, claimName
FROM identity_user_claims
LEFT JOIN identity_claims 
  ON identity_claims.id = identity_user_claims.claimId
WHERE identity_user_claims.userId = ?
`, id)

	if err != nil {
		return nil
	}

	for userClaimsRows.Next() {
		var claim dto.UserClaimDTO
		userClaimsRows.Scan(&claim.ID, &claim.Name)
		result = append(result, claim)
	}

	db.Close()

	return result
}

func (u SqlDBUserContextAdapter) UpsertUserClaims(user dto.UserDTO) error {
	db := u.getTenantRepository().Connect()

	validUserClaims := make([]dto.UserClaimDTO, 0)
	dbClaims := make([]dto.UserClaimDTO, 0)

	// Validating the claims for the user to see if they all exist
	for _, userClaim := range user.Claims {
		var claim dto.UserClaimDTO
		dbClaim := db.QueryRowContext(`
SELECT
  id
FROM identity_claims
WHERE
  id = ?
`, userClaim.ID)
		dbClaim.Scan(&claim.ID)

		if claim.ID != "" {
			validUserClaims = append(validUserClaims, userClaim)
		}
	}

	rows, err := db.QueryContext(`
SELECT
  identity_claims.id AS id,
  identity_claims.claimName as claimName
FROM identity_user_claims
LEFT JOIN identity_claims
  ON identity_claims.id = identity_user_claims.claimId
WHERE
identity_user_claims.userId = ?
  `, user.ID)

	if err != nil {
		return err
	}

	// parsing the current user claims
	for rows.Next() {
		var claim dto.UserClaimDTO
		rows.Scan(&claim.ID, &claim.Name)
		dbClaims = append(dbClaims, claim)
	}

	for _, dbClaim := range dbClaims {
		exists := false
		for _, validUserClaim := range validUserClaims {
			if strings.EqualFold(dbClaim.ID, validUserClaim.ID) {
				exists = true
				break
			}
		}

		if !exists {
			_, err = db.QueryContext(`
DELETE FROM 
  identity_user_claims
WHERE 
  userId = ? 
AND 
  claimId = ?;
`, user.ID, dbClaim.ID)

			if err != nil {
				return err
			}
		}
	}

	for _, userClaim := range validUserClaims {
		exists := false
		for _, dbClaim := range dbClaims {
			if strings.EqualFold(dbClaim.ID, userClaim.ID) {
				exists = true
				break
			}
		}
		if !exists {
			_, err = db.QueryContext(`
INSERT INTO 
  identity_user_claims(userId, claimId)
VALUES(?,?);
`, user.ID, userClaim.ID)

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (u SqlDBUserContextAdapter) GetUserRolesById(id string) []dto.UserRoleDTO {
	result := make([]dto.UserRoleDTO, 0)

	db := u.getTenantRepository().Connect()

	userRolesRows, err := db.QueryContext(`
SELECT 
  id, roleName 
FROM identity_user_roles
LEFT JOIN identity_roles
  ON identity_roles.id = identity_user_roles.roleId
WHERE identity_user_roles.userId = ?
`, id)

	if err != nil {
		return nil
	}

	for userRolesRows.Next() {
		var role dto.UserRoleDTO
		userRolesRows.Scan(&role.ID, &role.Name)
		result = append(result, role)
	}

	db.Close()

	return result
}

func (u SqlDBUserContextAdapter) UpsertUserRoles(user dto.UserDTO) error {
	db := u.getTenantRepository().Connect()

	validUserRoles := make([]dto.UserRoleDTO, 0)
	dbRoles := make([]dto.UserRoleDTO, 0)

	// Validating the claims for the user to see if they all exist
	for _, userRole := range user.Roles {
		var role dto.UserRoleDTO
		dbRole := db.QueryRowContext(`
SELECT
  id
FROM identity_roles
WHERE
  id = ?
`, userRole.ID)
		dbRole.Scan(&role.ID)

		if role.ID != "" {
			validUserRoles = append(validUserRoles, userRole)
		}
	}

	rows, err := db.QueryContext(`
SELECT
  identity_roles.id AS id,
  identity_roles.roleName as roleName
FROM identity_user_roles
LEFT JOIN identity_roles
  ON identity_roles.id = identity_user_roles.roleId
WHERE
identity_user_roles.userId = ?
  `, user.ID)

	if err != nil {
		return err
	}

	// parsing the current user claims
	for rows.Next() {
		var role dto.UserRoleDTO
		rows.Scan(&role.ID, &role.Name)
		dbRoles = append(dbRoles, role)
	}

	for _, dbRole := range dbRoles {
		exists := false
		for _, validUserRole := range validUserRoles {
			if strings.EqualFold(dbRole.ID, validUserRole.ID) {
				exists = true
				break
			}
		}

		if !exists {
			_, err = db.QueryContext(`
DELETE FROM 
  identity_user_roles
WHERE 
  userId = ? 
AND 
  roleId = ?;
`, user.ID, dbRole.ID)

			if err != nil {
				return err
			}
		}

	}

	for _, userRole := range validUserRoles {
		exists := false
		for _, dbRole := range dbRoles {
			if strings.EqualFold(dbRole.ID, userRole.ID) {
				exists = true
				break
			}
		}
		if !exists {
			_, err = db.QueryContext(`
INSERT INTO 
  identity_user_roles(userId, roleId)
VALUES(?,?);
`, user.ID, userRole.ID)

			if err != nil {
				return err
			}
		}

	}

	return nil
}

func (u SqlDBUserContextAdapter) getTenantRepository() *sql.SqlFactory {
	return sql.Get().TenantDatabase()
}
