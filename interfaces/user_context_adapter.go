package interfaces

import "github.com/cjlapao/common-go-identity/database/dto"

type UserContextAdapter interface {
	GetUserById(id string) *dto.UserDTO
	GetUserByEmail(email string) *dto.UserDTO
	GetUserByUsername(username string) *dto.UserDTO
	GetUser(id string) *dto.UserDTO
	UpsertUser(user dto.UserDTO) error
	RemoveUser(id string) bool
	UpdateUserPassword(id string, password string) error
	GetUserRefreshToken(id string) *string
	UpdateUserRefreshToken(id string, token string) bool

	// RecoveryTokens
	CleanUserRecoveryToken(id string) error
	GetUserRecoveryToken(id string) *string
	UpdateUserRecoveryToken(id string, token string) bool

	CleanUserEmailVerificationToken(id string) error
	GetUserEmailVerificationToken(id string) *string
	UpdateUserEmailVerificationToken(id string, token string) bool
	SetEmailVerificationState(id string, state bool) bool

	GetUserRolesById(id string) []dto.UserRoleDTO
	UpsertUserRoles(user dto.UserDTO) error
	GetUserClaimsById(id string) []dto.UserClaimDTO
	UpsertUserClaims(user dto.UserDTO) error
}
