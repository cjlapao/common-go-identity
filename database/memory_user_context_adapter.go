package database

import (
	"strings"

	"github.com/cjlapao/common-go-identity/database/dto"
)

type MemoryUserContextAdapter struct {
	Users []dto.UserDTO
}

func NewMemoryUserAdapter() *MemoryUserContextAdapter {
	context := MemoryUserContextAdapter{}
	context.Users = GetDefaultUsers()

	return &context
}

func (c *MemoryUserContextAdapter) GetUserById(id string) *dto.UserDTO {
	users := GetDefaultUsers()
	var user dto.UserDTO
	found := false
	for _, usr := range users {
		if strings.EqualFold(id, usr.ID) {
			user = usr
			found = true
			break
		}
	}

	if found {
		return &user
	}
	return nil
}

func (c *MemoryUserContextAdapter) GetUserByEmail(email string) *dto.UserDTO {
	users := GetDefaultUsers()
	var user dto.UserDTO
	found := false
	for _, usr := range users {
		if strings.EqualFold(email, usr.Email) {
			user = usr
			found = true
			break
		}
	}

	if found {
		return &user
	}
	return nil
}

func (c *MemoryUserContextAdapter) GetUserByUsername(username string) *dto.UserDTO {
	users := GetDefaultUsers()
	var user dto.UserDTO
	found := false
	for _, usr := range users {
		if strings.EqualFold(username, usr.Username) {
			user = usr
			found = true
			break
		}
	}

	if found {
		return &user
	}
	return nil
}

func (c *MemoryUserContextAdapter) UpsertUser(user dto.UserDTO) error {
	c.Users = append(c.Users, user)
	return nil
}

func (u MemoryUserContextAdapter) RemoveUser(id string) bool {
	return true
}

func (c *MemoryUserContextAdapter) GetUserRefreshToken(id string) *string {
	user := c.GetUserById(id)
	token := ""
	if user != nil {
		token = *user.RefreshToken
	}

	return &token
}

func (c *MemoryUserContextAdapter) UpdateUserRefreshToken(id string, token string) bool {
	user := c.GetUserById(id)
	if user != nil {
		user.RefreshToken = &token
		return true
	}
	return false
}

func (c *MemoryUserContextAdapter) GetUserEmailVerificationToken(id string) *string {
	user := c.GetUserById(id)
	token := ""
	if user != nil {
		token = *user.EmailVerifyToken
	}

	return &token
}

func (c *MemoryUserContextAdapter) UpdateUserEmailVerificationToken(id string, token string) bool {
	user := c.GetUserById(id)
	if user != nil {
		user.EmailVerifyToken = &token
		return true
	}

	return false
}

// TODO: Implement MemoryUser GetUserClaimsById
func (u MemoryUserContextAdapter) GetUserClaimsById(id string) []dto.UserClaimDTO {
	result := make([]dto.UserClaimDTO, 0)

	return result
}

// TODO: Implement MemoryUser UpsertUserClaims
func (u MemoryUserContextAdapter) UpsertUserClaims(user dto.UserDTO) error {
	return nil
}

// TODO: Implement MemoryUser GetUserRolesById
func (u MemoryUserContextAdapter) GetUserRolesById(id string) []dto.UserRoleDTO {
	result := make([]dto.UserRoleDTO, 0)
	return result
}

// TODO: Implement MemoryUser UpsertUserRoles
func (u MemoryUserContextAdapter) UpsertUserRoles(user dto.UserDTO) error {
	return nil
}

// TODO: Implement MemoryUser CleanUserRecoveryToken
func (u MemoryUserContextAdapter) CleanUserRecoveryToken(id string) error {
	return nil
}

// TODO: Implement MemoryUser UpdateUserRecoverToken
func (u MemoryUserContextAdapter) UpdateUserRecoveryToken(id string, token string) bool {
	return false
}

// TODO: Implement MemoryUser GetUserRecoveryToken
func (u MemoryUserContextAdapter) GetUserRecoveryToken(id string) *string {
	result := ""
	return &result
}

// TODO: Implement MongoDB UpdateUserPassword
func (u MemoryUserContextAdapter) UpdateUserPassword(id string, password string) error {
	return nil
}

// TODO: Implement MemoryUser CleanUserEmailVerificationToken
func (u MemoryUserContextAdapter) CleanUserEmailVerificationToken(id string) error {
	return nil
}

// TODO: Implement MemoryUser UpdateVerifyUserEmail
func (u MemoryUserContextAdapter) SetEmailVerificationState(id string, state bool) bool {
	return false
}
