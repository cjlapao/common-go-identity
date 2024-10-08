package models

import (
	cryptorand "github.com/cjlapao/common-go-cryptorand"
	"github.com/cjlapao/common-go/constants"
	"github.com/cjlapao/common-go/security"
	"github.com/cjlapao/common-go/validators"
)

// User entity
type User struct {
	ID               string      `json:"id" bson:"_id"`
	Email            string      `json:"email" bson:"email"`
	EmailVerified    bool        `json:"emailVerified" bson:"emailVerified"`
	Username         string      `json:"username" bson:"username"`
	FirstName        string      `json:"firstName" bson:"firstName"`
	LastName         string      `json:"lastName" bson:"lastName"`
	DisplayName      string      `json:"displayName" bson:"displayName"`
	Password         string      `json:"password" bson:"password"`
	Token            string      `json:"-" bson:"-"`
	RefreshToken     string      `json:"refreshToken" bson:"refreshToken"`
	RecoveryToken    string      `json:"recoveryToken" bson:"recoveryToken"`
	EmailVerifyToken string      `json:"emailVerifyToken" bson:"emailVerifyToken"`
	InvalidAttempts  int         `json:"invalidAttempts" bson:"invalidAttempts"`
	Blocked          bool        `json:"blocked" bson:"blocked"`
	BlockedUntil     string      `json:"blockedUntil" bson:"blockedUntil"`
	Roles            []UserRole  `json:"roles" bson:"roles"`
	Claims           []UserClaim `json:"claims" bson:"claims"`
}

func NewUser() *User {
	id, idErr := cryptorand.GetRandomString(constants.ID_SIZE)
	if idErr != nil {
		return nil
	}

	user := User{
		ID: id,
	}

	user.Roles = make([]UserRole, 0)
	user.Claims = make([]UserClaim, 0)

	return &user
}

func (u User) GetHashedPassword() string {
	if u.Password != "" {
		return u.HashPassword(u.Password)
	}
	return ""
}

func (u User) HashPassword(password string) string {
	if password != "" {
		return security.SHA256Encode(password)
	}

	return ""
}

func (u User) IsValid() bool {
	if u.ID == "" {
		return false
	}
	if u.Username == "" {
		return false
	}
	if u.Email == "" {
		return false
	}
	isEmailValid := validators.ValidateEmailAddress(u.Email)
	if !isEmailValid {
		return false
	}
	if u.Password == "" {
		return false
	}
	// if len(u.Claims) == 0 {
	// 	return false
	// }
	if len(u.Roles) == 0 {
		return false
	}

	return true
}
