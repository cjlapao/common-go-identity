package dto

type UserDTO struct {
	ID               string         `json:"id" bson:"_id"`
	Email            string         `json:"email" bson:"email"`
	EmailVerified    bool           `json:"emailVerified" bson:"emailVerified"`
	Username         string         `json:"username" bson:"username"`
	FirstName        string         `json:"firstName" bson:"firstName"`
	LastName         string         `json:"lastName" bson:"lastName"`
	DisplayName      string         `json:"displayName" bson:"displayName"`
	Password         string         `json:"password" bson:"password"`
	RefreshToken     *string        `json:"refreshToken" bson:"refreshToken"`
	RecoveryToken    *string        `json:"recoveryToken" bson:"recoveryToken"`
	EmailVerifyToken *string        `json:"emailVerifyToken" bson:"emailVerifyToken"`
	InvalidAttempts  int            `json:"invalidAttempts" bson:"invalidAttempts"`
	Blocked          bool           `json:"blocked" bson:"blocked"`
	BlockedUntil     *string        `json:"blockedUntil" bson:"blockedUntil"`
	Roles            []UserRoleDTO  `json:"roles" bson:"roles"`
	Claims           []UserClaimDTO `json:"claims" bson:"claims"`
}

type UserClaimDTO struct {
	ID   string `json:"id" bson:"_id"`
	Name string `json:"claimName" bson:"claimName"`
}

type UserRoleDTO struct {
	ID   string `json:"id" bson:"_id"`
	Name string `json:"roleName" bson:"roleName"`
}
