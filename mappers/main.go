package mappers

import (
	"github.com/cjlapao/common-go-identity/database/dto"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go/security"
)

func ToUserRole(userRole dto.UserRoleDTO) models.UserRole {
	return models.UserRole{
		ID:   userRole.ID,
		Name: userRole.Name,
	}
}

func ToUserRoles(userRoles []dto.UserRoleDTO) []models.UserRole {
	result := make([]models.UserRole, 0)
	for _, roleDto := range userRoles {
		role := ToUserRole(roleDto)
		result = append(result, role)
	}

	return result
}

func ToUserRoleDTO(userRole models.UserRole) dto.UserRoleDTO {
	return dto.UserRoleDTO{
		ID:   userRole.ID,
		Name: userRole.Name,
	}
}

func ToUserRolesDTO(userRoles []models.UserRole) []dto.UserRoleDTO {
	result := make([]dto.UserRoleDTO, 0)
	for _, role := range userRoles {
		roleDTO := ToUserRoleDTO(role)
		result = append(result, roleDTO)
	}

	return result
}

func ToUserClaim(userClaim dto.UserClaimDTO) models.UserClaim {
	return models.UserClaim{
		ID:   userClaim.ID,
		Name: userClaim.Name,
	}
}

func ToUserClaims(userClaims []dto.UserClaimDTO) []models.UserClaim {
	result := make([]models.UserClaim, 0)
	for _, claimDto := range userClaims {
		claim := ToUserClaim(claimDto)
		result = append(result, claim)
	}

	return result
}

func ToUserClaimDTO(userClaim models.UserClaim) dto.UserClaimDTO {
	return dto.UserClaimDTO{
		ID:   userClaim.ID,
		Name: userClaim.Name,
	}
}

func ToUserClaimsDTO(userClaims []models.UserClaim) []dto.UserClaimDTO {
	result := make([]dto.UserClaimDTO, 0)
	for _, claim := range userClaims {
		claimDTO := ToUserClaimDTO(claim)
		result = append(result, claimDTO)
	}

	return result
}

func ToUser(user dto.UserDTO) models.User {
	decodedRefreshToken := ""
	decodedRecoveryToken := ""
	decodedEmailVerifyToken := ""
	var err error

	if user.RefreshToken != nil {
		decodedRefreshToken, err = security.DecodeBase64String(*user.RefreshToken)
		if err != nil {
			decodedRefreshToken = ""
		}
	}

	if user.RecoveryToken != nil {
		decodedRecoveryToken, err = security.DecodeBase64String(*user.RecoveryToken)
		if err != nil {
			decodedRecoveryToken = ""
		}
	}

	if user.EmailVerifyToken != nil {
		decodedEmailVerifyToken, err = security.DecodeBase64String(*user.EmailVerifyToken)
		if err != nil {
			decodedEmailVerifyToken = ""
		}
	}

	return models.User{
		ID:               user.ID,
		Email:            user.Email,
		EmailVerified:    user.EmailVerified,
		Username:         user.Username,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		DisplayName:      user.DisplayName,
		Password:         user.Password,
		RefreshToken:     decodedRefreshToken,
		RecoveryToken:    decodedRecoveryToken,
		EmailVerifyToken: decodedEmailVerifyToken,
		InvalidAttempts:  user.InvalidAttempts,
		Blocked:          user.Blocked,
		BlockedUntil:     *user.BlockedUntil,
		Roles:            ToUserRoles(user.Roles),
		Claims:           ToUserClaims(user.Claims),
	}
}

func ToUserDTO(user models.User) dto.UserDTO {
	encodedRefreshToken, _ := security.EncodeString(user.RefreshToken)
	encodedRecoveryToken, _ := security.EncodeString(user.RecoveryToken)
	encodedEmailVerifyToken, _ := security.EncodeString(user.EmailVerifyToken)

	return dto.UserDTO{
		ID:               user.ID,
		Email:            user.Email,
		EmailVerified:    user.EmailVerified,
		Username:         user.Username,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		DisplayName:      user.DisplayName,
		Password:         user.Password,
		RefreshToken:     &encodedRefreshToken,
		RecoveryToken:    &encodedRecoveryToken,
		EmailVerifyToken: &encodedEmailVerifyToken,
		InvalidAttempts:  user.InvalidAttempts,
		Blocked:          user.Blocked,
		BlockedUntil:     &user.BlockedUntil,
		Roles:            ToUserRolesDTO(user.Roles),
		Claims:           ToUserClaimsDTO(user.Claims),
	}
}
