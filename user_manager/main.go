package user_manager

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	execution_context "github.com/cjlapao/common-go-execution-context"
	"github.com/cjlapao/common-go-identity/authorization_context"
	"github.com/cjlapao/common-go-identity/database/dto"
	"github.com/cjlapao/common-go-identity/interfaces"
	"github.com/cjlapao/common-go-identity/jwt"
	"github.com/cjlapao/common-go-identity/mappers"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go/security"
	"github.com/cjlapao/common-go/validators"
)

var globalUserManager *UserManager

type UserManager struct {
	ExecutionContext     *execution_context.Context
	AuthorizationContext *authorization_context.AuthorizationContext
	UserContext          interfaces.UserContextAdapter
}

func Get() *UserManager {
	if globalUserManager != nil {
		return globalUserManager
	}

	return New()
}

func New() *UserManager {
	ctx := execution_context.Get()
	authCtx := authorization_context.GetCurrent()
	result := UserManager{
		UserContext:          authCtx.UserDatabaseAdapter,
		ExecutionContext:     ctx,
		AuthorizationContext: authCtx,
	}

	globalUserManager = &result
	return globalUserManager
}

func (um *UserManager) GetUserById(id string) *models.User {
	dtoUser := um.UserContext.GetUserByEmail(id)
	if dtoUser == nil {
		return nil
	}

	user := mappers.ToUser(*dtoUser)
	return &user
}

func (um *UserManager) GetUserByEmail(email string) *models.User {
	dtoUser := um.UserContext.GetUserByEmail(email)
	if dtoUser == nil {
		return nil
	}

	user := mappers.ToUser(*dtoUser)
	return &user
}
func (um *UserManager) GetUserByUsername(username string) *models.User {
	dtoUser := um.UserContext.GetUserByEmail(username)
	if dtoUser == nil {
		return nil
	}

	user := mappers.ToUser(*dtoUser)
	return &user
}
func (um *UserManager) UpsertUser(user models.User) error {
	return um.UserContext.UpsertUser(mappers.ToUserDTO(user))
}

func (um *UserManager) RemoveUser(id string) bool {
	return um.UserContext.RemoveUser(id)
}

func (um *UserManager) GetUserRefreshToken(id string) *string {
	return um.UserContext.GetUserRefreshToken(id)
}
func (um *UserManager) UpdateUserRefreshToken(id string, token string) bool {
	return um.UserContext.UpdateUserRefreshToken(id, token)
}

func (um *UserManager) GetUserRolesById(id string) []models.UserRole {
	return mappers.ToUserRoles(um.UserContext.GetUserRolesById(id))
}
func (um *UserManager) UpsertUserRoles(user models.User) error {
	return um.UserContext.UpsertUserRoles(mappers.ToUserDTO(user))
}
func (um *UserManager) GetUserClaimsById(id string) []models.UserClaim {
	return mappers.ToUserClaims(um.UserContext.GetUserClaimsById(id))
}
func (um *UserManager) UpsertUserClaims(user models.User) error {
	return um.UserContext.UpsertUserClaims(mappers.ToUserDTO(user))
}

func (um *UserManager) GenerateUserEmailVerificationToken(user models.User) string {
	defaultKey := um.AuthorizationContext.KeyVault.GetDefaultKey()
	if defaultKey == nil || defaultKey.ID == "" {
		err := NewUserManagerError(InvalidKeyError, errors.New("no default encryption key defined"))
		err.Log()
		return ""
	}

	recoverToken := jwt.GenerateVerifyEmailToken(um.AuthorizationContext.Options.KeyId, user)

	if recoverToken == "" {
		err := NewUserManagerError(InvalidTokenError, fmt.Errorf("generated token is empty for user %v", user.ID))
		err.Log()
		return ""
	}

	return recoverToken
}

func (um *UserManager) AddUser(user models.User) *UserManagerError {
	if !user.IsValid() {
		err := NewUserManagerError(InvalidModelError, fmt.Errorf("user %v failed validation", user.ID))
		err.Log()
		return &err
	}

	if !validators.ValidateEmailAddress(user.Email) {
		err := NewUserManagerError(PasswordValidationError, fmt.Errorf("user %v failed validation, err: %v", user.ID, "invalid email address"))
		err.Log()
		return &err
	}

	passwordValidation := um.ValidatePassword(user.Password)
	if !passwordValidation.IsValid() {
		strErrors := make([]string, 0)
		for _, err := range passwordValidation.Errors {
			strErrors = append(strErrors, err.String())
		}

		err := NewUserManagerError(PasswordValidationError, fmt.Errorf("user %v failed validation, err: %v", user.ID, strings.Join(strErrors, ",")))
		err.Log()
		return &err
	}

	dbUser := um.GetUserByEmail(user.Email)
	if dbUser != nil && dbUser.Email != "" {
		err := NewUserManagerError(UserAlreadyExistsError, fmt.Errorf("user %v already exists in database", user.ID))
		err.Log()
		return &err
	}

	user.Password = user.GetHashedPassword()
	if err := um.UpsertUser(user); err != nil {
		err := NewUserManagerError(DatabaseError, fmt.Errorf("there was an error persisting user %v into database", user.ID), err)
		err.Log()
		return &err
	}

	return nil
}

func (um *UserManager) UpdateEmailVerificationToken(userID string) (*models.User, *UserManagerError) {
	var user *dto.UserDTO

	if strings.ContainsAny(userID, "@") {
		user = um.UserContext.GetUserByEmail(userID)
	} else {
		user = um.UserContext.GetUserById(userID)
	}

	if user == nil {
		err := NewUserManagerError(DatabaseError, errors.New("user not found in database"))
		err.Log()
		return nil, &err
	}

	emailToken := um.GenerateUserEmailVerificationToken(mappers.ToUser(*user))
	if emailToken == "" {
		err := NewUserManagerError(InvalidTokenError, fmt.Errorf("error encoding token for user %v", user.ID))
		err.Log()
		return nil, &err
	}

	encodedToken, err := security.EncodeString(emailToken)
	if err != nil {
		err := NewUserManagerError(InvalidTokenError, fmt.Errorf("error encoding token for user %v", user.ID))
		err.Log()
		return nil, &err
	}
	if !um.UserContext.UpdateUserEmailVerificationToken(user.ID, encodedToken) {
		err := NewUserManagerError(DatabaseError, fmt.Errorf("error persisting recovery token for user %v", user.ID))
		err.Log()
		return nil, &err
	}

	resultUser := mappers.ToUser(*user)
	resultUser.EmailVerifyToken = emailToken

	return &resultUser, nil
}

func (um *UserManager) ValidateEmailVerificationToken(userID string, token string, scope string) *UserManagerError {
	usr := um.UserContext.GetUserById(userID)

	if usr == nil {
		resultErr := NewUserManagerError(InvalidTokenError, fmt.Errorf("user %v was not found in database", userID))
		resultErr.Log()
		return &resultErr
	}

	// um.UserContext.CleanUserEmailVerificationToken(userID)

	if usr.EmailVerifyToken == nil || !strings.EqualFold(*usr.EmailVerifyToken, token) {
		resultErr := NewUserManagerError(InvalidTokenError, fmt.Errorf("token for user %v did not match with database", userID))
		resultErr.Log()
		return &resultErr
	}

	decodedToken, err := security.DecodeBase64String(token)

	if err != nil {
		resultErr := NewUserManagerError(InvalidTokenError, fmt.Errorf("there was an error decoding the recovery token for user %v", userID))
		resultErr.Log()
		return &resultErr
	}

	_, err = jwt.ValidateTokenByScope(decodedToken, usr.Email, scope)
	if err != nil {
		resultErr := NewUserManagerError(DatabaseError, fmt.Errorf("token for user %v is not valid for scope %v", userID, scope))
		resultErr.InnerErrors = append(resultErr.InnerErrors, err)
		resultErr.Log()
		return &resultErr
	}

	return nil
}

func (um *UserManager) SetEmailVerificationState(userID string, state bool) *UserManagerError {
	if !um.UserContext.SetEmailVerificationState(userID, state) {
		resultErr := NewUserManagerError(DatabaseError, fmt.Errorf("error updating email verification state for user %v", userID))
		resultErr.Log()
		return &resultErr
	}

	return nil
}

// func (um *UserManager) UpdateUserEmailVerifyToken(id string) bool {
// 	return um.UserContext.UpdateUserEmailVerifyToken(id, token)
// }

func (um *UserManager) UpdatePassword(userId string, password string) *UserManagerError {
	passwordValidation := um.ValidatePassword(password)
	if !passwordValidation.IsValid() {
		strErrors := make([]string, 0)
		for _, err := range passwordValidation.Errors {
			strErrors = append(strErrors, err.String())
		}

		err := NewUserManagerError(PasswordValidationError, fmt.Errorf("password did not pass validation rules, errors: %v", strings.Join(strErrors, ",")))
		return &err
	}

	user := models.User{
		Password: password,
	}

	err := um.UserContext.UpdateUserPassword(userId, user.GetHashedPassword())

	if err != nil {
		returnErr := NewUserManagerError(DatabaseError, err)
		return &returnErr
	}

	return nil
}

func (um *UserManager) UpdateRecoveryToken(userID string) (*models.User, *UserManagerError) {
	var user *dto.UserDTO

	if strings.ContainsAny(userID, "@") {
		user = um.UserContext.GetUserByEmail(userID)
	} else {
		user = um.UserContext.GetUserById(userID)
	}

	if user == nil {
		err := NewUserManagerError(DatabaseError, errors.New("user not found in database"))
		err.Log()
		return nil, &err
	}

	defaultKey := um.AuthorizationContext.KeyVault.GetDefaultKey()
	if defaultKey == nil || defaultKey.ID == "" {
		err := NewUserManagerError(InvalidKeyError, errors.New("no default encryption key defined"))
		err.Log()
		return nil, &err
	}

	recoverToken := jwt.GenerateRecoverToken(um.AuthorizationContext.Options.KeyId, mappers.ToUser(*user))

	if recoverToken == "" {
		err := NewUserManagerError(InvalidTokenError, fmt.Errorf("generated token is empty for user %v", user.ID))
		err.Log()
		return nil, &err
	}

	encodedToken, err := security.EncodeString(recoverToken)
	if err != nil {
		err := NewUserManagerError(InvalidTokenError, fmt.Errorf("error encoding token for user %v", user.ID))
		err.Log()
		return nil, &err
	}

	if !um.UserContext.UpdateUserRecoveryToken(user.ID, encodedToken) {
		err := NewUserManagerError(DatabaseError, fmt.Errorf("error persisting recovery token for user %v", user.ID))
		err.Log()
		return nil, &err
	}

	resultUsr := mappers.ToUser(*user)
	resultUsr.RecoveryToken = recoverToken
	return &resultUsr, nil
}

func (um *UserManager) GetCurrentRecoveryToken(userId string) (*string, *UserManagerError) {
	user := um.UserContext.GetUserById(userId)
	if user == nil {
		err := NewUserManagerError(DatabaseError, errors.New("user not found in database"))
		err.Log()
		return nil, &err
	}

	recoveryToken := um.UserContext.GetUserRecoveryToken(user.ID)

	if recoveryToken == nil {
		err := NewUserManagerError(InvalidTokenError, fmt.Errorf("no recovery token found for user %v", user.ID))
		err.Log()
		return nil, &err
	}

	return recoveryToken, nil
}

func (um *UserManager) ValidateRecoveryToken(userId string, token string, scope string, cleanup bool) *UserManagerError {

	if strings.ContainsAny(userId, "@") {
		user := um.UserContext.GetUserByEmail(userId)
		if user == nil {
			resultErr := NewUserManagerError(InvalidTokenError, fmt.Errorf("user %v no found in database", userId))
			resultErr.Log()
			return &resultErr
		}
		userId = user.ID
	}

	dbToken := um.UserContext.GetUserRecoveryToken(userId)

	if cleanup {
		um.UserContext.CleanUserRecoveryToken(userId)
	}

	if dbToken == nil || !strings.EqualFold(*dbToken, token) {
		resultErr := NewUserManagerError(InvalidTokenError, fmt.Errorf("token for user %v did not match with database", userId))
		resultErr.Log()
		return &resultErr
	}

	decodedToken, err := security.DecodeBase64String(token)

	if err != nil {
		resultErr := NewUserManagerError(InvalidTokenError, fmt.Errorf("there was an error decoding the recovery token for user %v", userId))
		resultErr.Log()
		return &resultErr
	}

	_, err = jwt.ValidateTokenByScope(decodedToken, userId, scope)
	if err != nil {
		resultErr := NewUserManagerError(DatabaseError, fmt.Errorf("token for user %v is not valid for scope %v", userId, scope))
		resultErr.InnerErrors = append(resultErr.InnerErrors, err)
		resultErr.Log()
		return &resultErr
	}

	return nil
}

func (um *UserManager) ValidatePassword(password string) PasswordValidationResult {
	result := NewPasswordValidationResult()
	if um.AuthorizationContext.Options.PasswordRules.RequiresCapital {
		expression := "[A-Z]{1,}"
		r, _ := regexp.Compile(expression)
		if !r.MatchString(password) {
			result.Errors = append(result.Errors, MissingCapital)
		}
	}

	if um.AuthorizationContext.Options.PasswordRules.RequiresSpecial {
		expression := "[" + um.AuthorizationContext.Options.PasswordRules.AllowedSpecials + "]{1,}"
		r, _ := regexp.Compile(expression)
		if !r.MatchString(password) {
			result.Errors = append(result.Errors, MissingSpecial)
		}
	}

	if um.AuthorizationContext.Options.PasswordRules.RequiresNumber {
		expression := "[\\d]{1,}"
		r, _ := regexp.Compile(expression)
		if !r.MatchString(password) {
			result.Errors = append(result.Errors, MissingNumber)

		}
	}

	if strings.ContainsAny(password, " ") && !um.AuthorizationContext.Options.PasswordRules.AllowsSpaces {
		result.Errors = append(result.Errors, ContainsDisallowedSpace)
	}

	if len(password) < um.AuthorizationContext.Options.PasswordRules.MinimumSize {
		result.Errors = append(result.Errors, InvalidMinimumSize)
	}

	return result
}
