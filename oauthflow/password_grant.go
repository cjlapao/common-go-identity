package oauthflow

import (
	"fmt"
	"strings"
	"time"

	"github.com/cjlapao/common-go-identity/authorization_context"
	"github.com/cjlapao/common-go-identity/jwt"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-identity/user_manager"
	"github.com/cjlapao/common-go/security"
)

type PasswordGrantFlow struct{}

func (passwordGrantFlow PasswordGrantFlow) Authenticate(request *models.OAuthLoginRequest) (*models.OAuthLoginResponse, *models.OAuthErrorResponse) {
	var errorResponse models.OAuthErrorResponse
	authCtx := authorization_context.Clone()
	usrManager := user_manager.Get()
	user := usrManager.GetUserByUsername(request.Username)

	if user == nil || user.ID == "" {
		if user == nil {
			errorResponse = models.OAuthErrorResponse{
				Error:            models.OAuthInvalidClientError,
				ErrorDescription: fmt.Sprintf("User %v was not found", request.Username),
			}
		} else if user.Email == "" {
			errorResponse = models.OAuthErrorResponse{
				Error:            models.OAuthInvalidClientError,
				ErrorDescription: fmt.Sprintf("User %v was not found", request.Username),
			}
		} else {
			errorResponse = models.OAuthErrorResponse{
				Error:            models.OAuthInvalidClientError,
				ErrorDescription: "Unknown error",
			}
		}
		logger.Error(errorResponse.ErrorDescription)
		return nil, &errorResponse
	}

	password := security.SHA256Encode(request.Password)

	if password != user.Password {
		errorResponse = models.OAuthErrorResponse{
			Error:            models.OAuthInvalidClientError,
			ErrorDescription: fmt.Sprintf("Invalid password for user %v", request.Username),
		}
		logger.Error(errorResponse.ErrorDescription)
		return nil, &errorResponse
	}

	if authCtx.ValidationOptions.VerifiedEmail && !user.EmailVerified {
		errorResponse = models.OAuthErrorResponse{
			Error:            models.OAuthEmailNotVerified,
			ErrorDescription: fmt.Sprintf("User %v email not verified", request.Username),
		}
		logger.Error(errorResponse.ErrorDescription)
		return nil, &errorResponse

	}

	if user.Blocked {
		errorResponse = models.OAuthErrorResponse{
			Error:            models.OAuthUserBlocked,
			ErrorDescription: fmt.Sprintf("User %v is blocked", request.Username),
		}
		logger.Error(errorResponse.ErrorDescription)
		return nil, &errorResponse
	}

	token, err := jwt.GenerateDefaultUserToken(*user)
	if err != nil {
		errorResponse = models.OAuthErrorResponse{
			Error:            models.OAuthInvalidClientError,
			ErrorDescription: fmt.Sprintf("There was an error validating user token, %v", err.Error()),
		}
		return nil, &errorResponse
	}

	encodedToken, err := security.EncodeString(token.RefreshToken)
	if err != nil {
		errorResponse = models.OAuthErrorResponse{
			Error:            models.OAuthInvalidClientError,
			ErrorDescription: fmt.Sprintf("There was an error encoding user token, %v", err.Error()),
		}
		return nil, &errorResponse
	}

	authCtx.UserDatabaseAdapter.UpdateUserRefreshToken(user.ID, encodedToken)

	expiresIn := authCtx.Options.TokenDuration * 60
	response := models.OAuthLoginResponse{
		AccessToken:  token.Token,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    fmt.Sprintf("%v", expiresIn),
		TokenType:    "Bearer",
		Scope:        authCtx.Scope,
	}

	logger.Success("Token for user %v was generated successfully", user.Username)

	return &response, nil
}

func (passwordGrantFlow PasswordGrantFlow) RefreshToken(request *models.OAuthLoginRequest) (*models.OAuthLoginResponse, *models.OAuthErrorResponse) {
	var errorResponse models.OAuthErrorResponse
	authCtx := authorization_context.New()

	userEmail := jwt.GetTokenClaim(request.RefreshToken, "sub")
	// encodedToken, err := security.EncodeString(request.RefreshToken)
	// if err != nil {
	// 	errorResponse = models.OAuthErrorResponse{
	// 		Error:            models.OAuthInvalidRequestError,
	// 		ErrorDescription: fmt.Sprintf("Unable to decode the token for user %s", userEmail),
	// 	}
	// 	logger.Error(errorResponse.ErrorDescription)
	// 	return nil, &errorResponse
	// }
	usrManager := user_manager.Get()
	user := usrManager.GetUserByEmail(userEmail)

	if user == nil {
		errorResponse = models.OAuthErrorResponse{
			Error:            models.OAuthInvalidClientError,
			ErrorDescription: fmt.Sprintf("User %v was not found", userEmail),
		}
		logger.Error(errorResponse.ErrorDescription)
		return nil, &errorResponse
	}

	if user.ID == "" {
		if user.DisplayName != "" {
			errorResponse = models.OAuthErrorResponse{
				Error:            models.OAuthInvalidClientError,
				ErrorDescription: fmt.Sprintf("User %v was not found", user.DisplayName),
			}
		} else {
			errorResponse = models.OAuthErrorResponse{
				Error:            models.OAuthInvalidClientError,
				ErrorDescription: "Unknown error",
			}
		}
		logger.Error(errorResponse.ErrorDescription)
		return nil, &errorResponse
	}

	userRefreshToken := user.RefreshToken
	if !strings.EqualFold(request.RefreshToken, userRefreshToken) {
		errorResponse = models.OAuthErrorResponse{
			Error:            models.OAuthInvalidClientError,
			ErrorDescription: "Refresh token is invalid",
		}
		logger.Error(errorResponse.ErrorDescription)
		return nil, &errorResponse
	}

	token, err := jwt.ValidateRefreshToken(request.RefreshToken, user.Email)
	if err != nil {
		errorResponse = models.OAuthErrorResponse{
			Error:            models.OAuthInvalidClientError,
			ErrorDescription: fmt.Sprintf("There was an error validating user token, %v", err.Error()),
		}
		return nil, &errorResponse
	}

	newToken, err := jwt.GenerateDefaultUserToken(*user)
	if err != nil {
		errorResponse = models.OAuthErrorResponse{
			Error:            models.OAuthInvalidClientError,
			ErrorDescription: fmt.Sprintf("There was an error generating the new user token, %v", err.Error()),
		}
		return nil, &errorResponse
	}

	expiresIn := authCtx.Options.TokenDuration * 60
	response := models.OAuthLoginResponse{
		AccessToken:  newToken.Token,
		RefreshToken: request.RefreshToken,
		ExpiresIn:    fmt.Sprintf("%v", expiresIn),
		TokenType:    "Bearer",
		Scope:        authCtx.Scope,
	}

	todayPlus30 := time.Now().Add((time.Hour * 24) * 30)
	if token.ExpiresAt.Before(todayPlus30) {
		response.RefreshToken = newToken.RefreshToken
		authCtx.UserDatabaseAdapter.UpdateUserRefreshToken(user.ID, newToken.RefreshToken)
	}

	logger.Success("Token for user %v was generated successfully", user.Username)

	return &response, nil
}
