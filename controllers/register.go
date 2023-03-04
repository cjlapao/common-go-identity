package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/cjlapao/common-go-identity/constants"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-identity/oauthflow"
	"github.com/cjlapao/common-go-identity/user_manager"
	"github.com/cjlapao/common-go-restapi/controllers"
)

// Register Create an user in the tenant
func (c *AuthorizationControllers) Register(isPublic bool) controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBaseContext(r)
		var registerRequest models.OAuthRegisterRequest

		ctx.MapRequestBody(&registerRequest)

		user := models.NewUser()
		user.Username = registerRequest.Username
		user.Email = registerRequest.Email
		user.FirstName = registerRequest.FirstName
		user.LastName = registerRequest.LastName
		user.DisplayName = user.FirstName + " " + user.LastName
		user.Password = registerRequest.Password
		user.InvalidAttempts = 0
		user.EmailVerified = false

		if user.Username == "" {
			user.Username = user.Email
		}

		if ctx.AuthorizationContext.ValidationOptions.VerifiedEmail {
			emailVerificationToken := ctx.UserManager.GenerateUserEmailVerificationToken(*user)
			if emailVerificationToken == "" {
				w.WriteHeader(http.StatusBadRequest)
				responseError := models.NewOAuthErrorResponse(models.OAuthInvalidRequestError, "Error generating email verification code")
				ctx.NotifyError(models.RegistrationRequest, &responseError, registerRequest)
				json.NewEncoder(w).Encode(responseError)
				return
			}

			user.EmailVerifyToken = emailVerificationToken
		}

		if !isPublic {
			if registerRequest.Claims != nil && len(registerRequest.Claims) > 0 {
				for _, claim := range registerRequest.Claims {
					user.Claims = append(user.Claims, models.NewUserClaim(claim, claim))
				}
			} else {
				user.Claims = append(user.Claims, constants.ReadClaim)
			}

			if registerRequest.Roles != nil && len(registerRequest.Roles) > 0 {
				for _, role := range registerRequest.Roles {
					user.Roles = append(user.Roles, models.NewUserRole(role, role))
				}
			} else {
				user.Roles = append(user.Roles, constants.RegularUserRole)
			}
		} else {
			user.Claims = append(user.Claims, constants.ReadClaim)
			user.Roles = append(user.Roles, constants.RegularUserRole)
		}

		if err := ctx.UserManager.AddUser(*user); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			var responseError models.OAuthErrorResponse

			switch err.Error {
			case user_manager.DatabaseError:
				responseError = models.NewOAuthErrorResponse(models.OAuthInvalidRequestError, "Error in User Model")
			case user_manager.PasswordValidationError:
				responseError = models.NewOAuthErrorResponse(models.OAuthPasswordValidation, "Password failed validation")
			case user_manager.InvalidModelError:
				responseError = models.NewOAuthErrorResponse(models.OAuthUserValidation, "User failed validation")
			case user_manager.UserAlreadyExistsError:
				responseError = models.NewOAuthErrorResponse(models.OAuthUserExists, "User already exists")
			default:
				responseError = models.NewOAuthErrorResponse(models.UnknownError, "Unknown error")
			}

			ctx.NotifyError(models.RegistrationRequest, &responseError, registerRequest)
			json.NewEncoder(w).Encode(responseError)
			return
		}

		response := oauthflow.OAuthRegistrationResponse{
			ID:            user.ID,
			Email:         user.Email,
			EmailVerified: user.EmailVerified,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			DisplayName:   user.DisplayName,
			Roles:         user.Roles,
			Claims:        user.Claims,
		}

		if err := ctx.NotifySuccess(models.RegistrationRequest, *user); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			ctx.Logger.Exception(err, "error calling back the notification callback for %s", models.ConfigurationRequest.String())
			responseErr := models.OAuthErrorResponse{
				Error:            models.UnknownError,
				ErrorDescription: "there was unknown error",
			}
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		json.NewEncoder(w).Encode(response)
	}
}
