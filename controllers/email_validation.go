package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cjlapao/common-go-identity/authorization_context"
	"github.com/cjlapao/common-go-identity/constants"
	"github.com/cjlapao/common-go-identity/environment"
	"github.com/cjlapao/common-go-identity/jwt"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-identity/user_manager"
	"github.com/cjlapao/common-go-restapi/controllers"
)

// TODO: Implement better logging
// Register Create an user in the tenant
func (c *AuthorizationControllers) EmailVerificationRequest() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBaseContext(r)
		// trying to read the user from the body if not in the url
		if ctx.UserID == "" {
			var verifyEmailRequest models.OAuthVerifyEmailRequest
			ctx.MapRequestBody(&verifyEmailRequest)
			ctx.UserID = verifyEmailRequest.Email
		}

		usr := ctx.UserManager.GetUser(ctx.UserID)
		if usr == nil {
			w.WriteHeader(http.StatusUnauthorized)
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: "user not found",
			}

			ctx.NotifyError(models.EmailValidationRequest, &responseErr, nil)
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		ctx.UserID = usr.ID

		usr, err := ctx.UserManager.UpdateEmailVerificationToken(ctx.UserID)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			err.Log()
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: err.String(),
			}

			ctx.NotifyError(models.EmailValidationRequest, &responseErr, nil)
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		notifyData := models.User{
			ID:               usr.ID,
			Email:            usr.Email,
			EmailVerifyToken: usr.EmailVerifyToken,
			DisplayName:      usr.DisplayName,
			FirstName:        usr.FirstName,
			LastName:         usr.LastName,
		}

		if err := ctx.NotifySuccess(models.EmailValidationRequest, notifyData); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			ctx.Logger.Exception(err, "error calling back the notification callback for %s", models.ConfigurationRequest.String())
			responseErr := models.OAuthErrorResponse{
				Error:            models.UnknownError,
				ErrorDescription: "there was unknown error",
			}
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		ctx.Logger.Info("User %v requested a email verification token successfully", ctx.UserID)
		w.WriteHeader(http.StatusAccepted)
	}
}

func (c *AuthorizationControllers) VerifyEmail() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		var verifyEmail models.OAuthVerifyEmail

		ctx := NewBaseContext(r)
		ctx.MapRequestBody(&verifyEmail)

		usr := ctx.UserManager.GetUser(verifyEmail.UserID)
		if usr == nil {
			w.WriteHeader(http.StatusUnauthorized)
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: "user not found",
			}
			ctx.NotifyError(models.EmailValidation, &responseErr, verifyEmail)
			json.NewEncoder(w).Encode(responseErr)
			return
		}
		ctx.UserID = usr.ID

		if err := ctx.UserManager.ValidateEmailVerificationToken(ctx.UserID, verifyEmail.EmailToken, constants.EmailVerificationScope); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			err.Log()
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: err.String(),
			}
			ctx.NotifyError(models.EmailValidation, &responseErr, verifyEmail)
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		if err := ctx.UserManager.SetEmailVerificationState(ctx.UserID, true); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			err.Log()
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: err.String(),
			}
			ctx.NotifyError(models.EmailValidation, &responseErr, verifyEmail)
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		notifyData := models.User{
			ID:               usr.ID,
			Email:            usr.Email,
			EmailVerifyToken: verifyEmail.EmailToken,
			Username:         usr.Username,
			FirstName:        usr.FirstName,
			LastName:         usr.LastName,
		}

		if err := ctx.NotifySuccess(models.EmailValidation, notifyData); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			ctx.Logger.Exception(err, "error calling back the notification callback for %s", models.ConfigurationRequest.String())
			responseErr := models.OAuthErrorResponse{
				Error:            models.UnknownError,
				ErrorDescription: "there was unknown error",
			}
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		env := environment.Get()

		if env.GenerateEmailVerificationResponseToken() {
			// Getting the user from the user manager and generating a token for the user to login
			usrManager := user_manager.Get()
			user := usrManager.GetUserById(usr.ID)
			token, err := jwt.GenerateDefaultUserToken(*user)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				ctx.Logger.Exception(err, "There was an error validating user token for %s", models.ConfigurationRequest.String())
				responseErr := models.OAuthErrorResponse{
					Error:            models.UnknownError,
					ErrorDescription: err.Error(),
				}
				json.NewEncoder(w).Encode(responseErr)
				return
			}

			authCtx := authorization_context.Clone()
			expiresIn := authCtx.Options.TokenDuration * 60
			response := models.OAuthVerifyEmailResponse{
				Email:        usr.Email,
				AccessToken:  token.Token,
				RefreshToken: token.RefreshToken,
				ExpiresIn:    fmt.Sprintf("%v", expiresIn),
				TokenType:    "Bearer",
			}

			ctx.Logger.Info("User %v email was verified successfully", ctx.UserID)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		} else {
			ctx.Logger.Info("User %v email was verified successfully", ctx.UserID)
			w.WriteHeader(http.StatusOK)
		}
	}
}
