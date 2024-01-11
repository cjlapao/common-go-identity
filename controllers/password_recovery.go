package controllers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/cjlapao/common-go-identity/constants"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-restapi/controllers"
)

// TODO: Implement better logging
// Register Create an user in the tenant
func (c *AuthorizationControllers) RecoverPasswordRequest() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBaseContext(r)

		// trying to read the user from the body if not in the url
		if ctx.UserID == "" {
			var passwordRecoveryRequest models.OAuthRecoverPasswordRequest
			ctx.MapRequestBody(&passwordRecoveryRequest)
			ctx.UserID = passwordRecoveryRequest.Email
		}

		usr, err := ctx.UserManager.UpdateRecoveryToken(ctx.UserID)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			err.Log()
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: err.String(),
			}
			ctx.NotifyError(models.PasswordRecoveryRequest, &responseErr, usr)
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		// Notifying the callback if active
		notificationData := models.User{
			ID:            usr.ID,
			Email:         usr.Email,
			RecoveryToken: usr.RecoveryToken,
			DisplayName:   usr.DisplayName,
			FirstName:     usr.FirstName,
			LastName:      usr.LastName,
		}

		if err := ctx.NotifySuccess(models.PasswordRecoveryRequest, notificationData); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			ctx.Logger.Exception(err, "error calling back the notification callback for %s", models.ConfigurationRequest.String())
			responseErr := models.OAuthErrorResponse{
				Error:            models.UnknownError,
				ErrorDescription: "there was unknown error",
			}
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		ctx.Logger.Info("User %v requested a recovery password token successfully", ctx.UserID)
		w.WriteHeader(http.StatusAccepted)
	}
}

func (c *AuthorizationControllers) ValidateRecoverPasswordToken() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		var validateToken models.OAuthRecoverPasswordValidateRequest

		ctx := NewBaseContext(r)
		ctx.MapRequestBody(&validateToken)
		if ctx.UserID == "" {
			ctx.UserID = validateToken.UserID
		}

		if err := ctx.UserManager.ValidateRecoveryToken(ctx.UserID, validateToken.RecoverToken, constants.PasswordRecoveryScope, false); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			err.Log()
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: err.String(),
			}
			ctx.NotifyError(models.PasswordRecoveryValidation, &responseErr, validateToken)
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		notificationData := models.User{
			ID:            ctx.UserID,
			RecoveryToken: validateToken.RecoverToken,
		}

		if err := ctx.NotifySuccess(models.PasswordRecoveryValidation, notificationData); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			ctx.Logger.Exception(err, "error calling back the notification callback for %s", models.ConfigurationRequest.String())
			responseErr := models.OAuthErrorResponse{
				Error:            models.UnknownError,
				ErrorDescription: "there was unknown error",
			}

			json.NewEncoder(w).Encode(responseErr)
			return
		}

		ctx.Logger.Info("User %v recovered token was validated successfully", ctx.UserID)
		w.WriteHeader(http.StatusOK)
	}
}

func (c *AuthorizationControllers) RecoverPassword() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		var recoverPassword models.OAuthRecoverPasswordChangeRequest

		ctx := NewBaseContext(r)
		ctx.MapRequestBody(&recoverPassword)
		usr := ctx.UserManager.GetUser(recoverPassword.UserID)
		if usr.ID == "" {
			w.WriteHeader(http.StatusUnauthorized)
			responseErr := models.OAuthErrorResponse{
				Error: models.OAuthInvalidRequestError,
			}
			responseErr.Log()
			ctx.NotifyError(models.PasswordRecovery, &responseErr, recoverPassword)
			json.NewEncoder(w).Encode(responseErr)
			return
		}
		ctx.UserID = usr.ID

		if err := ctx.UserManager.ValidateRecoveryToken(ctx.UserID, recoverPassword.RecoverToken, constants.PasswordRecoveryScope, true); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			err.Log()
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: err.String(),
			}
			ctx.NotifyError(models.PasswordRecovery, &responseErr, recoverPassword)
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		if err := ctx.UserManager.UpdatePassword(ctx.UserID, recoverPassword.NewPassword); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			err.Log()
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: err.String(),
			}

			ctx.NotifyError(models.PasswordRecovery, &responseErr, recoverPassword)
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		notificationData := models.User{
			ID: ctx.UserID,
		}

		if err := ctx.NotifySuccess(models.PasswordRecovery, notificationData); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			ctx.Logger.Exception(err, "error calling back the notification callback for %s", models.ConfigurationRequest.String())
			responseErr := models.OAuthErrorResponse{
				Error:            models.UnknownError,
				ErrorDescription: "there was unknown error",
			}
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		ctx.Logger.Info("User %v recovered password successfully", ctx.UserID)
		w.WriteHeader(http.StatusOK)
	}
}

func (c *AuthorizationControllers) ChangePassword() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		var changePassword models.OAuthChangePassword

		ctx := NewBaseContext(r)
		ctx.MapRequestBody(&changePassword)

		usr := ctx.UserManager.GetUser(ctx.UserID)
		if usr.ID == "" {
			w.WriteHeader(http.StatusUnauthorized)
			responseErr := models.OAuthErrorResponse{
				Error: models.OAuthInvalidRequestError,
			}
			responseErr.Log()
			ctx.NotifyError(models.PasswordChange, &responseErr, changePassword)
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		ctx.UserID = usr.ID

		oldPassword := usr.HashPassword(changePassword.OldPassword)
		if !strings.EqualFold(oldPassword, usr.Password) {
			w.WriteHeader(http.StatusUnauthorized)
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthPasswordMismatch,
				ErrorDescription: "Passwords do not match.",
			}

			responseErr.Log()
			ctx.NotifyError(models.PasswordChange, &responseErr, changePassword)
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		if err := ctx.UserManager.UpdatePassword(ctx.UserID, changePassword.NewPassword); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			err.Log()
			responseErr := models.OAuthErrorResponse{
				Error: models.OAuthInvalidRequestError,
			}

			err.Log()
			ctx.NotifyError(models.PasswordChange, &responseErr, changePassword)
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		notificationData := models.User{
			ID: ctx.UserID,
		}

		if err := ctx.NotifySuccess(models.PasswordChange, notificationData); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			ctx.Logger.Exception(err, "error calling back the notification callback for %s", models.ConfigurationRequest.String())
			responseErr := models.OAuthErrorResponse{
				Error:            models.UnknownError,
				ErrorDescription: "there was unknown error",
			}
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		ctx.Logger.Info("User %v changed password successfully", ctx.UserID)
		w.WriteHeader(http.StatusOK)
	}
}
