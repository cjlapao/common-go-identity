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

		if err := ctx.UserManager.UpdateRecoveryToken(ctx.UserID); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			err.Log()
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: err.String(),
			}
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		ctx.Logger.Info("User %v requested a recovery password token successfully", ctx.UserID)
		w.WriteHeader(http.StatusAccepted)
	}
}

func (c *AuthorizationControllers) RecoverPassword() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		var recoverPassword models.OAuthRecoverPassword

		ctx := NewBaseContext(r)
		ctx.MapRequestBody(&recoverPassword)

		if err := ctx.UserManager.ValidateRecoveryToken(ctx.UserID, recoverPassword.RecoverToken, constants.PasswordRecoveryScope); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			err.Log()
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: err.String(),
			}
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

		usr := ctx.UserManager.GetUserById(ctx.UserID)
		if usr.ID == "" {
			w.WriteHeader(http.StatusUnauthorized)
			responseErr := models.OAuthErrorResponse{
				Error: models.OAuthInvalidRequestError,
			}

			responseErr.Log()
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		oldPassword := usr.HashPassword(changePassword.OldPassword)
		if !strings.EqualFold(oldPassword, usr.Password) {
			w.WriteHeader(http.StatusUnauthorized)
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthPasswordMismatch,
				ErrorDescription: "Passwords do not match.",
			}

			responseErr.Log()
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
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		ctx.Logger.Info("User %v changed password successfully", ctx.UserID)
		w.WriteHeader(http.StatusOK)
	}
}