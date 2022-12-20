package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/cjlapao/common-go-identity/constants"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-restapi/controllers"
)

// TODO: Implement better logging
// Register Create an user in the tenant
func (c *AuthorizationControllers) EmailVerificationRequest() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBaseContext(r)

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

		if err := ctx.NotifySuccess(models.EmailValidationRequest, verifyEmail); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			ctx.Logger.Exception(err, "error calling back the notification callback for %s", models.ConfigurationRequest.String())
			responseErr := models.OAuthErrorResponse{
				Error:            models.UnknownError,
				ErrorDescription: "there was unknown error",
			}
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		ctx.Logger.Info("User %v email was verified successfully", ctx.UserID)
		w.WriteHeader(http.StatusOK)
	}
}
