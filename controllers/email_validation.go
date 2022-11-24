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

		if err := ctx.UserManager.UpdateEmailVerificationToken(ctx.UserID); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			err.Log()
			responseErr := models.OAuthErrorResponse{
				Error:            models.OAuthInvalidRequestError,
				ErrorDescription: err.String(),
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
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		ctx.Logger.Info("User %v email was verified successfully", ctx.UserID)
		w.WriteHeader(http.StatusOK)
	}
}
