package controllers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/cjlapao/common-go-identity-otp/totp"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-restapi/controllers"
)

// Configuration Returns the OpenID Oauth configuration endpoint
func (c *AuthorizationControllers) OtpForEmailValidation() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBaseContext(r)

		options := totp.TotpOptions{
			Period: 5 * 60,
		}

		code, err := totp.GenerateCode("JBSWY3DPEHPK3PXP", time.Now().UTC(), &options)
		if err != nil {
			ctx.Logger.Exception(err, "error generating the totp code")
			w.WriteHeader(http.StatusInternalServerError)
			responseErr := models.OAuthErrorResponse{
				Error:            models.UnknownError,
				ErrorDescription: "there was unknown error",
			}
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		json.NewEncoder(w).Encode(code)
	}
}
