package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-identity/oauthflow"
	"github.com/cjlapao/common-go-restapi/controllers"
)

// Login Generate a token for a valid user
func (c *AuthorizationControllers) Token() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBaseContext(r)
		var loginRequest models.OAuthLoginRequest
		ctx.MapRequestBody(&loginRequest)

		switch loginRequest.GrantType {
		case "password":
			response, errorResponse := oauthflow.PasswordGrantFlow{}.Authenticate(&loginRequest)
			if errorResponse != nil {
				switch errorResponse.Error {
				case models.OAuthInvalidClientError:
					w.WriteHeader(http.StatusUnauthorized)
				default:
					w.WriteHeader(http.StatusBadRequest)
				}

				ctx.NotifyError(models.TokenRequest, errorResponse, loginRequest)
				json.NewEncoder(w).Encode(*errorResponse)
				return
			}

			ctx.NotifySuccess(models.TokenRequest, loginRequest)
			json.NewEncoder(w).Encode(*response)
			return
		case "refresh_token":
			if loginRequest.Username != "" {
				response, errorResponse := oauthflow.PasswordGrantFlow{}.RefreshToken(&loginRequest)
				if errorResponse != nil {
					switch errorResponse.Error {
					case models.OAuthInvalidClientError:
						w.WriteHeader(http.StatusUnauthorized)
					default:
						w.WriteHeader(http.StatusBadRequest)
					}

					ctx.NotifyError(models.TokenRequest, errorResponse, loginRequest)
					json.NewEncoder(w).Encode(*errorResponse)
					return
				}

				ctx.NotifySuccess(models.TokenRequest, loginRequest)
				json.NewEncoder(w).Encode(*response)
				return
			} else if loginRequest.ClientID != "" {
				// TODO: Implement client id validations
				w.WriteHeader(http.StatusBadRequest)
				ErrGrantNotSupported.Log()

				ctx.NotifyError(models.TokenRequest, &ErrGrantNotSupported, loginRequest)
				json.NewEncoder(w).Encode(ErrGrantNotSupported)
				return
			} else {
				w.WriteHeader(http.StatusBadRequest)
				ErrGrantNotSupported.Log()

				ctx.NotifyError(models.TokenRequest, &ErrGrantNotSupported, loginRequest)
				json.NewEncoder(w).Encode(ErrGrantNotSupported)
				return
			}
		case "external_provider":
			if loginRequest.Username != "" {
				response, errorResponse := oauthflow.PasswordGrantFlow{}.RefreshToken(&loginRequest)
				if errorResponse != nil {
					switch errorResponse.Error {
					case models.OAuthInvalidClientError:
						w.WriteHeader(http.StatusUnauthorized)
					default:
						w.WriteHeader(http.StatusBadRequest)
					}

					ctx.NotifyError(models.TokenRequest, errorResponse, loginRequest)
					json.NewEncoder(w).Encode(*errorResponse)
					return
				}

				ctx.NotifySuccess(models.TokenRequest, loginRequest)
				json.NewEncoder(w).Encode(*response)
				return
			} else if loginRequest.ClientID != "" {
				// TODO: Implement client id validations
				w.WriteHeader(http.StatusBadRequest)
				ErrGrantNotSupported.Log()

				ctx.NotifyError(models.TokenRequest, &ErrGrantNotSupported, loginRequest)
				json.NewEncoder(w).Encode(ErrGrantNotSupported)
				return
			} else {
				w.WriteHeader(http.StatusBadRequest)
				ErrGrantNotSupported.Log()

				ctx.NotifyError(models.TokenRequest, &ErrGrantNotSupported, loginRequest)
				json.NewEncoder(w).Encode(ErrGrantNotSupported)
				return
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
			ErrGrantNotSupported.Log()

			ctx.NotifyError(models.TokenRequest, &ErrGrantNotSupported, loginRequest)
			json.NewEncoder(w).Encode(ErrGrantNotSupported)
			return
		}
	}
}
