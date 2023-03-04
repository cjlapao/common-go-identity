package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cjlapao/common-go-identity/jwt"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-restapi/controllers"
)

// Introspection Validates a token in the context returning an openid oauth introspect response
func (c *AuthorizationControllers) Introspection() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBaseContext(r)
		token := r.FormValue("token")

		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			ErrEmptyToken.Log()
			json.NewEncoder(w).Encode(ErrEmptyToken)
			return
		}

		userToken, err := jwt.ValidateUserToken(token, ctx.AuthorizationContext.Scope, ctx.AuthorizationContext.Audiences...)

		if err != nil {
			response := models.OAuthIntrospectResponse{
				Active: false,
			}

			ErrInvalidToken.Log()
			c.Logger.Error("Token for user %v is not valid, %v", userToken.DisplayName, err.Error())
			json.NewEncoder(w).Encode(response)
			return
		}

		response := models.OAuthIntrospectResponse{
			Active:    true,
			ID:        userToken.ID,
			TokenType: userToken.Scope,
			Subject:   userToken.User,
			ExpiresAt: fmt.Sprintf("%v", userToken.ExpiresAt.Unix()),
			IssuedAt:  fmt.Sprintf("%v", userToken.IssuedAt.Unix()),
			Issuer:    userToken.Issuer,
		}

		ctx.Logger.Success("Token for user %v was validated successfully", userToken.DisplayName)
		json.NewEncoder(w).Encode(response)
	}
}
