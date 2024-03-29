package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-restapi/controllers"
	"github.com/cjlapao/common-go/automapper"
)

// Jwks Returns the public keys for the openid oauth configuration endpoint for validation
func (c *AuthorizationControllers) Jwks() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBaseContext(r)
		response := models.OAuthJwksResponse{
			Keys: make([]models.OAuthJwksKey, 0),
		}
		key := models.OAuthJwksKey{}
		defaultKey := ctx.AuthorizationContext.KeyVault.GetDefaultKey()
		if len(defaultKey.JWK.Keys) >= 1 {
			automapper.Map(defaultKey.JWK.Keys[0], &key)
		}

		key.ID = defaultKey.ID
		response.Keys = append(response.Keys, key)

		json.NewEncoder(w).Encode(response)
	}
}
