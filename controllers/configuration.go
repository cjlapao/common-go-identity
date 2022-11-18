package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-restapi/controllers"
	"github.com/cjlapao/common-go/helper/http_helper"
	"github.com/cjlapao/common-go/service_provider"
)

// Configuration Returns the OpenID Oauth configuration endpoint
func (c *AuthorizationControllers) Configuration() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		baseurl := service_provider.Get().GetBaseUrl(r)

		response := models.OAuthConfigurationResponse{
			Issuer:                baseurl + http_helper.JoinUrl(c.Context.Authorization.Options.ControllerPrefix, c.Context.Authorization.TenantId),
			JwksURI:               baseurl + http_helper.JoinUrl(c.Context.Authorization.Options.ControllerPrefix, c.Context.Authorization.TenantId, ".well-known", "openid-configuration", "jwks"),
			AuthorizationEndpoint: baseurl + http_helper.JoinUrl(c.Context.Authorization.Options.ControllerPrefix, c.Context.Authorization.TenantId, "authorize"),
			TokenEndpoint:         baseurl + http_helper.JoinUrl(c.Context.Authorization.Options.ControllerPrefix, c.Context.Authorization.TenantId, "token"),
			UserinfoEndpoint:      baseurl + http_helper.JoinUrl(c.Context.Authorization.Options.ControllerPrefix, c.Context.Authorization.TenantId, "userinfo"),
			IntrospectionEndpoint: baseurl + http_helper.JoinUrl(c.Context.Authorization.Options.ControllerPrefix, c.Context.Authorization.TenantId, "introspection"),
		}

		json.NewEncoder(w).Encode(response)
	}
}
