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
		ctx := NewBaseContext(r)

		baseurl := service_provider.Get().GetBaseUrl(r)

		response := models.OAuthConfigurationResponse{
			Issuer:                baseurl + http_helper.JoinUrl(c.AuthorizationContext.Options.ControllerPrefix, c.AuthorizationContext.TenantId),
			JwksURI:               baseurl + http_helper.JoinUrl(c.AuthorizationContext.Options.ControllerPrefix, c.AuthorizationContext.TenantId, ".well-known", "openid-configuration", "jwks"),
			AuthorizationEndpoint: baseurl + http_helper.JoinUrl(c.AuthorizationContext.Options.ControllerPrefix, c.AuthorizationContext.TenantId, "authorize"),
			TokenEndpoint:         baseurl + http_helper.JoinUrl(c.AuthorizationContext.Options.ControllerPrefix, c.AuthorizationContext.TenantId, "token"),
			UserinfoEndpoint:      baseurl + http_helper.JoinUrl(c.AuthorizationContext.Options.ControllerPrefix, c.AuthorizationContext.TenantId, "userinfo"),
			IntrospectionEndpoint: baseurl + http_helper.JoinUrl(c.AuthorizationContext.Options.ControllerPrefix, c.AuthorizationContext.TenantId, "introspection"),
		}

		if err := ctx.NotifySuccess(models.ConfigurationRequest, response); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			ctx.Logger.Exception(err, "error calling back the notification callback for %s", models.ConfigurationRequest.String())
			responseErr := models.OAuthErrorResponse{
				Error:            models.UnknownError,
				ErrorDescription: "there was unknown error",
			}
			json.NewEncoder(w).Encode(responseErr)
			return
		}

		json.NewEncoder(w).Encode(response)
	}
}
