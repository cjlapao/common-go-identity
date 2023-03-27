//lint:file-ignore SA1029 //This is a constant
//lint:file-ignore ST1005 //This is a constant
package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/cjlapao/common-go-identity/api_key_manager"
	"github.com/cjlapao/common-go-identity/authorization_context"
	"github.com/cjlapao/common-go-identity/constants"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-restapi/controllers"
	"github.com/gorilla/mux"
)

func ApiKeyAuthorizationMiddlewareAdapter(roles []string, claims []string) controllers.Adapter {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var authorizationContext *authorization_context.AuthorizationContext
			authCtxFromRequest := r.Context().Value(constants.AUTHORIZATION_CONTEXT_KEY)
			if authCtxFromRequest != nil {
				authorizationContext = authCtxFromRequest.(*authorization_context.AuthorizationContext)
			} else {
				authorizationContext = authorization_context.New()
			}

			// If the authorization context is already authorized we will skip this middleware
			if authorizationContext.IsAuthorized {
				next.ServeHTTP(w, r)
				return
			}

			logger.Info("%sApiKey Authorization layer started", logger.GetRequestPrefix(r, false))
			vars := mux.Vars(r)
			tenantId := vars["tenantId"]

			apiKey, err := extractApiKey(r.Header)
			if err != nil {
				logger.Info("%sNo Api Key was found in the request, skipping", logger.GetRequestPrefix(r, false))
				next.ServeHTTP(w, r)
				return
			}

			// If the tenantId is not set in the URL we will try to get it from the ApiKey
			if tenantId == "" && apiKey.TenantId != "" {
				tenantId = apiKey.TenantId
			}

			// if no tenant is set we will assume it is the global tenant
			if tenantId == "" {
				tenantId = "global"
			}

			if authorizationContext.ApiKeyManager == nil {
				authError := models.OAuthErrorResponse{
					Error:            models.OAuthUnauthorizedClient,
					ErrorDescription: "No ApiKeyManager was set in the AuthorizationContext",
				}

				logger.Error("%sNo ApiKeyManager was set in the AuthorizationContext", logger.GetRequestPrefix(r, false))
				authorizationContext.IsAuthorized = false
				authorizationContext.AuthorizationError = &authError

				ctx := context.WithValue(r.Context(), constants.AUTHORIZATION_CONTEXT_KEY, authorizationContext)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			isValid, err := authorizationContext.ApiKeyManager.Validate(apiKey)
			if err != nil {
				authError := models.OAuthErrorResponse{
					Error:            models.OAuthUnauthorizedClient,
					ErrorDescription: err.Error(),
				}

				logger.Error("%s%s", logger.GetRequestPrefix(r, false), err.Error())
				authorizationContext.IsAuthorized = false
				authorizationContext.AuthorizationError = &authError

				ctx := context.WithValue(r.Context(), constants.AUTHORIZATION_CONTEXT_KEY, authorizationContext)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if !isValid {
				authError := models.OAuthErrorResponse{
					Error:            models.OAuthUnauthorizedClient,
					ErrorDescription: "The Api Key is not valid",
				}

				logger.Error("%sThe Api Key is not valid", logger.GetRequestPrefix(r, false))
				authorizationContext.IsAuthorized = false
				authorizationContext.AuthorizationError = &authError

				ctx := context.WithValue(r.Context(), constants.AUTHORIZATION_CONTEXT_KEY, authorizationContext)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			authorizationContext.IsAuthorized = true
			authorizationContext.IsMicroService = true
			authorizationContext.AuthorizedBy = "ApiKeyAuthorization"
			ctx := context.WithValue(r.Context(), constants.AUTHORIZATION_CONTEXT_KEY, authorizationContext)
			logger.Info("%ApiKey Authorization layer finished", logger.GetRequestPrefix(r, false))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractApiKey(headers http.Header) (*api_key_manager.ApiKeyHeader, error) {
	authHeader := headers.Get("ApiKey")
	if authHeader == "" {
		err := errors.New("No Api Key was found in the request")
		return nil, err
	}

	decodedKey, err := base64.StdEncoding.DecodeString(authHeader)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(string(decodedKey), ":")
	if len(parts) != 4 {
		err := errors.New("The Api Key is not in the correct format")
		return nil, err
	}

	return &api_key_manager.ApiKeyHeader{
		TenantId: parts[0],
		UserId:   parts[1],
		Key:      parts[2],
		Value:    parts[3],
	}, nil
}
