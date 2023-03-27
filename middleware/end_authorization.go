package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/cjlapao/common-go-identity/authorization_context"
	"github.com/cjlapao/common-go-identity/constants"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-restapi/controllers"
)

// EndAuthorizationMiddlewareAdapter This cleans the context of any previous users
// token left in memory and rereading all of the default options for the next request
func EndAuthorizationMiddlewareAdapter() controllers.Adapter {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authorizationContext := r.Context().Value(constants.AUTHORIZATION_CONTEXT_KEY)
			if authorizationContext != nil {
				auth := authorizationContext.(*authorization_context.AuthorizationContext)
				if !auth.IsAuthorized {
					w.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(w).Encode(auth.AuthorizationError)
					logger.Info("%sAuthorization Layer Finished", logger.GetRequestPrefix(r, false))
					return
				}

				next.ServeHTTP(w, r)
				logger.Info("%sAuthorization Layer Finished", logger.GetRequestPrefix(r, false))
			} else {
				response := models.OAuthErrorResponse{
					Error:            models.OAuthUnauthorizedClient,
					ErrorDescription: "no authorization context was found in the request",
				}

				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(response)
				return
			}
		})
	}
}
