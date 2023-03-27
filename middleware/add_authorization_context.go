//lint:file-ignore SA1029 //This is a constant
package middleware

import (
	"context"
	"net/http"

	"github.com/cjlapao/common-go-identity/authorization_context"
	"github.com/cjlapao/common-go-identity/constants"
	restapi "github.com/cjlapao/common-go-restapi"
	"github.com/cjlapao/common-go-restapi/controllers"
)

func AddAuthorizationContextMiddlewareAdapter() controllers.Adapter {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Context().Value(restapi.REQUEST_ID_KEY)
			authorizationContext := authorization_context.Clone()

			// Adding the request id if it exist
			if id != nil {
				authorizationContext.RequestId = id.(string)
			}

			// Adding a new Authorization Request to the Request
			ctx := context.WithValue(r.Context(), constants.AUTHORIZATION_CONTEXT_KEY, authorizationContext)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
