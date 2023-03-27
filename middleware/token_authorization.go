//lint:file-ignore SA1029 //This is a constant
//lint:file-ignore ST1005 //This is a constant
package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/cjlapao/common-go-identity/authorization_context"
	"github.com/cjlapao/common-go-identity/constants"
	"github.com/cjlapao/common-go-identity/jwt"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-identity/user_manager"
	"github.com/cjlapao/common-go-restapi/controllers"
	"github.com/cjlapao/common-go/helper/http_helper"
	"github.com/gorilla/mux"
)

// TokenAuthorizationMiddlewareAdapter validates a Authorization Bearer during a rest api call
// It can take an array of roles and claims to further validate the token in a more granular
// view, it also can take an OR option in both if the role or claim are coma separated.
// For example a claim like "_read,_write" will be valid if the user either has a _read claim
// or a _write claim making them both valid
func TokenAuthorizationMiddlewareAdapter(roles []string, claims []string) controllers.Adapter {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var authorizationContext *authorization_context.AuthorizationContext
			authCtxFromRequest := r.Context().Value(constants.AUTHORIZATION_CONTEXT_KEY)
			if authCtxFromRequest != nil {
				authorizationContext = authCtxFromRequest.(*authorization_context.AuthorizationContext)
			} else {
				authorizationContext = authorization_context.New()
			}

			// this is not for us, move on
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				authorizationContext.IsAuthorized = false
				ctx := context.WithValue(r.Context(), constants.AUTHORIZATION_CONTEXT_KEY, authorizationContext)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			usrManager := user_manager.Get()
			// we do not have enough information to validate the token
			if authorizationContext.UserDatabaseAdapter == nil {
				authorizationContext.IsAuthorized = false
				ctx := context.WithValue(r.Context(), constants.AUTHORIZATION_CONTEXT_KEY, authorizationContext)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			vars := mux.Vars(r)
			tenantId := vars["tenantId"]
			var userToken *models.UserToken
			var dbUser *models.User
			var validateError error
			var err error
			var userClaims = make([]string, 0)
			var userRoles = make([]string, 0)
			var isSuperUser = false

			// if no tenant is set we will assume it is the global tenant
			if tenantId == "" {
				tenantId = "global"
			}

			// Setting the tenant in the context
			authorizationContext.SetRequestIssuer(r, tenantId)

			//Starting authorization layer of the token
			authorized := true
			logger.Info("%sToken Authorization layer started", logger.GetRequestPrefix(r, false))

			// Getting the token for validation
			jwt_token, valid := http_helper.GetAuthorizationToken(r.Header)
			if !valid {
				authorized = false
				validateError = errors.New("bearer token not found in request")
				logger.Error("%sError validating token, %v", logger.GetRequestPrefix(r, false), validateError.Error())
			}

			// Validating userToken against the keys
			if authorized {
				var validateUserTokenError error
				if authorizationContext.Options.KeyVaultEnabled {
					userToken, validateUserTokenError = jwt.ValidateUserToken(jwt_token, authorizationContext)
				} else if authorizationContext.Options.PublicKey != "" {
					userToken, validateUserTokenError = jwt.ValidateUserToken(jwt_token, authorizationContext)
				} else {
					validateUserTokenError = errors.New("no public or private key found to validate token")
				}

				if validateUserTokenError != nil {
					authorized = false
					validateError = errors.New("bearer token is not valid, " + validateUserTokenError.Error())
					logger.Error("%sError validating token, %v", logger.GetRequestPrefix(r, false), validateError.Error())
				}
			}

			// Making sure the user token does contain the necessary fields
			if userToken == nil || userToken.User == "" {
				authorized = false
				validateError = errors.New("bearer token has invalid user")
				logger.Error("%sError validating token, %v", logger.GetRequestPrefix(r, false), validateError.Error())
			}

			// Checking if the user is a supper user, if so we will not check any roles or claims as he will have access to it
			if len(roles) > 0 {
				for _, role := range roles {
					if role == constants.SuperUser {
						logger.Info("%sSuper User %v was found, authorizing", logger.GetRequestPrefix(r, false), userToken.User)
						authorized = true
						isSuperUser = true
						break
					}
				}
			}

			// To gain speed we will only get the db user if there is any role or claim to validate
			// otherwise we don't need anything else to validate it
			if (len(roles) > 0 || len(claims) > 0) && !isSuperUser {
				// Getting the user from the database to validate roles and claims
				if authorized {
					dbUser = usrManager.GetUserByEmail(userToken.User)
					if dbUser == nil || dbUser.ID == "" {
						authorized = false
						validateError = errors.New("bearer token user was not found in database, potentially revoked, " + userToken.User)
						logger.Error("%sError validating token, %v", logger.GetRequestPrefix(r, false), validateError.Error())
					}
				}

				if authorized {
					userRoles, userClaims = getUserRolesAndClaims(dbUser)
				}

				// Validating user roles
				if authorized && len(roles) > 0 && len(userRoles) > 0 {
					err = validateUserRoles(userRoles, roles)
					if err != nil {
						authorized = false
						validateError = errors.New("bearer token user does not contain one or more roles required by the context, " + err.Error())
						logger.Error("%sError validating token, %v", logger.GetRequestPrefix(r, false), validateError.Error())
					}
				}

				// Validating user claims
				if authorized && len(claims) > 0 && len(userClaims) > 0 {
					err = validateUserClaims(userClaims, claims)
					if err != nil {
						authorized = false
						validateError = errors.New("bearer token user does not contain one or more claims required by the context, " + err.Error())
						logger.Error("%sError validating token, %v", logger.GetRequestPrefix(r, false), validateError.Error())
					}
				}
			}

			if authorized && userToken != nil && userToken.ID != "" {
				oldOptions := authorizationContext.Options
				oldBaseUrl := authorizationContext.BaseUrl

				user := authorization_context.NewUserContext()
				user.ID = userToken.UserID
				user.TokenID = userToken.ID
				user.Nonce = userToken.Nonce
				user.Email = userToken.User
				user.Audiences = userToken.Audiences
				user.Issuer = userToken.Issuer
				user.ValidatedClaims = claims
				user.Roles = userToken.Roles

				authorizationContext.User = user
				// if oldBaseUrl == "" {
				// 	oldBaseUrl = ctx.Authorization.GetBaseUrl(r)
				// }

				authorization_context.NewFromUser(user)
				authorizationContext.Options = oldOptions
				authorizationContext.BaseUrl = oldBaseUrl
				authorizationContext.Issuer = authorizationContext.GetBaseUrl(r) + "/auth/" + tenantId
				authorizationContext.TenantId = userToken.TenantId
				authorizationContext.IsAuthorized = true
				authorizationContext.AuthorizedBy = "TokenAuthorization"

				logger.Info("%sUser %s was authorized successfully.", logger.GetRequestPrefix(r, false), user.Email)
			} else {
				response := models.OAuthErrorResponse{
					Error:            models.OAuthUnauthorizedClient,
					ErrorDescription: validateError.Error(),
				}

				authorizationContext.IsAuthorized = false
				authorizationContext.AuthorizationError = &response

				if userToken != nil && userToken.User != "" {
					logger.Error("%sUser "+userToken.User+" failed to authorize, %v", logger.GetRequestPrefix(r, false), response.ErrorDescription)
				} else {
					logger.Error("%sRequest failed to authorize, %v", logger.GetRequestPrefix(r, false), response.ErrorDescription)
				}
			}

			ctx := context.WithValue(r.Context(), constants.AUTHORIZATION_CONTEXT_KEY, authorizationContext)
			logger.Info("%sToken Authorization layer finished", logger.GetRequestPrefix(r, false))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func getUserRolesAndClaims(user *models.User) (roles []string, claims []string) {
	roles = make([]string, 0)
	claims = make([]string, 0)

	if user == nil || user.ID == "" {
		return roles, claims
	}

	if !user.IsValid() {
		return roles, claims
	}

	for _, role := range user.Roles {
		roles = append(roles, role.ID)
	}

	for _, claim := range user.Claims {
		claims = append(claims, claim.ID)
	}

	return roles, claims
}

func validateUserRoles(roles []string, requiredRoles []string) error {
	var validateError error

	// Getting user roles and claims
	validatedRoles := make(map[string]bool)

	if len(requiredRoles) > 0 {
		if len(roles) == 0 {
			validateError = errors.New("user does not contain any roles")
			logger.Error(validateError.Error())
			return validateError
		} else {
			for _, requiredRole := range requiredRoles {
				foundRole := false
				for _, role := range roles {
					requiredRoleArr := strings.Split(requiredRole, ",")
					if len(requiredRoleArr) == 1 {
						if strings.EqualFold(requiredRole, role) {
							foundRole = true
							break
						}
					} else if len(requiredRoleArr) > 1 {
						for _, splitRequiredRole := range requiredRoleArr {
							if strings.EqualFold(splitRequiredRole, role) {
								foundRole = true
								break
							}
						}
						if foundRole {
							break
						}
					}
				}

				validatedRoles[requiredRole] = foundRole
			}
		}
	}

	for roleName, found := range validatedRoles {
		if !found {
			validateError = errors.New("user does not contain required role " + roleName)
			logger.Error(validateError.Error())
			return validateError
		}
	}

	return nil
}

func validateUserClaims(claims []string, requiredClaims []string) error {
	var validateError error

	// Getting user claims and claims
	validatedClaims := make(map[string]bool)

	if len(requiredClaims) > 0 {
		if len(claims) == 0 {
			validateError = errors.New("user does not contain any claims")
			logger.Error(validateError.Error())
			return validateError
		} else {
			for _, requiredClaim := range requiredClaims {
				foundClaim := false
				for _, claim := range claims {
					requiredClaimArr := strings.Split(requiredClaim, ",")
					if len(requiredClaimArr) == 1 {
						if strings.EqualFold(requiredClaim, claim) {
							foundClaim = true
							break
						}
					} else if len(requiredClaimArr) > 1 {
						for _, splitRequiredClaim := range requiredClaimArr {
							if strings.EqualFold(splitRequiredClaim, claim) {
								foundClaim = true
								break
							}
						}
						if foundClaim {
							break
						}
					}
				}

				validatedClaims[requiredClaim] = foundClaim
			}
		}

	}

	for claimName, found := range validatedClaims {
		if !found {
			validateError = errors.New("user does not contain required claim " + claimName)
			logger.Error(validateError.Error())
			return validateError
		}
	}

	return nil
}
