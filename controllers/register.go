package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/cjlapao/common-go-identity/constants"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-restapi/controllers"
)

// Register Create an user in the tenant
func (c *AuthorizationControllers) Register(isPublic bool) controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBaseContext(r)
		var registerRequest models.OAuthRegisterRequest

		ctx.MapRequestBody(&registerRequest)

		user := models.NewUser()
		user.Username = registerRequest.Username
		user.Email = registerRequest.Email
		user.FirstName = registerRequest.FirstName
		user.LastName = registerRequest.LastName
		user.DisplayName = user.FirstName + " " + user.LastName
		user.Password = registerRequest.Password
		user.InvalidAttempts = 0
		user.EmailVerified = false

		if !isPublic {
			if registerRequest.Claims != nil && len(registerRequest.Claims) > 0 {
				for _, claim := range registerRequest.Claims {
					user.Claims = append(user.Claims, models.NewUserClaim(claim, claim))
				}
			} else {
				user.Claims = append(user.Claims, constants.ReadClaim)
			}

			if registerRequest.Roles != nil && len(registerRequest.Roles) > 0 {
				for _, role := range registerRequest.Roles {
					user.Roles = append(user.Roles, models.NewUserRole(role, role))
				}
			} else {
				user.Roles = append(user.Roles, constants.RegularUserRole)
			}
		} else {
			user.Claims = append(user.Claims, constants.ReadClaim)
			user.Roles = append(user.Roles, constants.RegularUserRole)
		}

		if err := ctx.UserManager.AddUser(*user); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			ErrException.Log()
			json.NewEncoder(w).Encode(ErrException)
			return
		}
		json.NewEncoder(w).Encode(user)
	}
}
