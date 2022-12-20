package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-restapi/controllers"
)

// TODO: Implement UserManager
// Revoke Revokes a user or a user refresh tenant, when revoking a user
// this will remove the user from the database deleting it
func (c *AuthorizationControllers) Revoke() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBaseContext(r)
		var revokeRequest models.OAuthRevokeRequest

		ctx.MapRequestBody(&revokeRequest)

		if revokeRequest.ClientID == "" {
			w.WriteHeader(http.StatusBadRequest)
			ErrEmptyUserID.Log()

			ctx.NotifyError(models.TokenRevoked, &ErrEmptyUserID, revokeRequest)
			json.NewEncoder(w).Encode(ErrEmptyUserID)
			return
		}

		usr := ctx.UserManager.GetUserById(revokeRequest.ClientID)

		if usr == nil || usr.ID == "" {
			w.WriteHeader(http.StatusBadRequest)
			ErrUserNotFound.Log()

			ctx.NotifyError(models.TokenRevoked, &ErrUserNotFound, revokeRequest)
			json.NewEncoder(w).Encode(ErrUserNotFound)
			return
		}

		// There is no revoke token filled in so we will be removing the user
		// otherwise we will only revoke the refresh token
		switch revokeRequest.GrantType {
		case "revoke_user":
			removeResult := ctx.UserManager.RemoveUser(usr.ID)

			if !removeResult {
				w.WriteHeader(http.StatusBadRequest)
				ErrUserNotRemoved.Log()
				ctx.NotifyError(models.TokenRevoked, &ErrUserNotRemoved, usr)
				json.NewEncoder(w).Encode(ErrUserNotRemoved)
				return
			}
		case "revoke_token":
			if !ctx.UserManager.UpdateUserRefreshToken(usr.ID, "") {
				w.WriteHeader(http.StatusBadRequest)
				ErrTokenNotFound.Log()
				ctx.NotifyError(models.TokenRevoked, &ErrTokenNotFound, usr)
				json.NewEncoder(w).Encode(ErrUserNotRemoved)
				return
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
			ErrGrantNotSupported.Log()
			ctx.NotifyError(models.TokenRevoked, &ErrGrantNotSupported, usr)
			json.NewEncoder(w).Encode(ErrGrantNotSupported)
			return
		}

		w.WriteHeader(http.StatusAccepted)
	}
}
