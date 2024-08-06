package authorization_context

import (
	cryptorand "github.com/cjlapao/common-go-cryptorand"
	"github.com/cjlapao/common-go/constants"
)

type UserContext struct {
	TokenID         string
	Nonce           string
	ID              string
	Username        string
	Email           string
	DisplayName     string
	Tenant          string
	Audiences       []string
	Issuer          string
	ValidatedClaims []string
	Roles           []string
}

func NewUserContext() *UserContext {
	id, err := cryptorand.GetRandomString(constants.ID_SIZE)
	if err != nil {
		return nil
	}

	user := UserContext{
		ID:              id,
		ValidatedClaims: make([]string, 0),
		Roles:           make([]string, 0),
	}

	return &user
}
