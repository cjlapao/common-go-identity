package api_key_manager

import (
	cryptorand "github.com/cjlapao/common-go-cryptorand"
	"github.com/cjlapao/common-go/constants"
	"github.com/cjlapao/common-go/guard"
)

type ApiKeyRole struct {
	ID   string `json:"id" bson:"_id"`
	Name string `json:"name" bson:"name"`
}

func NewApiKeyRole(name string) *ApiKeyRole {
	if err := guard.EmptyOrNil(name); err != nil {
		logger.Exception(err, "There was an error creating the api Key")
	}

	id, err := cryptorand.GetRandomString(constants.ID_SIZE)
	if err != nil {
		return nil
	}
	result := ApiKeyRole{
		ID:   id,
		Name: name,
	}

	return &result
}
