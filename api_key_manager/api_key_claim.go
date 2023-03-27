package api_key_manager

import (
	cryptorand "github.com/cjlapao/common-go-cryptorand"
	"github.com/cjlapao/common-go/constants"
	"github.com/cjlapao/common-go/guard"
)

type ApiKeyClaim struct {
	ID   string `json:"id" bson:"_id"`
	Name string `json:"name" bson:"name"`
}

func NewApiKeyClaim(name string) *ApiKeyClaim {
	if err := guard.EmptyOrNil(name); err != nil {
		logger.Exception(err, "There was an error creating the api Key claim")
	}

	result := ApiKeyClaim{
		ID:   cryptorand.GetRandomString(constants.ID_SIZE),
		Name: name,
	}

	return &result
}
