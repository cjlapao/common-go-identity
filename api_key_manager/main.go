package api_key_manager

import (
	"errors"

	log "github.com/cjlapao/common-go-logger"
)

var ErrApiKeyNotFound = errors.New("api key was not found")

var logger = log.Get()
