package database

import (
	"errors"

	log "github.com/cjlapao/common-go-logger"
)

var logger = log.Get()

var ErrUserNotValid = errors.New("user model is not valid")
var ErrUnknown = errors.New("unknown error occurred")
