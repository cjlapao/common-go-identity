package database

import (
	"errors"

	"github.com/cjlapao/common-go/log"
)

var logger = log.Get()

var ErrUserNotValid = errors.New("user model is not valid")
var ErrUnknown = errors.New("unknown error occurred")
