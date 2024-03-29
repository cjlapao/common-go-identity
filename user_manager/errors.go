package user_manager

import (
	"fmt"

	log "github.com/cjlapao/common-go-logger"
)

// UserManagerErrorType Enum
type UserManagerErrorType int64

const (
	DatabaseError UserManagerErrorType = iota
	UserAlreadyExistsError
	InvalidModelError
	InvalidTokenError
	InvalidKeyError
	PasswordValidationError
	EmailValidationError
	UnknownError
)

func (UserManagerErrorType UserManagerErrorType) String() string {
	return toUserManagerErrorTypeString[UserManagerErrorType]
}

func (UserManagerErrorType UserManagerErrorType) FromString(keyType string) UserManagerErrorType {
	return toUserManagerErrorTypeID[keyType]
}

var toUserManagerErrorTypeString = map[UserManagerErrorType]string{
	DatabaseError:           "database_error",
	InvalidModelError:       "invalid_model_error",
	InvalidTokenError:       "invalid_token_error",
	InvalidKeyError:         "invalid_key_error",
	PasswordValidationError: "password_validation_error",
	EmailValidationError:    "EmailValidationError",
	UserAlreadyExistsError:  "user_already_exists_error",
	UnknownError:            "unknown_error",
}

var toUserManagerErrorTypeID = map[string]UserManagerErrorType{
	"database_error":            DatabaseError,
	"invalid_model_error":       InvalidModelError,
	"invalid_token_error":       InvalidTokenError,
	"invalid_key_error":         InvalidKeyError,
	"EmailValidationError":      EmailValidationError,
	"user_already_exists_error": UserAlreadyExistsError,
	"unknown_error":             UnknownError,
}

type UserManagerError struct {
	logger      *log.LoggerService
	Error       UserManagerErrorType `json:"error"`
	InnerErrors []error              `json:"inner_error,omitempty"`
}

func NewUserManagerError(err UserManagerErrorType, innerErrors ...error) UserManagerError {
	errorResponse := UserManagerError{
		logger:      log.Get(),
		Error:       err,
		InnerErrors: innerErrors,
	}

	return errorResponse

}

func (uError UserManagerError) String() string {
	message := fmt.Sprintf("An error occurred, %v", uError.Error.String())
	for _, innerError := range uError.InnerErrors {
		message += fmt.Sprintf("\n    %v", innerError.Error())
	}

	return message
}

func (uError UserManagerError) Log() {
	uError.logger.Error(uError.String())
}
