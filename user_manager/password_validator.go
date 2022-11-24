package user_manager

import (
	"github.com/cjlapao/common-go/log"
)

type PasswordValidationErrorType int64

const (
	InvalidMinimumSize PasswordValidationErrorType = iota
	MissingSpecial
	MissingNumber
	MissingCapital
	ContainsDisallowedSpace
)

func (PasswordValidationErrorType PasswordValidationErrorType) String() string {
	return toPasswordValidationErrorTypeString[PasswordValidationErrorType]
}

func (PasswordValidationErrorType PasswordValidationErrorType) FromString(keyType string) PasswordValidationErrorType {
	return toPasswordValidationErrorTypeID[keyType]
}

var toPasswordValidationErrorTypeString = map[PasswordValidationErrorType]string{
	InvalidMinimumSize:      "invalid_size",
	MissingSpecial:          "missing_special_characters",
	MissingNumber:           "missing_number",
	MissingCapital:          "missing_capital",
	ContainsDisallowedSpace: "contains_disallowed_space",
}

var toPasswordValidationErrorTypeID = map[string]PasswordValidationErrorType{
	"database_error":            InvalidMinimumSize,
	"invalid_model_error":       MissingSpecial,
	"invalid_token_error":       MissingNumber,
	"invalid_key_error":         MissingCapital,
	"contains_disallowed_space": ContainsDisallowedSpace,
}

type PasswordValidationResult struct {
	logger *log.Logger
	Errors []PasswordValidationErrorType `json:"error"`
}

func NewPasswordValidationResult() PasswordValidationResult {
	errorResponse := PasswordValidationResult{
		logger: log.Get(),
		Errors: make([]PasswordValidationErrorType, 0),
	}

	return errorResponse
}

func (val PasswordValidationResult) IsValid() bool {
	return len(val.Errors) == 0
}
