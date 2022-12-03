package models

import (
	"bytes"
	"encoding/json"
)

// OAuthNotificationType Enum
type OAuthNotificationType int64

const (
	RegistrationCompleteNotificationType OAuthNotificationType = iota
	EmailValidationRequest
	EmailValidation
	PasswordRecoveryRequest
	PasswordRecovery
	PasswordChange
	TokenRequest
	TokenRevoked
)

func (OAuthNotificationType OAuthNotificationType) String() string {
	return toOAuthNotificationTypeString[OAuthNotificationType]
}

func (oOAuthNotificationType OAuthNotificationType) FromString(keyType string) OAuthNotificationType {
	return toOAuthNotificationTypeID[keyType]
}

var toOAuthNotificationTypeString = map[OAuthNotificationType]string{
	RegistrationCompleteNotificationType: "RegistrationCompleteNotificationType",
	EmailValidationRequest:               "EmailValidationRequest",
	EmailValidation:                      "EmailValidation",
	PasswordRecoveryRequest:              "PasswordRecoveryRequest",
	PasswordRecovery:                     "PasswordRecovery",
	PasswordChange:                       "PasswordChange",
	TokenRequest:                         "TokenRequest",
	TokenRevoked:                         "TokenRevoked",
}

var toOAuthNotificationTypeID = map[string]OAuthNotificationType{
	"RegistrationCompleteNotificationType": RegistrationCompleteNotificationType,
	"EmailValidationRequest":               EmailValidationRequest,
	"EmailValidation":                      EmailValidation,
	"PasswordRecoveryRequest":              PasswordRecoveryRequest,
	"PasswordRecovery":                     PasswordRecovery,
	"PasswordChange":                       PasswordChange,
	"TokenRequest":                         TokenRequest,
	"TokenRevoked":                         TokenRevoked,
}

func (OAuthNotificationType OAuthNotificationType) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(toOAuthNotificationTypeString[OAuthNotificationType])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (OAuthNotificationType *OAuthNotificationType) UnmarshalJSON(b []byte) error {
	var key string
	err := json.Unmarshal(b, &key)
	if err != nil {
		return err
	}

	*OAuthNotificationType = toOAuthNotificationTypeID[key]
	return nil
}

type OAuthNotification struct {
	Type  OAuthNotificationType
	Data  interface{}
	Error *OAuthErrorResponse
}
