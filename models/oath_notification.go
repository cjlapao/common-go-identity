package models

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/cjlapao/common-go/helper/http_helper"
)

// OAuthNotificationType Enum
type OAuthNotificationType int64

const (
	RegistrationRequest OAuthNotificationType = iota
	EmailValidationRequest
	EmailValidation
	PasswordRecoveryRequest
	PasswordRecoveryValidation
	PasswordRecovery
	PasswordChange
	TokenRequest
	TokenRevoked
	ConfigurationRequest
)

func (OAuthNotificationType OAuthNotificationType) String() string {
	return toOAuthNotificationTypeString[OAuthNotificationType]
}

func (oOAuthNotificationType OAuthNotificationType) FromString(keyType string) OAuthNotificationType {
	return toOAuthNotificationTypeID[keyType]
}

var toOAuthNotificationTypeString = map[OAuthNotificationType]string{
	RegistrationRequest:        "RegistrationRequest",
	EmailValidationRequest:     "EmailValidationRequest",
	EmailValidation:            "EmailValidation",
	PasswordRecoveryRequest:    "PasswordRecoveryRequest",
	PasswordRecoveryValidation: "PasswordRecoveryValidation",
	PasswordRecovery:           "PasswordRecovery",
	PasswordChange:             "PasswordChange",
	TokenRequest:               "TokenRequest",
	TokenRevoked:               "TokenRevoked",
	ConfigurationRequest:       "ConfigurationRequest",
}

var toOAuthNotificationTypeID = map[string]OAuthNotificationType{
	"RegistrationRequest":        RegistrationRequest,
	"EmailValidationRequest":     EmailValidationRequest,
	"EmailValidation":            EmailValidation,
	"PasswordRecoveryRequest":    PasswordRecoveryRequest,
	"PasswordRecoveryValidation": PasswordRecoveryValidation,
	"PasswordRecovery":           PasswordRecovery,
	"PasswordChange":             PasswordChange,
	"TokenRequest":               TokenRequest,
	"TokenRevoked":               TokenRevoked,
	"ConfigurationRequest":       ConfigurationRequest,
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
	Type    OAuthNotificationType
	Data    interface{}
	Request *http.Request
	Error   *OAuthErrorResponse
}

func (n OAuthNotification) Success() bool {
	return n.Error == nil
}

func (n OAuthNotification) GetBody(dest interface{}) error {
	return http_helper.MapRequestBody(n.Request, dest)
}
