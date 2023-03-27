package api_key_manager

import "time"

type ApiKeyValidationOptions struct {
	ValidateExpiry      bool
	ExpirySkewInSeconds time.Duration
	ValidateBlocked     bool
	ValidateRoles       bool
	ValidateClaims      bool
}
