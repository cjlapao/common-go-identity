package authorization_context

import (
	"github.com/cjlapao/common-go/security/encryption"
)

type AuthorizationOptions struct {
	KeyVaultEnabled            bool
	TokenDuration              int
	RefreshTokenDuration       int
	VerifyEmailTokenDuration   int
	RecoverTokenDuration       int
	OtpSecret                  string
	OptDuration                int
	EmailVerificationProcessor string
	SignatureType              encryption.EncryptionKeyType
	SignatureSize              encryption.EncryptionKeySize
	PrivateKey                 string
	PublicKey                  string
	KeyId                      string
	ControllerPrefix           string
	PasswordRules              PasswordRules
}

type AuthorizationValidationOptions struct {
	Audiences       bool
	ExpiryDate      bool
	Subject         bool
	Issuer          bool
	VerifiedEmail   bool
	NotBefore       bool
	Tenant          bool
	AttemptsToBlock int
	BlockDuration   int
}

type PasswordRules struct {
	RequiresCapital bool
	RequiresSpecial bool
	RequiresNumber  bool
	MinimumSize     int
	AllowsSpaces    bool
	AllowedSpecials string
}
