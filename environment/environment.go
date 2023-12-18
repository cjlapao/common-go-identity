package environment

import (
	"strconv"
	"strings"

	"github.com/cjlapao/common-go/configuration"
	"github.com/cjlapao/common-go/helper/http_helper"
	"github.com/cjlapao/common-go/helper/strhelper"
)

const (
	ISSUER_ENV_VAR_NAME                               = "identity__issuer"
	TOKEN_DURATION_ENV_VAR_NAME                       = "identity__token_duration"
	CLOCK_SKEW_ENV_VAR_NAME                           = "identity__clock_skew"
	REFRESH_TOKEN_DURATION_ENV_VAR_NAME               = "identity__refresh_token_duration"
	VERIFY_EMAIL_TOKEN_DURATION_ENV_VAR_NAME          = "identity__verify_email_token_duration"
	RECOVER_TOKEN_DURATION_ENV_VAR_NAME               = "identity__recover_token_duration"
	SCOPE_ENV_VAR_NAME                                = "identity__scope"
	AUTHORIZATION_TYPE_ENV_VAR_NAME                   = "identity__authorization_type"
	API_PORT_ENV_VAR_NAME                             = "identity__api_port"
	API_PREFIX_ENV_VAR_NAME                           = "identity__api_prefix"
	CONTROLLER_PREFIX_ENV_VAR_NAME                    = "identity__controller_prefix"
	VALIDATION_PASSWORD_REQUIRE_CAPITAL_ENV_VAR_NAME  = "identity__validation__password__require_capital"
	VALIDATION_PASSWORD_REQUIRE_SPECIAL_ENV_VAR_NAME  = "identity__validation__password__require_special"
	VALIDATION_PASSWORD_REQUIRE_NUMBER_ENV_VAR_NAME   = "identity__validation__password__require_number"
	VALIDATION_PASSWORD_MIN_SIZE_ENV_VAR_NAME         = "identity__validation__password__min_size"
	VALIDATION_PASSWORD_ALLOW_SPACES_ENV_VAR_NAME     = "identity__validation__password__allow_spaces"
	VALIDATION_PASSWORD_ALLOWED_SPECIALS_ENV_VAR_NAME = "identity__validation__password__allowed_specials"
	VERIFY_EMAIL_PROCESSOR_ENV_VAR_NAME               = "identity__verify_email_processor"
	OTP_DEFAULT_DURATION_ENV_VAR_NAME                 = "identity__otp_default_duration"
	OTP_SECRET_ENV_VAR_NAME                           = "identity__otp_secret"
)

var currentEnv *Environment

type Environment struct {
	issuer                            string
	clockSkew                         int
	tokenDuration                     int
	refreshTokenDuration              int
	verifyEmailTokenDuration          int
	verifyEmailProcessor              string
	otpDefaultDuration                int
	otpSecret                         string
	recoverTokenDuration              int
	scope                             string
	authorizationType                 string
	apiPort                           string
	apiPrefix                         string
	controllerPrefix                  string
	passwordValidationRequireCapital  bool
	passwordValidationRequireSpecial  bool
	passwordValidationRequireNumber   bool
	passwordValidationMinSize         int
	passwordValidationAllowSpaces     bool
	passwordValidationAllowedSpecials string
}

func New() *Environment {
	config := configuration.Get()
	env := Environment{
		issuer:                   config.GetString(ISSUER_ENV_VAR_NAME),
		clockSkew:                config.GetInt(CLOCK_SKEW_ENV_VAR_NAME),
		tokenDuration:            config.GetInt(TOKEN_DURATION_ENV_VAR_NAME),
		refreshTokenDuration:     config.GetInt(REFRESH_TOKEN_DURATION_ENV_VAR_NAME),
		verifyEmailTokenDuration: config.GetInt(VERIFY_EMAIL_TOKEN_DURATION_ENV_VAR_NAME),
		recoverTokenDuration:     config.GetInt(RECOVER_TOKEN_DURATION_ENV_VAR_NAME),
		scope:                    config.GetString(SCOPE_ENV_VAR_NAME),
		authorizationType:        config.GetString(AUTHORIZATION_TYPE_ENV_VAR_NAME),
		apiPort:                  config.GetString(API_PORT_ENV_VAR_NAME),
		apiPrefix:                config.GetString(API_PREFIX_ENV_VAR_NAME),
		controllerPrefix:         config.GetString(CONTROLLER_PREFIX_ENV_VAR_NAME),
		verifyEmailProcessor:     config.GetString(VERIFY_EMAIL_PROCESSOR_ENV_VAR_NAME),
		otpSecret:                config.GetString(OTP_SECRET_ENV_VAR_NAME),
		otpDefaultDuration:       config.GetInt(OTP_DEFAULT_DURATION_ENV_VAR_NAME),
	}

	// password default config
	passwordRequireCapital := config.GetString(VALIDATION_PASSWORD_REQUIRE_CAPITAL_ENV_VAR_NAME)
	if passwordRequireCapital != "" {
		env.passwordValidationRequireCapital = strhelper.ToBoolean(passwordRequireCapital)
	} else {
		env.passwordValidationRequireCapital = true
	}

	passwordRequireSpecial := config.GetString(VALIDATION_PASSWORD_REQUIRE_SPECIAL_ENV_VAR_NAME)
	if passwordRequireSpecial != "" {
		env.passwordValidationRequireSpecial = strhelper.ToBoolean(passwordRequireSpecial)
	} else {
		env.passwordValidationRequireSpecial = true
	}

	passwordRequireNumber := config.GetString(VALIDATION_PASSWORD_REQUIRE_NUMBER_ENV_VAR_NAME)
	if passwordRequireNumber != "" {
		env.passwordValidationRequireNumber = strhelper.ToBoolean(passwordRequireNumber)
	} else {
		env.passwordValidationRequireNumber = true
	}

	passwordMinimumSize := config.GetString(VALIDATION_PASSWORD_MIN_SIZE_ENV_VAR_NAME)
	if passwordMinimumSize != "" {
		size, err := strconv.Atoi(passwordMinimumSize)
		if err == nil {
			env.passwordValidationMinSize = size
		}
	} else {
		env.passwordValidationMinSize = 8
	}

	passwordAllowSpaces := config.GetString(VALIDATION_PASSWORD_ALLOW_SPACES_ENV_VAR_NAME)
	if passwordAllowSpaces != "" {
		env.passwordValidationAllowSpaces = strhelper.ToBoolean(passwordAllowSpaces)
	} else {
		env.passwordValidationAllowSpaces = true
	}

	passwordAllowedSpecials := config.GetString(VALIDATION_PASSWORD_ALLOWED_SPECIALS_ENV_VAR_NAME)
	if passwordAllowedSpecials != "" {
		env.passwordValidationAllowedSpecials = passwordAllowedSpecials
	}

	return &env
}

func Get() *Environment {
	if currentEnv != nil {
		return currentEnv
	}

	return New()
}

func Refresh() *Environment {
	return New()
}

func (env *Environment) Issuer() string {
	// TODO: Improve the issuer calculations with overrides
	if env.issuer == "" {
		env.issuer = "http://localhost"
		if env.apiPort != "" {
			env.issuer += ":" + env.apiPort
		}
		if env.apiPrefix != "" {
			if strings.HasPrefix(env.apiPrefix, "/") {
				env.issuer += env.apiPrefix
			} else {
				env.issuer += "/" + env.apiPrefix
			}
		}
		env.issuer += http_helper.JoinUrl("global")
	}

	return env.issuer
}

func (env *Environment) ClockSkew() int {
	if env.clockSkew <= 0 {
		env.clockSkew = 1000
	}

	return env.clockSkew
}

func (env *Environment) TokenDuration() int {
	if env.tokenDuration <= 0 {
		env.tokenDuration = 60
	}

	return env.tokenDuration
}

func (env *Environment) RefreshTokenDuration() int {
	if env.refreshTokenDuration <= 0 {
		env.refreshTokenDuration = 131400
	}

	return env.refreshTokenDuration
}

func (env *Environment) VerifyEmailTokenDuration() int {
	if env.verifyEmailTokenDuration <= 0 {
		env.verifyEmailTokenDuration = 1440
	}

	return env.verifyEmailTokenDuration
}

func (env *Environment) RecoverTokenDuration() int {
	if env.recoverTokenDuration <= 0 {
		env.recoverTokenDuration = 60
	}

	return env.recoverTokenDuration
}

func (env *Environment) Scope() string {
	if env.scope == "" {
		env.scope = "authorization"
	}

	return env.scope
}

func (env *Environment) AuthorizationType() string {
	if env.authorizationType == "" {
		env.authorizationType = "hmac"
	}

	return env.scope
}

func (env *Environment) ControllerPrefix() string {
	if env.controllerPrefix == "" {
		env.controllerPrefix = "auth"
	}

	return env.controllerPrefix
}

func (env *Environment) ApiPort() string {
	return env.apiPort
}

func (env *Environment) ApiPrefix() string {
	return env.apiPrefix
}

func (env *Environment) PasswordValidationRequireCapital() bool {
	return env.passwordValidationRequireCapital
}

func (env *Environment) PasswordValidationRequireSpecial() bool {
	return env.passwordValidationRequireSpecial
}

func (env *Environment) PasswordValidationRequireNumber() bool {
	return env.passwordValidationRequireNumber
}

func (env *Environment) PasswordValidationMinSize() int {
	if env.passwordValidationMinSize == 0 {
		env.passwordValidationMinSize = 8
	}

	return env.passwordValidationMinSize
}

func (env *Environment) PasswordValidationAllowSpaces() bool {
	return env.passwordValidationAllowSpaces
}

func (env *Environment) PasswordValidationAllowedSpecials() string {
	if env.passwordValidationAllowedSpecials == "" {
		env.passwordValidationAllowedSpecials = "@$!%*#?&"
	}

	return env.passwordValidationAllowedSpecials
}

func (env *Environment) VerifyEmailProcessor() string {
	if env.verifyEmailProcessor == "" {
		env.verifyEmailProcessor = "otp"
	}

	switch env.verifyEmailProcessor {
	case "otp":
		return "otp"
	case "jwt":
		return "jwt"
	default:
		return "otp"
	}
}

func (env *Environment) OtpDefaultDuration() int {
	if env.otpDefaultDuration == 0 {
		env.otpDefaultDuration = 300
	}

	return env.otpDefaultDuration
}

func (env *Environment) OtpSecret() string {
	return env.otpSecret
}
