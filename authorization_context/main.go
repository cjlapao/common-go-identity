package authorization_context

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/cjlapao/common-go-identity/jwt_keyvault"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go/configuration"
	"github.com/cjlapao/common-go/helper/http_helper"
	"github.com/cjlapao/common-go/helper/strhelper"
	"github.com/cjlapao/common-go/log"
	"github.com/cjlapao/common-go/service_provider"
)

var logger = log.Get()
var ErrNoPrivateKey = errors.New("no private key found")

type AuthorizationContext struct {
	User                 *UserContext
	TenantId             string
	Issuer               string
	Scope                string
	Audiences            []string
	BaseUrl              string
	Options              AuthorizationOptions
	ValidationOptions    AuthorizationValidationOptions
	KeyVault             *jwt_keyvault.JwtKeyVaultService
	NotificationCallback func(notification models.OAuthNotification) error
}

var currentAuthorizationContext *AuthorizationContext

func NewFromUser(user *UserContext) *AuthorizationContext {
	newContext := AuthorizationContext{
		User: user,
		ValidationOptions: AuthorizationValidationOptions{
			Audiences:     false,
			ExpiryDate:    true,
			Subject:       true,
			Issuer:        true,
			VerifiedEmail: false,
			NotBefore:     false,
			Tenant:        false,
		},
		Audiences: make([]string, 0),
	}

	newContext.KeyVault = jwt_keyvault.Get()
	newContext.WithDefaultOptions()

	currentAuthorizationContext = &newContext
	return currentAuthorizationContext
}

func New() *AuthorizationContext {
	user := NewUserContext()

	return NewFromUser(user)
}

func (a *AuthorizationContext) WithOptions(options AuthorizationOptions) *AuthorizationContext {
	a.Options = options
	return a
}

func (a *AuthorizationContext) WithDefaultOptions() *AuthorizationContext {
	config := configuration.Get()
	issuer := config.GetString("JWT_ISSUER")
	tokenDuration := config.GetInt("JWT_TOKEN_DURATION")
	refreshTokenDuration := config.GetInt("JWT_REFRESH_TOKEN_DURATION")
	verifyEmailTokenDuration := config.GetInt("JWT_VERIFY_EMAIL_TOKEN_DURATION")
	recoverTokenDuration := config.GetInt("JWT_RECOVER_TOKEN_DURATION")
	scope := config.GetString("JWT_SCOPE")
	authorizationType := config.GetString("JWT_AUTH_TYPE")

	// Setting the default startup issuer to the localhost if it was not set
	// TODO: Improve the issuer calculations with overrides
	if issuer == "" {
		apiPort := config.GetString("HTTP_PORT")
		apiPrefix := config.GetString("API_PREFIX")
		issuer = "http://localhost"
		if apiPort != "" {
			issuer += ":" + apiPort
		}
		if apiPrefix != "" {
			if strings.HasPrefix(apiPrefix, "/") {
				issuer += apiPrefix
			} else {
				issuer += "/" + apiPrefix
			}
		}
		issuer += http_helper.JoinUrl("global")
	}

	if a.Issuer == "" {
		a.Issuer = issuer
	}

	// Setting the default duration of the token to an hour
	if tokenDuration <= 0 {
		tokenDuration = 60
	}

	// Setting the default duration of the refresh token to 3 months
	if refreshTokenDuration <= 0 {
		refreshTokenDuration = 131400
	}

	// Setting the default duration of the verify email token to 1 day
	if verifyEmailTokenDuration <= 0 {
		verifyEmailTokenDuration = 1440
	}

	if recoverTokenDuration <= 0 {
		recoverTokenDuration = 60
	}

	// Setting the default scope of the tokens
	if scope == "" {
		scope = "authorization"
	}

	// Setting the scope if it has not been set before
	if a.Scope == "" {
		a.Scope = scope
	}

	// Setting the default authorization signature type to HMAC
	if authorizationType == "" {
		authorizationType = "hmac"
	}

	// Setting the default durations into the Options object
	a.Options = AuthorizationOptions{
		TokenDuration:            tokenDuration,
		RefreshTokenDuration:     refreshTokenDuration,
		VerifyEmailTokenDuration: verifyEmailTokenDuration,
		RecoverTokenDuration:     recoverTokenDuration,
		PasswordRules: PasswordRules{
			RequiresCapital: true,
			RequiresSpecial: true,
			RequiresNumber:  true,
			AllowsSpaces:    true,
			MinimumSize:     8,
			AllowedSpecials: "@$!%*#?&",
		},
	}

	// password default config
	password_require_capital := config.GetString("authorization__password__require_capital")
	if password_require_capital != "" {
		a.Options.PasswordRules.RequiresCapital = strhelper.ToBoolean(password_require_capital)
	}

	password_require_special := config.GetString("authorization__password__require_special")
	if password_require_special != "" {
		a.Options.PasswordRules.RequiresSpecial = strhelper.ToBoolean(password_require_special)
	}

	password_require_number := config.GetString("authorization__password__require_number")
	if password_require_number != "" {
		a.Options.PasswordRules.RequiresNumber = strhelper.ToBoolean(password_require_number)
	}

	password_minimum_size := config.GetString("authorization__password__minimum_size")
	if password_minimum_size != "" {
		size, err := strconv.Atoi(password_minimum_size)
		if err == nil {
			a.Options.PasswordRules.MinimumSize = size
		}
	}

	password_allow_spaces := config.GetString("authorization__password__allow_spaces")
	if password_allow_spaces != "" {
		a.Options.PasswordRules.AllowsSpaces = strhelper.ToBoolean(password_allow_spaces)
	}

	password_allowed_specials := config.GetString("authorization__password__allowed_specials")
	if password_allowed_specials != "" {
		a.Options.PasswordRules.AllowedSpecials = password_allowed_specials
	}

	return a
}

func (a *AuthorizationContext) WithAudience(audience string) *AuthorizationContext {
	found := false
	for _, inAudience := range a.Audiences {
		if strings.EqualFold(inAudience, audience) {
			found = true
			break
		}
	}
	if !found {
		a.Audiences = append(a.Audiences, audience)
	}

	return a
}

func (a *AuthorizationContext) WithIssuer(issuer string) *AuthorizationContext {
	a.Issuer = issuer

	return a
}

func (a *AuthorizationContext) WithDuration(tokenDuration int) *AuthorizationContext {
	a.Options.TokenDuration = tokenDuration

	return a
}

func (a *AuthorizationContext) WithScope(scope string) *AuthorizationContext {
	a.Scope = scope

	return a
}

func (a *AuthorizationContext) WithPublicKey(key string) *AuthorizationContext {
	a.Options.KeyVaultEnabled = false
	logger.Info("Initializing Authorization layer with no signing capability.")
	a.Options.KeyVaultEnabled = false
	logger.Debug("Using public key %v", key)
	a.Options.PublicKey = key
	return a
}

func (a *AuthorizationContext) WithKeyVault() *AuthorizationContext {
	a.Options.KeyVaultEnabled = true
	a.Options.PublicKey = ""
	return a
}

func (a *AuthorizationContext) GetKeyVault() *jwt_keyvault.JwtKeyVaultService {
	return a.KeyVault
}

func (a *AuthorizationContext) SetRequestIssuer(r *http.Request, tenantId string) string {
	if a.BaseUrl == "" {
		a.BaseUrl = service_provider.Get().GetBaseUrl(r)
	}

	a.Issuer = a.GetBaseUrl(r) + "/auth/" + tenantId
	a.Issuer = strings.Trim(a.Issuer, "/")
	return a.Issuer
}

func (a *AuthorizationContext) GetBaseUrl(r *http.Request) string {
	config := service_provider.Get().Configuration
	if a.BaseUrl == "" {
		return service_provider.Get().GetBaseUrl(r)
	}

	protocol := "http"
	if r.TLS != nil {
		protocol = "https"
	}

	issuer := strings.ReplaceAll(a.BaseUrl, "https", "")
	issuer = strings.ReplaceAll(issuer, "http", "")
	issuer = strings.ReplaceAll(issuer, "://", "")
	if strings.HasSuffix(issuer, "/") {
		issuer = strings.Trim(issuer, "/")
	}

	baseUrl := protocol + "://" + issuer
	apiPrefix := config.GetString("API_PREFIX")
	if apiPrefix != "" {
		if strings.HasPrefix(apiPrefix, "/") {
			baseUrl += apiPrefix
		} else {
			baseUrl += "/" + apiPrefix
		}
	}

	return baseUrl
}

func GetCurrent() *AuthorizationContext {
	if currentAuthorizationContext != nil {
		return currentAuthorizationContext
	}

	return nil
}
