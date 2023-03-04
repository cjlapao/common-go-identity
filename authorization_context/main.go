package authorization_context

import (
	"errors"
	"net/http"
	"strings"

	"github.com/cjlapao/common-go-identity-oauth2/oauth2context"
	"github.com/cjlapao/common-go-identity/environment"
	"github.com/cjlapao/common-go-identity/interfaces"
	"github.com/cjlapao/common-go-identity/jwt_keyvault"
	"github.com/cjlapao/common-go-identity/models"
	log "github.com/cjlapao/common-go-logger"
	"github.com/cjlapao/common-go/service_provider"
)

var logger = log.Get()
var ErrNoPrivateKey = errors.New("no private key found")

type AuthorizationContext struct {
	User                 *UserContext
	OauthContext         *oauth2context.Oauth2Context
	TenantId             string
	Issuer               string
	Scope                string
	Audiences            []string
	BaseUrl              string
	Options              *AuthorizationOptions
	ValidationOptions    *AuthorizationValidationOptions
	KeyVault             *jwt_keyvault.JwtKeyVaultService
	UserDatabaseAdapter  interfaces.UserContextAdapter
	NotificationCallback func(notification models.OAuthNotification) error
}

var currentAuthorizationCtx *AuthorizationContext

func NewFromUser(user *UserContext) *AuthorizationContext {
	// Creating the new context using the default values if it does not exist
	if currentAuthorizationCtx == nil {
		context := AuthorizationContext{}
		context.WithDefaultOptions()
		currentAuthorizationCtx = &context
	}

	// Resetting the current context for this user leaving everything else
	currentAuthorizationCtx.Audiences = make([]string, 0)
	if currentAuthorizationCtx.ValidationOptions == nil {
		currentAuthorizationCtx.ValidationOptions = &AuthorizationValidationOptions{
			Audiences:     false,
			ExpiryDate:    true,
			Subject:       true,
			Issuer:        true,
			VerifiedEmail: false,
			NotBefore:     false,
			Tenant:        false,
		}
	}
	if currentAuthorizationCtx.KeyVault == nil {
		currentAuthorizationCtx.KeyVault = jwt_keyvault.Get()
	}

	return currentAuthorizationCtx
}

func New() *AuthorizationContext {
	user := NewUserContext()

	return NewFromUser(user)
}

func (a *AuthorizationContext) WithOptions(options AuthorizationOptions) *AuthorizationContext {
	a.Options = &options
	return a
}

func (a *AuthorizationContext) WithDefaultOptions() *AuthorizationContext {
	env := environment.Get()

	// Setting the default startup issuer to the localhost if it was not set
	if a.Issuer == "" {
		a.Issuer = env.Issuer()
	}

	// Setting the scope if it has not been set before
	if a.Scope == "" {
		a.Scope = env.Scope()
	}

	// Setting the default durations into the Options object
	a.Options = &AuthorizationOptions{
		ControllerPrefix:         env.ControllerPrefix(),
		TokenDuration:            env.TokenDuration(),
		RefreshTokenDuration:     env.RefreshTokenDuration(),
		VerifyEmailTokenDuration: env.VerifyEmailTokenDuration(),
		RecoverTokenDuration:     env.RecoverTokenDuration(),
		PasswordRules: PasswordRules{
			RequiresCapital: env.PasswordValidationRequireCapital(),
			RequiresSpecial: env.PasswordValidationRequireSpecial(),
			RequiresNumber:  env.PasswordValidationRequireNumber(),
			AllowsSpaces:    env.PasswordValidationAllowSpaces(),
			MinimumSize:     env.PasswordValidationMinSize(),
			AllowedSpecials: env.PasswordValidationAllowedSpecials(),
		},
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
	// if currentAuthorizationCtx == nil {
	// 	return New()
	// }

	return currentAuthorizationCtx
}

func WithDefaultAuthorization() *AuthorizationContext {
	return New()
}

func WithAuthorization(options AuthorizationOptions) *AuthorizationContext {
	return New().WithOptions(options)
}
