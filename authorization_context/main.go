package authorization_context

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/cjlapao/common-go-identity-oauth2/oauth2context"
	"github.com/cjlapao/common-go-identity/api_key_manager"
	"github.com/cjlapao/common-go-identity/environment"
	"github.com/cjlapao/common-go-identity/interfaces"
	"github.com/cjlapao/common-go-identity/jwt_keyvault"
	"github.com/cjlapao/common-go-identity/models"
	log "github.com/cjlapao/common-go-logger"
	"github.com/cjlapao/common-go/helper/http_helper"
	"github.com/cjlapao/common-go/service_provider"
	"github.com/pascaldekloe/jwt"
)

var logger = log.Get()
var ErrNoPrivateKey = errors.New("no private key found")

type AuthorizationContext struct {
	OauthContext         *oauth2context.Oauth2Context
	RequestId            string
	TenantId             string
	Issuer               string
	Scope                string
	Audiences            []string
	BaseUrl              string
	Options              *AuthorizationOptions
	ValidationOptions    *AuthorizationValidationOptions
	KeyVault             *jwt_keyvault.JwtKeyVaultService
	ApiKeyManager        *api_key_manager.ApiKeyManager
	UserDatabaseAdapter  interfaces.UserContextAdapter
	NotificationCallback func(notification models.OAuthNotification) error
	IsAuthorized         bool
	IsMicroService       bool
	AuthorizationError   *models.OAuthErrorResponse
	AuthorizedBy         string
	User                 *UserContext
	users                []UserContext
}

var baseAuthorizationCtx *AuthorizationContext

func NewFromUser(user *UserContext) *AuthorizationContext {
	// Creating the new context using the default values if it does not exist
	if baseAuthorizationCtx == nil {
		context := AuthorizationContext{}
		context.WithDefaultOptions()
		baseAuthorizationCtx = &context
	}

	newContext := AuthorizationContext{
		OauthContext:         baseAuthorizationCtx.OauthContext,
		TenantId:             baseAuthorizationCtx.TenantId,
		Issuer:               baseAuthorizationCtx.Issuer,
		Scope:                baseAuthorizationCtx.Scope,
		Audiences:            make([]string, 0),
		BaseUrl:              baseAuthorizationCtx.BaseUrl,
		Options:              baseAuthorizationCtx.Options,
		ValidationOptions:    baseAuthorizationCtx.ValidationOptions,
		KeyVault:             baseAuthorizationCtx.KeyVault,
		UserDatabaseAdapter:  baseAuthorizationCtx.UserDatabaseAdapter,
		NotificationCallback: baseAuthorizationCtx.NotificationCallback,
	}

	// Resetting the current context for this user leaving everything else
	if newContext.ValidationOptions == nil {
		newContext.ValidationOptions = &AuthorizationValidationOptions{
			Audiences:     false,
			ExpiryDate:    true,
			Subject:       true,
			Issuer:        true,
			VerifiedEmail: false,
			NotBefore:     false,
			Tenant:        false,
		}
	}
	if newContext.KeyVault == nil {
		newContext.KeyVault = jwt_keyvault.Get()
	}

	return &newContext
}

func Clone() *AuthorizationContext {
	// Creating the new context using the default values if it does not exist
	if baseAuthorizationCtx == nil {
		context := AuthorizationContext{}
		context.WithDefaultOptions()
		baseAuthorizationCtx = &context
	}

	newContext := AuthorizationContext{
		OauthContext:         baseAuthorizationCtx.OauthContext,
		Issuer:               baseAuthorizationCtx.Issuer,
		Scope:                baseAuthorizationCtx.Scope,
		Audiences:            make([]string, 0),
		BaseUrl:              baseAuthorizationCtx.BaseUrl,
		Options:              baseAuthorizationCtx.Options,
		ValidationOptions:    baseAuthorizationCtx.ValidationOptions,
		KeyVault:             baseAuthorizationCtx.KeyVault,
		IsAuthorized:         false,
		RequestId:            "",
		TenantId:             "",
		AuthorizationError:   nil,
		AuthorizedBy:         "",
		User:                 nil,
		UserDatabaseAdapter:  baseAuthorizationCtx.UserDatabaseAdapter,
		NotificationCallback: baseAuthorizationCtx.NotificationCallback,
	}

	// Resetting the current context for this user leaving everything else
	if newContext.ValidationOptions == nil {
		newContext.ValidationOptions = &AuthorizationValidationOptions{
			Audiences:     false,
			ExpiryDate:    true,
			Subject:       true,
			Issuer:        true,
			VerifiedEmail: false,
			NotBefore:     false,
			Tenant:        false,
		}
	}

	if newContext.KeyVault == nil {
		newContext.KeyVault = jwt_keyvault.Get()
	}

	if newContext.ApiKeyManager == nil {
		newContext.ApiKeyManager = api_key_manager.GetApiKeyManager()
	}

	return &newContext
}

func New() *AuthorizationContext {
	user := NewUserContext()

	return NewFromUser(user)
}

func Init() *AuthorizationContext {
	if baseAuthorizationCtx == nil {
		context := AuthorizationContext{
			users: make([]UserContext, 0),
		}

		context.WithDefaultOptions()
		baseAuthorizationCtx = &context
	}
	return baseAuthorizationCtx
}

func GetBaseContext() *AuthorizationContext {
	if baseAuthorizationCtx == nil {
		return Init()
	}

	return baseAuthorizationCtx
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

	// Setting default validate options
	a.ValidationOptions = &AuthorizationValidationOptions{
		Audiences:     false,
		ExpiryDate:    true,
		Subject:       true,
		Issuer:        true,
		VerifiedEmail: false,
		NotBefore:     false,
		Tenant:        false,
	}

	// Setting the default durations into the Options object
	a.Options = &AuthorizationOptions{
		ControllerPrefix:           env.ControllerPrefix(),
		TokenDuration:              env.TokenDuration(),
		RefreshTokenDuration:       env.RefreshTokenDuration(),
		VerifyEmailTokenDuration:   env.VerifyEmailTokenDuration(),
		RecoverTokenDuration:       env.RecoverTokenDuration(),
		OtpSecret:                  env.OtpSecret(),
		OptDuration:                env.OtpDefaultDuration(),
		EmailVerificationProcessor: env.VerifyEmailProcessor(),
		PasswordRules: PasswordRules{
			RequiresCapital: env.PasswordValidationRequireCapital(),
			RequiresSpecial: env.PasswordValidationRequireSpecial(),
			RequiresNumber:  env.PasswordValidationRequireNumber(),
			AllowsSpaces:    env.PasswordValidationAllowSpaces(),
			MinimumSize:     env.PasswordValidationMinSize(),
			AllowedSpecials: env.PasswordValidationAllowedSpecials(),
		},
	}

	if a.KeyVault == nil {
		a.KeyVault = jwt_keyvault.Get()
	}

	if a.ApiKeyManager == nil {
		a.ApiKeyManager = api_key_manager.GetApiKeyManager()
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

// TODO: This is a temporary solution until we have a better way to handle this
func (a *AuthorizationContext) WithApiKey(key api_key_manager.ApiKey) *AuthorizationContext {
	a.ApiKeyManager.Add(&key)

	return a
}

func (a *AuthorizationContext) GetKeyVault() *jwt_keyvault.JwtKeyVaultService {
	return a.KeyVault
}

func (a *AuthorizationContext) SetRequestIssuer(r *http.Request, tenantId string) string {
	if a.BaseUrl == "" {
		a.BaseUrl = service_provider.Get().GetBaseUrl(r)
	}

	if a.Issuer == "" {
		a.Issuer = a.GetBaseUrl(r) + "/auth/" + tenantId
		a.Issuer = strings.Trim(a.Issuer, "/")
	}

	a.TenantId = tenantId
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

func SetUserContext(context interfaces.UserContextAdapter) *AuthorizationContext {
	baseCtx := GetBaseContext()
	baseCtx.UserDatabaseAdapter = context
	return baseCtx
}

func WithDefaultAuthorization() *AuthorizationContext {
	return Init()
}

func WithAuthorization(options AuthorizationOptions) *AuthorizationContext {
	return Init().WithOptions(options)
}

func GetUserIdFromRequest(r *http.Request) string {
	jwt_token, valid := http_helper.GetAuthorizationToken(r.Header)
	if !valid {
		return ""
	}
	rawToken, err := jwt.ParseWithoutCheck([]byte(jwt_token))
	if err != nil {
		return ""
	}
	rawJsonToken, _ := rawToken.Raw.MarshalJSON()
	var userToken models.UserToken
	if err := json.Unmarshal(rawJsonToken, &userToken); err != nil {
		return ""
	}

	return userToken.UserID
}

func GetUserSubjectFromRequest(r *http.Request) string {
	jwt_token, valid := http_helper.GetAuthorizationToken(r.Header)
	if !valid {
		return ""
	}
	rawToken, err := jwt.ParseWithoutCheck([]byte(jwt_token))
	if err != nil {
		return ""
	}
	rawJsonToken, _ := rawToken.Raw.MarshalJSON()
	var userToken models.UserToken
	if err := json.Unmarshal(rawJsonToken, &userToken); err != nil {
		return ""
	}

	return userToken.Email
}
