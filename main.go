package identity

import (
	"net/http"

	execution_context "github.com/cjlapao/common-go-execution-context"
	"github.com/cjlapao/common-go-identity/controllers"
	"github.com/cjlapao/common-go-identity/database/memory"
	"github.com/cjlapao/common-go-identity/interfaces"
	"github.com/cjlapao/common-go-identity/middleware"
	log "github.com/cjlapao/common-go-logger"
	restapi "github.com/cjlapao/common-go-restapi"
	restapi_controller "github.com/cjlapao/common-go-restapi/controllers"
	"github.com/cjlapao/common-go/helper/http_helper"
	"github.com/gorilla/mux"
)

var logger = log.Get()
var httpListener *restapi.HttpListener

//TODO: Create API_KEY authorization
//TODO: Get jwt public key using openid configuration
//TODO: Cache the openid configuration for tokens based in the subject
//TODO: repurpose the JWT Keyvault as a generic key vault to keep secrets
//TODO: Make all errors variables for reusability purpose
//TODO: Move all log.error to log.exception for a cleaner implementation

func WithDefaultAuthentication(l *restapi.HttpListener) *restapi.HttpListener {
	httpListener = l
	context := memory.NewMemoryUserAdapter()
	return WithAuthentication(l, context)
}

func WithAuthentication(l *restapi.HttpListener, context interfaces.UserContextAdapter) *restapi.HttpListener {
	httpListener = l
	ctx := execution_context.Get()
	if ctx.Authorization != nil {
		defaultAuthControllers := controllers.NewAuthorizationControllers(context)

		l.AddController(defaultAuthControllers.Token(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "token"), "POST")
		l.AddController(defaultAuthControllers.Token(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", "token"), "POST")

		// Password Recovery
		l.AddController(defaultAuthControllers.RecoverPasswordRequest(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "users", "{userID}", "password", "recover", "request"), "POST")
		l.AddController(defaultAuthControllers.RecoverPasswordRequest(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", "users", "{userID}", "password", "recover", "request"), "POST")
		l.AddController(defaultAuthControllers.ValidateRecoverPasswordToken(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "users", "{userID}", "password", "recover", "validate"), "POST")
		l.AddController(defaultAuthControllers.ValidateRecoverPasswordToken(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", "users", "{userID}", "password", "recover", "validate"), "POST")
		l.AddController(defaultAuthControllers.RecoverPassword(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "users", "{userID}", "password", "recover"), "POST")
		l.AddController(defaultAuthControllers.RecoverPassword(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", "users", "{userID}", "password", "recover"), "POST")
		AddAuthorizedController(l, defaultAuthControllers.ChangePassword(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "users", "{userID}", "password", "change"), "POST")
		AddAuthorizedController(l, defaultAuthControllers.ChangePassword(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", "users", "{userID}", "password", "change"), "POST")

		// Email Verification
		l.AddController(defaultAuthControllers.EmailVerificationRequest(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "users", "{userID}", "email", "request"), "POST")
		l.AddController(defaultAuthControllers.EmailVerificationRequest(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", "users", "{userID}", "email", "request"), "POST")
		l.AddController(defaultAuthControllers.VerifyEmail(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "users", "{userID}", "email", "verify"), "POST")
		l.AddController(defaultAuthControllers.VerifyEmail(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", "users", "{userID}", "email", "verify"), "POST")

		l.AddController(defaultAuthControllers.Introspection(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "token", "introspect"), "POST")
		l.AddController(defaultAuthControllers.Introspection(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", "token", "introspect"), "POST")
		if l.Options.PublicRegistration {
			l.AddController(defaultAuthControllers.Register(true), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "register"), "POST")
			l.AddController(defaultAuthControllers.Register(true), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", "register"), "POST")
		} else {
			AddAuthorizedControllerWithRoles(l, defaultAuthControllers.Register(false), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "register"), []string{"_su,_admin"}, "POST")
			AddAuthorizedControllerWithRoles(l, defaultAuthControllers.Register(false), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", "register"), []string{"_su,_admin"}, "POST")
		}

		AddAuthorizedControllerWithRoles(l, defaultAuthControllers.Revoke(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "revoke"), []string{"_su,_admin"}, "POST")
		AddAuthorizedControllerWithRoles(l, defaultAuthControllers.Revoke(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", "revoke"), []string{"_su,_admin"}, "POST")

		l.AddController(defaultAuthControllers.Configuration(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, ".well-known", "openid-configuration"), "GET")
		l.AddController(defaultAuthControllers.Configuration(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", ".well-known", "openid-configuration"), "GET")
		l.AddController(defaultAuthControllers.Jwks(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, ".well-known", "openid-configuration", "jwks"), "GET")
		l.AddController(defaultAuthControllers.Jwks(), http_helper.JoinUrl(ctx.Authorization.Options.ControllerPrefix, "{tenantId}", ".well-known", "openid-configuration", "jwks"), "GET")
		l.DefaultAdapters = append([]restapi_controller.Adapter{middleware.EndAuthorizationMiddlewareAdapter()}, l.DefaultAdapters...)
		l.Options.EnableAuthentication = true
	} else {
		l.Logger.Error("No authorization context found, ignoring")
	}
	return l
}

func AddAuthorizedController(l *restapi.HttpListener, c restapi_controller.Controller, path string, methods ...string) {
	l.Controllers = append(l.Controllers, c)
	var subRouter *mux.Router
	if len(methods) > 0 {
		subRouter = l.Router.Methods(methods...).Subrouter()
	} else {
		subRouter = l.Router.Methods("GET").Subrouter()
	}
	adapters := make([]restapi_controller.Adapter, 0)
	adapters = append(adapters, l.DefaultAdapters...)
	adapters = append(adapters, middleware.TokenAuthorizationMiddlewareAdapter([]string{}, []string{}))

	if l.Options.ApiPrefix != "" {
		path = http_helper.JoinUrl(l.Options.ApiPrefix, path)
	}

	subRouter.HandleFunc(path,
		restapi_controller.Adapt(
			http.HandlerFunc(c),
			adapters...).ServeHTTP)
}

func AddAuthorizedControllerWithRoles(l *restapi.HttpListener, c restapi_controller.Controller, path string, roles []string, methods ...string) {
	AddAuthorizedControllerWithRolesAndClaims(l, c, path, roles, []string{}, methods...)
}

func AddAuthorizedControllerWithClaims(l *restapi.HttpListener, c restapi_controller.Controller, path string, claims []string, methods ...string) {
	AddAuthorizedControllerWithRolesAndClaims(l, c, path, []string{}, claims, methods...)
}

func AddAuthorizedControllerWithRolesAndClaims(l *restapi.HttpListener, c restapi_controller.Controller, path string, roles []string, claims []string, methods ...string) {
	l.Controllers = append(l.Controllers, c)
	var subRouter *mux.Router
	if len(methods) > 0 {
		subRouter = l.Router.Methods(methods...).Subrouter()
	} else {
		subRouter = l.Router.Methods("GET").Subrouter()
	}
	adapters := make([]restapi_controller.Adapter, 0)
	adapters = append(adapters, l.DefaultAdapters...)
	adapters = append(adapters, middleware.TokenAuthorizationMiddlewareAdapter(roles, claims))

	if l.Options.ApiPrefix != "" {
		path = http_helper.JoinUrl(l.Options.ApiPrefix, path)
	}

	subRouter.HandleFunc(path,
		restapi_controller.Adapt(
			http.HandlerFunc(c),
			adapters...).ServeHTTP)
}
