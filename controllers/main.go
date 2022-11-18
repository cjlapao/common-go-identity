package controllers

import (
	"net/http"

	"github.com/cjlapao/common-go-identity/database"
	"github.com/cjlapao/common-go-identity/interfaces"
	"github.com/cjlapao/common-go-identity/middleware"
	"github.com/cjlapao/common-go-restapi/controllers"
	"github.com/cjlapao/common-go/execution_context"
	"github.com/cjlapao/common-go/log"
	"github.com/gorilla/mux"
)

// AuthorizationControllers
type AuthorizationControllers struct {
	Logger  *log.Logger
	Context *execution_context.Context
}

func NewDefaultAuthorizationControllers() *AuthorizationControllers {
	ctx := execution_context.Get()
	context := database.NewMemoryUserAdapter()
	ctx.UserDatabaseAdapter = context
	controllers := AuthorizationControllers{
		Logger:  log.Get(),
		Context: ctx,
	}

	return &controllers
}

func NewAuthorizationControllers(context interfaces.UserContextAdapter) *AuthorizationControllers {
	ctx := execution_context.Get()
	ctx.UserDatabaseAdapter = context
	controllers := AuthorizationControllers{
		Logger:  log.Get(),
		Context: ctx,
	}

	return &controllers
}

func (l *HttpListener) AddAuthorizedController(c controllers.Controller, path string, methods ...string) {
	l.Controllers = append(l.Controllers, c)
	var subRouter *mux.Router
	if len(methods) > 0 {
		subRouter = l.Router.Methods(methods...).Subrouter()
	} else {
		subRouter = l.Router.Methods("GET").Subrouter()
	}
	adapters := make([]controllers.Adapter, 0)
	adapters = append(adapters, l.DefaultAdapters...)
	adapters = append(adapters, middleware.TokenAuthorizationMiddlewareAdapter([]string{}, []string{}))

	if l.Options.ApiPrefix != "" {
		path = joinUrl(l.Options.ApiPrefix, path)
	}

	subRouter.HandleFunc(path,
		controllers.Adapt(
			http.HandlerFunc(c),
			adapters...).ServeHTTP)
}

func (l *HttpListener) WithDefaultAuthentication() *HttpListener {
	context := database.NewMemoryUserAdapter()
	return l.WithAuthentication("", context)
}

func (l *HttpListener) WithAuthentication(prefix string, context interfaces.UserContextAdapter) *HttpListener {
	ctx := execution_context.Get()
	if ctx.Authorization != nil {
		defaultAuthControllers := authControllers.NewAuthorizationControllers(context)

		l.AddController(defaultAuthControllers.Token(), joinUrl(prefix, "token"), "POST")
		l.AddController(defaultAuthControllers.Token(), joinUrl(prefix, "token"), "POST")
		l.AddController(defaultAuthControllers.Introspection(), joinUrl(prefix, "token/introspect"), "POST")
		l.AddController(defaultAuthControllers.Introspection(), joinUrl(prefix, "{tenantId}/token/introspect"), "POST")
		l.AddAuthorizedControllerWithRoles(defaultAuthControllers.Register(), joinUrl(prefix, "register"), []string{"_su,_admin"}, "POST")
		l.AddAuthorizedControllerWithRoles(defaultAuthControllers.Register(), joinUrl(prefix, "{tenantId}/register"), []string{"_su,_admin"}, "POST")
		l.AddAuthorizedControllerWithRoles(defaultAuthControllers.Revoke(), joinUrl(prefix, "revoke"), []string{"_su,_admin"}, "POST")
		l.AddAuthorizedControllerWithRoles(defaultAuthControllers.Revoke(), joinUrl(prefix, "{tenantId}/revoke"), []string{"_su,_admin"}, "POST")

		l.AddController(defaultAuthControllers.Configuration(), joinUrl(prefix, ".well-known/openid-configuration"), "GET")
		l.AddController(defaultAuthControllers.Configuration(), joinUrl(prefix, "{tenantId}/.well-known/openid-configuration"), "GET")
		l.AddController(defaultAuthControllers.Jwks(), joinUrl(prefix, ".well-known/openid-configuration/jwks"), "GET")
		l.AddController(defaultAuthControllers.Jwks(), joinUrl(prefix, "{tenantId}/.well-known/openid-configuration/jwks"), "GET")
		l.DefaultAdapters = append([]controllers.Adapter{middleware.EndAuthorizationMiddlewareAdapter()}, l.DefaultAdapters...)
		l.Options.EnableAuthentication = true
	} else {
		l.Logger.Error("No authorization context found, ignoring")
	}
	return l
}

func (l *HttpListener) AddAuthorizedControllerWithRoles(c controllers.Controller, path string, roles []string, methods ...string) {
	l.AddAuthorizedControllerWithRolesAndClaims(c, path, roles, []string{}, methods...)
}

func (l *HttpListener) AddAuthorizedControllerWithClaims(c controllers.Controller, path string, claims []string, methods ...string) {
	l.AddAuthorizedControllerWithRolesAndClaims(c, path, []string{}, claims, methods...)
}

func (l *HttpListener) AddAuthorizedControllerWithRolesAndClaims(c controllers.Controller, path string, roles []string, claims []string, methods ...string) {
	l.Controllers = append(l.Controllers, c)
	var subRouter *mux.Router
	if len(methods) > 0 {
		subRouter = l.Router.Methods(methods...).Subrouter()
	} else {
		subRouter = l.Router.Methods("GET").Subrouter()
	}
	adapters := make([]controllers.Adapter, 0)
	adapters = append(adapters, l.DefaultAdapters...)
	adapters = append(adapters, middleware.TokenAuthorizationMiddlewareAdapter(roles, claims))

	if l.Options.ApiPrefix != "" {
		path = joinUrl(l.Options.ApiPrefix, path)
	}

	subRouter.HandleFunc(path,
		controllers.Adapt(
			http.HandlerFunc(c),
			adapters...).ServeHTTP)
}
