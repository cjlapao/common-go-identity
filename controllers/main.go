package controllers

import (
	"github.com/cjlapao/common-go-identity/authorization_context"
	"github.com/cjlapao/common-go-identity/database/memory"
	"github.com/cjlapao/common-go-identity/interfaces"
	log "github.com/cjlapao/common-go-logger"
	"github.com/cjlapao/common-go/execution_context"
)

// AuthorizationControllers
type AuthorizationControllers struct {
	Logger               *log.LoggerService
	Context              *execution_context.Context
	AuthorizationContext *authorization_context.AuthorizationContext
}

func NewDefaultAuthorizationControllers() *AuthorizationControllers {
	ctx := execution_context.Get()
	authCtx := authorization_context.New()
	context := memory.NewMemoryUserAdapter()

	authCtx.UserDatabaseAdapter = context
	ctx.UserDatabaseAdapter = context
	controllers := AuthorizationControllers{
		Logger:               log.Get(),
		Context:              ctx,
		AuthorizationContext: authCtx,
	}

	return &controllers
}

func NewAuthorizationControllers(context interfaces.UserContextAdapter) *AuthorizationControllers {
	ctx := execution_context.Get()
	ctx.UserDatabaseAdapter = context
	authorization_context.GetBaseContext()
	authorization_context.SetUserContext(context)
	controllers := AuthorizationControllers{
		Logger:  log.Get(),
		Context: ctx,
	}

	return &controllers
}
