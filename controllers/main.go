package controllers

import (
	"github.com/cjlapao/common-go-identity/database/memory"
	"github.com/cjlapao/common-go-identity/interfaces"
	log "github.com/cjlapao/common-go-logger"
	"github.com/cjlapao/common-go/execution_context"
)

// AuthorizationControllers
type AuthorizationControllers struct {
	Logger  *log.LoggerService
	Context *execution_context.Context
}

func NewDefaultAuthorizationControllers() *AuthorizationControllers {
	ctx := execution_context.Get()
	context := memory.NewMemoryUserAdapter()
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
