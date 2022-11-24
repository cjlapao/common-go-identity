package controllers

import (
	"net/http"

	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go-identity/user_manager"
	"github.com/cjlapao/common-go/execution_context"
	"github.com/cjlapao/common-go/helper/http_helper"
	"github.com/cjlapao/common-go/log"
	"github.com/gorilla/mux"
)

type BaseControllerContext struct {
	Logger           *log.Logger
	Request          *http.Request
	Response         *http.Response
	ExecutionContext *execution_context.Context
	TenantID         string
	UserID           string
	User             *models.User
	UserManager      *user_manager.UserManager
}

func NewBaseContext(r *http.Request) *BaseControllerContext {
	context := BaseControllerContext{
		ExecutionContext: execution_context.Get(),
		Request:          r,
		UserManager:      user_manager.Get(),
		Logger:           log.Get(),
	}

	vars := mux.Vars(r)
	context.TenantID = vars["tenantId"]
	// if no tenant is set we will assume it is the global tenant
	if context.TenantID == "" {
		context.TenantID = "global"
	}

	context.UserID = vars["userID"]

	// Setting the tenant in the context
	context.ExecutionContext.Authorization.SetRequestIssuer(r, context.TenantID)

	return &context
}

func (ctx *BaseControllerContext) MapRequestBody(dest interface{}) error {
	return http_helper.MapRequestBody(ctx.Request, dest)
}
