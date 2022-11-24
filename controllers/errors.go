package controllers

import (
	"github.com/cjlapao/common-go-identity/models"
)

var (
	// ErrEmptyUserID User ID is an empty string
	ErrEmptyUserID = models.NewOAuthErrorResponse(models.OAuthInvalidClientError, "User ID is nil or empty.")
	// ErrInvalidUser User did not pass the object validation
	ErrInvalidUser = models.NewOAuthErrorResponse(models.OAuthInvalidClientError, "User did not pass validation.")
	// ErrInvalidUser User did not pass the object validation
	ErrInvalidPasswordValidation = models.NewOAuthErrorResponse(models.OAuthInvalidClientError, "User did not pass password validation.")
	// ErrEmailNotVerified User did not pass the object validation
	ErrEmailNotVerified = models.NewOAuthErrorResponse(models.OAuthInvalidClientError, "User did not validate email address.")

	// ErrUserNotFound User was not found in the database context
	ErrUserNotFound = models.NewOAuthErrorResponse(models.OAuthInvalidClientError, "User not found.")
	// ErrUserNotRemoved There was an error removing the user from the database context
	ErrUserNotRemoved = models.NewOAuthErrorResponse(models.OAuthInvalidClientError, "DB error, user not removed.")
	// ErrUserAlreadyExists The user already exists in the database
	ErrUserAlreadyExists = models.NewOAuthErrorResponse(models.OAuthInvalidClientError, "User already exists.")

	// ErrEmptyToken No User database context found error response
	ErrEmptyToken = models.NewOAuthErrorResponse(models.OAuthInvalidRequestError, "JWT token is nil or empty.")
	// ErrTokenNotFound No User database context found error response
	ErrTokenNotFound = models.NewOAuthErrorResponse(models.OAuthInvalidRequestError, "JWT token was not found, please check your authorization header or request body.")
	// ErrInvalidToken No User database context found error response
	ErrInvalidToken = models.NewOAuthErrorResponse(models.OAuthInvalidRequestError, "JWT token did not pass validation.")

	// ErrGrantNotSupported No User database context found error response
	ErrGrantNotSupported = models.NewOAuthErrorResponse(models.OAuthUnsupportedGrantType, "Grant is not currently supported by the system.")

	// ErrGrantNotSupported No User database context found error response
	ErrException = models.NewOAuthErrorResponse(models.OAuthUnsupportedGrantType, "Something went wrong on our side, please try again later")
)
