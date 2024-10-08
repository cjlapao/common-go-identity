// Package jwt provides the needed functions to generate tokens for users
package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	cryptorand "github.com/cjlapao/common-go-cryptorand"
	execution_context "github.com/cjlapao/common-go-execution-context"
	"github.com/cjlapao/common-go-identity/authorization_context"
	identity_constants "github.com/cjlapao/common-go-identity/constants"
	"github.com/cjlapao/common-go-identity/jwt_keyvault"
	"github.com/cjlapao/common-go-identity/models"
	"github.com/cjlapao/common-go/constants"
	"github.com/cjlapao/common-go/security/encryption"
	"github.com/pascaldekloe/jwt"
)

// GenerateDefaultUserToken generates a jwt user token with the default audiences in the context
// It returns a user token object and an error if it exists
func GenerateDefaultUserToken(user models.User) (*models.UserToken, error) {
	ctx := authorization_context.New()

	return GenerateUserTokenForAudiences("", user, ctx.Audiences...)
}

// GenerateUserToken
func GenerateUserToken(keyId string, user models.User) (*models.UserToken, error) {
	ctx := authorization_context.New()

	return GenerateUserTokenForAudiences(keyId, user, ctx.Audiences...)
}

func GenerateUserTokenForAudiences(keyId string, user models.User, audiences ...string) (*models.UserToken, error) {
	ctx := authorization_context.New()

	return GenerateUserTokenForKeyAndAudiences(keyId, user, ctx.Audiences...)
}

func GenerateUserTokenForKeyAndAudiences(keyId string, user models.User, audiences ...string) (*models.UserToken, error) {
	var userToken models.UserToken
	var userTokenClaims jwt.Claims
	ctx := execution_context.Get()
	authCtx := authorization_context.New()
	now := time.Now().Round(time.Second)
	nowSkew := now.Add((time.Minute * 2))
	nowNegativeSkew := now.Add((time.Minute * 2) * -1)
	validUntil := nowSkew.Add(time.Minute * time.Duration(authCtx.Options.TokenDuration))

	userTokenClaims.Subject = user.Email
	userTokenClaims.Issuer = authCtx.Issuer
	userTokenClaims.Issued = jwt.NewNumericTime(nowSkew)
	if authCtx.ValidationOptions.NotBefore {
		userTokenClaims.NotBefore = jwt.NewNumericTime(nowNegativeSkew)
	}

	id, idErr := cryptorand.GetRandomString(constants.ID_SIZE)
	if idErr != nil {
		return nil, idErr
	}

	userTokenClaims.Expires = jwt.NewNumericTime(validUntil)
	userTokenClaims.ID = id

	// Adding Custom Claims to the token
	userClaims := make(map[string]interface{})
	userClaims["scope"] = authCtx.Scope
	userClaims["uid"] = user.ID
	userClaims["name"] = user.DisplayName
	userClaims["given_name"] = user.FirstName
	userClaims["family_name"] = user.LastName

	// Adding the email verification to the token if the validation is on
	if authCtx.ValidationOptions.VerifiedEmail {
		userClaims["email_verified"] = user.EmailVerified
	}

	// Adding the correlation nonce to the token if it exists
	if ctx.CorrelationId != "" {
		userClaims["nonce"] = ctx.CorrelationId
	}

	// Adding the tenantId if it exists
	if authCtx.TenantId != "" {
		userClaims["tid"] = authCtx.TenantId
	}

	userTokenClaims.KeyID = authCtx.Options.KeyId

	// Reading all of the roles
	roles := make([]string, 0)
	for _, role := range user.Roles {
		roles = append(roles, role.ID)
	}
	userClaims["roles"] = roles

	// Reading all the audiences
	if len(audiences) > 0 {
		userTokenClaims.Audiences = audiences
	}

	userTokenClaims.Set = userClaims

	var token string
	var err error

	token, err = signToken(keyId, userTokenClaims)
	if err != nil {
		logger.Error("There was an error generating a jwt token for user %v with key id %v", user.Username, keyId)
		return nil, err
	}

	userToken = models.UserToken{
		Token:     token,
		ExpiresAt: validUntil,
		NotBefore: nowNegativeSkew,
		Audiences: audiences,
		Issuer:    userTokenClaims.Issuer,
		UsedKeyID: keyId,
	}

	refreshToken, err := GenerateRefreshToken(keyId, user)
	if err == nil {
		userToken.RefreshToken = refreshToken
	}

	return &userToken, nil
}

// GenerateRefreshToken generates a refresh token for the user with a
func GenerateRefreshToken(keyId string, user models.User) (string, error) {
	var refreshTokenClaims jwt.Claims
	authCtx := authorization_context.New()
	now := time.Now().Round(time.Second)
	nowSkew := now.Add((time.Hour * 2))
	nowNegativeSkew := now.Add((time.Minute * 2) * -1)
	validUntil := nowSkew.Add(time.Minute * time.Duration(authCtx.Options.RefreshTokenDuration))

	refreshTokenClaims.Subject = user.Email
	refreshTokenClaims.Issuer = authCtx.Issuer
	refreshTokenClaims.Issued = jwt.NewNumericTime(nowSkew)
	if authCtx.ValidationOptions.NotBefore {
		refreshTokenClaims.NotBefore = jwt.NewNumericTime(nowNegativeSkew)
	}
	id, idErr := cryptorand.GetRandomString(constants.ID_SIZE)
	if idErr != nil {
		return "", idErr
	}
	refreshTokenClaims.Expires = jwt.NewNumericTime(validUntil)
	refreshTokenClaims.ID = id

	// Custom Claims
	customClaims := make(map[string]interface{})
	customClaims["scope"] = identity_constants.RefreshTokenScope
	customClaims["name"] = user.DisplayName
	customClaims["given_name"] = user.FirstName
	customClaims["family_name"] = user.LastName
	customClaims["uid"] = user.ID
	if authCtx.TenantId != "" {
		customClaims["tid"] = authCtx.TenantId
	}
	refreshTokenClaims.KeyID = authCtx.Options.KeyId
	refreshTokenClaims.Set = customClaims

	refreshToken, err := signToken(keyId, refreshTokenClaims)
	if err != nil {
		logger.Error("There was an error signing the refresh token for user %v with key id %v", user.Username, keyId)
		return "", err
	}

	return refreshToken, nil
}

func GenerateVerifyEmailToken(keyId string, user models.User) string {
	var emailVerificationTokenClaims jwt.Claims
	authCtx := authorization_context.New()
	now := time.Now().Round(time.Second)
	nowSkew := now.Add((time.Hour * 2))
	nowNegativeSkew := now.Add((time.Minute * 2) * -1)
	validUntil := nowSkew.Add(time.Minute * time.Duration(authCtx.Options.VerifyEmailTokenDuration))

	emailVerificationTokenClaims.Subject = user.Email
	emailVerificationTokenClaims.Issuer = authCtx.Issuer
	emailVerificationTokenClaims.Issued = jwt.NewNumericTime(nowSkew)
	if authCtx.ValidationOptions.NotBefore {
		emailVerificationTokenClaims.NotBefore = jwt.NewNumericTime(nowNegativeSkew)
	}

	id, idErr := cryptorand.GetRandomString(constants.ID_SIZE)
	if idErr != nil {
		return ""
	}

	emailVerificationTokenClaims.Expires = jwt.NewNumericTime(validUntil)
	emailVerificationTokenClaims.ID = id

	// Custom Claims
	customClaims := make(map[string]interface{})
	customClaims["scope"] = identity_constants.EmailVerificationScope
	customClaims["name"] = user.DisplayName
	customClaims["given_name"] = user.FirstName
	customClaims["family_name"] = user.LastName
	customClaims["uid"] = user.ID
	if authCtx.TenantId != "" {
		customClaims["tid"] = authCtx.TenantId
	}
	emailVerificationTokenClaims.KeyID = authCtx.Options.KeyId
	emailVerificationTokenClaims.Set = customClaims
	emailVerificationToken, err := signToken(keyId, emailVerificationTokenClaims)
	if err != nil {
		logger.Error("There was an error signing the email verification token for user %v with key id %v", user.Username, keyId)
		return ""
	}

	return emailVerificationToken
}

func GenerateRecoverToken(keyId string, user models.User) string {
	var recoverTokenClaims jwt.Claims
	authCtx := authorization_context.New()
	now := time.Now().Round(time.Second)
	nowSkew := now.Add((time.Hour * 2))
	nowNegativeSkew := now.Add((time.Minute * 2) * -1)
	validUntil := nowSkew.Add(time.Minute * time.Duration(authCtx.Options.RecoverTokenDuration))

	recoverTokenClaims.Subject = user.ID
	recoverTokenClaims.Issuer = authCtx.Issuer
	recoverTokenClaims.Issued = jwt.NewNumericTime(nowSkew)
	if authCtx.ValidationOptions.NotBefore {
		recoverTokenClaims.NotBefore = jwt.NewNumericTime(nowNegativeSkew)
	}
	id, idErr := cryptorand.GetRandomString(constants.ID_SIZE)
	if idErr != nil {
		return ""
	}
	recoverTokenClaims.Expires = jwt.NewNumericTime(validUntil)
	recoverTokenClaims.ID = id

	// Custom Claims
	customClaims := make(map[string]interface{})
	customClaims["scope"] = identity_constants.PasswordRecoveryScope
	customClaims["name"] = user.DisplayName
	customClaims["given_name"] = user.FirstName
	customClaims["family_name"] = user.LastName
	customClaims["uid"] = user.ID
	if authCtx.TenantId != "" {
		customClaims["tid"] = authCtx.TenantId
	}
	recoverTokenClaims.KeyID = authCtx.Options.KeyId
	recoverTokenClaims.Set = customClaims
	recoveryToken, err := signToken(keyId, recoverTokenClaims)
	if err != nil {
		logger.Error("There was an error signing the recovery token for user %v with key id %v", user.Username, keyId)
		return ""
	}

	return recoveryToken
}

func ValidateUserToken(token string, authorizationContext *authorization_context.AuthorizationContext) (*models.UserToken, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}

	var tokenBytes []byte
	var verifiedToken *jwt.Claims
	tokenBytes = []byte(token)
	var err error
	var signKey *jwt_keyvault.JwtKeyVaultItem

	rawToken, err := jwt.ParseWithoutCheck(tokenBytes)
	if err != nil {
		return nil, err
	}

	if authorizationContext.Options.KeyVaultEnabled {
		// Verifying signature using the key that was sign with
		signKey = authorizationContext.KeyVault.GetKey(rawToken.KeyID)
		switch kt := signKey.PrivateKey.(type) {
		case *ecdsa.PrivateKey:
			key := kt.PublicKey
			verifiedToken, err = jwt.ECDSACheck(tokenBytes, &key)
			if err != nil {
				return nil, err
			}
		case string:
			verifiedToken, err = jwt.HMACCheck(tokenBytes, []byte(kt))
			if err != nil {
				return nil, err
			}
		case *rsa.PrivateKey:
			key := kt.PublicKey
			verifiedToken, err = jwt.RSACheck(tokenBytes, &key)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if authorizationContext.Options.PublicKey == "" {
			err = errors.New("public key not present for validation")
			return nil, err
		}

		var tokenHeader RawCertificateHeader
		err = json.Unmarshal(rawToken.RawHeader, &tokenHeader)
		if err != nil {
			return nil, err
		}
		switch tokenHeader.Algorithm {
		case "HS256", "HS384", "HS512":
			publicKey, err := base64.StdEncoding.DecodeString(authorizationContext.Options.PublicKey)
			if err != nil {
				return nil, err
			}
			verifiedToken, err = jwt.HMACCheck(tokenBytes, publicKey)
			if err != nil {
				return nil, err
			}
		case "ES256", "ES384", "ES512":
			publicKey := encryption.ECDSAHelper{}.DecodePublicKeyFromPem(authorizationContext.Options.PublicKey)
			if publicKey == nil {
				return nil, errors.New("invalid public key")
			}
			verifiedToken, err = jwt.ECDSACheck(tokenBytes, publicKey)
			if err != nil {
				return nil, err
			}
		case "RS256", "RS384", "RS512":
			publicKey := encryption.RSAHelper{}.DecodePublicKeyFromPem(authorizationContext.Options.PublicKey)
			if publicKey == nil {
				return nil, errors.New("invalid public key")
			}
			verifiedToken, err = jwt.RSACheck(tokenBytes, publicKey)
			if err != nil {
				return nil, err
			}
		}
	}

	if verifiedToken == nil {
		err = errors.New("no public or private key found, exiting")
		return nil, err
	}

	// Transforming token into a user token
	rawJsonToken, _ := verifiedToken.Raw.MarshalJSON()
	var userToken models.UserToken
	err = json.Unmarshal(rawJsonToken, &userToken)
	if err != nil {
		return nil, errors.New("token is not formated correctly")
	}

	// Validating the scope of the token
	if !strings.EqualFold(authorizationContext.Scope, userToken.Scope) {
		return &userToken, errors.New("token scope is not valid")
	}

	// Validating the token not before property
	if authorizationContext.ValidationOptions.NotBefore {
		if userToken.NotBefore.After(time.Now()) {
			return &userToken, errors.New("token is not yet valid")
		}
	}

	// Validating expiry token
	if userToken.ExpiresAt.Before(time.Now()) {
		return &userToken, errors.New("token is expired")
	}

	// If we require the Issuer to be validated we will be validating it
	if authorizationContext.ValidationOptions.Issuer {
		if !strings.EqualFold(userToken.Issuer, authorizationContext.Issuer) {
			return &userToken, errors.New("token is not valid for subject " + userToken.DisplayName)
		}
	}

	// Validating if the email has been verified
	if authorizationContext.ValidationOptions.VerifiedEmail {
		if !userToken.EmailVerified {
			return &userToken, errors.New("email is not verified for subject " + userToken.DisplayName)
		}
	}

	// Validating if the token contains the necessary audiences
	if authorizationContext.ValidationOptions.Audiences && len(authorizationContext.Audiences) > 0 {
		if len(authorizationContext.Audiences) == 0 || len(userToken.Audiences) == 0 {
			return &userToken, errors.New("no audiences to validate subject " + userToken.DisplayName)
		}
		isValid := true
		for _, audience := range authorizationContext.Audiences {
			wasFound := false
			for _, userAudience := range userToken.Audiences {
				if strings.EqualFold(userAudience, audience) {
					wasFound = true
				}
			}
			if !wasFound {
				isValid = false
				break
			}
		}

		if !isValid {
			return &userToken, errors.New("one or more required audience was not found for subject " + userToken.DisplayName)
		}
	}

	// Validating if the token tenant id is the same as the context
	if authorizationContext.ValidationOptions.Tenant {
		if authorizationContext.TenantId == "" || userToken.TenantId == "" {
			return &userToken, errors.New("no tenant was not found for subject " + userToken.DisplayName)
		}
		if !strings.EqualFold(authorizationContext.TenantId, userToken.TenantId) {
			return &userToken, errors.New("token is not valid for tenant " + userToken.TenantId + " for subject " + userToken.DisplayName)
		}
	}

	return &userToken, nil
}

func ValidateRefreshToken(token string, user string) (*models.UserToken, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}

	authCtx := authorization_context.New()
	var tokenBytes []byte
	var verifiedToken *jwt.Claims
	tokenBytes = []byte(token)
	var err error
	var signKey *jwt_keyvault.JwtKeyVaultItem
	rawToken, err := jwt.ParseWithoutCheck(tokenBytes)
	if err != nil {
		return nil, err
	}

	// Verifying signature using the key that was sign with
	signKey = authCtx.KeyVault.GetKey(rawToken.KeyID)
	switch kt := signKey.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		key := kt.PublicKey
		verifiedToken, err = jwt.ECDSACheck(tokenBytes, &key)
		if err != nil {
			return nil, err
		}
	case string:
		verifiedToken, err = jwt.HMACCheck(tokenBytes, []byte(kt))
		if err != nil {
			return nil, err
		}
	case *rsa.PrivateKey:
		key := kt.PublicKey
		verifiedToken, err = jwt.RSACheck(tokenBytes, &key)
		if err != nil {
			return nil, err
		}
	}

	// Transforming token into a user token
	rawJsonToken, _ := verifiedToken.Raw.MarshalJSON()
	var userToken models.UserToken
	err = json.Unmarshal(rawJsonToken, &userToken)
	if err != nil {
		return nil, errors.New("token is not formatted correctly")
	}

	// Validating the scope of the token
	if !strings.EqualFold(user, userToken.User) {
		return &userToken, errors.New("token user is not valid")
	}

	// Validating the scope of the token
	if !strings.EqualFold(identity_constants.RefreshTokenScope, userToken.Scope) {
		return &userToken, errors.New("token scope is not valid")
	}

	// Validating expiry token
	if userToken.ExpiresAt.Before(time.Now()) {
		return &userToken, errors.New("token is expired")
	}

	// If we require the Issuer to be validated we will be validating it
	if authCtx.ValidationOptions.Issuer {
		if !strings.EqualFold(userToken.Issuer, authCtx.Issuer) {
			return &userToken, errors.New("token is not valid for subject " + userToken.DisplayName)
		}
	}

	// Validating if the token tenant id is the same as the context
	if authCtx.ValidationOptions.Tenant {
		if authCtx.TenantId == "" || userToken.TenantId == "" {
			return &userToken, errors.New("no tenant was not found for subject " + userToken.DisplayName)
		}
		if !strings.EqualFold(authCtx.TenantId, userToken.TenantId) {
			return &userToken, errors.New("token is not valid for tenant " + userToken.TenantId + " for subject " + userToken.DisplayName)
		}
	}

	return &userToken, nil
}

func ValidateTokenByScope(token string, userId string, scope string) (*models.UserToken, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}

	authCtx := authorization_context.New()
	var tokenBytes []byte
	var verifiedToken *jwt.Claims
	tokenBytes = []byte(token)
	var err error
	var signKey *jwt_keyvault.JwtKeyVaultItem
	rawToken, err := jwt.ParseWithoutCheck(tokenBytes)
	if err != nil {
		return nil, err
	}

	// Verifying signature using the key that was sign with
	signKey = authCtx.KeyVault.GetKey(rawToken.KeyID)
	switch kt := signKey.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		key := kt.PublicKey
		verifiedToken, err = jwt.ECDSACheck(tokenBytes, &key)
		if err != nil {
			return nil, err
		}
	case string:
		verifiedToken, err = jwt.HMACCheck(tokenBytes, []byte(kt))
		if err != nil {
			return nil, err
		}
	case *rsa.PrivateKey:
		key := kt.PublicKey
		verifiedToken, err = jwt.RSACheck(tokenBytes, &key)
		if err != nil {
			return nil, err
		}
	}

	// Transforming token into a user token
	rawJsonToken, _ := verifiedToken.Raw.MarshalJSON()
	var userToken models.UserToken
	err = json.Unmarshal(rawJsonToken, &userToken)
	if err != nil {
		return nil, errors.New("token is not formatted correctly")
	}

	// Validating the scope of the token
	if !strings.EqualFold(userId, userToken.User) {
		return &userToken, errors.New("token user is not valid")
	}

	// Validating the scope of the token
	if !strings.EqualFold(scope, userToken.Scope) {
		return &userToken, errors.New("token scope is not valid")
	}

	// Validating expiry token
	if userToken.ExpiresAt.Before(time.Now()) {
		return &userToken, errors.New("token is expired")
	}

	// If we require the Issuer to be validated we will be validating it
	if authCtx.ValidationOptions.Issuer {
		if !strings.EqualFold(userToken.Issuer, authCtx.Issuer) {
			return &userToken, errors.New("token is not valid for subject " + userToken.DisplayName)
		}
	}

	// Validating if the token tenant id is the same as the context
	if authCtx.ValidationOptions.Tenant {
		if authCtx.TenantId == "" || userToken.TenantId == "" {
			return &userToken, errors.New("no tenant was not found for subject " + userToken.DisplayName)
		}
		if !strings.EqualFold(authCtx.TenantId, userToken.TenantId) {
			return &userToken, errors.New("token is not valid for tenant " + userToken.TenantId + " for subject " + userToken.DisplayName)
		}
	}

	return &userToken, nil
}

func signToken(keyId string, claims jwt.Claims) (string, error) {
	authCtx := authorization_context.New()
	var rawToken []byte
	var err error
	var signKey *jwt_keyvault.JwtKeyVaultItem
	if keyId == "" {
		signKey = authCtx.KeyVault.GetDefaultKey()
	} else {
		signKey = authCtx.KeyVault.GetKey(keyId)
	}
	if signKey == nil {
		err = errors.New("signing key was not found")
		logger.Error("There was an error signing the token with key %v, it was not found int the key vault", keyId)
		return "", err
	}
	var extraHeaders []byte

	// Signing the token using the key encryption type
	switch kt := signKey.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		// Adding extra headers for some signing cases
		extraHeaders, _ = json.Marshal(RawCertificateHeader{
			KeyId: signKey.ID,
			X5T:   signKey.Thumbprint,
		})
		switch signKey.Size {
		case encryption.Bit256:
			rawToken, err = claims.ECDSASign("ES256", kt, extraHeaders)
		case encryption.Bit384:
			rawToken, err = claims.ECDSASign("ES384", kt, extraHeaders)
		case encryption.Bit512:
			rawToken, err = claims.ECDSASign("ES512", kt, extraHeaders)
		}
	case string:
		// Adding extra headers for some signing cases
		extraHeaders, _ = json.Marshal(RawCertificateHeader{
			KeyId: signKey.ID,
		})
		switch signKey.Size {
		case encryption.Bit256:
			rawToken, err = claims.HMACSign("HS256", []byte(kt), extraHeaders)
		case encryption.Bit384:
			rawToken, err = claims.HMACSign("HS384", []byte(kt), extraHeaders)
		case encryption.Bit512:
			rawToken, err = claims.HMACSign("HS512", []byte(kt), extraHeaders)
		}
	case *rsa.PrivateKey:
		// Adding extra headers for some signing cases
		extraHeaders, _ = json.Marshal(RawCertificateHeader{
			KeyId: signKey.ID,
			X5T:   signKey.Thumbprint,
		})
		switch signKey.Size {
		case encryption.Bit256:
			rawToken, err = claims.RSASign("RS256", kt, extraHeaders)
		case encryption.Bit384:
			rawToken, err = claims.RSASign("RS384", kt, extraHeaders)
		case encryption.Bit512:
			rawToken, err = claims.RSASign("RS512", kt, extraHeaders)
		}
	}

	if err != nil {
		return "", err
	}

	return string(rawToken), nil
}
