package main

import (
	"fmt"
	"os"
	"strings"

	execution_context "github.com/cjlapao/common-go-execution-context"
	identity "github.com/cjlapao/common-go-identity"
	"github.com/cjlapao/common-go-identity/authorization_context"
	"github.com/cjlapao/common-go-identity/database/sql"
	"github.com/cjlapao/common-go-identity/models"
	log "github.com/cjlapao/common-go-logger"
	restapi "github.com/cjlapao/common-go-restapi"
	"github.com/cjlapao/common-go/helper"
	"github.com/cjlapao/common-go/security/encryption"
	"github.com/cjlapao/common-go/version"
)

var ver = "0.0.1"
var services = execution_context.Get().Services
var logger = log.Get()

func main() {
	SetVersion()
	getVersion := helper.GetFlagSwitch("version", false)
	if getVersion {
		format := helper.GetFlagValue("o", "json")
		switch strings.ToLower(format) {
		case "json":
			fmt.Println(services.Version.PrintVersion(int(version.JSON)))
		case "yaml":
			fmt.Println(services.Version.PrintVersion(int(version.JSON)))
		default:
			fmt.Println("Please choose a valid format, this can be either json or yaml")
		}
		os.Exit(0)
	}

	services.Version.PrintAnsiHeader()

	configFile := helper.GetFlagValue("config", "")
	if configFile != "" {
		services.Logger.Command("Loading configuration from " + configFile)
		services.Configuration.LoadFromFile(configFile)
	}

	defer func() {
	}()

	Init()
}

func SetVersion() {
	services.Version.Name = "Common Go Identity Example"
	services.Version.Author = "Carlos Lapao"
	services.Version.License = "MIT"
	strVer, err := version.FromString(ver)
	if err == nil {
		services.Version.Major = strVer.Major
		services.Version.Minor = strVer.Minor
		services.Version.Build = strVer.Build
		services.Version.Rev = strVer.Rev
	}
}

func Init() {
	// applyMigration := helper.GetFlagSwitch("migrate", false)
	// if applyMigration {
	// 	database.Init()
	// }

	ctx := execution_context.Get()
	authCtx := authorization_context.WithDefaultAuthorization()
	issuer := ctx.Configuration.GetString("ISSUER")
	domain := ctx.Configuration.GetString("DOMAIN")
	apiPrefix := ctx.Configuration.GetString("ENDPOINT_PREFIX")
	authCtx.WithAudience(issuer)
	authCtx.WithKeyVault()
	authCtx.WithIssuer(issuer)

	if domain != "" {
		authCtx.BaseUrl = domain
	}

	authCtx.ValidationOptions.VerifiedEmail = true
	kv := authCtx.KeyVault
	kv.WithBase64HmacKey("HMAC", "dGVzdGluZw==", encryption.Bit256)
	kv.SetDefaultKey("HMAC")

	listener := restapi.GetHttpListener()
	listener.Options.ApiPrefix = apiPrefix
	listener.AddJsonContent().AddLogger().AddHealthCheck()
	listener.WithPublicUserRegistration()
	identity.WithAuthentication(listener, sql.SqlDBUserContextAdapter{})
	authCtx.NotificationCallback = IdentityCallback

	applyMigration := helper.GetFlagSwitch("migrate", false)
	if applyMigration {
		sql.SqlDBUserContextAdapter{}.ApplyMigrations()
		os.Exit(0)
	}

	listener.Start()
}

func IdentityCallback(n models.OAuthNotification) error {
	return nil
}
