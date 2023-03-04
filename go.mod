module github.com/cjlapao/common-go-identity

go 1.19

require (
	github.com/cjlapao/common-go v0.0.39
	github.com/cjlapao/common-go-cryptorand v0.0.5
	github.com/cjlapao/common-go-database v0.0.4
	github.com/cjlapao/common-go-execution-context v0.0.2
	github.com/cjlapao/common-go-identity-oauth2 v0.0.6
	github.com/cjlapao/common-go-logger v0.0.2
	github.com/cjlapao/common-go-restapi v0.0.11
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/pascaldekloe/jwt v1.12.0
)

require (
	github.com/elliotchance/orderedmap/v2 v2.2.0 // indirect
	github.com/fatih/color v1.14.1 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/go-sql-driver/mysql v1.7.0 // indirect
	github.com/golang/snappy v0.0.1 // indirect
	github.com/gorilla/handlers v1.5.1 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/montanaflynn/stats v0.0.0-20171201202039-1bf9dbcd8cbe // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.1 // indirect
	github.com/xdg-go/stringprep v1.0.3 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	go.mongodb.org/mongo-driver v1.11.2 // indirect
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.3.7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/cjlapao/common-go-database => ../common-go-database

replace github.com/cjlapao/common-go-restapi => ../common-go-restapi

replace github.com/cjlapao/common-go-identity-oauth2 => ../common-go-identity-oauth2
