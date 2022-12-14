package database

import (
	"fmt"

	"github.com/cjlapao/common-go-identity/database/dto"
	"github.com/cjlapao/common-go/configuration"
	"github.com/cjlapao/common-go/helper/reflect_helper"
	"github.com/cjlapao/common-go/security"
)

func GetDefaultUsers() []dto.UserDTO {
	config := configuration.Get()
	users := make([]dto.UserDTO, 0)
	var adminUser dto.UserDTO
	var demoUser dto.UserDTO

	adminUsername := config.GetString("ADMIN_USERNAME")
	adminPassword := config.GetString("ADMIN_PASSWORD")

	if reflect_helper.IsNilOrEmpty(adminUsername) {
		adminUser = dto.UserDTO{
			ID:        "592D8E5C-6F5D-40A0-9348-80131B083715",
			Email:     "admin@localhost.com",
			FirstName: "Administrator",
			LastName:  "User",
			Username:  "admin@localhost.com",
			Password:  "a075d17f3d453073853f813838c15b8023b8c487038436354fe599c3942e1f95",
		}
	} else {
		adminUser = dto.UserDTO{
			ID:        "592D8E5C-6F5D-40A0-9348-80131B083715",
			Email:     fmt.Sprintf("%v@localhost", adminUsername),
			FirstName: "Administrator",
			LastName:  "User",
			Username:  adminUsername,
		}
	}

	if reflect_helper.IsNilOrEmpty(adminPassword) {
		security.SHA256Encode("p@ssw0rd")
	} else {
		adminUser.Password = security.SHA256Encode(adminPassword)
	}

	// adminUser.Roles = append(adminUser.Roles, mappers.ToUserRoleDTO(constants.AdminRole), mappers.ToUserRoleDTO(constants.RegularUserRole))
	// adminUser.Claims = append(adminUser.Claims, mappers.ToUserClaimDTO(constants.ReadClaim), mappers.ToUserClaimDTO(constants.ReadWriteClaim), mappers.ToUserClaimDTO(constants.RemoveClaim))

	demoUsername := config.GetString("DEMO_USERNAME")
	demoPassword := config.GetString("DEMO_PASSWORD")

	if reflect_helper.IsNilOrEmpty(demoUsername) {
		demoUser = dto.UserDTO{
			ID:        "C54C2A9B-CA73-4188-875A-F26026A38B58",
			Email:     "demo@localhost.com",
			FirstName: "Demo",
			LastName:  "User",
			Username:  "demo@localhost.com",
			Password:  "2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea",
		}
	} else {
		demoUser = dto.UserDTO{
			ID:        "C54C2A9B-CA73-4188-875A-F26026A38B58",
			Email:     fmt.Sprintf("%v@localhost", demoUsername),
			FirstName: "Administrator",
			LastName:  "User",
			Username:  demoUsername,
		}
	}

	if reflect_helper.IsNilOrEmpty(demoPassword) {
		security.SHA256Encode("demo")
	} else {
		demoUser.Password = security.SHA256Encode(demoPassword)
	}

	// demoUser.Roles = append(demoUser.Roles, mappers.ToUserRoleDTO(constants.RegularUserRole))
	// demoUser.Claims = append(demoUser.Claims, mappers.ToUserClaimDTO(constants.ReadClaim))

	users = append(users, adminUser)
	users = append(users, demoUser)

	return users
}
