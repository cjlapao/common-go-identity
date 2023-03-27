package dto

type ApiKeyDto struct {
	Id           string        `json:"id" bson:"_id"`
	Name         string        `json:"name" bson:"name"`
	Blocked      bool          `json:"blocked" bson:"blocked"`
	BlockedUntil string        `json:"blockedUntil" bson:"blockedUntil"`
	Key          string        `json:"key" bson:"key"`
	Roles        []ApiRoleDto  `json:"roles" bson:"roles"`
	Claims       []ApiClaimDto `json:"claims" bson:"claims"`
}

type ApiClaimDto struct {
	ID   string `json:"id" bson:"_id"`
	Name string `json:"claimName" bson:"claimName"`
}

type ApiRoleDto struct {
	ID   string `json:"id" bson:"_id"`
	Name string `json:"roleName" bson:"roleName"`
}
