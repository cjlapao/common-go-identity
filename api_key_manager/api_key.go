package api_key_manager

import "time"

type ApiKey struct {
	Id          string        `json:"id" bson:"_id"`
	TenantId    string        `json:"tenantId" bson:"tenantId"`
	Name        string        `json:"name" bson:"name"`
	KeyValue    string        `json:"keyValue" bson:"keyValue"`
	Description string        `json:"description,omitempty" bson:"description"`
	ValidFrom   time.Time     `json:"validFrom" bson:"validFrom"`
	ValidTo     time.Time     `json:"validTo" bson:"validTo"`
	Blocked     bool          `json:"blocked" bson:"blocked"`
	Roles       []ApiKeyRole  `json:"roles" bson:"roles"`
	Claims      []ApiKeyClaim `json:"claims" bson:"claims"`
}
