package api_key_manager

type ApiKeyHeader struct {
	TenantId string `json:"tenantId"`
	UserId   string `json:"userId"`
	Key      string `json:"key"`
	Value    string `json:"value"`
}
