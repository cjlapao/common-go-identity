package api_key_manager

type ApiKeyContextAdapter interface {
	Get(key string) (*ApiKey, error)
	GetAll() ([]*ApiKey, error)
	Delete(key string) error
	Add(key *ApiKey) error
}
