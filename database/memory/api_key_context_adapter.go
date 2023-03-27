package memory

import (
	"github.com/cjlapao/common-go-identity/api_key_manager"
)

type MemoryApiKeyContextAdapter struct {
	Keys []*api_key_manager.ApiKey
}

func NewMemoryApiKeyAdapter() *MemoryApiKeyContextAdapter {
	context := MemoryApiKeyContextAdapter{}
	context.Keys = make([]*api_key_manager.ApiKey, 0)

	return &context
}

func (c *MemoryApiKeyContextAdapter) Get(keyId string) (*api_key_manager.ApiKey, error) {
	for _, apiKey := range c.Keys {
		if apiKey.Id == keyId {
			return apiKey, nil
		}
	}

	return nil, nil
}

func (c *MemoryApiKeyContextAdapter) GetAll() ([]*api_key_manager.ApiKey, error) {
	return c.Keys, nil
}

func (c *MemoryApiKeyContextAdapter) Delete(keyId string) error {
	for i, apiKey := range c.Keys {
		if apiKey.Id == keyId {
			c.Keys = append(c.Keys[:i], c.Keys[i+1:]...)
			return nil
		}
	}

	return nil
}

func (c *MemoryApiKeyContextAdapter) Add(key *api_key_manager.ApiKey) error {
	shouldAdd := true
	for i, apiKey := range c.Keys {
		if apiKey.Id == key.Id {
			c.Keys[i] = key
			shouldAdd = false
			break
		}
	}

	if shouldAdd {
		c.Keys = append(c.Keys, key)
	}

	return nil
}
