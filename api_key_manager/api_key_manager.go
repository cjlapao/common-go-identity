package api_key_manager

import (
	"errors"
	"strings"
	"sync"
	"time"

	cryptorand "github.com/cjlapao/common-go-cryptorand"
	"github.com/cjlapao/common-go/constants"
	"github.com/cjlapao/common-go/guard"
)

var (
	globalApiKeyManager *ApiKeyManager
	mu                  sync.Mutex
)

type ApiKeyManager struct {
	apiKeyContextAdapter ApiKeyContextAdapter
	ValidationOptions    ApiKeyValidationOptions
	CachedKeys           []*ApiKey
}

func EmptyApiKeyManager() *ApiKeyManager {
	apiKeyManager := ApiKeyManager{
		ValidationOptions: ApiKeyValidationOptions{
			ValidateExpiry:      true,
			ValidateBlocked:     true,
			ValidateRoles:       true,
			ValidateClaims:      true,
			ExpirySkewInSeconds: 5 * time.Second,
		},
		CachedKeys: make([]*ApiKey, 0),
	}

	globalApiKeyManager = &apiKeyManager

	return globalApiKeyManager
}

func GetApiKeyManager() *ApiKeyManager {
	mu.Lock()
	defer mu.Unlock()

	if globalApiKeyManager == nil {
		EmptyApiKeyManager()
	}

	return globalApiKeyManager
}

func (apiKeyManager *ApiKeyManager) WithValidationOptions(options ApiKeyValidationOptions) *ApiKeyManager {
	apiKeyManager.ValidationOptions = options
	return apiKeyManager
}

func (apiKeyManager *ApiKeyManager) SetContextAdapter(contextAdapter ApiKeyContextAdapter) {
	apiKeyManager.apiKeyContextAdapter = contextAdapter
}

func (apiKeyManager *ApiKeyManager) Refresh() error {
	keys, err := apiKeyManager.apiKeyContextAdapter.GetAll()
	if err != nil {
		return err
	}

	apiKeyManager.CachedKeys = append(apiKeyManager.CachedKeys, keys...)

	return nil
}

func (apiKeyManager *ApiKeyManager) Get(keyId string) (*ApiKey, error) {
	// Caching the keys if none exist
	if len(apiKeyManager.CachedKeys) == 0 {
		apiKeyManager.Refresh()
	}

	for _, apiKey := range apiKeyManager.CachedKeys {
		if strings.EqualFold(apiKey.Id, keyId) {
			return apiKey, nil
		}
	}

	contextKey, err := apiKeyManager.apiKeyContextAdapter.Get(keyId)
	if err != nil {
		return nil, err
	}

	// caching the key
	if contextKey != nil {
		apiKeyManager.CachedKeys = append(apiKeyManager.CachedKeys, contextKey)
	}

	return contextKey, nil
}

func (apiKeyManager *ApiKeyManager) Validate(requestKey *ApiKeyHeader) (bool, error) {
	if requestKey.Key == "" || requestKey.Value == "" {
		return false, errors.New("Invalid Api Key")
	}

	apiKey, err := apiKeyManager.Get(requestKey.Key)
	if err != nil {
		return false, err
	}

	if apiKey == nil {
		return false, errors.New("Invalid Api Key")
	}

	if apiKey.KeyValue != requestKey.Value {
		return false, errors.New("Invalid Api Key")
	}

	if apiKeyManager.ValidationOptions.ValidateExpiry && apiKey.ValidFrom.After(time.Now().Add(apiKeyManager.ValidationOptions.ExpirySkewInSeconds)) {
		return false, errors.New("Api key not valid yet")
	}

	if apiKeyManager.ValidationOptions.ValidateExpiry && apiKey.ValidTo.Before(time.Now().Add(-apiKeyManager.ValidationOptions.ExpirySkewInSeconds)) {
		return false, errors.New("Api key expired")
	}

	if apiKeyManager.ValidationOptions.ValidateBlocked && apiKey.Blocked {
		return false, errors.New("Api key is blocked")
	}

	return true, nil
}

func (apiKeyManager *ApiKeyManager) Add(key *ApiKey) error {
	if key == nil {
		return errors.New("Key cannot be nil")
	}

	if err := guard.EmptyOrNil(key.Name); err != nil {
		return err
	}

	if err := guard.EmptyOrNil(key.KeyValue); err != nil {
		return err
	}

	var cachedApiKey *ApiKey

	for idx, apiKey := range apiKeyManager.CachedKeys {
		if strings.EqualFold(apiKey.Name, key.Name) {
			apiKeyManager.CachedKeys[idx].KeyValue = key.KeyValue
			apiKeyManager.CachedKeys[idx].TenantId = key.TenantId
			apiKeyManager.CachedKeys[idx].Description = key.Description
			apiKeyManager.CachedKeys[idx].ValidFrom = key.ValidFrom
			apiKeyManager.CachedKeys[idx].ValidTo = key.ValidTo
			apiKeyManager.CachedKeys[idx].Roles = key.Roles
			apiKeyManager.CachedKeys[idx].Claims = key.Claims
			cachedApiKey = apiKey
			break
		}
	}

	id, err := cryptorand.GetRandomString(constants.ID_SIZE)
	if err != nil {
		return nil
	}

	if cachedApiKey == nil {
		cachedApiKey = &ApiKey{
			Id:          id,
			Name:        key.Name,
			KeyValue:    key.KeyValue,
			TenantId:    key.TenantId,
			Description: key.Description,
			ValidFrom:   key.ValidFrom,
			ValidTo:     key.ValidTo,
			Roles:       key.Roles,
			Claims:      key.Claims,
		}

		if key.Id != "" {
			cachedApiKey.Id = key.Id
		}

		apiKeyManager.CachedKeys = append(apiKeyManager.CachedKeys, cachedApiKey)
	}

	if err := apiKeyManager.apiKeyContextAdapter.Add(cachedApiKey); err != nil {
		return err
	}

	return nil
}

func (apiKeyManager *ApiKeyManager) IsEnabled() bool {
	return apiKeyManager.apiKeyContextAdapter != nil
}
