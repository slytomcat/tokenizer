package database

import "time"

// TokenData is a token data that stored for notification support
type TokenData struct {
	OutSystem       string
	RequestorID     string
	Status          string
	StatusTimestamp time.Time
	Last4           string
	AssetURL        string
}

// Connector - database connection interface
type Connector interface {
	StoreTokenInfo(key string, ti *TokenData) error
	GetTokenInfo(key string) (*TokenData, error)
	StoreAsset(key, url string) error
	GetAsset(key string) (string, error)
	// GetOutSysCBURL(oSys string) (string, error)
	// GetTRSecrets(trid) (secrets, error)
}
