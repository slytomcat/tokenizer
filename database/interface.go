package database

import (
	"crypto/rsa"
	"time"
)

// TokenData is a token data that stored for notification support
type TokenData struct {
	OutSystem       string
	RequestorID     string
	Status          string
	StatusTimestamp time.Time
	Last4           string
	AssetURL        string
}

// OutSysInfo - out system information
type OutSysInfo struct {
	OutSystem string
	CBURL     string
}

// TRSecrets - secrets to singn/encrypt/decrypt requests/responces to/from VISA API
type TRSecrets struct {
	APIKey     string
	SingKey    *rsa.PrivateKey
	EncryptKey *rsa.PublicKey
	DecryptKey *rsa.PrivateKey
}

// Connector - database connection interface
type Connector interface {
	StoreTokenInfo(tur string, ti *TokenData) error
	GetTokenInfo(tur string) (*TokenData, error)
	StoreAsset(AssetID, url string) error
	GetAsset(AssetID string) (string, error)
	StoreOutSysInfo(oSys string, oSysInfo *OutSysInfo) error
	GetOutSysInfo(oSys string) (*OutSysInfo, error)
	StoreTRSecrets(trid string, trSecrets *TRSecrets) error
	GetTRSecrets(trid string) (*TRSecrets, error)
}
