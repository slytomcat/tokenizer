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
	Cobranded       bool
	CobrandName     string
	IssuerName      string
	AssuranceLevel  int
}

// OutSysInfo - out system information
type OutSysInfo struct {
	CBURL   string
	TRIDURL string
	// EncryptKey *rsa.PublicKey  // Key for sensitive data encryption in responces to out system requests
	// DecryptKey *rsa.PrivateKey // Key for sensitive data decryption in requests from out system
}

// TRSecrets - secrets to singn/encrypt/decrypt requests/responces to/from VISA API
type TRSecrets struct {
	APIKey     string
	SingKey    *rsa.PrivateKey
	EncryptKey *rsa.PublicKey
	DecryptKey *rsa.PrivateKey
}

// Asset - asset data: set of URLs on pictures in cloud storage
type Asset struct {
	PicURL string
	// InactivePicURL       string
	// MobilePicURL         string
	// MobileInactivePicURL string
}

// Merchant is merchant ifo required for TRID API call-backs
type Merchant struct {
	OutSystem string
}

// Connector - database connection interface
type Connector interface {
	StoreTokenInfo(tur string, ti *TokenData) error
	GetTokenInfo(tur string) (*TokenData, error)
	StoreOutSysInfo(oSys string, oSysInfo *OutSysInfo) error
	GetOutSysInfo(oSys string) (*OutSysInfo, error)
	StoreTRSecrets(trid string, trSecrets *TRSecrets) error
	GetTRSecrets(trid string) (*TRSecrets, error)
	StoreMerchant(id string, mi *Merchant) error
	GetMerchant(id string) (*Merchant, error)
	StoreAsset(assetID string, asset *Asset) error
	GetAsset(assetID string) (*Asset, error)
	Check() error
}
