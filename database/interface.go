package database

import (
	"crypto/rsa"
	"time"
)

// TokenData is a token data that stored for notification support
type TokenData struct {
	OutSystem       string    // out system
	RequestorID     string    // TRID
	Status          string    // token current status
	StatusTimestamp time.Time // timestamp of current token status
	Last4           string    // last 4 digits of tokenized card
	AssetURL        string    // URL for card picture
	Cobranded       bool      // is the card cobranded
	CobrandName     string    // name of cobanding entity
	IssuerName      string    // Issuer bank name
	AssuranceLevel  int       // token assurance level
}

// OutSysInfo - out system information
type OutSysInfo struct {
	CBURL   string // call-back end-point URL for token udate notifications
	TRIDURL string // call-back end-point URL for TRID API notifications
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
	// Token data methods
	StoreTokenInfo(tur string, ti *TokenData) error
	GetTokenInfo(tur string) (*TokenData, error)
	// Out system information methods
	StoreOutSysInfo(oSys string, oSysInfo *OutSysInfo) error
	GetOutSysInfo(oSys string) (*OutSysInfo, error)
	// TR secrets data methods
	StoreTRSecrets(trid string, trSecrets *TRSecrets) error
	GetTRSecrets(trid string) (*TRSecrets, error)
	// Merchant data methods
	StoreMerchant(id string, mi *Merchant) error
	GetMerchant(id string) (*Merchant, error)
	// Assets data methods
	StoreAsset(assetID string, asset *Asset) error
	GetAsset(assetID string) (*Asset, error)
	// health check
	Check() error
}
