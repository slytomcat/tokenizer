package mdes

// CardAccountData hold the card data
type CardAccountData struct {
	AccountNumber string `json:"accountNumber"`
	ExpiryMonth   string `json:"expiryMonth"`
	ExpiryYear    string `json:"expiryYear"`
	SecurityCode  string `json:"securityCode"`
}

// TokenInfo bla-bla
type TokenInfo struct {
	TokenUniqueReference    string
	TokenPanSuffix          string
	TokenExpiry             string
	PanUniqueReference      string
	PanSuffix               string
	PanExpiry               string
	BrandAssetID            string
	ProductCategory         string
	DsrpCapable             bool
	PaymentAccountReference string
}

// MediaContent bla-bla
type MediaContent struct {
	Type   string
	Data   string
	Heigth string
	Width  string
}

// TokenStatus bla-bla
type TokenStatus struct {
	TokenUniqueReference string
	Status               string
	StatusTimestamp      string
	SuspendedBy          []string
}

// TransactData bla-bla
type TransactData struct {
	TokenUniqueReference string `json:"tokenUniqueReference"`
	CryptogramType       string `json:"cryptogramType"`
	TransactionType      string `json:"transactionType"`
}

// CryptogramData bla-bla
type CryptogramData struct {
	AccountNumber         string
	ApplicationExpiryDate string
	Track2Equivalent      string
	De55Data              string
	De48se43Data          string
}

// TokenizerAPI universal API for tokenization via different payment networks
type TokenizerAPI interface {
	Tokenize(CardAccountData, string) (*TokenInfo, error)
	GetAsset(string) ([]MediaContent, error)
	Suspend([]string) ([]TokenStatus, error)
	Unsuspend([]string) ([]TokenStatus, error)
	Delete([]string) ([]TokenStatus, error)
	Transact(TransactData) (*CryptogramData, error)
}
