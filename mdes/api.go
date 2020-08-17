package mdes

// CardAccountData hold the card data
type CardAccountData struct {
	AccountNumber string `json:"accountNumber"`
	ExpiryMonth   string `json:"expiryMonth"`
	ExpiryYear    string `json:"expiryYear"`
	SecurityCode  string `json:"securityCode"`
}

// MCError bla-bla
type MCError struct {
	ErrorCode        string
	ErrorDescription string
	ResponseHost     string
	ResponseID       string
	Errors           []struct {
		Source      string
		ErrorCode   string
		Description string
		ReasonCode  string
		Recoverable bool
	}
}

// MCTokenInfo bla-bla
type MCTokenInfo struct {
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

// TokenInfo bla bla
type TokenInfo struct {
	TokenPanSuffix      string
	AccountPanSuffix    string
	TokenExpiry         string
	AccountPanExpiry    string
	DsrpCapable         bool
	TokenAssuranceLevel int
	ProductCategory     string
}

// MCMediaContent MediaContent bla-bla
type MCMediaContent struct {
	Type   string
	Data   string
	Heigth string
	Width  string
}

// MCMediaContents bla-bla
type MCMediaContents []MCMediaContent

// MCTokenStatus TokenStatus bla-bla
type MCTokenStatus struct {
	TokenUniqueReference string
	Status               string
	EventReasonCode      string
	StatusTimestamp      string
	SuspendedBy          []string
}

// MCProductConfig bla-bla
type MCProductConfig struct {
	//BrandLogoAssetID              string
	//IssuerLogoAssetID             string
	IsCoBranded string
	CoBrandName string
	//CoBrandLogoAssetID            string
	CardBackgroundCombinedAssetID string
	//CardBackgroundAssetID         string
	//IconAssetID                   string
	//ForegroundColor               string
	IssuerName                 string
	ShortDescription           string
	LongDescription            string
	CustomerServiceURL         string
	CustomerServiceEmail       string
	CustomerServicePhoneNumber string
	OnlineBankingLoginURL      string
	TermsAndConditionsURL      string
	PrivacyPolicyURL           string
	IssuerProductConfigCode    string
}

// MCNotificationTokensData bla-bla
type MCNotificationTokensData struct {
	Tokens []MCNotificationTokenData
}

// MCNotificationTokenData bla-bla
type MCNotificationTokenData struct {
	MCTokenStatus
	ProductConfig MCProductConfig
	TokenInfo     MCTokenInfo
}

// TransactData bla-bla
type TransactData struct {
	TokenUniqueReference string `json:"tokenUniqueReference"`
	CryptogramType       string `json:"cryptogramType"`
	TransactionType      string `json:"transactionType"`
}

// MCCryptogramData CryptogramData bla-bla
type MCCryptogramData struct {
	AccountNumber         string
	ApplicationExpiryDate string
	Track2Equivalent      string
	De55Data              string
	De48se43Data          string
}
