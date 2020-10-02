package mdes

// MCError error structure
type MCError struct {
	ErrorCode        string `json:"errorCode"`
	ErrorDescription string `json:"errorDescription"`
	ResponseHost     string `json:"responseHost"`
	ResponseID       string `json:"responseId"`
	Errors           []struct {
		Source      string `json:"source"`
		ErrorCode   string `json:"errorCode"`
		Description string `json:"description"`
		ReasonCode  string `json:"reasonCode"`
		Recoverable bool   `json:"recoverable"`
	} `json:"errors"`
}

// CardAccountData hold the card data
type CardAccountData struct {
	AccountNumber string `json:"accountNumber"`
	ExpiryMonth   string `json:"expiryMonth"`
	ExpiryYear    string `json:"expiryYear"`
	SecurityCode  string `json:"securityCode"`
}

// TokenInfo MC API struct
type TokenInfo struct {
	TokenUniqueReference    string
	TokenPanSuffix          string
	TokenExpiry             string
	PanUniqueReference      string
	AccountPanSuffix        string
	AccountPanExpiry        string
	BrandAssetID            string
	ProductCategory         string
	PaymentAccountReference string
	TokenAssuranceLevel     int
	IsCoBranded             bool
	CoBrandName             string
	IssuerName              string
}

// MediaContent bla-bla
type MediaContent struct {
	Type   string
	Data   string
	Heigth int
	Width  int
}

// MediaContents bla-bla
type MediaContents []MediaContent

// TokenStatus TokenStatus bla-bla
type TokenStatus struct {
	TokenUniqueReference string
	Status               string
	EventReasonCode      string
	StatusTimestamp      string
	SuspendedBy          []string
}

// ProductConfig bla-bla
type ProductConfig struct {
	// BrandLogoAssetID              string
	// IssuerLogoAssetID             string
	// CoBrandLogoAssetID            string
	// CardBackgroundAssetID         string
	// IconAssetID                   string
	// ForegroundColor               string
	CardBackgroundCombinedAssetID string
	IsCoBranded                   string
	CoBrandName                   string
	IssuerName                    string
	ShortDescription              string
	LongDescription               string
	CustomerServiceURL            string
	CustomerServiceEmail          string
	CustomerServicePhoneNumber    string
	OnlineBankingLoginURL         string
	TermsAndConditionsURL         string
	PrivacyPolicyURL              string
	IssuerProductConfigCode       string
}

// NotificationTokensData bla-bla
type NotificationTokensData struct {
	Tokens []NotificationTokenData
}

// NotificationTokenData bla-bla
type NotificationTokenData struct {
	TokenStatus
	ProductConfig ProductConfig
	TokenInfo     TokenInfo
}

// TransactData bla-bla
type TransactData struct {
	TokenUniqueReference string `json:"tokenUniqueReference"`
	CryptogramType       string `json:"cryptogramType"`
	TransactionType      string `json:"transactionType"`
}

// CryptogramData CryptogramData bla-bla
type CryptogramData struct {
	AccountNumber         string
	ApplicationExpiryDate string
	Track2Equivalent      string
	De55Data              string
	De48se43Data          string
}

// TokenRequestor - information for new TRID registration
type TokenRequestor struct {
	EntityID                                   string `json:"entityId"`
	PaymentAppID                               string `json:"paymentAppId"`
	ConsumerFacingEntityName                   string `json:"consumerFacingEntityName"`
	DebitCreditIndicator                       string `json:"debitCreditIndicator"`
	ProvidePaymentAccountReference             bool   `json:"providePaymentAccountReference"`
	EnableTransactionIssuerResponseInformation bool   `json:"enableTransactionIssuerResponseInformation"`
	WrappedEncryptionHashAlgorithm             string `json:"wrappedEncryptionHashAlgorithm"`
}
