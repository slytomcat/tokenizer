package mdes

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"sync"

	oauth "github.com/mastercard/oauth1-signer-go"
)

// MDESapi TokenizerAPI implementation for MasterCard MDES Digital enabled API
type MDESapi struct {
	oAuthSigner        *oauth.Signer
	storedDecryptKey   *rsa.PrivateKey
	storedEncryptKey   *rsa.PublicKey
	storedEncryptKeyFP string
	mutex              *sync.RWMutex  // RWmutex requered for KeyExchangeManager
	ourputRe           *regexp.Regexp // compiled regexp for output filtration
	urlTokenize        string
	urlTransact        string
	urlSuspend         string
	urlUnsuspend       string
	urlDelete          string
	urlGetAssets       string
	urlGetToken        string
	urlSearch          string
}

// encryptedPayload structure of encrypted payload of MDES API
type encryptedPayload struct {
	EncryptedData        string `json:"encryptedData"`        //
	EncryptedKey         string `json:"encryptedKey"`         //
	OaepHashingAlgorithm string `json:"oaepHashingAlgorithm"` //
	PublicKeyFingerprint string `json:"publicKeyFingerprint"` //
	Iv                   string `json:"iv"`                   //
}

// NewMDESapi creates new MDESapi implementation
func NewMDESapi(path string) (*MDESapi, error) {
	// TO DO: run KeyExchangeManager goroutine ho handle key renewal process
	// c := make(chan os.Signal, 1)
	// signal.Notify(c, syscall.SIGUSR1)
	// // start KeyExchangeManager
	// go func() {
	// 	// sleep until a signal is received.
	// 	<-c
	// 	// update keys from storage
	// }()
	// OR use web-hook to register merchant and/or upload keys.
	// But in case of time-based key exchange it is necessary to create the waiting
	// goroutine (on key receiving and on initial loading of keys during startup)

	mAPI := &MDESapi{
		mutex: &sync.RWMutex{}, // RWmutex requered for KeyExchangeManager
	}
	var err error
	mAPI.ourputRe, err = regexp.Compile(`"data":"[^"]*"`)
	if err != nil {
		log.Printf("regexp creation error: %v", err)
	}

	// TO DO: read path from config or load keys from DB
	if err := mAPI.initKeys(path); err != nil {
		return nil, err
	}

	// TO DO: read env and sys from config
	MDESenv := "static/"  // can be "mtf/" or "" for PROD
	MDESsys := "sandbox." // can be "" for MTF and PROD

	mAPI.urlTokenize = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/tokenize", MDESsys, MDESenv)
	mAPI.urlTransact = fmt.Sprintf("https://%sapi.mastercard.com/mdes/remotetransaction/%s1/0/transact", MDESsys, MDESenv)
	mAPI.urlSuspend = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/suspend", MDESsys, MDESenv)
	mAPI.urlUnsuspend = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/unsuspend", MDESsys, MDESenv)
	mAPI.urlDelete = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/delete", MDESsys, MDESenv)
	mAPI.urlGetAssets = fmt.Sprintf("https://%sapi.mastercard.com/mdes/assets/%s1/0/asset/", MDESsys, MDESenv)
	mAPI.urlGetToken = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/getToken", MDESsys, MDESenv)
	mAPI.urlSearch = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/searchTokens", MDESsys, MDESenv)

	return mAPI, nil
}

// request makes request with oAuth header by 'url' with 'payload'. It returns responce body and error
func (m MDESapi) request(method, url string, payload []byte) ([]byte, error) {

	request, _ := http.NewRequest(method, url, bytes.NewReader(payload))
	if method == "POST" {
		request.Header.Add("Content-Type", "application/json")
	}
	request.Header.Add("Accept", "application/json")

	// sign the request
	if err := m.signer().Sign(request); err != nil {
		return nil, fmt.Errorf("request signing error: %w", err)
	}

	log.Printf("    <<<<<<<    Request URL: %s\n", url)
	log.Printf("    <<<<<<<    Request Heder:\n%v\n", request.Header)
	log.Printf("    <<<<<<<    Request Body:\n%s\n", payload)

	// get responce
	responce, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request sending error: %w", err)
	}
	defer responce.Body.Close()

	body, err := ioutil.ReadAll(responce.Body)
	if err != nil {
		return nil, fmt.Errorf("responce body reading error: %w", err)
	}

	output := m.ourputRe.ReplaceAll(body, []byte(`"data":"--<--data skiped-->--"`))
	log.Printf("    >>>>>>>    Response: %s\n%s\n", responce.Status, output)

	return body, nil
}

// encryptPayload encrypts the payload
func (m MDESapi) encryptPayload(payload []byte) (*encryptedPayload, error) {

	// get session key as secure random
	sessionKey, err := getRandom(16) // 128 bit
	if err != nil {
		return nil, fmt.Errorf("seesion key creation error: %w", err)
	}

	// get latest encryption keq and it's fingerprint
	encryptKey, encryptKeyFP := m.encryptKey()

	// encrypt the session key  !!! hash alg is fixed in this implementation
	encyptedKey, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, encryptKey, sessionKey, nil)
	if err != nil {
		return nil, fmt.Errorf("seesion key encryption error: %w", err)
	}

	iv, ciphertext, err := encryptAESCBC(sessionKey, payload)
	if err != nil {
		return nil, fmt.Errorf("payload encryption error: %w", err)
	}

	// make and return the encryptedPayload struct
	return &encryptedPayload{
		EncryptedData:        hex.EncodeToString(ciphertext),
		EncryptedKey:         hex.EncodeToString(encyptedKey),
		OaepHashingAlgorithm: "SHA512", // !!! hash alg is fixed in this implementation
		PublicKeyFingerprint: encryptKeyFP,
		Iv:                   hex.EncodeToString(iv),
	}, nil
}

// decryptPayload decrypts the payload
func (m MDESapi) decryptPayload(ePayload *encryptedPayload) ([]byte, error) {

	// decode HEX data from EncryptedPayload
	ciphertext, err := hex.DecodeString(ePayload.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("encrypted data decoding error: %w", err)
	}
	encryptedKey, err := hex.DecodeString(ePayload.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("encrypted key decoding error: %w", err)
	}
	iv, err := hex.DecodeString(ePayload.Iv)
	if err != nil {
		return nil, fmt.Errorf("iv decoding error: %w", err)
	}

	// select hash alghorithm
	var hash hash.Hash
	switch ePayload.OaepHashingAlgorithm {
	case "SHA512":
		hash = sha512.New()
	case "SHA256":
		hash = sha256.New()
	default:
		return nil, fmt.Errorf("unknown hash algorithm: %s", ePayload.OaepHashingAlgorithm)
	}
	// TO DO: select privite key by ePayload.PublicKeyFingerprint
	// decrypt encryptedKey
	sessionKey, err := rsa.DecryptOAEP(hash, rand.Reader, m.decrypKey(), encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypted key decryption error: %w", err)
	}

	// decrypt ciphertext
	opentext, err := decryptAESCBC(sessionKey, iv, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("encrypted data decryption error: %w", err)
	}
	return opentext, nil
}

// Tokenize is the universal API implementation of MDES Tokenize API call
func (m MDESapi) Tokenize(RequestorID string, cardData CardAccountData, source string) (*TokenInfo, error) {

	payloadToEncrypt, _ := json.Marshal(struct {
		CardAccountData CardAccountData `json:"cardAccountData"`
		Source          string          `json:"source"`
	}{
		cardData,
		source,
	})

	encrPayload, err := m.encryptPayload(payloadToEncrypt)
	if err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(struct {
		ResponseHost       string `json:"responseHost"`
		RequestID          string `json:"requestId"`
		TaskID             string `json:"taskId"`
		TokenType          string `json:"tokenType"`
		TokenRequestorID   string `json:"tokenRequestorId"`
		FundingAccountInfo struct {
			EncryptedPayload encryptedPayload `json:"encryptedPayload"`
		} `json:"fundingAccountInfo"`
	}{
		ResponseHost:     "assist.ru",
		RequestID:        "12344321", // TO DO: make uniq ID here
		TaskID:           "12344321", // TO DO: make uniq ID here
		TokenType:        "CLOUD",    //constant
		TokenRequestorID: RequestorID,
		FundingAccountInfo: struct {
			EncryptedPayload encryptedPayload `json:"encryptedPayload"`
		}{
			EncryptedPayload: *encrPayload,
		},
	})

	// >>> remove in PROD env
	// log.Print(string(payload))
	// <<< remove in PROD env

	response, err := m.request("POST", m.urlTokenize, payload)
	if err != nil {
		return nil, err
	}

	responseStruct := struct {
		AuthenticationMethods []struct {
			ID    int
			Type  string
			Value string
		}
		TokenUniqueReference string
		PanUniqueReference   string
		Status               string
		StatusTimestamp      string
		ProductConfig        struct {
			BrandLogoAssetID              string
			IssuerLogoAssetID             string
			IsCoBranded                   string
			CoBrandName                   string
			CoBrandLogoAssetID            string
			CardBackgroundCombinedAssetID string
			CardBackgroundAssetID         string
			IconAssetID                   string
			ForegroundColor               string
			IssuerName                    string
			ShortDescription              string
			LongDescription               string
			CustomerServiceURL            string
			CustomerServiceEmail          string
			CustomerServicePhoneNumber    string
			OonlineBankingLoginURL        string
			TermsAndConditionsURL         string
			PrivacyPolicyURL              string
			IssuerProductConfigCode       string
		}
		TokenInfo struct {
			TokenPanSuffix      string
			AccountPanSuffix    string
			TokenExpiry         string
			AccountPanExpiry    string
			DsrpCapable         bool
			TokenAssuranceLevel int
			ProductCategory     string
		}
		TokenDetail encryptedPayload
	}{}

	if err := json.Unmarshal(response, &responseStruct); err != nil {
		return nil, err
	}

	decrypted, err := m.decryptPayload(&responseStruct.TokenDetail)
	if err != nil {
		return nil, err
	}

	// >>> remove in PROD env
	log.Printf("Decrypted(myPrivKey) payload:\n%s\n", decrypted)
	// <<< remove in PROD env

	tokenDetail := struct {
		AccountHolderData struct {
			AccountHolderName              string
			ConsumerIdentifier             string
			AccountHolderEmailAddress      string
			AccountHolderMobilePhoneNumber struct {
				CountryDialInCode int
				PhoneNumber       int
			}
		}
		PaymentAccountReference string
	}{}

	err = json.Unmarshal(decrypted, &tokenDetail)
	if err != nil {
		return nil, err
	}

	return &TokenInfo{
		TokenUniqueReference:    responseStruct.TokenUniqueReference,
		TokenPanSuffix:          responseStruct.TokenInfo.TokenPanSuffix,
		TokenExpiry:             responseStruct.TokenInfo.TokenExpiry,
		PanUniqueReference:      responseStruct.PanUniqueReference,
		PanSuffix:               responseStruct.TokenInfo.AccountPanSuffix,
		PanExpiry:               responseStruct.TokenInfo.AccountPanExpiry,
		BrandAssetID:            responseStruct.ProductConfig.CardBackgroundAssetID,
		ProductCategory:         responseStruct.TokenInfo.ProductCategory,
		DsrpCapable:             responseStruct.TokenInfo.DsrpCapable,
		PaymentAccountReference: tokenDetail.PaymentAccountReference,
	}, nil
}

// Search is the universal API implementation of MDES SearchToken API call
func (m MDESapi) Search(RequestorID, tokenURef, panURef string, cardData CardAccountData) ([]TokenStatus, error) {

	// TO DO: generate random ID
	reqID := "123456"
	respHost := "assist.ru"
	payload := []byte{}
	switch {
	case tokenURef != "":
		type td struct {
			TokenUniqueReference string `json:"tokenUniqueReference"`
		}
		payload, _ = json.Marshal(struct {
			RequestID          string `json:"requestId"`
			ResponseHost       string `json:"responseHost"`
			TokenRequestorID   string `json:"tokenRequestorId"`
			FundingAccountInfo td     `json:"fundingAccountInfo"`
		}{
			RequestID:        reqID,
			ResponseHost:     respHost,
			TokenRequestorID: RequestorID,
			FundingAccountInfo: td{
				TokenUniqueReference: tokenURef,
			},
		})
	case panURef != "":
		type td struct {
			PanUniqueReference string `json:"panUniqueReference"`
		}
		payload, _ = json.Marshal(struct {
			RequestID          string `json:"requestId"`
			ResponseHost       string `json:"responseHost"`
			TokenRequestorID   string `json:"tokenRequestorId"`
			FundingAccountInfo td     `json:"fundingAccountInfo"`
		}{
			RequestID:        reqID,
			ResponseHost:     respHost,
			TokenRequestorID: RequestorID,
			FundingAccountInfo: td{
				PanUniqueReference: panURef,
			},
		})
	case cardData.AccountNumber != "":

		payloadToEncrypt, _ := json.Marshal(struct {
			CardAccountData CardAccountData `json:"cardAccountData"`
		}{
			cardData,
		})

		encrPayload, err := m.encryptPayload(payloadToEncrypt)
		if err != nil {
			return nil, err
		}

		type td struct {
			EncryptedPayload encryptedPayload `json:"encryptedPayload"`
		}

		payload, _ = json.Marshal(struct {
			RequestID          string `json:"requestId"`
			ResponseHost       string `json:"responseHost"`
			TokenRequestorID   string `json:"tokenRequestorId"`
			FundingAccountInfo td     `json:"fundingAccountInfo"`
		}{
			RequestID:        reqID,
			ResponseHost:     respHost,
			TokenRequestorID: RequestorID,
			FundingAccountInfo: td{
				EncryptedPayload: *encrPayload,
			},
		})
	default:
		return nil, errors.New("incorrect request parameters")
	}

	response, err := m.request("POST", m.urlSearch, payload)
	if err != nil {
		return nil, err
	}

	responseData := struct {
		Tokens []TokenStatus
	}{
		Tokens: []TokenStatus{},
	}

	if err := json.Unmarshal(response, &responseData); err != nil {
		return nil, err
	}

	return responseData.Tokens, nil
}

// GetToken is the universal API implementation of MDES SearchToken API call
func (m MDESapi) GetToken(RequestorID, tokenURef string) (*TokenInfo, error) {

	// TO DO: generate random ID
	reqID := "123456"
	respHost := "assist.ru"

	payload, _ := json.Marshal(struct {
		RequestID    string `json:"requestId"`
		ResponseHost string `json:"responseHost"`
		//TokenRequestorID     string `json:"tokenRequestorId"`
		TokenUniqueReference string `json:"tokenUniqueReference"`
		PaymentAppInstanceID string `json:"paymentAppInstanceId"`
		IincludeTokenDetail  string `json:"includeTokenDetail"`
	}{
		RequestID:    reqID,
		ResponseHost: respHost,
		//TokenRequestorID:     RequestorID,
		TokenUniqueReference: tokenURef,
		PaymentAppInstanceID: "123456789",
		IincludeTokenDetail:  "true",
	})

	response, err := m.request("POST", m.urlGetToken, payload)
	if err != nil {
		return nil, err
	}
	responseStruct := struct {
		Token struct {
			TokenUniqueReference string
			PanUniqueReference   string
			Status               string
			StatusTimestamp      string
			ProductConfig        struct {
				BrandLogoAssetID              string
				IssuerLogoAssetID             string
				IsCoBranded                   string
				CoBrandName                   string
				CoBrandLogoAssetID            string
				CardBackgroundCombinedAssetID string
				CardBackgroundAssetID         string
				IconAssetID                   string
				ForegroundColor               string
				IssuerName                    string
				ShortDescription              string
				LongDescription               string
				CustomerServiceURL            string
				CustomerServiceEmail          string
				CustomerServicePhoneNumber    string
				OonlineBankingLoginURL        string
				TermsAndConditionsURL         string
				PrivacyPolicyURL              string
				IssuerProductConfigCode       string
			}

			TokenInfo struct {
				TokenPanSuffix      string
				AccountPanSuffix    string
				TokenExpiry         string
				AccountPanExpiry    string
				DsrpCapable         bool
				TokenAssuranceLevel int
				ProductCategory     string
			}
		}
		TokenDetail encryptedPayload
	}{}

	if err := json.Unmarshal(response, &responseStruct); err != nil {
		return nil, err
	}

	decrypted, err := m.decryptPayload(&responseStruct.TokenDetail)
	if err != nil {
		return nil, err
	}

	// >>> remove in PROD env
	log.Printf("Decrypted(myPrivKey) payload:\n%s\n", decrypted)
	// <<< remove in PROD env

	tokenDetail := struct {
		TokenNumber             string
		ExpiryMonth             string
		paymentAccountReference string
		dataValidUntilTimestamp string
		PaymentAccountReference string
	}{}

	err = json.Unmarshal(decrypted, &tokenDetail)
	if err != nil {
		return nil, err
	}

	return &TokenInfo{
		TokenUniqueReference:    responseStruct.Token.TokenUniqueReference,
		TokenPanSuffix:          responseStruct.Token.TokenInfo.TokenPanSuffix,
		TokenExpiry:             responseStruct.Token.TokenInfo.TokenExpiry,
		PanUniqueReference:      responseStruct.Token.PanUniqueReference,
		PanSuffix:               responseStruct.Token.TokenInfo.AccountPanSuffix,
		PanExpiry:               responseStruct.Token.TokenInfo.AccountPanExpiry,
		BrandAssetID:            responseStruct.Token.ProductConfig.CardBackgroundAssetID,
		ProductCategory:         responseStruct.Token.TokenInfo.ProductCategory,
		DsrpCapable:             responseStruct.Token.TokenInfo.DsrpCapable,
		PaymentAccountReference: tokenDetail.PaymentAccountReference,
	}, nil
}

// Transact is the universal API implementation of MDES Transact API call
func (m MDESapi) Transact(transactdata TransactData) (*CryptogramData, error) {

	req := struct {
		ResponseHost         string `json:"responseHost"`
		RequestID            string `json:"requestId"`
		TokenUniqueReference string `json:"tokenUniqueReference"`
		CryptogramType       string `json:"cryptogramType"`
	}{
		ResponseHost:         "assist.ru",
		RequestID:            "2093809230",
		TokenUniqueReference: transactdata.TokenUniqueReference,
		CryptogramType:       transactdata.CryptogramType,
	}

	payload, _ := json.Marshal(req)

	respone, err := m.request("POST", m.urlTransact, payload)
	if err != nil {
		return nil, err
	}

	responceData := struct {
		EncryptedPayload encryptedPayload
	}{
		EncryptedPayload: encryptedPayload{},
	}

	if err := json.Unmarshal(respone, &responceData); err != nil {
		return nil, err
	}

	decrypted, err := m.decryptPayload(&responceData.EncryptedPayload)
	if err != nil {
		return nil, err
	}

	// >>> remove in PROD env
	log.Printf("Decrypted(myPrivKey) payload:\n%s\n", decrypted)
	// <<< remove in PROD env

	returnData := CryptogramData{}

	if err := json.Unmarshal(decrypted, &returnData); err != nil {
		return nil, err
	}

	return &returnData, nil
}

// Suspend is the universal API implementation of MDES Suspend API call
func (m MDESapi) Suspend(tokens []string, causedBy, reasonCode string) ([]TokenStatus, error) {

	return m.manageTokens(m.urlSuspend, tokens, causedBy, reasonCode)
}

// Unsuspend is the universal API implementation of MDES Unsuspend API call
func (m MDESapi) Unsuspend(tokens []string, causedBy, reasonCode string) ([]TokenStatus, error) {

	return m.manageTokens(m.urlUnsuspend, tokens, causedBy, reasonCode)
}

// Delete is the universal API implementation of MDES Delete API call
func (m MDESapi) Delete(tokens []string, causedBy, reasonCode string) ([]TokenStatus, error) {

	return m.manageTokens(m.urlDelete, tokens, causedBy, reasonCode)
}

// manageTokens - backend for suspend|unsuspend|delete universal API implementation of MDES Transact API calls
func (m MDESapi) manageTokens(url string, tokens []string, causedBy, reasonCode string) ([]TokenStatus, error) {

	req := struct {
		ResponseHost          string   `json:"responseHost"`
		RequestID             string   `json:"requestId"`
		TokenUniqueReferences []string `json:"tokenUniqueReferences"`
		CausedBy              string   `json:"causedBy"`
		ReasonCode            string   `json:"reasonCode"`
	}{
		ResponseHost:          "assist.ru",
		RequestID:             "2093809230",
		TokenUniqueReferences: tokens,
		CausedBy:              causedBy,
		ReasonCode:            reasonCode,
	}

	payload, _ := json.Marshal(req)

	respone, err := m.request("POST", url, payload)
	if err != nil {
		return nil, err
	}

	responceData := struct {
		Tokens []TokenStatus
	}{
		Tokens: []TokenStatus{},
	}

	if err := json.Unmarshal(respone, &responceData); err != nil {
		return nil, err
	}

	return responceData.Tokens, nil
}

// GetAsset is the universal API implementation of MDES GetAsset API call
func (m MDESapi) GetAsset(assetID string) ([]MediaContent, error) {

	respone, err := m.request("GET", m.urlGetAssets+assetID, nil)
	if err != nil {
		return nil, err
	}

	responceData := struct {
		MediaContents []MediaContent
	}{}

	if err := json.Unmarshal(respone, &responceData); err != nil {
		return nil, err
	}

	return responceData.MediaContents, nil
}

// Notify is call-back handler
func (m MDESapi) Notify(payload []byte) (string, error) {

	reqData := struct {
		ResponseHost     string
		RequestID        string
		EncryptedPayload encryptedPayload
	}{}

	if err := json.Unmarshal(payload, &reqData); err != nil {
		return "", err
	}

	decrypted, err := m.decryptPayload(&reqData.EncryptedPayload)
	if err != nil {
		return reqData.RequestID, err
	}

	// TO DO: handle notification
	log.Printf("Notify decrypted payload:\n%s\n", decrypted)

	return reqData.RequestID, nil
}
