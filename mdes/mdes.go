package mdes

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sync"

	oauth "github.com/mastercard/oauth1-signer-go"
)

var (
	mdesAPI *MDESapi
)

// MDESapi TokenizerAPI implementation for MasterCard MDES Digital enabled API
type MDESapi struct {
	oAuthSigner        *oauth.Signer
	storedDecryptKey   *rsa.PrivateKey
	storedEncryptKey   *rsa.PublicKey
	storedEncryptKeyFP string
	mutex              *sync.RWMutex // RWmutex requered for KeyExchangeManager
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
func NewMDESapi() (*MDESapi, error) {
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

	if err := mAPI.initKeys(); err != nil {
		return nil, err
	}

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

	log.Printf("\n    <<<<<<<    Request Heder:\n%v\n", request.Header)
	log.Printf("\n    <<<<<<<    Request Body:\n%s\n", payload)

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

	log.Printf("\n    >>>>>>>    Response: %s\n%s\n", responce.Status, body)

	return body, nil
}

// encryptPayload encrypts the payload
func (m MDESapi) encryptPayload(payload []byte) (*encryptedPayload, error) {

	// get session key as secure random
	sessionKey := make([]byte, 16) // 128 bit
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		return nil, fmt.Errorf("seesion key creation error: %w", err)
	}

	// encrypt the session key  !!! hash alg is fixed in this implementation
	encryptKey, encryptKeyFP := m.encryptKey()

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

	// decode HEX data from encryptedPayload
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
	url := "https://sandbox.api.mastercard.com/mdes/digitization/static/1/0/tokenize"

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
	log.Print(string(payload))
	// <<< remove in PROD env

	respose, err := m.request("POST", url, payload)
	if err != nil {
		return nil, err
	}

	resposeStruct := struct {
		AuthenticationMethods []struct {
			ID    int
			Type  string
			Value string
		}
		TokenUniqueReference string
		PanUniqueReference   string
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

	if err := json.Unmarshal(respose, &resposeStruct); err != nil {
		return nil, err
	}

	decrypted, err := m.decryptPayload(&resposeStruct.TokenDetail)
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
			PaymentAccountReference string
		}
	}{}

	err = json.Unmarshal(decrypted, &tokenDetail)
	if err != nil {
		return nil, err
	}

	return &TokenInfo{
		TokenUniqueReference:    resposeStruct.TokenUniqueReference,
		TokenPanSuffix:          resposeStruct.TokenInfo.TokenPanSuffix,
		TokenExpiry:             resposeStruct.TokenInfo.TokenExpiry,
		PanUniqueReference:      resposeStruct.PanUniqueReference,
		PanSuffix:               resposeStruct.TokenInfo.AccountPanSuffix,
		PanExpiry:               resposeStruct.TokenInfo.AccountPanExpiry,
		BrandAssetID:            resposeStruct.ProductConfig.CardBackgroundAssetID,
		ProductCategory:         resposeStruct.TokenInfo.ProductCategory,
		DsrpCapable:             resposeStruct.TokenInfo.DsrpCapable,
		PaymentAccountReference: tokenDetail.AccountHolderData.PaymentAccountReference,
	}, nil
}

// Transact is the universal API implementation of MDES Transact API call
// func (m MDESapi) Transact(TransactData) (*CryptogramData, error) {
// 	return &CryptogramData{}, nil
// }

//func GetAsset(string) ([]MediaContent, error)
//func Suspend([]string) ([]TokenStatus, error)
//func Unsuspend([]string) ([]TokenStatus, error)
//func Delete([]string) ([]TokenStatus, error)
