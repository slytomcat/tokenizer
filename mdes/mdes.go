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
	"time"

	"github.com/go-redis/redis/v7"
	oauth "github.com/mastercard/oauth1-signer-go"
	"github.com/slytomcat/tokenizer/database"
)

const (
	prefix = "MC-" // prefix for keys in storage
)

type keywfp struct {
	Key         string
	Fingerprint string
}

// MDESconf configuration for MDES
type MDESconf struct {
	System      string
	EndPont     string
	SignKey     string
	EcryptKey   string
	EncrypKeyFp string
	//DecryptKey  string
	DecryptKeys []keywfp // to support multiple keys
	APIKey      string
}

// MDESapi TokenizerAPI implementation for MasterCard MDES Digital enabled API
type MDESapi struct {
	oAuthSigner *oauth.Signer
	//storedDecryptKey *rsa.PrivateKey
	storedDecryptKeys  map[string]*rsa.PrivateKey //- to support multiple keys
	storedEncryptKey   *rsa.PublicKey
	storedEncryptKeyFP string
	mutex              *sync.RWMutex  // RWmutex requered for KeyExchangeManager
	ourputRe           *regexp.Regexp // compiled regexp for output filtration
	urlTokenize        string
	urlTransact        string
	urlSuspend         string
	urlUnsuspend       string
	urlDelete          string
	urlGetAsset        string
	urlGetToken        string
	urlSearch          string
	db                 redis.UniversalClient
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
func NewMDESapi(conf *MDESconf, db redis.UniversalClient) (*MDESapi, error) {
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
		db:    db,
	}

	var err error
	mAPI.ourputRe, err = regexp.Compile(`"data":"[^"]*"`)
	if err != nil {
		log.Printf("regexp creation error: %v", err)
	}

	if err := mAPI.initKeys(conf); err != nil {
		return nil, err
	}

	MDESenv, MDESsys := "", ""
	switch conf.System {
	case "SandBox":
		MDESenv = "static/"  // can be "mtf/" or "" for PROD
		MDESsys = "sandbox." // can be "" for MTF and PROD
	case "MTF":
		MDESenv = "mtf/"
		MDESsys = ""
	case "PROD":
		MDESenv = ""
		MDESsys = ""
	}

	mAPI.urlTokenize = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/tokenize", MDESsys, MDESenv)
	mAPI.urlTransact = fmt.Sprintf("https://%sapi.mastercard.com/mdes/remotetransaction/%s1/0/transact", MDESsys, MDESenv)
	mAPI.urlSuspend = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/suspend", MDESsys, MDESenv)
	mAPI.urlUnsuspend = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/unsuspend", MDESsys, MDESenv)
	mAPI.urlDelete = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/delete", MDESsys, MDESenv)
	mAPI.urlGetAsset = fmt.Sprintf("https://%sapi.mastercard.com/mdes/assets/%s1/0/asset/", MDESsys, MDESenv)
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

	// fiter output
	output := m.ourputRe.ReplaceAll(body, []byte(`"data":"--<--data skiped-->--"`))
	log.Printf("    >>>>>>>    Response: %s\n%s\n", responce.Status, output)

	// check the status code
	if responce.StatusCode != 200 {
		return nil, fmt.Errorf("responce error: %s", responce.Status)
	}

	// check body for error
	if bytes.Contains(body, []byte("errorCode")) {
		// get error details
		errData := MCError{}
		err := json.Unmarshal(body, &errData)
		if err != nil {
			return nil, fmt.Errorf("unmarshling error structure error: %v", err)
		}
		return nil, fmt.Errorf("responce error received: %+v", errData)
	}

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
	// decrypt encryptedKey
	sessionKey, err := rsa.DecryptOAEP(hash, rand.Reader, m.decrypKey(ePayload.PublicKeyFingerprint), encryptedKey, nil)
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
func (m MDESapi) Tokenize(outSystem, requestorID string, cardData CardAccountData, source string) (*MCTokenInfo, error) {

	payloadToEncrypt, _ := json.Marshal(struct {
		CardAccountData CardAccountData `json:"cardAccountData"`
		Source          string          `json:"source"`
	}{
		CardAccountData: cardData,
		Source:          source,
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
		TokenRequestorID: requestorID,
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
		MCTokenStatus
		ProductConfig MCProductConfig
		TokenInfo     MCTokenInfo
		TokenDetail   encryptedPayload
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
	// run assets loading to cache in separate goroutine
	go m.asyncGetAsset(responseStruct.ProductConfig.CardBackgroundCombinedAssetID)

	// store token data in separate goroutine
	go m.asyncStoreTokenData(outSystem, requestorID, responseStruct.TokenUniqueReference, responseStruct.Status, responseStruct.StatusTimestamp)

	return &MCTokenInfo{
		TokenUniqueReference:    responseStruct.TokenUniqueReference,
		TokenPanSuffix:          responseStruct.TokenInfo.TokenPanSuffix,
		TokenExpiry:             responseStruct.TokenInfo.TokenExpiry,
		PanUniqueReference:      responseStruct.TokenInfo.PanUniqueReference,
		PanSuffix:               responseStruct.TokenInfo.PanSuffix,
		PanExpiry:               responseStruct.TokenInfo.PanExpiry,
		BrandAssetID:            responseStruct.ProductConfig.CardBackgroundCombinedAssetID,
		ProductCategory:         responseStruct.TokenInfo.ProductCategory,
		DsrpCapable:             responseStruct.TokenInfo.DsrpCapable,
		PaymentAccountReference: tokenDetail.PaymentAccountReference,
	}, nil
}

// storeTokenData strores token data in to cache.
// It should be run in separate goroutine
func (m MDESapi) asyncStoreTokenData(outSystem, requestorID, tokenUniqueReference, status, statusTimestamp string) {
	data, _ := json.Marshal(database.TokenData{
		OutSystem:   outSystem,
		RequestorID: requestorID,
	})

	err := m.db.Set(prefix+tokenUniqueReference, data, 0).Err()
	if err != nil {
		log.Printf("ERROR: token info storing error: %v", err)
	} else {
		log.Printf("INFO: stored info for token %s: %s", prefix+tokenUniqueReference, data)
	}
}

// Search is the universal API implementation of MDES SearchToken API call
func (m MDESapi) Search(RequestorID, tokenURef, panURef string, cardData CardAccountData) ([]MCTokenStatus, error) {

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
		Tokens []MCTokenStatus
	}{}

	if err := json.Unmarshal(response, &responseData); err != nil {
		return nil, err
	}

	return responseData.Tokens, nil
}

// GetToken is the universal API implementation of MDES SearchToken API call
func (m MDESapi) GetToken(RequestorID, tokenURef string) (*MCTokenInfo, error) {

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
			MCTokenStatus
			ProductConfig MCProductConfig
			TokenInfo     MCTokenInfo
		}
		TokenDetail encryptedPayload
	}{}

	if err := json.Unmarshal(response, &responseStruct); err != nil {
		return nil, err
	}

	// run background assets loading to cache
	go m.asyncGetAsset(responseStruct.Token.ProductConfig.CardBackgroundCombinedAssetID)

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

	return &MCTokenInfo{
		TokenUniqueReference:    responseStruct.Token.TokenUniqueReference,
		TokenPanSuffix:          responseStruct.Token.TokenInfo.TokenPanSuffix,
		TokenExpiry:             responseStruct.Token.TokenInfo.TokenExpiry,
		PanUniqueReference:      responseStruct.Token.TokenInfo.PanUniqueReference,
		PanSuffix:               responseStruct.Token.TokenInfo.PanSuffix,
		PanExpiry:               responseStruct.Token.TokenInfo.PanExpiry,
		BrandAssetID:            responseStruct.Token.ProductConfig.CardBackgroundCombinedAssetID,
		ProductCategory:         responseStruct.Token.TokenInfo.ProductCategory,
		DsrpCapable:             responseStruct.Token.TokenInfo.DsrpCapable,
		PaymentAccountReference: tokenDetail.PaymentAccountReference,
	}, nil
}

// Transact is the universal API implementation of MDES Transact API call
func (m MDESapi) Transact(transactdata TransactData) (*MCCryptogramData, error) {

	payload, _ := json.Marshal(struct {
		ResponseHost         string `json:"responseHost"`
		RequestID            string `json:"requestId"`
		TokenUniqueReference string `json:"tokenUniqueReference"`
		CryptogramType       string `json:"cryptogramType"`
	}{
		ResponseHost:         "assist.ru",
		RequestID:            "2093809230",
		TokenUniqueReference: transactdata.TokenUniqueReference,
		CryptogramType:       transactdata.CryptogramType,
	})

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

	returnData := MCCryptogramData{}

	if err := json.Unmarshal(decrypted, &returnData); err != nil {
		return nil, err
	}

	return &returnData, nil
}

// Suspend is the universal API implementation of MDES Suspend API call
func (m MDESapi) Suspend(tokens []string, causedBy, reasonCode string) ([]MCTokenStatus, error) {

	return m.manageTokens(m.urlSuspend, tokens, causedBy, reasonCode)
}

// Unsuspend is the universal API implementation of MDES Unsuspend API call
func (m MDESapi) Unsuspend(tokens []string, causedBy, reasonCode string) ([]MCTokenStatus, error) {

	return m.manageTokens(m.urlUnsuspend, tokens, causedBy, reasonCode)
}

// Delete is the universal API implementation of MDES Delete API call
func (m MDESapi) Delete(tokens []string, causedBy, reasonCode string) ([]MCTokenStatus, error) {

	return m.manageTokens(m.urlDelete, tokens, causedBy, reasonCode)
}

// manageTokens - backend for suspend|unsuspend|delete universal API implementation of MDES Transact API calls
func (m MDESapi) manageTokens(url string, tokens []string, causedBy, reasonCode string) ([]MCTokenStatus, error) {

	payload, _ := json.Marshal(struct {
		ResponseHost          string   `json:"responseHost"`
		RequestID             string   `json:"requestId"`
		TokenUniqueReferences []string `json:"tokenUniqueReferences"`
		CausedBy              string   `json:"causedBy"`
		ReasonCode            string   `json:"reasonCode"`
	}{
		ResponseHost:          "assist.ru",
		RequestID:             "2093809230", // TO DO: make it unique
		TokenUniqueReferences: tokens,
		CausedBy:              causedBy,
		ReasonCode:            reasonCode,
	})

	respone, err := m.request("POST", url, payload)
	if err != nil {
		return nil, err
	}

	responceData := struct {
		Tokens []MCTokenStatus
	}{}

	if err := json.Unmarshal(respone, &responceData); err != nil {
		return nil, err
	}

	return responceData.Tokens, nil
}

// GetAsset is the universal API implementation of MDES GetAsset API call
func (m MDESapi) GetAsset(assetID string) (MCMediaContents, error) {

	responce := []byte{}

	data, err := m.db.Get(prefix + assetID).Result()
	if err != nil {
		responce, err = m.request("GET", m.urlGetAsset+assetID, nil)
		if err != nil {
			return nil, fmt.Errorf("getting asset error: %v", err)
		}
		// store th the asset to cache in separate goroutine
		go m.asyncStoreAsset(assetID, responce)

	} else {
		responce = []byte(data)
		log.Printf("media for assetID: %s received from cache", assetID)
	}

	responceData := struct {
		MediaContents MCMediaContents
	}{}

	if err := json.Unmarshal(responce, &responceData); err != nil {
		return nil, err
	}

	return responceData.MediaContents, nil
}

// asyncGetAsset checks assets existance in cache. If it is not exists then get asset from MDES and store it into cache.
// It is suitable to be run asynchronously in separate goroutine as it doesn't perform unnecessary data formating that GetAsset do.
func (m MDESapi) asyncGetAsset(assetID string) {
	if assetID != "" {
		n, err := m.db.Exists(prefix + assetID).Result()
		if err != nil {
			log.Printf("checking assets existance error:%v", err)
			return
		}
		if n == 0 {
			responce, err := m.request("GET", m.urlGetAsset+assetID, nil)
			if err != nil {
				log.Printf("getting asset error: %v", err)
				return
			}
			// since this is already running in a separate goroutine, there is no need to perform asset saving asynchronously
			m.asyncStoreAsset(assetID, responce)
		}
	}
}

// asyncStoreAsset stores asset into cache. It is suitable to be run in separate goroutine.
func (m MDESapi) asyncStoreAsset(assetID string, data []byte) {
	err := m.db.Set(prefix+assetID, string(data), time.Duration(time.Hour*8760)).Err() //1  year expiration ?
	if err != nil {
		log.Printf("media storage error: %v", err)
	} else {
		log.Printf("media for assetID: %s stored to cache", assetID)
	}
}

// Notify is call-back handler
func (m MDESapi) Notify(payload []byte) (string, error) {
	// unwrap the received data
	reqData := struct {
		ResponseHost     string
		RequestID        string
		EncryptedPayload encryptedPayload
	}{}

	if err := json.Unmarshal(payload, &reqData); err != nil {
		return "", err
	}

	// Decrypt data
	decrypted, err := m.decryptPayload(&reqData.EncryptedPayload)
	if err != nil {
		return reqData.RequestID, err
	}

	log.Printf("Notify decrypted payload:\n%s\n", decrypted)

	// ! ! ! TESTING TRICK (REMOVE IT BY MOVING TO MTF):
	// Falsificate decrypted data with the response from the Search Token request
	decrypted = []byte(`{"tokens":[{"tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","status":"ACTIVE","statusTimestamp":"2017-09-05T00:00:00.000Z"},{"tokenUniqueReference":"DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","status":"ACTIVE","statusTimestamp":"2017-09-06T00:00:00.000Z"},{"tokenUniqueReference":"DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532","status":"SUSPENDED","suspendedBy":["TOKEN_REQUESTOR"],"statusTimestamp":"2017-09-07T00:00:00.000Z"}]}`)
	log.Printf("Falsificated payload:\n%s\n", decrypted)
	// REMOVE IT BY MOVING TO MTF|PROD ! ! !

	// unwrap decrypted data
	responceData := MCNotificationTokensData{}

	err = json.Unmarshal(decrypted, &responceData)
	if err != nil {
		return reqData.RequestID, err
	}

	if len(responceData.Tokens) == 0 {
		return reqData.RequestID, errors.New("no data in the list of Tokns")
	}

	// forward notifications for each token
	for _, t := range responceData.Tokens {
		// TO DO: make notification record in db: set("notify"+prefix+t.TokenUniqueReference+timeStamp, json.marshal(t))
		// handle notification forwarding in separate goroutine
		go m.asyncForwardNotification(t) // + "notify"+prefix+t.TokenUniqueReference+timeStamp to handle the notification record
	}
	return reqData.RequestID, nil
}

func (m MDESapi) asyncForwardNotification(t MCNotificationTokenData) {

	// read token related info from storage
	s, err := m.db.Get(prefix + t.TokenUniqueReference).Result()
	if err != nil {
		if err != redis.Nil {
			log.Printf("ERROR: bd access error: %v", err)
		} else {
			log.Printf("n: token %s not found in DB", t.TokenUniqueReference)
		}
		return
	}

	// unwrap stored token data
	storedTokenData := database.TokenData{}
	err = json.Unmarshal([]byte(s), &storedTokenData)
	if err != nil {
		log.Printf("ERROR: marshaling stored token data error: %v", err)
		return
	}

	// update the token asset if it is changed
	go m.asyncGetAsset(t.ProductConfig.CardBackgroundCombinedAssetID)

	log.Printf("INFO: notification for token/system/requestorId: %s/%s/%s", t.TokenUniqueReference, storedTokenData.OutSystem, storedTokenData.RequestorID)

	// TO DO:
	// format data to send
	// update notfication record: set("notify"+prefix+t.TokenUniqueReference+timeStamp, json.marshal(data + recipient), 0)
	// l: send notification
	// get responce
	// if no responce then
	//   if the number of sending attempts is not exceeded
	//      sleep and repeat from l
	//   else
	//      log the problem
	//      return (leaving notification record in db. it will be hanled by scaner)
	// delete notification record from db^ delete("notify"+prefix+t.TokenUniqueReference+timeStamp)

}
