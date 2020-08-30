// Package mdes - MDES API adapter
// It handles the requests singining, data encryption and decryption according to MDES protocol requerements
// It provides the following methods to interact with MDES API:
// - Tokenize - card tokenization
// - Transact - dPand and cryptogram provider for transactions by token
// - Delete - allows to delete token
// - GetAsset - provides media assets
// The adapter also handles the notification call-backs from the MDES side. The http/https call-back listener is configured by the adapter configuration.
// The busines logic level have to provide the call-back handler function in the adapter creation call.
// Adapter provides the ShutDown function for gracefull shutdown of the call-back lestener.
package mdes

import (
	"bytes"
	"context"
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
	tools "github.com/slytomcat/tokenizer/tools"
)

type keywfp struct {
	Key         string
	Fingerprint string
}

// Config configuration for MDES
type Config struct {
	System           string
	CallBackURI      string
	CallBackHostPort string
	TLSCert          string
	TLSKey           string
	SignKey          string
	EcryptKey        string
	EncrypKeyFp      string
	DecryptKeys      []keywfp // to support multiple keys
	APIKey           string
}

// MDESapi TokenizerAPI implementation for MasterCard MDES Digital enabled API
type MDESapi struct {
	oAuthSigner        *oauth.Signer
	storedDecryptKeys  map[string]*rsa.PrivateKey //- to support multiple keys
	storedEncryptKey   *rsa.PublicKey
	storedEncryptKeyFP string
	mutex              *sync.RWMutex  // RWmutex requered for KeyExchangeManager
	ourputRe           *regexp.Regexp // compiled regexp for output filtration
	urlTokenize        string
	urlTransact        string
	urlDelete          string
	urlGetAsset        string
	// urlSuspend         string
	// urlUnsuspend       string
	// urlGetToken        string
	// urlSearch          string
	cbHandler func(NotificationTokenData)
	ShutDown  func() error // adapter gracefull sutdown function
}

// encryptedPayload structure of encrypted payload of MDES API
type encryptedPayload struct {
	EncryptedData        string `json:"encryptedData"`        //
	EncryptedKey         string `json:"encryptedKey"`         //
	OaepHashingAlgorithm string `json:"oaepHashingAlgorithm"` //
	PublicKeyFingerprint string `json:"publicKeyFingerprint"` //
	Iv                   string `json:"iv"`                   //
}

// NewMDESapi creates new MDESapi adapter implementation.
func NewMDESapi(conf *Config, cbHandler func(NotificationTokenData)) (*MDESapi, error) {

	mAPI := &MDESapi{
		mutex:     &sync.RWMutex{}, // RWmutex requered for KeyExchangeManager
		cbHandler: cbHandler,
	}

	var err error
	mAPI.ourputRe, err = regexp.Compile(`"data":"[^"]*"`)
	if err != nil {
		log.Printf("ERROR: regexp creation error: %v", err)
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
	default:
		return nil, errors.New("wrong system type")
	}

	mAPI.urlTokenize = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/tokenize", MDESsys, MDESenv)
	mAPI.urlTransact = fmt.Sprintf("https://%sapi.mastercard.com/mdes/remotetransaction/%s1/0/transact", MDESsys, MDESenv)
	mAPI.urlDelete = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/delete", MDESsys, MDESenv)
	mAPI.urlGetAsset = fmt.Sprintf("https://%sapi.mastercard.com/mdes/assets/%s1/0/asset/", MDESsys, MDESenv)
	// mAPI.urlSuspend = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/suspend", MDESsys, MDESenv)
	// mAPI.urlUnsuspend = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/unsuspend", MDESsys, MDESenv)
	// mAPI.urlGetToken = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/getToken", MDESsys, MDESenv)
	// mAPI.urlSearch = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/searchTokens", MDESsys, MDESenv)

	// start CallBack service
	server := http.Server{
		Addr: conf.CallBackHostPort,
		Handler: callBackHandler{
			cbFunc: mAPI.notify,
			path:   conf.CallBackURI,
		},
	}

	mAPI.ShutDown = func() error { return server.Shutdown(context.Background()) }

	go func() {
		log.Printf("INFO: Starting MDES callback service at %s", conf.CallBackHostPort)
		var err error
		if conf.TLSCert == "" && tools.DEBUG {
			err = server.ListenAndServe()
		} else {
			err = server.ListenAndServeTLS(conf.TLSCert, conf.TLSKey)
		}

		if !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
		log.Printf("INFO: MDES callback service: %v", err)
	}()

	return mAPI, nil
}

type callBackHandler struct {
	cbFunc func([]byte) (string, error)
	path   string
}

func (c callBackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.Path != c.path {
		log.Printf("ERROR: wrong metod/path: %s%s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("ERROR: notification body reading error:%v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id, err := c.cbFunc(body)
	if err != nil {
		log.Printf("ERROR: notification handling error: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	responce, _ := json.Marshal(struct {
		ResponseHost string `json:"responseHost"`
		ResponseID   string `json:"responseId"`
	}{
		ResponseHost: "assist.ru",
		ResponseID:   id,
	})

	w.Header().Add("Content-Type", "application/json")
	w.Write(responce)

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

	// TO DO decide what to output in log/debug concole
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
	// TO DO decide what to output in log/debug concole
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
func (m MDESapi) Tokenize(outSystem, requestorID string, cardData CardAccountData, source string) (*TokenInfo, error) {

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
		TokenStatus
		ProductConfig ProductConfig
		TokenInfo     TokenInfo
		TokenDetail   encryptedPayload
	}{}

	if err := json.Unmarshal(response, &responseStruct); err != nil {
		return nil, err
	}

	decrypted, err := m.decryptPayload(&responseStruct.TokenDetail)
	if err != nil {
		return nil, err
	}

	tools.Debug("Decrypted(myPrivKey) payload:\n%s\n", decrypted)

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
	responseStruct.TokenInfo.TokenUniqueReference = responseStruct.TokenUniqueReference
	responseStruct.TokenInfo.PaymentAccountReference = tokenDetail.PaymentAccountReference
	responseStruct.TokenInfo.BrandAssetID = responseStruct.ProductConfig.CardBackgroundCombinedAssetID
	// ! ! ! TESTING TRICK (REMOVE IT BY MOVING TO MTF):
	// Falsificate assetID
	responseStruct.TokenInfo.BrandAssetID = "3789637f-32a1-4810-a138-4bf34501c509"
	// REMOVE IT BY MOVING TO MTF|PROD ! ! !
	return &responseStruct.TokenInfo, nil
}

// Transact implementation of MDES Transact API call
func (m MDESapi) Transact(tur string) (*CryptogramData, error) {

	payload, _ := json.Marshal(struct {
		ResponseHost         string `json:"responseHost"`
		RequestID            string `json:"requestId"`
		TokenUniqueReference string `json:"tokenUniqueReference"`
		CryptogramType       string `json:"cryptogramType"`
	}{
		ResponseHost:         "assist.ru",
		RequestID:            "2093809230",
		TokenUniqueReference: tur,
		CryptogramType:       "UCAF",
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

	tools.Debug("Decrypted(myPrivKey) payload:\n%s\n", decrypted)

	returnData := CryptogramData{}

	if err := json.Unmarshal(decrypted, &returnData); err != nil {
		return nil, err
	}

	return &returnData, nil
}

// // Suspend is implementation of MDES Suspend API call
// func (m MDESapi) Suspend(tokens []string, causedBy, reasonCode string) ([]MCTokenStatus, error) {

// 	return m.manageTokens(m.urlSuspend, tokens, causedBy, reasonCode)
// }

// // Unsuspend is implementation of MDES Unsuspend API call
// func (m MDESapi) Unsuspend(tokens []string, causedBy, reasonCode string) ([]MCTokenStatus, error) {

// 	return m.manageTokens(m.urlUnsuspend, tokens, causedBy, reasonCode)
// }

// Delete is implementation of MDES Delete API call
func (m MDESapi) Delete(tokens []string, causedBy, reasonCode string) ([]TokenStatus, error) {

	//	return m.manageTokens(m.urlDelete, tokens, causedBy, reasonCode)
	//}

	// manageTokens - backend for suspend|unsuspend|delete universal API implementation of MDES Transact API calls
	//func (m MDESapi) manageTokens(url string, tokens []string, causedBy, reasonCode string) ([]TokenStatus, error) {

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

	respone, err := m.request("POST", m.urlDelete, payload) //url, payload)
	if err != nil {
		return nil, err
	}

	responceData := struct {
		Tokens []TokenStatus
	}{}

	if err := json.Unmarshal(respone, &responceData); err != nil {
		return nil, err
	}

	return responceData.Tokens, nil
}

// GetAsset is the implementation of MDES GetAsset API call
func (m MDESapi) GetAsset(assetID string) (*MediaContent, error) {

	responce, err := m.request("GET", m.urlGetAsset+assetID, nil)
	if err != nil {
		return nil, fmt.Errorf("getting asset error: %v", err)
	}
	responceData := struct {
		MediaContents MediaContents
	}{}

	if err := json.Unmarshal(responce, &responceData); err != nil {
		return nil, err
	}

	if len(responceData.MediaContents) < 1 {
		return nil, errors.New("no media data received")
	}

	return &responceData.MediaContents[0], nil
}

// notify is call-back handler
func (m MDESapi) notify(payload []byte) (string, error) {
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

	tools.Debug("Notify decrypted payload:\n%s\n", decrypted)

	// ! ! ! TESTING TRICK (REMOVE IT BY MOVING TO MTF):
	// Falsificate decrypted data with the response from the Search Token request
	decrypted = []byte(`{"tokens":[{"tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","status":"ACTIVE","statusTimestamp":"2017-09-05T00:00:00.000Z"},{"tokenUniqueReference":"DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","status":"ACTIVE","statusTimestamp":"2017-09-06T00:00:00.000Z"},{"tokenUniqueReference":"DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532","status":"SUSPENDED","suspendedBy":["TOKEN_REQUESTOR"],"statusTimestamp":"2017-09-07T00:00:00.000Z"}]}`)
	//log.Printf("Falsificated payload:\n%s\n", decrypted)
	// REMOVE IT BY MOVING TO MTF|PROD ! ! !

	// unwrap decrypted data
	responceData := NotificationTokensData{}

	err = json.Unmarshal(decrypted, &responceData)
	if err != nil {
		return reqData.RequestID, err
	}

	if len(responceData.Tokens) == 0 {
		return reqData.RequestID, errors.New("no data in the list of Tokens")
	}

	// forward notifications for each token
	for _, t := range responceData.Tokens {
		go m.cbHandler(t)
	}
	return reqData.RequestID, nil
}

// //GetToken is implementation of MDES SearchToken API call
// func (m MDESapi) GetToken(RequestorID, tokenURef string) (*TokenInfo, error) {

// 	// TO DO: generate random ID
// 	reqID := "123456"
// 	respHost := "assist.ru"

// 	payload, _ := json.Marshal(struct {
// 		RequestID    string `json:"requestId"`
// 		ResponseHost string `json:"responseHost"`
// 		//TokenRequestorID     string `json:"tokenRequestorId"`
// 		TokenUniqueReference string `json:"tokenUniqueReference"`
// 		PaymentAppInstanceID string `json:"paymentAppInstanceId"`
// 		IincludeTokenDetail  string `json:"includeTokenDetail"`
// 	}{
// 		RequestID:    reqID,
// 		ResponseHost: respHost,
// 		//TokenRequestorID:     RequestorID,
// 		TokenUniqueReference: tokenURef,
// 		PaymentAppInstanceID: "123456789",
// 		IincludeTokenDetail:  "true",
// 	})

// 	response, err := m.request("POST", m.urlGetToken, payload)
// 	if err != nil {
// 		return nil, err
// 	}
// 	responseStruct := struct {
// 		Token struct {
// 			MCTokenStatus
// 			ProductConfig MCProductConfig
// 			TokenInfo     MCTokenInfo
// 		}
// 		TokenDetail encryptedPayload
// 	}{}

// 	if err := json.Unmarshal(response, &responseStruct); err != nil {
// 		return nil, err
// 	}

// 	decrypted, err := m.decryptPayload(&responseStruct.TokenDetail)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// >>> remove in PROD env
// 	log.Printf("Decrypted(myPrivKey) payload:\n%s\n", decrypted)
// 	// <<< remove in PROD env

// 	tokenDetail := struct {
// 		TokenNumber             string
// 		ExpiryMonth             string
// 		paymentAccountReference string
// 		dataValidUntilTimestamp string
// 		PaymentAccountReference string
// 	}{}

// 	err = json.Unmarshal(decrypted, &tokenDetail)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &TokenInfo{
// 		TokenUniqueReference:    responseStruct.Token.TokenUniqueReference,
// 		TokenPanSuffix:          responseStruct.Token.TokenInfo.TokenPanSuffix,
// 		TokenExpiry:             responseStruct.Token.TokenInfo.TokenExpiry,
// 		PanUniqueReference:      responseStruct.Token.TokenInfo.PanUniqueReference,
// 		PanSuffix:               responseStruct.Token.TokenInfo.AccountPanSuffix,
// 		PanExpiry:               responseStruct.Token.TokenInfo.AccountPanExpiry,
// 		BrandAssetID:            responseStruct.Token.ProductConfig.CardBackgroundCombinedAssetID,
// 		ProductCategory:         responseStruct.Token.TokenInfo.ProductCategory,
// 		PaymentAccountReference: tokenDetail.PaymentAccountReference,
// 	}, nil
// }

// // Search is implementation of MDES SearchToken API call
// func (m MDESapi) Search(RequestorID, tokenURef, panURef string, cardData CardAccountData) ([]MCTokenStatus, error) {

// 	// TO DO: generate random ID
// 	reqID := "123456"
// 	respHost := "assist.ru"
// 	payload := []byte{}
// 	switch {
// 	case tokenURef != "":
// 		type td struct {
// 			TokenUniqueReference string `json:"tokenUniqueReference"`
// 		}
// 		payload, _ = json.Marshal(struct {
// 			RequestID          string `json:"requestId"`
// 			ResponseHost       string `json:"responseHost"`
// 			TokenRequestorID   string `json:"tokenRequestorId"`
// 			FundingAccountInfo td     `json:"fundingAccountInfo"`
// 		}{
// 			RequestID:        reqID,
// 			ResponseHost:     respHost,
// 			TokenRequestorID: RequestorID,
// 			FundingAccountInfo: td{
// 				TokenUniqueReference: tokenURef,
// 			},
// 		})
// 	case panURef != "":
// 		type td struct {
// 			PanUniqueReference string `json:"panUniqueReference"`
// 		}
// 		payload, _ = json.Marshal(struct {
// 			RequestID          string `json:"requestId"`
// 			ResponseHost       string `json:"responseHost"`
// 			TokenRequestorID   string `json:"tokenRequestorId"`
// 			FundingAccountInfo td     `json:"fundingAccountInfo"`
// 		}{
// 			RequestID:        reqID,
// 			ResponseHost:     respHost,
// 			TokenRequestorID: RequestorID,
// 			FundingAccountInfo: td{
// 				PanUniqueReference: panURef,
// 			},
// 		})
// 	case cardData.AccountNumber != "":

// 		payloadToEncrypt, _ := json.Marshal(struct {
// 			CardAccountData CardAccountData `json:"cardAccountData"`
// 		}{
// 			cardData,
// 		})

// 		encrPayload, err := m.encryptPayload(payloadToEncrypt)
// 		if err != nil {
// 			return nil, err
// 		}

// 		type td struct {
// 			EncryptedPayload encryptedPayload `json:"encryptedPayload"`
// 		}

// 		payload, _ = json.Marshal(struct {
// 			RequestID          string `json:"requestId"`
// 			ResponseHost       string `json:"responseHost"`
// 			TokenRequestorID   string `json:"tokenRequestorId"`
// 			FundingAccountInfo td     `json:"fundingAccountInfo"`
// 		}{
// 			RequestID:        reqID,
// 			ResponseHost:     respHost,
// 			TokenRequestorID: RequestorID,
// 			FundingAccountInfo: td{
// 				EncryptedPayload: *encrPayload,
// 			},
// 		})
// 	default:
// 		return nil, errors.New("incorrect request parameters")
// 	}

// 	response, err := m.request("POST", m.urlSearch, payload)
// 	if err != nil {
// 		return nil, err
// 	}

// 	responseData := struct {
// 		Tokens []MCTokenStatus
// 	}{}

// 	if err := json.Unmarshal(response, &responseData); err != nil {
// 		return nil, err
// 	}

// 	return responseData.Tokens, nil
// }
