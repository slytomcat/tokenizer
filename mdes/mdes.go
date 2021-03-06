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
	"io"
	"log"
	"net/http"
	"regexp"

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
	TRIDcbURI        string
	TLSCert          string
	TLSKey           string
	SignKey          string
	SignKeyPassw     string
	EcryptKey        string
	EncrypKeyFp      string
	DecryptKeyPassw  string
	DecryptKeys      []keywfp // to support multiple keys
	APIKey           string
	ResponseHost     string
}

// MDESapi TokenizerAPI implementation for MasterCard MDES Digital enabled API
type MDESapi struct {
	ShutDown           func() error // adapter gracefull sutdown function
	cbHandler          func(NotificationTokenData)
	tridHandler        func(string, string)
	oAuthSigner        *oauth.Signer
	storedDecryptKeys  map[string]*rsa.PrivateKey //- to support multiple keys
	storedEncryptKey   *rsa.PublicKey
	storedEncryptKeyFP string
	ourputRe           *regexp.Regexp // compiled regexp for output filtration
	urlTokenize        string
	urlTransact        string
	urlDelete          string
	urlGetAsset        string
	urlSuspend         string
	urlUnsuspend       string
	urlNewTRID         string
	urlGetToken        string
	urlSearch          string
	sandbox            bool
	responseHost       string
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
func NewMDESapi(conf *Config, cbHandler func(NotificationTokenData), tridHandler func(string, string)) (*MDESapi, error) {

	mAPI := &MDESapi{
		cbHandler:    cbHandler,
		tridHandler:  tridHandler,
		responseHost: conf.ResponseHost,
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
		mAPI.sandbox = true
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

	// MDES API request URLs
	mAPI.urlTokenize = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/tokenize", MDESsys, MDESenv)
	mAPI.urlTransact = fmt.Sprintf("https://%sapi.mastercard.com/mdes/remotetransaction/%s1/0/transact", MDESsys, MDESenv)
	mAPI.urlDelete = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/delete", MDESsys, MDESenv)
	mAPI.urlGetAsset = fmt.Sprintf("https://%sapi.mastercard.com/mdes/assets/%s1/0/asset/", MDESsys, MDESenv)
	mAPI.urlSuspend = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/suspend", MDESsys, MDESenv)
	mAPI.urlUnsuspend = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/unsuspend", MDESsys, MDESenv)
	mAPI.urlGetToken = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/getToken", MDESsys, MDESenv)
	mAPI.urlSearch = fmt.Sprintf("https://%sapi.mastercard.com/mdes/digitization/%s1/0/searchTokens", MDESsys, MDESenv)

	// TRID API request URL
	mAPI.urlNewTRID = fmt.Sprintf("https://%sapi.mastercard.com/customerIdAssignment/%stridManagement/requestTokenRequestorId", MDESsys, MDESenv)

	// start CallBack service
	server := http.Server{
		Addr: conf.CallBackHostPort,
		Handler: callBackHandler{
			cbFunc:       mAPI.notify,
			path:         conf.CallBackURI,
			tridFunc:     mAPI.tridCB,
			tridpath:     conf.TRIDcbURI,
			responseHost: conf.ResponseHost,
		},
	}

	mAPI.ShutDown = func() error { return server.Shutdown(context.Background()) }

	go func() {
		var err error
		if conf.TLSCert == "" {
			log.Printf("INFO: Starting http MDES callback service at %s", conf.CallBackHostPort)
			err = server.ListenAndServe()
		} else {
			go func() {
				log.Print("INFO: http to https redirect service at :80")
				err := http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "https://"+conf.CallBackHostPort+r.RequestURI, http.StatusMovedPermanently)
				}))
				if !errors.Is(err, http.ErrServerClosed) {
					panic(err)
				}
			}()
			log.Printf("INFO: Starting MDES callback service at %s", conf.CallBackHostPort)
			err = server.ListenAndServeTLS(conf.TLSCert, conf.TLSKey)
		}

		if !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
		log.Printf("INFO: MDES callback service: %v", err)
	}()

	return mAPI, nil
}

// request makes request with oAuth header by 'url' with 'payload'. It returns response body and error
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
	header, _ := json.Marshal(request.Header)
	log.Printf("    <<<<<<<    Request Heder:\n%v\n", string(header))
	log.Printf("    <<<<<<<    Request Body:\n%s\n", payload)

	// get response
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Printf("request sending error: %v", err)
		return nil, fmt.Errorf("request sending error: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Printf("response body reading error: %v", err)
		return nil, fmt.Errorf("response body reading error: %w", err)
	}

	// fiter output
	output := m.ourputRe.ReplaceAll(body, []byte(`"data":"--<--data skiped-->--"`))
	// TO DO decide what to output in log/debug concole
	log.Printf("    >>>>>>>    Response: %s\n%s\n", response.Status, output)

	// check the status code
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("response error: %s", response.Status)
	}

	// check body for error
	if bytes.Contains(body, []byte("errorCode")) {
		// get error details
		errData := MCError{}
		err := json.Unmarshal(body, &errData)
		if err != nil {
			return nil, fmt.Errorf("unmarshling error structure error: %v", err)
		}
		return nil, fmt.Errorf("response error received: %+v", errData)
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

	// encrypt the session key  !!! hash alg SHA512 is fixed in this implementation
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

	tools.Debug("encypted data: %s", payloadToEncrypt)

	encrPayload, err := m.encryptPayload(payloadToEncrypt)
	if err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(struct {
		// ResponseHost       string `json:"responseHost"`
		RequestID          string `json:"requestId"`
		TaskID             string `json:"taskId"`
		TokenType          string `json:"tokenType"`
		TokenRequestorID   string `json:"tokenRequestorId"`
		FundingAccountInfo struct {
			EncryptedPayload encryptedPayload `json:"encryptedPayload"`
		} `json:"fundingAccountInfo"`
	}{
		// ResponseHost:     m.responseHost,
		RequestID:        tools.UniqueID(),
		TaskID:           tools.UniqueID(),
		TokenType:        "CLOUD", //constant
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
		// AccountHolderData struct {
		// 	AccountHolderName              string
		// 	ConsumerIdentifier             string
		// 	AccountHolderEmailAddress      string
		// 	AccountHolderMobilePhoneNumber struct {
		// 		CountryDialInCode int
		// 		PhoneNumber       int
		// 	}
		// }
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
	if m.sandbox {
		responseStruct.TokenInfo.BrandAssetID = "3789637f-32a1-4810-a138-4bf34501c509"
	}
	// REMOVE IT BY MOVING TO MTF|PROD ! ! !
	responseStruct.TokenInfo.IsCoBranded = responseStruct.ProductConfig.IsCoBranded == "true"
	responseStruct.TokenInfo.CoBrandName = responseStruct.ProductConfig.CoBrandName
	responseStruct.TokenInfo.IssuerName = responseStruct.ProductConfig.IssuerName

	return &responseStruct.TokenInfo, nil
}

// Transact implementation of MDES Transact API call
func (m MDESapi) Transact(tur string) (*CryptogramData, error) {

	payload, _ := json.Marshal(struct {
		//ResponseHost         string `json:"responseHost"`
		RequestID            string `json:"requestId"`
		TokenUniqueReference string `json:"tokenUniqueReference"`
		DsrpType             string `json:"dsrpType"`
		//CryptogramType       string `json:"cryptogramType"`
		UnpredictableNumber string `json:"unpredictableNumber"`
	}{
		//ResponseHost:         m.responseHost,
		RequestID:            tools.UniqueID(),
		TokenUniqueReference: tur,
		DsrpType:             "UCAF",
		//CryptogramType:       "UCAF",
		UnpredictableNumber: tools.UnpredictableNumber(),
	})

	respone, err := m.request("POST", m.urlTransact, payload)
	if err != nil {
		return nil, err
	}

	responseData := struct {
		EncryptedPayload encryptedPayload
	}{}

	if err := json.Unmarshal(respone, &responseData); err != nil {
		return nil, err
	}

	decrypted, err := m.decryptPayload(&responseData.EncryptedPayload)
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

// Manage - common func for suspend|unsuspend|delete universal API implementation of MDES Transact API calls
func (m MDESapi) Manage(method string, tokens []string, causedBy, reasonCode string) ([]TokenStatus, error) {

	payload, _ := json.Marshal(struct {
		ResponseHost          string   `json:"responseHost"`
		RequestID             string   `json:"requestId"`
		TokenUniqueReferences []string `json:"tokenUniqueReferences"`
		CausedBy              string   `json:"causedBy"`
		ReasonCode            string   `json:"reasonCode"`
	}{
		ResponseHost:          m.responseHost,
		RequestID:             tools.UniqueID(),
		TokenUniqueReferences: tokens,
		CausedBy:              causedBy,
		ReasonCode:            reasonCode,
	})

	var url string
	switch method {
	case "D":
		url = m.urlDelete
	case "S":
		url = m.urlSuspend
	case "U":
		url = m.urlUnsuspend
	}
	respone, err := m.request("POST", url, payload)
	if err != nil {
		return nil, err
	}

	responseData := struct {
		Tokens []TokenStatus
	}{}

	if err := json.Unmarshal(respone, &responseData); err != nil {
		return nil, err
	}

	return responseData.Tokens, nil
}

// GetAsset is the implementation of MDES GetAsset API call
func (m MDESapi) GetAsset(assetID string) (*MediaContent, error) {

	response, err := m.request("GET", m.urlGetAsset+assetID, nil)
	if err != nil {
		return nil, fmt.Errorf("getting asset error: %v", err)
	}
	responseData := struct {
		MediaContents MediaContents
	}{}

	if err := json.Unmarshal(response, &responseData); err != nil {
		return nil, err
	}

	if len(responseData.MediaContents) < 1 {
		return nil, errors.New("no media data received")
	}

	return &responseData.MediaContents[0], nil
}

// Call-back handling staff

type callBackHandler struct {
	cbFunc       func([]byte) (string, error)
	path         string
	tridFunc     func([]byte) (string, error)
	tridpath     string
	responseHost string
}

func (c callBackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("ERROR: notification body reading error:%v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var rID string
	switch r.Method + r.URL.Path {
	case "POST" + c.path:
		log.Printf("INFO: NTU call-back received: %s", body)
		rID, err = c.cbFunc(body)
	case "POST" + c.tridpath:
		log.Printf("INFO: TRID API call-back received: %s", body)
		rID, err = c.tridFunc(body)
	case "GET/":
		w.Write([]byte("MDES - ok"))
		return
	default:
		log.Printf("ERROR: wrong metod/path: %s%s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if err != nil {
		log.Printf("ERROR: Call-back handling error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response, _ := json.Marshal(struct {
		ResponseHost string `json:"responseHost"`
		ResponseID   string `json:"responseId"`
	}{
		ResponseHost: c.responseHost,
		ResponseID:   rID,
	})

	w.Header().Add("Content-Type", "application/json")
	w.Write(response)
	return
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
	if m.sandbox {
		decrypted = []byte(`{"tokens":[{"tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","status":"ACTIVE","statusTimestamp":"2017-09-05T00:00:00.000Z"},{"tokenUniqueReference":"DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","status":"ACTIVE","statusTimestamp":"2017-09-06T00:00:00.000Z"},{"tokenUniqueReference":"DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532","status":"SUSPENDED","suspendedBy":["TOKEN_REQUESTOR"],"statusTimestamp":"2017-09-07T00:00:00.000Z"}]}`)
	}
	//log.Printf("Falsificated payload:\n%s\n", decrypted)
	// REMOVE IT BY MOVING TO MTF|PROD ! ! !

	// unwrap decrypted data
	responseData := NotificationTokensData{}

	err = json.Unmarshal(decrypted, &responseData)
	if err != nil {
		return reqData.RequestID, err
	}

	if len(responseData.Tokens) == 0 {
		return reqData.RequestID, errors.New("no data in the list of Tokens")
	}

	// forward notifications for each token
	for _, t := range responseData.Tokens {
		go m.cbHandler(t)
	}
	return reqData.RequestID, nil
}

func (m MDESapi) tridCB(payload []byte) (string, error) {

	type tr struct {
		EntityID         string
		TokenRequestorID string
	}
	rData := struct {
		ResponseHost    string
		RequestID       string
		TokenRequestors []tr
	}{}

	if err := json.Unmarshal(payload, &rData); err != nil {
		return "", err
	}

	if len(rData.TokenRequestors) == 0 {
		return rData.RequestID, errors.New("no data in the list of TRIDs")
	}

	for _, t := range rData.TokenRequestors {
		go m.tridHandler(t.EntityID, t.TokenRequestorID)
	}

	return rData.RequestID, nil
}

//GetToken is implementation of MDES SearchToken API call
func (m MDESapi) GetToken(rtid, tur string) (*TokenStatus, error) {

	payload, _ := json.Marshal(struct {
		RequestID string `json:"requestId"`
		//ResponseHost string `json:"responseHost"`
		//TokenRequestorID     string `json:"tokenRequestorId"`
		TokenUniqueReference string `json:"tokenUniqueReference"`
		//PaymentAppInstanceID string `json:"paymentAppInstanceId"`
		IincludeTokenDetail string `json:"includeTokenDetail"`
	}{
		RequestID: tools.UniqueID(),
		//ResponseHost: m.responseHost,
		//TokenRequestorID:     trid,
		TokenUniqueReference: tur,
		//PaymentAppInstanceID: "M4MCLOUDDSRP", // For M4M token requestors this value is 'M4MCLOUDDSRP' (trid-api.yaml)
		IincludeTokenDetail: "true",
	})

	response, err := m.request("POST", m.urlGetToken, payload)
	if err != nil {
		return nil, err
	}
	responseStruct := struct {
		Token struct {
			TokenStatus
			ProductConfig ProductConfig
			TokenInfo     TokenInfo
		}
		TokenDetail encryptedPayload
	}{}

	if err := json.Unmarshal(response, &responseStruct); err != nil {
		return nil, err
	}

	if len(responseStruct.TokenDetail.EncryptedData) > 0 {
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
	}
	return &TokenStatus{
		TokenUniqueReference: responseStruct.Token.TokenUniqueReference,
		Status:               responseStruct.Token.Status,
		StatusTimestamp:      responseStruct.Token.StatusTimestamp,
	}, nil
}

// Search is implementation of MDES SearchToken API call
func (m MDESapi) Search(trid, tur, panURef string, cardData CardAccountData) ([]TokenStatus, error) {

	reqID := tools.UniqueID()
	respHost := m.responseHost
	payload := []byte{}
	switch {
	case tur != "":
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
			TokenRequestorID: trid,
			FundingAccountInfo: td{
				TokenUniqueReference: tur,
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
			TokenRequestorID: trid,
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
			TokenRequestorID: trid,
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
	}{}

	if err := json.Unmarshal(response, &responseData); err != nil {
		return nil, err
	}

	return responseData.Tokens, nil
}
