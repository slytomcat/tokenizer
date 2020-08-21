package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-redis/redis/v7"
	database "github.com/slytomcat/tokenizer/database"
	"github.com/slytomcat/tokenizer/mdes"
	tools "github.com/slytomcat/tokenizer/tools"
)

var (
	m  *mdes.MDESapi
	db redis.UniversalClient
	// ConfigFile - is the path to the configuration file
	configFile        = flag.String("config", "./config.json", "`path` to the configuration file")
	version    string = "unknown version"
)

func init() {
	log.SetFlags(log.Ldate & log.Lmicroseconds)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage:\t"+filepath.Base(os.Args[0])+" [-config=<Path/to/config.json>]\n\nOptions:\n")
		flag.PrintDefaults()
	}
}

// APIconf configuration for API
type APIconf struct {
	HostPort string
	Cert     string
	Key      string
}

// Config is the service configuration values set
type Config struct {
	API  APIconf
	DB   database.DBConf
	MDES mdes.MDESconf
	//VISA - section for future VISA configuration values
}

func getConfig(path string) *Config {
	// create empty config
	configData := Config{
		API: APIconf{
			Cert: "", //"certs/MyCertificate.crt", //"certs/testCertificate.crt"
			Key:  "", //"certs/MyKey.key", //"certs/testKey.key"
		},
		MDES: mdes.MDESconf{},
	}

	err := tools.ReadJSON(path, &configData)
	if err != nil {
		log.Printf("WARNING: config file opening/reading/parsing error: %v", err)
	}

	err = json.Unmarshal([]byte(os.Getenv("TOKENIZER_CONF")), &configData)
	if err != nil {
		log.Printf("WARNING: config environment variable parsing error: %v", err)
	}

	log.Printf("INFO: service configuration: %+v", configData)

	return &configData
}

func main() {
	flag.Parse()

	if err := doMain(getConfig(*configFile)); err != nil {
		panic(err)
	}
}

func doMain(config *Config) error {

	// connect to databse
	db, err := database.Init(&config.DB)
	if err != nil {
		return err
	}

	// create MasterCard MDES protocol convertor instance
	m, err = mdes.NewMDESapi(&config.MDES, db)
	if err != nil {
		return err
	}

	// start service handlers

	// register API functions
	http.HandleFunc("/api/v1/tokenize", tokenizeHandler)
	http.HandleFunc("/api/v1/transact", transactHandler)
	http.HandleFunc("/api/v1/suspend", suspendHandler)
	http.HandleFunc("/api/v1/unsuspend", unsuspendHandler)
	http.HandleFunc("/api/v1/delete", deleteHandler)
	http.HandleFunc("/api/v1/getassets", getAssetsHandler)
	http.HandleFunc("/api/v1/gettoken", getTokenHandler)
	http.HandleFunc("/api/v1/search", searchHandler)

	// register call-back handler
	http.HandleFunc(config.MDES.EndPont, notifyHandler)

	if config.API.Cert != "" && config.API.Key != "" {
		log.Println("INFO: starting TLS server at", config.API.HostPort)
		return http.ListenAndServeTLS(config.API.HostPort, config.API.Cert, config.API.Key, nil)
	}
	log.Println("INFO: starting server at", config.API.HostPort)
	return http.ListenAndServe(config.API.HostPort, nil)
}

// test:
// curl -v -H "Content-Type: application/json" -d '{"requestorid":"123454","carddata":{"accountNumber":"5123456789012345","expiryMonth":"09","expiryYear":"21","securityCode":"123"},"source":"ACCOUNT_ADDED_MANUALLY"}' http://localhost:8080/api/v1/tokenize

func tokenizeHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reqData := struct {
		OutSystem   string
		RequestorID string
		CardData    mdes.CardAccountData
		Source      string
	}{
		CardData: mdes.CardAccountData{},
	}
	if err = json.Unmarshal(body, &reqData); err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenData, err := m.Tokenize(reqData.OutSystem, reqData.RequestorID, reqData.CardData, reqData.Source)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, _ := json.Marshal(tokenData)
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)
}

// test:
// curl -v -H "Content-Type: application/json" -d '{"tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","cryptogramType":"UCAF"}' http://localhost:8080/api/v1/transact

func transactHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reqData := mdes.TransactData{}
	if err = json.Unmarshal(body, &reqData); err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ransactData, err := m.Transact(reqData)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, _ := json.Marshal(ransactData)
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)
}

// test:
// curl -v -H "Content-Type: application/json" -d '{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}' http://localhost:8080/api/v1/suspend

func suspendHandler(w http.ResponseWriter, req *http.Request) {
	mangeTokens(m.Suspend, w, req)
}

// test:
// curl -v -H "Content-Type: application/json" -d '{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}' http://localhost:8080/api/v1/unsuspend

func unsuspendHandler(w http.ResponseWriter, req *http.Request) {
	mangeTokens(m.Unsuspend, w, req)
}

// test:
// curl -v -H "Content-Type: application/json" -d '{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}' http://localhost:8080/api/v1/delete

func deleteHandler(w http.ResponseWriter, req *http.Request) {
	mangeTokens(m.Delete, w, req)
}

// common handler for Suspens|Unsuspend|Delete API calls
func mangeTokens(action func([]string, string, string) ([]mdes.MCTokenStatus, error), w http.ResponseWriter, req *http.Request) {

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reqData := struct {
		TokenUniqueReferences []string
		CausedBy              string
		ReasonCode            string
	}{}
	if err = json.Unmarshal(body, &reqData); err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	responceData, err := action(reqData.TokenUniqueReferences, reqData.CausedBy, reqData.ReasonCode)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, _ := json.Marshal(responceData)
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)
}

// test:
// curl -v -H "Content-Type: application/json" -d '{"assetid":"3789637f-32a1-4810-a138-4bf34501c509"}' http://localhost:8080/api/v1/getassets
func getAssetsHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reqData := struct {
		AssetID string
	}{}
	if err = json.Unmarshal(body, &reqData); err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	responce, err := m.GetAsset(reqData.AssetID)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, _ := json.Marshal(responce)
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)
}

// test:
// curl -v -H "Content-Type: application/json" -d '{"encryptedPayload":{"publicKeyFingerprint":"982175aa53858f44de919c70b20e011681b9db0deec4f4c117da8ece86a4684e","encryptedKey":"65122ca45c6ceecfce46feec3ca5947f85a1ce96354690880d5c95afb627f0a76401e4c4217f8c783427f02ad1d918afb24c63a437ddb79f36f91ee1c36c199e0822192846c1c74a207e23f3d14ff63b6c12919415568f6edeaa4cbe06dc7850a6439885dd85f1460e8b746bce8a9b1308f69ee4655a3a3a41b7af394bcf1ed837b936dde98a43492c1c5db8442445e165f8c7da18a46fb1a9ea3a8c01b789d5bebbc342cecf54b70353a0f526ef4a218a36a661a425be041ecbd79374929d4e19e44cb84cc51fec2896bdd4d107e26f690ca1ded4eef417e424c316094754dea4520b2576dda13e8cd099369a73a262624652b3a49360c5650b7406f78de27d","oaepHashingAlgorithm":"SHA512","iv":"b1eda75ea7dc84c02ff33639f6a95263","encryptedData":"e2edbaa489b057d9b690eacbb6032fc5172d06bc0392e111cc855e5421cc8bad6f2ab6799a79d7e8c33f642ade2eeec8260278574f8f937869e74da2376956fdf37ddef9f6c4b2d9e6dfbda6040a6d74e6e66ed20afbcbfc382bcce4e04ce8d1569cfbb4748d908ecc247b521de5b60d056a3584586bb44d6d3b37244fbae6303e970a68d766726e49723912e6a43fe44b3bfd77611c178890f63b16f1e8a813185244d9d336c8024638f31d8eb0160be84d8b64be1561d42d366a6330ba3b532065bbaf8445c47055b335362d311420"},"requestID":"5a79a0ac-4b3b-43dc-bafb-ae94a5b3eeec","responseHost":"stl.services.mastercard.com/mdes"}' http://localhost:8080/callback/mdes
func notifyHandler(w http.ResponseWriter, req *http.Request) {
	payload, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Printf("notification body reading error: %v", err)
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	reqID, err := m.Notify(payload)
	if err != nil {
		log.Printf("notification handling error: %v", err)
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	responce, _ := json.Marshal(struct {
		ResponseHost string `json:"responseHost"`
		ResponseID   string `json:"responseId"`
	}{
		ResponseHost: "assist.ru",
		ResponseID:   reqID,
	})

	w.Header().Add("Content-Type", "application/json")
	w.Write(responce)
}

func getTokenHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	reqData := struct {
		RequestorID          string
		TokenUniqueReference string
	}{}

	if err = json.Unmarshal(body, &reqData); err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	responceData, err := m.GetToken(reqData.RequestorID, reqData.TokenUniqueReference)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, _ := json.Marshal(responceData)
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)

}

func searchHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reqData := struct {
		RequestorID           string
		TokenUniqueReferences string
		PanUniqueReference    string
		CardData              mdes.CardAccountData
	}{}

	if err = json.Unmarshal(body, &reqData); err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	responceData, err := m.Search(reqData.RequestorID, reqData.TokenUniqueReferences, reqData.PanUniqueReference, reqData.CardData)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, _ := json.Marshal(responceData)
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)

}
