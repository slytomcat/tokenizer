package main

// Manual tests via curl:

// TestTokenize
// curl -v -H "Content-Type: application/json" -d '{"outsystem":"A5","requestorid":"123454","carddata":{"type":"MC","accountNumber":"5123456789012345","expiry":"0921","securityCode":"123"},"source":"ACCOUNT_ADDED_MANUALLY"}' http://localhost:8080/api/v1/tokenize

// TestTransact
// curl -v -H "Content-Type: application/json" -d '{"tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","cryptogramType":"UCAF"}' http://localhost:8080/api/v1/transact

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"syscall"
	"testing"
	"time"

	tools "github.com/slytomcat/tokenizer/tools"
	"github.com/stretchr/testify/assert"
)

var (
	outputRe  *regexp.Regexp
	cbURL     string // URL (full) for MDES API Call-Back request
	tridCBURL string // URL (full) for TRID API Call-Back request
	apiURL    string // URL (partial) for API requests
	capiURL   string // URL (partial) for Config API requests
)

func TestMain(m *testing.M) {

	log.SetFlags(log.Lmicroseconds)
	// preparations
	cnf := Config{}
	err := tools.ReadJSON("config.json", &cnf)
	cbURL = "http://" + cnf.MDES.CallBackHostPort + cnf.MDES.CallBackURI
	tridCBURL = "http://" + cnf.MDES.CallBackHostPort + cnf.MDES.TRIDcbURI
	apiURL = "http://" + cnf.API.HostPort
	capiURL = "http://" + cnf.CfgAPI.HostPort

	outputRe, err = regexp.Compile(`"Data":"[^"]*"`)
	tools.PanicIf(err)

	go doMain(&cnf)

	time.Sleep(time.Second * 2)
	// run tests
	tErr := m.Run()

	// Clearance
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	time.Sleep(time.Millisecond * 600)

	os.Exit(tErr)
}

func request(url string, payload []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	tools.PanicIf(err)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	log.Printf("    >>>>>>>    Request URL: %s\n", url)
	log.Printf("    >>>>>>>    Request Body:\n%s\n", payload)

	responce, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request forwarding error: %w", err)
	}
	defer responce.Body.Close()

	body, err := io.ReadAll(responce.Body)
	if err != nil {
		return nil, fmt.Errorf("responce body reading error: %w", err)
	}

	output := outputRe.ReplaceAll(body, []byte(`"data":"--<--data skiped-->--"`))
	log.Printf("    <<<<<<<    Response: %s\n%s\n", responce.Status, output)

	if responce.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad responce code: %v", responce.StatusCode)
	}
	return body, nil
}

func TestTokenizeMC(t *testing.T) {
	_, err := request(apiURL+"/api/v1/tokenize",
		[]byte(`{"outsystem":"A5","requestorid":"123454","carddata":{"type":"MC","accountNumber":"5123456789012345","expiry":"0921","securityCode":"123"},"source":"ACCOUNT_ADDED_MANUALLY"}`),
	)
	assert.NoError(t, err)
	time.Sleep(time.Second * 2)
	log.Println("Waiting for storage of assests finished")
}

func TestTransactMC(t *testing.T) {
	_, err := request(apiURL+"/api/v1/transact",
		[]byte(`{"type":"MC","tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45"}`),
	)
	assert.NoError(t, err)
}

func TestDeleteMC(t *testing.T) {
	_, err := request(apiURL+"/api/v1/delete",
		[]byte(`{"type":"MC","tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}`),
	)
	assert.NoError(t, err)
}
func TestSuspendMC(t *testing.T) {
	_, err := request(apiURL+"/api/v1/suspend",
		[]byte(`{"type":"MC","tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}`),
	)
	assert.NoError(t, err)
}
func TestUnsuspendMC(t *testing.T) {
	_, err := request(apiURL+"/api/v1/unsuspend",
		[]byte(`{"type":"MC","tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}`),
	)
	assert.NoError(t, err)
}
func TestGetTokenMC(t *testing.T) {
	_, err := request(apiURL+"/api/v1/gettoken",
		[]byte(`{"OutSystem":"A5","RequestorID":"98765432101","tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45"}`),
	)
	assert.NoError(t, err)
}

func TestSearchMC(t *testing.T) {
	_, err := request(apiURL+"/api/v1/search",
		[]byte(`{"OutSystem":"A5","RequestorID":"98765432101","tokenUniqueReference":"", "TUR":"","carddata":{"accountNumber":"5123456789012345","expiry":"0921","SecurityCode":"123"}}`),
	)
	assert.NoError(t, err)
}

func TestNotifyMC(t *testing.T) {
	_, err := request(cbURL,
		[]byte(`{"encryptedPayload":{"publicKeyFingerprint":"982175aa53858f44de919c70b20e011681b9db0deec4f4c117da8ece86a4684e","encryptedKey":"65122ca45c6ceecfce46feec3ca5947f85a1ce96354690880d5c95afb627f0a76401e4c4217f8c783427f02ad1d918afb24c63a437ddb79f36f91ee1c36c199e0822192846c1c74a207e23f3d14ff63b6c12919415568f6edeaa4cbe06dc7850a6439885dd85f1460e8b746bce8a9b1308f69ee4655a3a3a41b7af394bcf1ed837b936dde98a43492c1c5db8442445e165f8c7da18a46fb1a9ea3a8c01b789d5bebbc342cecf54b70353a0f526ef4a218a36a661a425be041ecbd79374929d4e19e44cb84cc51fec2896bdd4d107e26f690ca1ded4eef417e424c316094754dea4520b2576dda13e8cd099369a73a262624652b3a49360c5650b7406f78de27d","oaepHashingAlgorithm":"SHA512","iv":"b1eda75ea7dc84c02ff33639f6a95263","encryptedData":"e2edbaa489b057d9b690eacbb6032fc5172d06bc0392e111cc855e5421cc8bad6f2ab6799a79d7e8c33f642ade2eeec8260278574f8f937869e74da2376956fdf37ddef9f6c4b2d9e6dfbda6040a6d74e6e66ed20afbcbfc382bcce4e04ce8d1569cfbb4748d908ecc247b521de5b60d056a3584586bb44d6d3b37244fbae6303e970a68d766726e49723912e6a43fe44b3bfd77611c178890f63b16f1e8a813185244d9d336c8024638f31d8eb0160be84d8b64be1561d42d366a6330ba3b532065bbaf8445c47055b335362d311420"},"requestID":"5a79a0ac-4b3b-43dc-bafb-ae94a5b3eeec","responseHost":"stl.services.mastercard.com/mdes"}`),
	)
	assert.NoError(t, err)
	// wait for cache updates
	time.Sleep(time.Second * 5)
	log.Println("Done waiting async storage")
}

func TestConfigOutSys(t *testing.T) {
	_, err := request(capiURL+"/capi/v1/addoutsystem",
		[]byte(`{"outsys":"A5","cburl":"http://s-t-c.tk:8080/echo","tridurl":"http://s-t-c.tk:8080/echo"}`),
	)
	assert.NoError(t, err)
	// wait for cache updates
	time.Sleep(time.Second)
	log.Println("Done waiting async storage")
}

func TestConfigTRSecrets(t *testing.T) {
	_, err := request(capiURL+"/capi/v1/addtrsecrets",
		[]byte(`{"trid":"123456","apikey":"LONGAPIKEY"}`),
	)
	assert.NoError(t, err)
	// wait for cache updates
	time.Sleep(time.Second)
	log.Println("Done waiting async storage")
}

func TestConfigNewTRID(t *testing.T) {
	_, err := request(capiURL+"/capi/v1/mc/tridregister",
		[]byte(`{"outSys":"A5","id":"739d27e5629d11e3949a0800200c9a66","name":"MERCHANT1"}`),
	)
	if err != nil {
		// assert.NoError(t, err)
		t.Logf("expected error (service not active yet): %v", err)
	}
	// wait for cache updates
	time.Sleep(time.Second)
	log.Println("Done waiting async storage")
}

func TestConfigTRIDCallBack(t *testing.T) {
	_, err := request(tridCBURL,
		[]byte(`{"requestID":"1234","tokenRequestors":[{"entityId":"739d27e5629d11e3949a0800200c9a66","TokenRequestorID":"098765"}]}`),
	)
	assert.NoError(t, err)
	// wait for cache updates
	time.Sleep(time.Second * 3)
	log.Println("Done waiting async storage")
}

func TestHealthCheck(t *testing.T) {
	_, err := request(apiURL+"/api/v1/healthcheck", []byte{})
	assert.NoError(t, err)
}

func TestServerKill(t *testing.T) {
	logger := log.Writer()
	r, w, _ := os.Pipe()
	log.SetOutput(w)

	syscall.Kill(syscall.Getpid(), syscall.SIGINT)

	time.Sleep(time.Second * 2)

	w.Close()
	log.SetOutput(logger)
	buf, err := io.ReadAll(r)
	assert.NoError(t, err)
	assert.Equal(t, string(buf), "http: Server closed")
	fmt.Printf("%s", buf)
}
