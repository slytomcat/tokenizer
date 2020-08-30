package main

// Manual tests via curl:

// TestTokenize
// curl -v -H "Content-Type: application/json" -d '{"requestorid":"123454","carddata":{"accountNumber":"5123456789012345","expiryMonth":"09","expiryYear":"21","securityCode":"123"},"source":"ACCOUNT_ADDED_MANUALLY"}' http://localhost:8080/api/v1/tokenize

// TestTransact
// curl -v -H "Content-Type: application/json" -d '{"tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","cryptogramType":"UCAF"}' http://localhost:8080/api/v1/transact

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"syscall"
	"testing"
	"time"
)

var (
	outputRe *regexp.Regexp
	cbURL    string // URL (full) for Call-Back request
	apiURL   string // URL (partial) for API requests
)

func TestMain(m *testing.M) {

	log.SetFlags(log.Lmicroseconds)
	// preporations
	cnf := Config{}
	err := tools.GetConfig(*configFile, )
	cbURL = "http://" + cnf.MDES.CallBackHostPort + cnf.MDES.CallBackURI
	apiURL = "http://" + cnf.API.HostPort

	go main()

	var err error

	outputRe, err = regexp.Compile(`"Data":"[^"]*"`)
	if err != nil {
		panic(fmt.Errorf("regexp creation error: %w", err))
	}

	time.Sleep(time.Second)
	// run tests
	tErr := m.Run()

	// Clearance
	// syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	time.Sleep(time.Millisecond * 600)

	os.Exit(tErr)
}

func request(url string, payload []byte) ([]byte, error) {
	request, _ := http.NewRequest("POST", url, bytes.NewReader(payload))
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Accept", "application/json")

	log.Printf("    >>>>>>>    Request URL: %s\n", url)
	log.Printf("    >>>>>>>    Request Body:\n%s\n", payload)

	responce, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request forwarding error: %w", err)
	}
	defer responce.Body.Close()

	body, err := ioutil.ReadAll(responce.Body)
	if err != nil {
		return nil, fmt.Errorf("responce body reading error: %w", err)
	}

	output := outputRe.ReplaceAll(body, []byte(`"data":"--<--data skiped-->--"`))
	log.Printf("    <<<<<<<    Response: %s\n%s\n", responce.Status, output)

	return body, nil
}

func TestTokenizeMC(t *testing.T) {
	_, err := request(apiURL+"/api/v1/tokenize",
		[]byte(`{"outsystem":"A5","requestorid":"123454","carddata":{"type":"MC","accountNumber":"5123456789012345","expiry":"0921","securityCode":"123"},"source":"ACCOUNT_ADDED_MANUALLY"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second * 2)
	log.Println("Waiting for storage of assests finished")
}

func TestTransactMC(t *testing.T) {
	_, err := request(apiURL+"/api/v1/transact",
		[]byte(`{"type":"MC","tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteMC(t *testing.T) {
	_, err := request(apiURL+"/api/v1/delete",
		[]byte(`{"type":"MC","tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
}
func TestNotifyMC(t *testing.T) {
	_, err := request(cbURL,
		[]byte(`{"encryptedPayload":{"publicKeyFingerprint":"982175aa53858f44de919c70b20e011681b9db0deec4f4c117da8ece86a4684e","encryptedKey":"65122ca45c6ceecfce46feec3ca5947f85a1ce96354690880d5c95afb627f0a76401e4c4217f8c783427f02ad1d918afb24c63a437ddb79f36f91ee1c36c199e0822192846c1c74a207e23f3d14ff63b6c12919415568f6edeaa4cbe06dc7850a6439885dd85f1460e8b746bce8a9b1308f69ee4655a3a3a41b7af394bcf1ed837b936dde98a43492c1c5db8442445e165f8c7da18a46fb1a9ea3a8c01b789d5bebbc342cecf54b70353a0f526ef4a218a36a661a425be041ecbd79374929d4e19e44cb84cc51fec2896bdd4d107e26f690ca1ded4eef417e424c316094754dea4520b2576dda13e8cd099369a73a262624652b3a49360c5650b7406f78de27d","oaepHashingAlgorithm":"SHA512","iv":"b1eda75ea7dc84c02ff33639f6a95263","encryptedData":"e2edbaa489b057d9b690eacbb6032fc5172d06bc0392e111cc855e5421cc8bad6f2ab6799a79d7e8c33f642ade2eeec8260278574f8f937869e74da2376956fdf37ddef9f6c4b2d9e6dfbda6040a6d74e6e66ed20afbcbfc382bcce4e04ce8d1569cfbb4748d908ecc247b521de5b60d056a3584586bb44d6d3b37244fbae6303e970a68d766726e49723912e6a43fe44b3bfd77611c178890f63b16f1e8a813185244d9d336c8024638f31d8eb0160be84d8b64be1561d42d366a6330ba3b532065bbaf8445c47055b335362d311420"},"requestID":"5a79a0ac-4b3b-43dc-bafb-ae94a5b3eeec","responseHost":"stl.services.mastercard.com/mdes"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	// wait for cache updates
	time.Sleep(time.Second)
	log.Println("Done waiting async storage")
}

func TestServerKill(t *testing.T) {
	logger := log.Writer()
	r, w, _ := os.Pipe()
	log.SetOutput(w)

	syscall.Kill(syscall.Getpid(), syscall.SIGINT)

	time.Sleep(time.Second * 2)

	w.Close()
	log.SetOutput(logger)
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Contains(buf, []byte("http: Server closed")) {
		t.Errorf("received unexpected output: %s", buf)
	}
	log.Printf("%s", buf)
}
