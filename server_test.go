package main

// Manual tests via curl:

// TestTokenize
// curl -v -H "Content-Type: application/json" -d '{"requestorid":"123454","carddata":{"accountNumber":"5123456789012345","expiryMonth":"09","expiryYear":"21","securityCode":"123"},"source":"ACCOUNT_ADDED_MANUALLY"}' http://localhost:8080/api/v1/tokenize

// TestTransact
// curl -v -H "Content-Type: application/json" -d '{"tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","cryptogramType":"UCAF"}' http://localhost:8080/api/v1/transact

// TestSuspend
// curl -v -H "Content-Type: application/json" -d '{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}' http://localhost:8080/api/v1/suspend

// TestUnsuspend
// curl -v -H "Content-Type: application/json" -d '{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}' http://localhost:8080/api/v1/unsuspend

// TestDelete
// curl -v -H "Content-Type: application/json" -d '{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}' http://localhost:8080/api/v1/delete

// TestGetAssets
// curl -v -H "Content-Type: application/json" -d '{"assetid":"3789637f-32a1-4810-a138-4bf34501c509"}' http://localhost:8080/api/v1/getassets

// TestNotify
// curl -v -H "Content-Type: application/json" -d '{"encryptedPayload":{"publicKeyFingerprint":"982175aa53858f44de919c70b20e011681b9db0deec4f4c117da8ece86a4684e","encryptedKey":"65122ca45c6ceecfce46feec3ca5947f85a1ce96354690880d5c95afb627f0a76401e4c4217f8c783427f02ad1d918afb24c63a437ddb79f36f91ee1c36c199e0822192846c1c74a207e23f3d14ff63b6c12919415568f6edeaa4cbe06dc7850a6439885dd85f1460e8b746bce8a9b1308f69ee4655a3a3a41b7af394bcf1ed837b936dde98a43492c1c5db8442445e165f8c7da18a46fb1a9ea3a8c01b789d5bebbc342cecf54b70353a0f526ef4a218a36a661a425be041ecbd79374929d4e19e44cb84cc51fec2896bdd4d107e26f690ca1ded4eef417e424c316094754dea4520b2576dda13e8cd099369a73a262624652b3a49360c5650b7406f78de27d","oaepHashingAlgorithm":"SHA512","iv":"b1eda75ea7dc84c02ff33639f6a95263","encryptedData":"e2edbaa489b057d9b690eacbb6032fc5172d06bc0392e111cc855e5421cc8bad6f2ab6799a79d7e8c33f642ade2eeec8260278574f8f937869e74da2376956fdf37ddef9f6c4b2d9e6dfbda6040a6d74e6e66ed20afbcbfc382bcce4e04ce8d1569cfbb4748d908ecc247b521de5b60d056a3584586bb44d6d3b37244fbae6303e970a68d766726e49723912e6a43fe44b3bfd77611c178890f63b16f1e8a813185244d9d336c8024638f31d8eb0160be84d8b64be1561d42d366a6330ba3b532065bbaf8445c47055b335362d311420"},"requestID":"5a79a0ac-4b3b-43dc-bafb-ae94a5b3eeec","responseHost":"stl.services.mastercard.com/mdes"}' http://localhost:8080/callback/mdes

// TestSearch
// curl -v -H "Content-Type: application/json" -d '{"requestorid":"98765432101","carddata":{"accountNumber":"5123456789012345","expiryMonth":"09","expiryYear":"21","securityCode":"123"}}' http://localhost:8080/api/v1/search

// TestGetToken
// curl -v -H "Content-Type: application/json" -d '{"requestorid":"98765432101","tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45"}' http://localhost:8080/api/v1/gettoken

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"testing"
	"time"
)

var (
	outputRe *regexp.Regexp
)

func TestMain(m *testing.M) {
	// preporations
	go func() {
		err := doMain()
		if err != nil {
			panic(err)
		}
	}()

	var err error

	outputRe, err = regexp.Compile(`"Data":"[^"]*"`)
	if err != nil {
		panic(fmt.Errorf("regexp creation error: %w", err))
	}

	time.Sleep(time.Millisecond * 100)
	// run tests
	tErr := m.Run()

	// Clearance
	// syscall.Kill(syscall.Getpid(), syscall.SIGINT)

	os.Exit(tErr)
}

func TestTokenize(t *testing.T) {
	_, err := requst("http://localhost:8080/api/v1/tokenize",
		[]byte(`{"requestorid":"123454","carddata":{"accountNumber":"5123456789012345","expiryMonth":"09","expiryYear":"21","securityCode":"123"},"source":"ACCOUNT_ADDED_MANUALLY"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTransact(t *testing.T) {
	_, err := requst("http://localhost:8080/api/v1/transact",
		[]byte(`{"tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","cryptogramType":"UCAF"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSuspend(t *testing.T) {
	_, err := requst("http://localhost:8080/api/v1/suspend",
		[]byte(`{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnsuspend(t *testing.T) {
	_, err := requst("http://localhost:8080/api/v1/unsuspend",
		[]byte(`{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDelete(t *testing.T) {
	_, err := requst("http://localhost:8080/api/v1/delete",
		[]byte(`{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
}
func TestGetAssets(t *testing.T) {
	_, err := requst("http://localhost:8080/api/v1/getassets",
		[]byte(`{"assetid":"3789637f-32a1-4810-a138-4bf34501c509"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
}
func TestNotify(t *testing.T) {
	_, err := requst("http://localhost:8080/callback/mdes",
		[]byte(`{"encryptedPayload":{"publicKeyFingerprint":"982175aa53858f44de919c70b20e011681b9db0deec4f4c117da8ece86a4684e","encryptedKey":"65122ca45c6ceecfce46feec3ca5947f85a1ce96354690880d5c95afb627f0a76401e4c4217f8c783427f02ad1d918afb24c63a437ddb79f36f91ee1c36c199e0822192846c1c74a207e23f3d14ff63b6c12919415568f6edeaa4cbe06dc7850a6439885dd85f1460e8b746bce8a9b1308f69ee4655a3a3a41b7af394bcf1ed837b936dde98a43492c1c5db8442445e165f8c7da18a46fb1a9ea3a8c01b789d5bebbc342cecf54b70353a0f526ef4a218a36a661a425be041ecbd79374929d4e19e44cb84cc51fec2896bdd4d107e26f690ca1ded4eef417e424c316094754dea4520b2576dda13e8cd099369a73a262624652b3a49360c5650b7406f78de27d","oaepHashingAlgorithm":"SHA512","iv":"b1eda75ea7dc84c02ff33639f6a95263","encryptedData":"e2edbaa489b057d9b690eacbb6032fc5172d06bc0392e111cc855e5421cc8bad6f2ab6799a79d7e8c33f642ade2eeec8260278574f8f937869e74da2376956fdf37ddef9f6c4b2d9e6dfbda6040a6d74e6e66ed20afbcbfc382bcce4e04ce8d1569cfbb4748d908ecc247b521de5b60d056a3584586bb44d6d3b37244fbae6303e970a68d766726e49723912e6a43fe44b3bfd77611c178890f63b16f1e8a813185244d9d336c8024638f31d8eb0160be84d8b64be1561d42d366a6330ba3b532065bbaf8445c47055b335362d311420"},"requestID":"5a79a0ac-4b3b-43dc-bafb-ae94a5b3eeec","responseHost":"stl.services.mastercard.com/mdes"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func requst(url string, payload []byte) ([]byte, error) {
	request, _ := http.NewRequest("POST", url, bytes.NewReader(payload))
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Accept", "application/json")

	log.Printf("    <<<<<<<    Request URL: %s\n", url)
	log.Printf("    <<<<<<<    Request Body:\n%s\n", payload)

	responce, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request sending error: %w", err)
	}
	defer responce.Body.Close()

	body, err := ioutil.ReadAll(responce.Body)
	if err != nil {
		return nil, fmt.Errorf("responce body reading error: %w", err)
	}

	output := outputRe.ReplaceAll(body, []byte(`"data":"--<--data skiped-->--"`))
	log.Printf("\n    >>>>>>>    Response: %s\n%s\n", responce.Status, output)

	return body, nil
}
