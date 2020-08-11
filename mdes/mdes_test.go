package mdes

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"
)

func init() {
	log.SetFlags(log.Lmicroseconds)

	var err error

	if mdesAPI, err = NewMDESapi("SandBoxKeys"); err != nil {
		panic(err)
	}
}

func TestDeleteRequest(t *testing.T) {

	fmt.Println("________________Delete________________")
	url := "https://sandbox.api.mastercard.com/mdes/digitization/static/1/0/delete"
	payload := `{
		"responseHost" : "assist.ru",
		"requestId" : "123456",
		"paymentAppInstanceId" : "123456789",
		"tokenUniqueReferences" : [
			"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45",
			"DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb",
			"DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],
		"causedBy" : "CARDHOLDER",
		"reasonCode" : "DEVICE_LOST",
		"reason" : "LOST_STOLEN_DEVICE"
	  }`
	_, err := mdesAPI.request("POST", url, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetAssetsRequest(t *testing.T) {
	_, err := mdesAPI.request("GET", "https://sandbox.api.mastercard.com/mdes/assets/static/1/0/asset/3789637f-32a1-4810-a138-4bf34501c509", []byte(""))
	if err != nil {
		t.Fatal(err)
	}
}

func TestPayloadEncryptionAndDecryption(t *testing.T) {

	payload := []byte(`{
		"cardAccountData": {
		  "accountNumber": "5123456789012345",
		  "expiryMonth": "09",
		  "expiryYear": "21",
		  "securityCode": "123"
		}
	  }`)
	log.Printf("Original payload: %s", payload)

	// temporary switch the encryptKey
	saveKey := mdesAPI.storedEncryptKey

	mdesAPI.storedEncryptKey = &mdesAPI.storedDecryptKey.PublicKey

	encrypted, err := mdesAPI.encryptPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	mdesAPI.storedEncryptKey = saveKey

	outJSON, err := json.Marshal(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Encrypted(myPubKey) payload: %s", outJSON)

	decrypted, err := mdesAPI.decryptPayload(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Decrypted(myPrivKey) payload: %s", decrypted)
}

func TestEncryptAndDecryptTokenizeRequest(t *testing.T) {

	fmt.Println("________________Tokenize________________")

	url := "https://sandbox.api.mastercard.com/mdes/digitization/static/1/0/tokenize"
	payload := `{
	"responseHost": "assist.ru",
	"requestId": "123456",
	"tokenType": "CLOUD",
	"tokenRequestorId": "123456789",
	"taskId": "123456",
	"fundingAccountInfo": {
		"encryptedPayload": %s}}`
	payload1 := []byte(`{
		"cardAccountData": {
		  "accountNumber": "5123456789012345",
		  "expiryMonth": "09",
		  "expiryYear": "21",
		  "securityCode": "123"
		},
		"source": "ACCOUNT_ADDED_MANUALLY"}`)

	encrPayload, err := mdesAPI.encryptPayload(payload1)
	if err != nil {
		t.Fatal(err)
	}
	encrPayloadJSON, err := json.Marshal(encrPayload)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := mdesAPI.request("POST", url, []byte(fmt.Sprintf(payload, encrPayloadJSON)))
	if err != nil {
		t.Fatal(err)
	}

	ePayload := struct {
		TokenDetail encryptedPayload
	}{}

	if err := json.Unmarshal(encrypted, &ePayload); err != nil {
		t.Fatal(err)
	}

	decrypted, err := mdesAPI.decryptPayload(&ePayload.TokenDetail)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("\nDecrypted(myPrivKey) payload:\n%s", decrypted)
}

func TestTransactRequestDecryption(t *testing.T) {

	fmt.Println("________________Transact________________")

	url := "https://sandbox.api.mastercard.com/mdes/remotetransaction/static/1/0/transact"
	payload := `{
		"requestId": "111111",
		"tokenUniqueReference": "DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45",
		"dsrpType": UCAF}`
	// 	 "M_CHIP",
	// 	"amount": 10,
	// 	"currencyCode": "USD",
	// 	"unpredictableNumber": "D4A1B2C3"
	// }`

	encrypted, err := mdesAPI.request("POST", url, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	ePayload := struct {
		EncryptedPayload encryptedPayload
	}{}

	if err := json.Unmarshal(encrypted, &ePayload); err != nil {
		t.Fatal(err)
	}

	decrypted, err := mdesAPI.decryptPayload(&ePayload.EncryptedPayload)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("\nDecrypted(myPrivKey) payload:\n%s", decrypted)
}

func TestTokenizeUniversalAPI(t *testing.T) {
	tData, err := mdesAPI.Tokenize(
		"123456", // requestorID
		CardAccountData{
			AccountNumber: "5123456789012345",
			ExpiryMonth:   "09",
			ExpiryYear:    "21",
			SecurityCode:  "123",
		},
		"ACCOUNT_ADDED_MANUALLY", // source
	)

	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Received token data:\n%v", tData)
}

func TestTransactUniversalAPI(t *testing.T) {
	cData, err := mdesAPI.Transact(
		TransactData{
			TokenUniqueReference: "DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45",
			CryptogramType:       "UCAF",
		},
	)

	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Received cryptogram data:\n%v", cData)
}

func TestSuspendUniversalAPI(t *testing.T) {
	sStats, err := mdesAPI.Suspend(
		[]string{
			"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45",
			"DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb",
			"DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532",
		},
		"CARDHOLDER",
		"OTHER",
	)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Received data:\n%v", sStats)
}

func TestUnsuspendUniversalAPI(t *testing.T) {
	sStats, err := mdesAPI.Suspend(
		[]string{
			"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45",
			"DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb",
			"DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532",
		},
		"CARDHOLDER",
		"OTHER",
	)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Received data:\n%v", sStats)
}

func TestDeleteUniversalAPI(t *testing.T) {
	sStats, err := mdesAPI.Suspend(
		[]string{
			"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45",
			"DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb",
			"DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532",
		},
		"CARDHOLDER",
		"OTHER",
	)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Received data:\n%v", sStats)
}
