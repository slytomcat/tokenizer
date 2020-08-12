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

func TestSearchUniversalAPI(t *testing.T) {
	tData, err := mdesAPI.Search("98765432101", "", "",
		CardAccountData{
			AccountNumber: "5123456789012345",
			ExpiryMonth:   "09",
			ExpiryYear:    "21",
			SecurityCode:  "123",
		})

	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Received tokens data:\n%v", tData)
}

func TestGetTokenUniversalAPI(t *testing.T) {
	tData, err := mdesAPI.GetToken("98765432101", "DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45")

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
	sStats, err := mdesAPI.Unsuspend(
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
	sStats, err := mdesAPI.Delete(
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

func TestGetAssetUniversalAPI(t *testing.T) {
	assets, err := mdesAPI.GetAsset("3789637f-32a1-4810-a138-4bf34501c509")
	if err != nil {
		t.Fatal(err)
	}
	// too long output
	//log.Printf("Received data:\n%v", assets)
	log.Printf("Media data received. Payload items: %d", len(assets))
}

func TestNotifyMDES(t *testing.T) {
	reqID, err := mdesAPI.Notify([]byte(`{"encryptedPayload":{"publicKeyFingerprint":"982175aa53858f44de919c70b20e011681b9db0deec4f4c117da8ece86a4684e","encryptedKey":"65122ca45c6ceecfce46feec3ca5947f85a1ce96354690880d5c95afb627f0a76401e4c4217f8c783427f02ad1d918afb24c63a437ddb79f36f91ee1c36c199e0822192846c1c74a207e23f3d14ff63b6c12919415568f6edeaa4cbe06dc7850a6439885dd85f1460e8b746bce8a9b1308f69ee4655a3a3a41b7af394bcf1ed837b936dde98a43492c1c5db8442445e165f8c7da18a46fb1a9ea3a8c01b789d5bebbc342cecf54b70353a0f526ef4a218a36a661a425be041ecbd79374929d4e19e44cb84cc51fec2896bdd4d107e26f690ca1ded4eef417e424c316094754dea4520b2576dda13e8cd099369a73a262624652b3a49360c5650b7406f78de27d","oaepHashingAlgorithm":"SHA512","iv":"b1eda75ea7dc84c02ff33639f6a95263","encryptedData":"e2edbaa489b057d9b690eacbb6032fc5172d06bc0392e111cc855e5421cc8bad6f2ab6799a79d7e8c33f642ade2eeec8260278574f8f937869e74da2376956fdf37ddef9f6c4b2d9e6dfbda6040a6d74e6e66ed20afbcbfc382bcce4e04ce8d1569cfbb4748d908ecc247b521de5b60d056a3584586bb44d6d3b37244fbae6303e970a68d766726e49723912e6a43fe44b3bfd77611c178890f63b16f1e8a813185244d9d336c8024638f31d8eb0160be84d8b64be1561d42d366a6330ba3b532065bbaf8445c47055b335362d311420"},"requestID":"5a79a0ac-4b3b-43dc-bafb-ae94a5b3eeec","responseHost":"stl.services.mastercard.com/mdes"}`))

	if err != nil {
		t.Fatal(err)
	}
	if reqID == "" {
		t.Fatal(`reqID == ""`)
	}
}
