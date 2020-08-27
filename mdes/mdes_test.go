package mdes

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/slytomcat/tokenizer/cache"
	"github.com/slytomcat/tokenizer/database"
	tools "github.com/slytomcat/tokenizer/tools"
)

var (
	mdesAPI *MDESapi
)

func init() {
	log.SetFlags(log.Lmicroseconds)

	configData := struct {
		DB    database.DBConf
		Cache cache.Config
		MDES  MDESconf
	}{}

	err := tools.ReadJSON("../config.json", &configData)
	if err != nil {
		log.Println(err)
	}

	err = json.Unmarshal([]byte(os.Getenv("TOKENIZER_CONF")), &configData)
	if err != nil {
		log.Println(err)
	}

	// connect to databse
	db, err := database.Init(&configData.DB)
	if err != nil {
		panic(err)
	}

	configData.MDES.EcryptKey = "SandBoxKeys/164401.crt"
	configData.MDES.SignKey = "SandBoxKeys/SandBox.p12"
	configData.MDES.DecryptKeys = []keywfp{
		keywfp{Key: "SandBoxKeys/key.p12", Fingerprint: "982175aa53858f44de919c70b20e011681b9db0deec4f4c117da8ece86a4684e"},
		keywfp{Key: "SandBoxKeys/key.p12", Fingerprint: "243e6992ea467f1cbb9973facfcc3bf17b5cd007"}, // for testing encryption a decryption
	}

	if mdesAPI, err = NewMDESapi(&configData.MDES, db, cache.NewCache(&configData.Cache)); err != nil {
		panic(err)
	}

	// clear assets cache
	db.Del(prefix + "3789637f-32a1-4810-a138-4bf34501c509")
	db.Del(prefix + "739d27e5-629d-11e3-949a-0800200c9a66")
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

	mdesAPI.storedEncryptKey = &mdesAPI.storedDecryptKeys["982175aa53858f44de919c70b20e011681b9db0deec4f4c117da8ece86a4684e"].PublicKey

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
		"A5",     // outSytem
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

	log.Printf("Received token data:\n%+v", tData)

	// wait for asset storage
	time.Sleep(time.Second * 2)
	log.Print("waiting for assets storage finished")
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

	log.Printf("Received tokens data:\n%+v", tData)

	tData, err = mdesAPI.Search("98765432101", "DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45", "",
		CardAccountData{})

	// error in sandbox
	log.Printf("Received expected error:\n%v", err)

	tData, err = mdesAPI.Search("98765432101", "", "FWSPMC000000000159f71f703d2141efaf04dd26803f922b",
		CardAccountData{})

	// error in sandbox
	log.Printf("Received expected error:\n%v", err)
}

func TestGetTokenUniversalAPI(t *testing.T) {
	tData, err := mdesAPI.GetToken("98765432101", "DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45")

	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Received token data:\n%+v", tData)
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

	log.Printf("Received cryptogram data:\n%+v", cData)
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

	log.Printf("Received data:\n%+v", sStats)
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

	log.Printf("Received data:\n%+v", sStats)
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

	log.Printf("Received data:\n%+v", sStats)
}

func TestGetAssetUniversalAPI(t *testing.T) {
	log.Println("___________First request ________________")

	url, err := mdesAPI.GetAsset("3789637f-32a1-4810-a138-4bf34501c509")
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("URL received:   %s", url)
	//
	time.Sleep(time.Second) // wait for first request to cache data
	// repeat request to chek the cache
	log.Println("___________Second request ________________")
	url, err = mdesAPI.GetAsset("3789637f-32a1-4810-a138-4bf34501c509")
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("URL from cache: %s", url)
}

func TestNotifyMDES(t *testing.T) {
	reqID, err := mdesAPI.Notify([]byte(`{"encryptedPayload":{"publicKeyFingerprint":"982175aa53858f44de919c70b20e011681b9db0deec4f4c117da8ece86a4684e","encryptedKey":"65122ca45c6ceecfce46feec3ca5947f85a1ce96354690880d5c95afb627f0a76401e4c4217f8c783427f02ad1d918afb24c63a437ddb79f36f91ee1c36c199e0822192846c1c74a207e23f3d14ff63b6c12919415568f6edeaa4cbe06dc7850a6439885dd85f1460e8b746bce8a9b1308f69ee4655a3a3a41b7af394bcf1ed837b936dde98a43492c1c5db8442445e165f8c7da18a46fb1a9ea3a8c01b789d5bebbc342cecf54b70353a0f526ef4a218a36a661a425be041ecbd79374929d4e19e44cb84cc51fec2896bdd4d107e26f690ca1ded4eef417e424c316094754dea4520b2576dda13e8cd099369a73a262624652b3a49360c5650b7406f78de27d","oaepHashingAlgorithm":"SHA512","iv":"b1eda75ea7dc84c02ff33639f6a95263","encryptedData":"e2edbaa489b057d9b690eacbb6032fc5172d06bc0392e111cc855e5421cc8bad6f2ab6799a79d7e8c33f642ade2eeec8260278574f8f937869e74da2376956fdf37ddef9f6c4b2d9e6dfbda6040a6d74e6e66ed20afbcbfc382bcce4e04ce8d1569cfbb4748d908ecc247b521de5b60d056a3584586bb44d6d3b37244fbae6303e970a68d766726e49723912e6a43fe44b3bfd77611c178890f63b16f1e8a813185244d9d336c8024638f31d8eb0160be84d8b64be1561d42d366a6330ba3b532065bbaf8445c47055b335362d311420"},"requestID":"5a79a0ac-4b3b-43dc-bafb-ae94a5b3eeec","responseHost":"stl.services.mastercard.com/mdes"}`))

	if err != nil {
		//t.Fatal(err)
		t.Logf("received expected error: %v", err)
	}
	if reqID == "" {
		t.Fatal(`reqID == ""`)
	}
	// wait for cache updates
	time.Sleep(time.Second)
	log.Println("Done")

}
