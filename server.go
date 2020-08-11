package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/slytomcat/tokenizer/mdes"
)

var (
	m *mdes.MDESapi
)

func main() {
	if err := doMain(); err != nil {
		panic(err)
	}
}

func doMain() error {
	var err error
	if m, err = mdes.NewMDESapi("mdes/SandBoxKeys"); err != nil {
		return err
	}

	http.HandleFunc("/api/v1/tokenize", tokenizeHandler)
	http.HandleFunc("/api/v1/transact", transactHandler)
	http.HandleFunc("/api/v1/suspend", suspendHandler)
	http.HandleFunc("/api/v1/unsuspend", unsuspendHandler)
	http.HandleFunc("/api/v1/delete", deleteHandler)
	log.Println("Starting server at :8080")
	return http.ListenAndServe(":8080", nil)
}

// test:
// curl -v POST -H "Content-Type: application/json" -d '{"requestorid":"123454","carddata":{"accountNumber":"5123456789012345","expiryMonth":"09","expiryYear":"21","securityCode":"123"},"source":"ACCOUNT_ADDED_MANUALLY"}' http://localhost:8080/api/v1/tokenize

func tokenizeHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	reqData := struct {
		RequestorID string
		CardData    mdes.CardAccountData
		Source      string
	}{
		CardData: mdes.CardAccountData{},
	}
	if err = json.Unmarshal(body, &reqData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	tokenData, err := m.Tokenize(reqData.RequestorID, reqData.CardData, reqData.Source)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	resp, _ := json.Marshal(tokenData)
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)
}

// test:
// curl -v POST -H "Content-Type: application/json" -d '{"tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","cryptogramType":"UCAF"}' http://localhost:8080/api/v1/transact

func transactHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	reqData := mdes.TransactData{}
	if err = json.Unmarshal(body, &reqData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	ransactData, err := m.Transact(reqData)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	resp, _ := json.Marshal(ransactData)
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)
}

// test:
// curl -v POST -H "Content-Type: application/json" -d '{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}' http://localhost:8080/api/v1/suspend
func suspendHandler(w http.ResponseWriter, req *http.Request) {
	mangeTokens(m.Suspend, w, req)
}

// test:
// curl -v POST -H "Content-Type: application/json" -d '{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}' http://localhost:8080/api/v1/unsuspend
func unsuspendHandler(w http.ResponseWriter, req *http.Request) {
	mangeTokens(m.Unsuspend, w, req)
}

// test:
// curl -v POST -H "Content-Type: application/json" -d '{"tokenUniqueReferences":["DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb","DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532"],"causedby":"CARDHOLDER","reasoncode":"OTHER"}' http://localhost:8080/api/v1/delete
func deleteHandler(w http.ResponseWriter, req *http.Request) {
	mangeTokens(m.Delete, w, req)
}

func mangeTokens(action func([]string, string, string) ([]mdes.TokenStatus, error), w http.ResponseWriter, req *http.Request) {

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	reqData := struct {
		TokenUniqueReferences []string
		CausedBy              string
		ReasonCode            string
	}{}
	if err = json.Unmarshal(body, &reqData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	responceData, err := action(reqData.TokenUniqueReferences, reqData.CausedBy, reqData.ReasonCode)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	resp, _ := json.Marshal(responceData)
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)
}
