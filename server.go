package main

import (
	"encoding/json"
	"io/ioutil"
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
