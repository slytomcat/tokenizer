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
	if m, err = mdes.NewMDESapi(); err != nil {
		return err
	}

	http.HandleFunc("/api/v1/tokenize", tokenizeHandler)
	return http.ListenAndServe(":8080", nil)
}

func tokenizeHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	reqData := struct {
		RequestorID string
		CardData    CardAccountData
		Source      string
	}{
		CardData: CardAccountData{},
	}
	if err = json.Unmarshal(body, &reqData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	tokenData, err := mdes.Tokenize(reqData.RequestorID, reqData.CardData, reqData.Source)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	resp, _ := json.Marshal(tokenData)
	w.Write(resp)
}
