package api

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
)

// Config - API configuration
type Config struct {
	HostPort string
	Cert     string
	Key      string
}

// TokenStatus - token status structure
type TokenStatus struct {
	TokenUniqueReference string
	Status               string
	StatusTimestamp      string
	SuspendedBy          []string
}

// PGAPI - payment gate API intreface
type PGAPI interface {
	Tokenize(string, string, string, string, string, string, string) (string, string, error)
	Delete(string, []string, string, string) ([]TokenStatus, error)
	Transact(string, string) (string, string, string, error)
}

// Handler - API handler
type Handler struct {
	apiHandler PGAPI
	ShutDown   func() error
	CallBack   func(string, []byte) error
}

func (h Handler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	switch req.Method + req.URL.Path {
	case "POST/api/v1/tokenize":
		h.tokenizeHandler(resp, req)
	case "POST/api/v1/delete":
		h.deleteHandler(resp, req)
	case "POST/api/v1/transact":
		h.transactHandler(resp, req)
	default:
		resp.WriteHeader(http.StatusBadRequest)
	}
}

// performs outSystem callback notification
func callBack(url string, body []byte) error {
	log.Printf("CallBack: %s\n%s", url, body)

	// TO DO: make call-back request to outSystem
	// return err if responceCode is not 200

	return nil
}

// NewAPI initialize the API and returns the *handler
func NewAPI(conf *Config, handler PGAPI) *Handler {

	server := http.Server{
		Addr: conf.HostPort,
	}

	hendl := Handler{
		apiHandler: handler,
		ShutDown:   func() error { return server.Shutdown(context.Background()) },
		CallBack:   callBack,
	}

	server.Handler = hendl

	go func() {
		log.Printf("Starting API service at %s", conf.HostPort)
		var err error
		if conf.Cert != "" {
			err = server.ListenAndServeTLS(conf.Cert, conf.Key)
		} else {
			err = server.ListenAndServe()
		}

		if !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
		log.Printf("INFO: %v", err)
	}()

	return &hendl
}

// test:
// curl -v -H "Content-Type: application/json" -d '{"requestorid":"123454","carddata":{"type":"MC","accountNumber":"5123456789012345","expiryMonth":"09","expiryYear":"21","securityCode":"123"},"source":"ACCOUNT_ADDED_MANUALLY"}' http://localhost:8080/api/v1/tokenize

func (h Handler) tokenizeHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reqData := struct {
		OutSystem   string
		RequestorID string
		CardData    struct {
			Type          string
			AccountNumber string
			Expiry        string
			SecurityCode  string
		}
		Source string
	}{}
	if err = json.Unmarshal(body, &reqData); err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token, status, err := h.apiHandler.Tokenize(
		reqData.OutSystem,
		reqData.RequestorID,
		reqData.CardData.Type,
		reqData.CardData.AccountNumber,
		reqData.CardData.Expiry,
		reqData.CardData.SecurityCode,
		reqData.Source)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, _ := json.Marshal(struct {
		TokenUniqueReferences string
		Status                string
	}{
		TokenUniqueReferences: token,
		Status:                status,
	})
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)
}

// test:
// curl -v -H "Content-Type: application/json" -d '{"tokenUniqueReference":"DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45","cryptogramType":"UCAF"}' http://localhost:8080/api/v1/transact

func (h Handler) transactHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reqData := struct {
		Type                 string
		TokenUniqueReference string
	}{}
	if err = json.Unmarshal(body, &reqData); err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	dpan, exp, crypto, err := h.apiHandler.Transact(reqData.Type, reqData.TokenUniqueReference)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, _ := json.Marshal(struct {
		DPAN   string
		Exp    string
		Crypto string
	}{
		DPAN:   dpan,
		Exp:    exp,
		Crypto: crypto,
	})
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)
}

// delete handler for API calls
func (h Handler) deleteHandler(w http.ResponseWriter, req *http.Request) {

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reqData := struct {
		Type                  string
		TokenUniqueReferences []string
		CausedBy              string
		ReasonCode            string
	}{}
	if err = json.Unmarshal(body, &reqData); err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	statuses, err := h.apiHandler.Delete(reqData.Type, reqData.TokenUniqueReferences, reqData.CausedBy, reqData.ReasonCode)
	if err != nil {
		// TO DO: provide more error details
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, _ := json.Marshal(statuses)
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)
}
