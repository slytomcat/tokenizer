package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/slytomcat/tokenizer/tools"
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
	Manage(string, string, []string, string, string) ([]TokenStatus, error)
	Transact(string, string) (string, string, string, error)
	HealthCheck() error
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
	case "POST/api/v1/suspend":
		h.suspendHandler(resp, req)
	case "POST/api/v1/unsuspend":
		h.unsuspendHandler(resp, req)
	case "POST/api/v1/transact":
		h.transactHandler(resp, req)
	case "POST/api/v1/healthcheck":
		h.healthCheck(resp, req)
	default:
		resp.WriteHeader(http.StatusBadRequest)
	}
}

// performs outSystem callback notification
func callBack(url string, body []byte) error {
	log.Printf("INFO: CallBack: %s\n%s", url, body)

	// TO DO: make call-back request to outSystem
	// return err if responceCode is not 200

	return nil
}

// NewAPI initialize the API and returns the *handler
func NewAPI(conf *Config, handler PGAPI) *Handler {

	server := http.Server{
		Addr: conf.HostPort,
	}

	apiHandler := Handler{
		apiHandler: handler,
		ShutDown:   func() error { return server.Shutdown(context.Background()) },
		CallBack:   callBack,
	}

	server.Handler = apiHandler

	go func() {
		log.Printf("INFO: Starting API service at %s", conf.HostPort)
		var err error
		if conf.Cert == "" {
			err = server.ListenAndServe()
		} else {
			err = server.ListenAndServeTLS(conf.Cert, conf.Key)
		}

		if !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
		log.Printf("INFO: API service: %v", err)
	}()

	return &apiHandler
}

// test:
// curl -v -H "Content-Type: application/json" -d '{"requestorid":"123454","carddata":{"type":"MC","accountNumber":"5123456789012345","expiryMonth":"09","expiryYear":"21","securityCode":"123"},"source":"ACCOUNT_ADDED_MANUALLY"}' http://localhost:8080/api/v1/tokenize

func (h Handler) tokenizeHandler(w http.ResponseWriter, req *http.Request) {
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

	if err := tools.ReadBodyToStruct(req.Body, &reqData); err != nil {
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

	reqData := struct {
		Type                 string
		TokenUniqueReference string
	}{}

	if err := tools.ReadBodyToStruct(req.Body, &reqData); err != nil {
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

func (h Handler) suspendHandler(w http.ResponseWriter, req *http.Request) {
	h.handle("S", w, req)
}
func (h Handler) unsuspendHandler(w http.ResponseWriter, req *http.Request) {
	h.handle("U", w, req)
}

func (h Handler) deleteHandler(w http.ResponseWriter, req *http.Request) {
	h.handle("D", w, req)
}

func (h Handler) handle(t string, w http.ResponseWriter, req *http.Request) {
	reqData := struct {
		Type                  string
		TokenUniqueReferences []string
		CausedBy              string
		ReasonCode            string
	}{}

	if err := tools.ReadBodyToStruct(req.Body, &reqData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	statuses, err := h.apiHandler.Manage(t, reqData.Type, reqData.TokenUniqueReferences, reqData.CausedBy, reqData.ReasonCode)
	if err != nil {
		// TO DO: log more error details
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, _ := json.Marshal(statuses)
	w.Header().Add("Content-Type", "application/json")
	w.Write(resp)
}

func (h Handler) healthCheck(w http.ResponseWriter, req *http.Request) {
	if err := h.apiHandler.HealthCheck(); err != nil {
		log.Printf("ERROR: health check failed with error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusOK)
}
