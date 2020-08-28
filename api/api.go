package api

import (
	"context"
	"errors"
	"log"
	"net/http"
)

// Config - API configuration
type Config struct {
	HostPort string
	Cert     string
	Key      string
}

// PGAPI - payment gate API intreface
type PGAPI interface {
	//Tokenize(outSystem, requestorID, cardType, pan, exp, cvc, cardHolder) (tokenRef, status, error)
	Tokenize(string, string, string, string, string, string, string) (string, string, error)
	//Suspend([]string) ([]TokenStatus, error)
	//Unsuspend([]string) ([]TokenStatus, error)
	Delete([]string) ([]string, error)
	//Transact(TransactData) (*CryptogramData, error)
	//GetToken(string, string) (*TokenInfo, error)
	//Search(string, string, string, CardAccountData) ([]TokenStatus, error)
}

type apiHandler struct {
	handler PGAPI
}

func (h apiHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	switch req.Method + req.URL.Path {
	case "POST/api/v1/tokenize":
	case "POST/api/v1/delete":
	case "POST/api/v1/transaction":
	case "POST/api/v1/gettoken":
	default:
		resp.WriteHeader(http.StatusBadRequest)
	}
}

// NewAPI initialize the API and returns the service graceful shutdown function
func NewAPI(conf Config, handler PGAPI) func() error {
	server := http.Server{
		Addr:    conf.HostPort,
		Handler: apiHandler{},
	}
	go func() {
		err := server.ListenAndServeTLS(conf.Cert, conf.Key)
		if !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
		log.Printf("INFO: %v", err)
	}()

	return func() error { return server.Shutdown(context.Background()) }
}
