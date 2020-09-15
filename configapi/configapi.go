package configapi

import (
	"context"
	"crypto/rsa"
	"errors"
	"log"
	"net/http"

	"github.com/slytomcat/tokenizer/tools"
)

// CfgAPI - configuration api handlers interface
type CfgAPI interface {
	SetOutSystem(oSys, cburl string) error
	RegisterMCTRID(id, name string) error
	SetTRSecrets(trid, apikey string, signkey, decryptkey *rsa.PrivateKey, encryptkey *rsa.PublicKey) error
}

// Config - API configuration
type Config struct {
	HostPort string
	Cert     string
	Key      string
}

// Capi is ...
type Capi struct {
	handler  CfgAPI
	ShutDown func() error
}

func (c Capi) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	switch req.Method + req.URL.Path {
	case "POST/capi/v1/addoutsystem":
		c.addOutSystem(resp, req)
	case "POST/capi/v1/addtrsecrets":
		c.addTRSecrets(resp, req)
	case "POST/capi/v1/mc/tridregister":
		c.newTRID(resp, req)
	default:
		resp.WriteHeader(http.StatusBadRequest)
	}
}

// NewConfigAPI creates new configuration adapter
func NewConfigAPI(conf *Config, handler CfgAPI) *Capi {

	server := http.Server{
		Addr: conf.HostPort,
	}

	capi := Capi{
		handler:  handler,
		ShutDown: func() error { return server.Shutdown(context.Background()) },
	}

	server.Handler = capi

	go func() {
		log.Printf("INFO: Starting Config API service at %s", conf.HostPort)
		var err error
		if conf.Cert == "" {
			err = server.ListenAndServe()
		} else {
			err = server.ListenAndServeTLS(conf.Cert, conf.Key)
		}

		if !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
		log.Printf("INFO: Config API service: %v", err)
	}()

	return &capi
}

func (c *Capi) addOutSystem(w http.ResponseWriter, r *http.Request) {

	reqData := struct {
		OutSys string
		CBURL  string
	}{}

	if err := tools.ReadBodyToStruct(r.Body, &reqData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := c.handler.SetOutSystem(reqData.OutSys, reqData.CBURL); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}
func (c *Capi) newTRID(w http.ResponseWriter, r *http.Request) {

	reqData := struct {
		ID   string
		Name string
		// keys in []byte
	}{}

	if err := tools.ReadBodyToStruct(r.Body, &reqData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err := c.handler.RegisterMCTRID(reqData.ID, reqData.Name)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write([]byte{})
}

func (c *Capi) addTRSecrets(w http.ResponseWriter, r *http.Request) {

	reqData := struct {
		TRID   string
		APIKey string
		// keys in []byte
	}{}

	if err := tools.ReadBodyToStruct(r.Body, &reqData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := c.handler.SetTRSecrets(reqData.TRID, reqData.APIKey, nil, nil, nil); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}
