package main

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/slytomcat/tokenizer/configapi"

	"github.com/slytomcat/tokenizer/api"
	"github.com/slytomcat/tokenizer/cache"

	database "github.com/slytomcat/tokenizer/database"
	"github.com/slytomcat/tokenizer/mdes"
	tools "github.com/slytomcat/tokenizer/tools"
)

const (
	mcPrefix   = "MC-"
	visaPrefix = "VS-"
)

var (
	m          *mdes.MDESapi      // MDES API adapter
	db         database.Connector // database adapter
	c          *cache.Cache       // cache adaptor
	configFile                    = flag.String("config", "./config.json", "`path` to the configuration file")
	version    string             = "unknown version"
)

func init() {
	log.SetFlags(log.Ldate & log.Lmicroseconds)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage:\t"+filepath.Base(os.Args[0])+" [-config=<Path/to/config.json>]\n\nOptions:\n")
		flag.PrintDefaults()
	}
}

// Config is the service configuration values set
type Config struct {
	API    api.Config
	DB     database.Config
	Cache  cache.Config
	MDES   mdes.Config
	CfgAPI configapi.Config
	//VISA - section for future VISA configuration values
}

func main() {

	flag.Parse()
	log.SetFlags(log.Lmicroseconds)
	log.Printf("tokenizer v.%s", version)
	log.Printf("debug %v", tools.DEBUG)

	// get configuration
	config := Config{}
	tools.PanicIf(tools.GetConfig(*configFile, "TOKENIZER_CONF", &config))

	doMain(&config)
}

func doMain(config *Config) {
	var err error
	// connect to databse
	db, err = database.NewDB(&config.DB)
	tools.PanicIf(err)

	// create MasterCard MDES protocol adapter instance
	m, err = mdes.NewMDESapi(&config.MDES, mdesNotifyForfard)
	tools.PanicIf(err)

	// Initialize cache
	c = cache.NewCache(&config.Cache)

	// Start API handler
	h := api.NewAPI(&config.API, handler{})

	// Start Configuration API handler
	cfg := configapi.NewConfigAPI(&config.CfgAPI, cfghandler{})
	// register CTRL-C signal chanel
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt)

	// wait for CTRL-C
	<-exit

	// Clearense
	collect, report := tools.ErrorCollector("clearence error(s): %v")
	collect(m.ShutDown())
	collect(h.ShutDown())
	collect(cfg.ShutDown())
	if err = report(); err != nil {
		panic(err)
	}
}

type handler struct{}

// Tokenize make token from card. It returns TUR and it's status
func (h handler) Tokenize(outS, trid, typ, pan, exp, cvc, source string) (string, string, error) {
	if len(exp) != 4 {
		return "", "", errors.New("wrong length of exp (must be 4)")
	}
	switch typ {
	case "MC":

		cardData := mdes.CardAccountData{
			AccountNumber: pan,
			ExpiryMonth:   exp[:2],
			ExpiryYear:    exp[2:],
			SecurityCode:  cvc,
		}
		tokenInfo, err := m.Tokenize(outS, trid, cardData, source)
		if err != nil {
			return "", "", err
		}
		// store token info for call back handling and start media cache update if requered
		go storeTokenData(outS, trid, typ, tokenInfo.TokenUniqueReference, "INACTIVE", time.Now(), tokenInfo.AccountPanSuffix, tokenInfo.BrandAssetID)

		return tokenInfo.TokenUniqueReference, "INACTIVE", nil
	case "VISA":
		return "", "", errors.New("unsupported yet card type")
	default:
		return "", "", errors.New("unsupported card type")
	}
}

// storeTokenData - stores token data for future token updates from MPS
func storeTokenData(outSystem, requestorID, typ, tokenUniqueReference, status string, statusTimestamp time.Time, last4, assetID string) {
	switch typ {
	case "MC":
		// get asset url
		assetURL, err := storeAsset(typ, assetID)
		if err != nil {
			log.Printf("ERROR: asset storage error: %v", err)
		}

		data := database.TokenData{
			OutSystem:       outSystem,
			RequestorID:     requestorID,
			Status:          status,
			StatusTimestamp: statusTimestamp,
			AssetURL:        assetURL,
			Last4:           last4,
		}

		err = db.StoreTokenInfo(mcPrefix+tokenUniqueReference, &data)
		if err != nil {
			log.Printf("ERROR: token info storing error: %v", err)
		} else {
			log.Printf("INFO: stored info for token %s: %+v", mcPrefix+tokenUniqueReference, data)
		}
	case "VISA":
		log.Print("unsupported yet card type")
	default:
		log.Print("unsupported card type")
	}

}

// storeAsset gets asset from MPS if it is not cached and store it into cache. It returns URL to stored image and error.
func storeAsset(typ, assetID string) (string, error) {
	switch typ {
	case "MC":
		// check assetID value
		if assetID == "" {
			return "", errors.New("AssetID = \"\"")
		}
		// check asset existance in cache
		assetData, err := db.GetAsset(mcPrefix + assetID)
		if err == nil {
			log.Printf("INFO: media for assetID: %s exists in cache", assetID)
			return assetData.PicURL, nil
		}

		// get asset data
		mediaData, err := m.GetAsset(assetID)
		if err != nil {
			return "", err
		}

		// get type
		tp := strings.Split(mediaData.Type, "/")
		if len(tp) != 2 {
			return "", fmt.Errorf("wrong type: %s", mediaData.Type)
		}

		assetID = mcPrefix + assetID
		key := assetID + "." + tp[1]

		url := c.GetURL(key)

		err = db.StoreAsset(assetID, &database.Asset{PicURL: url})
		if err != nil {
			return "", err
		}

		img, err := base64.StdEncoding.DecodeString(mediaData.Data)
		if err != nil {
			log.Printf("ERROR: BASE64 decoding error: %v", err)
		}

		err = c.Put(key, img)
		if err != nil {
			return "", err
		}

		return url, nil
	case "VISA":
		return "", errors.New("unsupported yet card type")
	default:
		return "", errors.New("unsupported card type")
	}
}

// Delete deletes tokens ad return the current tokens statuses
func (h handler) Delete(typ string, tokens []string, caused, reason string) ([]api.TokenStatus, error) {
	switch typ {

	case "MC":
		tokenStatuses, err := m.Delete(tokens, caused, reason)
		if err != nil {
			return nil, err
		}
		ts := []api.TokenStatus{}
		for _, t := range tokenStatuses {
			ts = append(ts, api.TokenStatus{
				TokenUniqueReference: t.TokenUniqueReference,
				Status:               t.Status,
				StatusTimestamp:      t.StatusTimestamp,
				SuspendedBy:          t.SuspendedBy,
			})
		}
		return ts, nil
	case "VISA":
		return nil, errors.New("unsupported yet card type")
	default:
		return nil, errors.New("unsupported card type")
	}
}

// Transact - returns the token DPAN and cryptogramms for payment by TUR
func (h handler) Transact(typ, tur string) (string, string, string, error) {
	switch typ {
	case "MC":

		res, err := m.Transact(tur)
		if err != nil {
			return "", "", "", err
		}
		// TO DO decide what to do with cryptograms
		return res.AccountNumber, res.ApplicationExpiryDate, res.Track2Equivalent, nil
	case "VISA":
		return "", "", "", errors.New("unsupported yet card type")
	default:
		return "", "", "", errors.New("unsupported card type")
	}
}

// MDES call-back notification forward
func mdesNotifyForfard(t mdes.NotificationTokenData) {

	// read token related info from storage
	tData, err := db.GetTokenInfo(mcPrefix + t.TokenUniqueReference)
	if err != nil {
		log.Printf("ERROR: getting token info from db error: %v", err)
		return
	}
	tools.Debug("received from DB: %+v", tData)

	assetURL, err := storeAsset("MC", t.ProductConfig.CardBackgroundCombinedAssetID)
	// update token data
	timeStamp, err := time.Parse(time.RFC3339, t.StatusTimestamp)
	if err != nil {
		timeStamp = time.Now()
	}

	// update only new data if data received
	update, updated := tools.Updater()
	update(&tData.AssetURL, assetURL)
	update(&tData.Last4, t.TokenInfo.AccountPanSuffix)
	update(&tData.Status, t.Status)
	if t.StatusTimestamp != "" {
		tData.StatusTimestamp = timeStamp
		*updated = true
	}
	if *updated {
		db.StoreTokenInfo(mcPrefix+t.TokenUniqueReference, tData)
	}

	// get data to make call-back to out system
	osysData, err := db.GetOutSysInfo(tData.OutSystem)
	if err != nil {
		log.Printf("ERROR: getting out system info from db error: %v", err)
		return
	}

	log.Printf("INFO: notification for outSytem: %s by cb URL: %s\nToken: %s TokenData: %+v", tData.OutSystem, osysData.CBURL, t.TokenUniqueReference, tData)

	// TO DO:
	// Put formated notification and URL into SQS
	// and ...
	// forget the rest!
	return

}

type cfghandler struct{}

func (c cfghandler) SetOutSystem(oSys, cburl string) error {
	return db.StoreOutSysInfo(oSys, &database.OutSysInfo{CBURL: cburl})
}
func (c cfghandler) SetTRSecrets(trid, apikey string, signkey, decryptkey *rsa.PrivateKey, encryptkey *rsa.PublicKey) error {
	return db.StoreTRSecrets(trid, &database.TRSecrets{
		APIKey:     apikey,
		SingKey:    signkey,
		DecryptKey: decryptkey,
		EncryptKey: encryptkey,
	})

}
