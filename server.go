package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/slytomcat/tokenizer/api"
	"github.com/slytomcat/tokenizer/cache"

	database "github.com/slytomcat/tokenizer/database"
	"github.com/slytomcat/tokenizer/mdes"
	tools "github.com/slytomcat/tokenizer/tools"
)

const (
	mcPrefix = "MC-"
)

var (
	m  *mdes.MDESapi
	db *database.DBConnect
	c  *cache.Cache
	// ConfigFile - is the path to the configuration file
	configFile        = flag.String("config", "./config.json", "`path` to the configuration file")
	version    string = "unknown version"
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
	API   api.Config
	DB    database.Config
	Cache cache.Config
	MDES  mdes.Config
	//VISA - section for future VISA configuration values
}

func getConfig(path string) *Config {

	// try to read config file
	configData := Config{}
	err := tools.ReadJSON(path, &configData)
	if err != nil {
		log.Printf("WARNING: config file opening/reading/parsing error: %v", err)
	}

	// try to read config from environment
	err = json.Unmarshal([]byte(os.Getenv("TOKENIZER_CONF")), &configData)
	if err != nil {
		log.Printf("WARNING: config environment variable parsing error: %v", err)
	}

	// REMOVE IT IN PROD
	log.Printf("INFO: service configuration: %+v", configData)

	return &configData
}

func main() {
	var err error

	flag.Parse()

	config := getConfig(*configFile)

	// connect to databse
	db, err = database.NewDB(&config.DB)
	if err != nil {
		panic(err)
	}

	// create MasterCard MDES protocol adapter instance
	m, err = mdes.NewMDESapi(&config.MDES, mdesNotifyForfard)
	if err != nil {
		panic(err)
	}

	// Initialize cache
	c = cache.NewCache(&config.Cache)

	// Start API handler
	h := api.NewAPI(&config.API, handler{})

	// register CTRL-C signal chanel
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt)

	// wait for CTRL-C
	<-exit

	// Clearense
	collect, report := tools.ErrorCollector("clearence error(s): %v")
	collect(m.ShutDown())
	collect(h.ShutDown())
	if err = report(); err != nil {
		panic(err)
	}
}

type handler struct{}

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
		go h.storeTokenData(outS, trid, typ, tokenInfo.TokenUniqueReference, "INACTIVE", time.Now(), tokenInfo.AccountPanSuffix, tokenInfo.BrandAssetID)

		return tokenInfo.TokenUniqueReference, "INACTIVE", nil
	case "VISA":
		return "", "", errors.New("unsupported yet card type")
	default:
		return "", "", errors.New("unsupported card type")
	}
}

func (h handler) storeTokenData(outSystem, requestorID, typ, tokenUniqueReference, status string, statusTimestamp time.Time, last4, assetID string) {
	switch typ {
	case "MC":
		// get asset url
		assetURL, err := h.storeAsset(typ, assetID)
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
		})

		err = db.StoreTokenInfo(mcPrefix+tokenUniqueReference, data))
		if err != nil {
			log.Printf("ERROR: token info storing error: %v", err)
		} else {
			log.Printf("INFO: stored info for token %s: %s", mcPrefix+tokenUniqueReference, data)
		}
	case "VISA":
		log.Print("unsupported yet card type")
	default:
		log.Print("unsupported card type")
	}

}

func (h handler) storeAsset(typ, assetID string) (string, error) {
	switch typ {
	case "MC":
		// check asset existance in cache
		url, err := db.GetAsset(mcPrefix + assetID)
		if err == nil {
			log.Printf("INFO: media for assetID: %s exists in cache", assetID)
			return url, nil
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

		url = c.GetURL(key)

		err = db.StoreAsset(assetID, url)
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
func mdesNotifyForfard(t mdes.NotificationTokenData)  {
	// read token related info from storage
	s, err := db.GetAsset(mcPrefix + t.TokenUniqueReference)
	if err != nil {
		log.Printf("ERROR: getting token info from db error: %v" err)
		return
	}

	// unwrap stored token data
	storedTokenData := database.TokenData{}
	err = json.Unmarshal([]byte(s), &storedTokenData)
	if err != nil {
		log.Printf("ERROR: unmarshaling stored token data error: %v", err)
		return 
	}

	// get asset URL and update the token asset if it is changed
	assetURL, err := m.GetAsset(t.ProductConfig.CardBackgroundCombinedAssetID)
	if err != nil {
		log.Printf("ERROR: getting asset error: %v", err)
	}

	log.Printf("INFO: notification for token/system/requestorId/assetURL: %s/%s/%s/%s", t.TokenUniqueReference, storedTokenData.OutSystem, storedTokenData.RequestorID, assetURL)

	// TO DO:
	// Get oUtSystem call-back URL from DB 
	// Put formated notification into SQS
	// forgot the rest:
	// update notfication record: set("notify"+prefix+t.TokenUniqueReference+timeStamp, json.marshal(data + recipient), 0)
	// l: send notification
	// get responce
	// if no responce then
	//   if the number of sending attempts is not exceeded
	//      sleep and repeat from l
	//   else
	//      log the problem
	//      return (leaving notification record in database it will be hanled by scaner)
	// delete notification record from db^ delete("notify"+prefix+t.TokenUniqueReference+timeStamp)
	return nil

}
