package main

import (
	"encoding/base64"
	"encoding/json"
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

	"github.com/go-redis/redis/v7"
	database "github.com/slytomcat/tokenizer/database"
	"github.com/slytomcat/tokenizer/mdes"
	tools "github.com/slytomcat/tokenizer/tools"
)

var (
	m  *mdes.MDESapi
	db redis.UniversalClient
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
	DB    database.DBConf
	Cache cache.Config
	MDES  mdes.MDESconf
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
	flag.Parse()

	if err := doMain(getConfig(*configFile)); err != nil {
		panic(err)
	}
}

func doMain(config *Config) error {
	var err error
	// connect to databse
	db, err = database.Init(&config.DB)
	if err != nil {
		return err
	}

	// create MasterCard MDES protocol convertor instance
	m, err = mdes.NewMDESapi(&config.MDES, mdesNotifyForfard)
	if err != nil {
		return err
	}

	c = cache.NewCache(&config.Cache)

	h := api.NewAPI(config.API, handler{})

	// register CTRL-C signal chanel
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt)

	// wait for CTRL-C
	<-exit

	// do cleanup
	m.ShutDown()
	return h.ShoutDown()

}

type handler struct{}

func (h handler) Tokenize(outS, trid, pan, exp, cvc, source string) (string, string, error) {

	// TO DO check the data
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
	go h.storeTokenData(outS, trid, tokenInfo.TokenUniqueReference, "INACTIVE", time.Now(), tokenInfo.PanSuffix, tokenInfo.BrandAssetID)

	return tokenInfo.TokenUniqueReference, "INACTIVE", nil
}

func (h handler) storeTokenData(outSystem, requestorID, tokenUniqueReference, status string, statusTimestamp time.Time, last4, assetID string) {

	// get asset url
	assetURL, err := h.storeAsset(assetID)
	if err != nil {
		log.Printf("ERROR: asset storage error: %v", err)
	}

	data, _ := json.Marshal(database.TokenData{
		OutSystem:       outSystem,
		RequestorID:     requestorID,
		Status:          status,
		StatusTimestamp: statusTimestamp,
		AssetURL:        assetURL,
	})

	err = db.Set("MC-"+tokenUniqueReference, data, 0).Err()
	if err != nil {
		log.Printf("ERROR: token info storing error: %v", err)
	} else {
		log.Printf("INFO: stored info for token %s: %s", "MC-"+tokenUniqueReference, data)
	}
}

func (h handler) storeAsset(assetID string) (string, error) {

	// check asset existance in cache
	url, err := db.Get("MC-" + assetID).Result()
	if err == nil {
		log.Printf("INFO: media for assetID: %s exists in cache", assetID)
		return url, nil
	}

	// get asset data
	mediaData, err := m.GetAsset(assetID)
	if err != nil {
		log.Printf("ERROR: getting asset error: %v", err)
	}

	// get type
	tp := strings.Split(mediaData.Type, "/")
	if len(tp) != 2 {
		return "", fmt.Errorf("wrong type: %s", mediaData.Type)
	}

	assetID = "MC-" + assetID
	key := assetID + "." + tp[1]

	url = c.GetURL(key)

	err = db.Set(assetID, url, time.Duration(time.Hour*8760)).Err() //1  year expiration ?
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
}

func (h handler) Delete(tokens []string, caused, reason string) ([]api.TokenStatus, error) {

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
}

func (h handler) Transact(tur string) (string, string, string, error) {

	res, err := m.Transact(tur)
	if err != nil {
		return "", "", "", err
	}
	// TO DO decide what to do with cryptograms
	return res.AccountNumber, res.ApplicationExpiryDate, res.Track2Equivalent, nil
}

func mdesNotifyForfard(t mdes.MCNotificationTokenData) error {
	// read token related info from storage
	s, err := db.Get("MC-" + t.TokenUniqueReference).Result()
	if err != nil {
		if err != redis.Nil {
			log.Printf("ERROR: bd access error: %v", err)
		} else {
			log.Printf("n: token %s not found in DB", t.TokenUniqueReference)
		}
		return err
	}

	// unwrap stored token data
	storedTokenData := database.TokenData{}
	err = json.Unmarshal([]byte(s), &storedTokenData)
	if err != nil {
		log.Printf("ERROR: marshaling stored token data error: %v", err)
		return err
	}

	// get asset URL and update the token asset if it is changed
	assetURL, err := m.GetAsset(t.ProductConfig.CardBackgroundCombinedAssetID)
	if err != nil {
		log.Printf("ERROR: getting asset error: %v", err)
	}

	log.Printf("INFO: notification for token/system/requestorId/assetURL: %s/%s/%s/%s", t.TokenUniqueReference, storedTokenData.OutSystem, storedTokenData.RequestorID, assetURL)

	// TO DO:
	// format data to send
	// update notfication record: set("notify"+prefix+t.TokenUniqueReference+timeStamp, json.marshal(data + recipient), 0)
	// l: send notification
	// get responce
	// if no responce then
	//   if the number of sending attempts is not exceeded
	//      sleep and repeat from l
	//   else
	//      log the problem
	//      return (leaving notification record in db. it will be hanled by scaner)
	// delete notification record from db^ delete("notify"+prefix+t.TokenUniqueReference+timeStamp)
	return nil

}
