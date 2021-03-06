package database

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v7"
)

// Config -  database connection configuration
type Config struct {
	Addrs    []string
	Password string
}

// DBConnect - data base connection
type DBConnect struct {
	r redis.UniversalClient
}

// NewDB creates DB connection
func NewDB(conf *Config) (Connector, error) {
	// TO DO: add more options for prod configuration
	db := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:    conf.Addrs,
		Password: conf.Password,
	})
	DB := &DBConnect{db}
	// try to ping database
	if err := DB.Check(); err != nil {
		return nil, err
	}
	return DB, nil
}

// Check pings the server to check the connection
func (db *DBConnect) Check() error {
	return db.r.Ping().Err()
}

// set sets the value for the key with the ttl
func (db *DBConnect) set(key string, value interface{}, ttl time.Duration) error {
	data, _ := json.Marshal(value)
	return db.r.Set(key, string(data), ttl).Err()
}

// Get returns the value of key
func (db *DBConnect) get(key string, value interface{}) error {
	data, err := db.r.Get(key).Result()
	if err != nil {
		value = nil //
		if err == redis.Nil {
			return fmt.Errorf("%s was not found in DB", key)
		}
		return err
	}
	return json.Unmarshal([]byte(data), &value)
}

// StoreTokenInfo - stores token info
func (db *DBConnect) StoreTokenInfo(tur string, ti *TokenData) error {
	return db.set(tur, ti, 0)
}

// GetTokenInfo returns the token info
func (db *DBConnect) GetTokenInfo(tur string) (*TokenData, error) {
	data := TokenData{}
	return &data, db.get(tur, &data)
}

// StoreOutSysInfo - stores out system info
func (db *DBConnect) StoreOutSysInfo(oSys string, oSysInfo *OutSysInfo) error {
	return db.set(oSys, oSysInfo, 0)
}

// GetOutSysInfo - returns out system info
func (db *DBConnect) GetOutSysInfo(oSys string) (*OutSysInfo, error) {
	data := OutSysInfo{}
	return &data, db.get(oSys, &data)
}

// StoreTRSecrets - stores TRID secrets
func (db *DBConnect) StoreTRSecrets(trid string, trSecrets *TRSecrets) error {
	return db.set(trid, trSecrets, 0)
}

// GetTRSecrets - returns TRID secrets
func (db *DBConnect) GetTRSecrets(trid string) (*TRSecrets, error) {
	data := TRSecrets{}
	return &data, db.get(trid, &data)
}

// StoreAsset - stores asset URL
func (db *DBConnect) StoreAsset(assetID string, asset *Asset) error {
	return db.set(assetID, asset, 0)
}

// GetAsset returns the asset URL
func (db *DBConnect) GetAsset(assetID string) (*Asset, error) {
	data := Asset{}
	return &data, db.get(assetID, &data)
}

// StoreMerchant - stores merchant info
func (db *DBConnect) StoreMerchant(id string, mi *Merchant) error {
	return db.set(id, mi, 0)
}

// GetMerchant - returns merchant info
func (db *DBConnect) GetMerchant(id string) (*Merchant, error) {
	data := Merchant{}
	return &data, db.get(id, &data)
}
