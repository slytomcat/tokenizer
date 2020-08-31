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
	// try to ping database
	if _, err := db.Ping().Result(); err != nil {
		return nil, err
	}
	return &DBConnect{db}, nil
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
	err := db.get(tur, &data)
	return &data, err
}

// StoreAsset - stores asset URL
func (db *DBConnect) StoreAsset(asset, url string) error {
	return db.r.Set(asset, url, 0).Err()
}

// GetAsset returns the asset URL
func (db *DBConnect) GetAsset(asset string) (string, error) {
	return db.r.Get(asset).Result()
}

// StoreOutSysInfo - stores out system info
func (db *DBConnect) StoreOutSysInfo(oSys string, oSysInfo *OutSysInfo) error {
	return db.set(oSys, oSysInfo, 0)
}

// GetOutSysInfo - stores out system info
func (db *DBConnect) GetOutSysInfo(oSys string) (*OutSysInfo, error) {
	data := OutSysInfo{}
	err := db.get(oSys, &data)
	return &data, err
}

// StoreTRSecrets - stores out system info
func (db *DBConnect) StoreTRSecrets(trid string, trSecrets *TRSecrets) error {
	return db.set(trid, trSecrets, 0)
}

// GetTRSecrets - stores out system info
func (db *DBConnect) GetTRSecrets(trid string) (*TRSecrets, error) {
	data := TRSecrets{}
	err := db.get(trid, &data)
	return &data, err
}
