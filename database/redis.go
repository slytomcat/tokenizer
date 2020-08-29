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

// Set sets the value for the key with the ttl
func (db *DBConnect) set(key, value string, ttl time.Duration) error {
	return db.r.Set(key, value, ttl).Err()
}

// Get returns the value of key
func (db *DBConnect) get(key string) (string, error) {
	res, err := db.r.Get(key).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("%s was not found in DB", key)
	}
	return res, err
}

// StoreTokenInfo - stores token info
func (db *DBConnect) StoreTokenInfo(key string, ti *TokenData) error {
	value, _ := json.Marshal(ti)
	return db.set(key, string(value), 0)
}

// GetTokenInfo returns the token info
func (db *DBConnect) GetTokenInfo(key string) (*TokenData, error) {
	value, err := db.get(key)
	if err != nil {
		return nil, err
	}
	ti := TokenData{}
	err = json.Unmarshal([]byte(value), &ti)
	if err != nil {
		return nil, err
	}
	return &ti, nil
}

// StoreAsset - stores asset info
func (db *DBConnect) StoreAsset(key, url string) error {
	return db.set(key, string(url), 0)
}

// GetAsset returns the token info
func (db *DBConnect) GetAsset(key string) (string, error) {
	url, err := db.get(key)
	if err != nil {
		return "", err
	}
	return url, nil
}
