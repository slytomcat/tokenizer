package database

import (
	"github.com/go-redis/redis/v7"
)

// DBConf database connection configuration
type DBConf struct {
	Addrs    []string
	Password string
}

// DBConnect - data base connection
type DBConnect struct {
	redis.UniversalClient
}

// TokenData is a token data that stored for notification support
type TokenData struct {
	OutSystem       string
	RequestorID     string
}

// Init creates DB connection
func Init(conf *DBConf) (redis.UniversalClient, error) {
	// TO DO: add more options for prod configuration
	db := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:    conf.Addrs,
		Password: conf.Password,
	})

	// try to ping database
	if _, err := db.Ping().Result(); err != nil {
		return nil, err
	}

	return DBConnect{db}, nil
}
