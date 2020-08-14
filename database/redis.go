package database

import (
	"github.com/go-redis/redis/v7"
)

// DBConf database connection configuration
type DBConf struct {
	Addrs    []string
	Password string
}

// Init creates DB connection
func Init(conf *DBConf) (*redis.UniversalClient, error) {

	db := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:    conf.Addrs,
		Password: conf.Password,
	})

	// try to ping data base
	if _, err := db.Ping().Result(); err != nil {
		return nil, err
	}

	return &db, nil
}
