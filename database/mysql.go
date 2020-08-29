package database

import (
	"database/sql"

	// MySQL engine
	_ "github.com/go-sql-driver/mysql"
)

// Db database connection
type Db struct {
	sql.DB
}

// Config - database configuration
type Config struct {
	DSN          string
	MaxOpenConns int
}

// NewDB - makes new database connection
func NewDB(conf Config) (*Db, error) {
	db, err := sql.Open("mysql", conf.DSN)
	if err != nil {
		return nil, err
	}

	// set the connection pool size
	db.SetMaxOpenConns(conf.MaxOpenConns)

	// Check the connection
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return &Db{}, nil
}

// Set sets the value for key
func (d *Db) StoreTokenData(key, value string) error {
	return nil
}

// Get returns the value of key
func (d *Db) Get(key string) (string, error) {
	return "", nil
}
