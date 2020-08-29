package database

import (
	"database/sql"

	// MySQL engine
	_ "github.com/go-sql-driver/mysql"
)

// Db database connection
type Db struct {
	db sql.DB
}

// ConfigS - database configuration
type ConfigS struct {
	DSN          string
	MaxOpenConns int
}

// NewDBs - makes new database connection
func NewDBs(conf *ConfigS) (Connector, error) {
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

// StoreTokenInfo - stores token info
func (d *Db) StoreTokenInfo(key string, ti *TokenData) error {
	// insert|update into TokenInfo where tur=:key
	return nil
}

// GetTokenInfo returns the token info
func (d *Db) GetTokenInfo(key string) (*TokenData, error) {
	// select * from TokenInfo where tur=:key
	return nil, nil
}

// StoreAsset - stores asset info
func (d *Db) StoreAsset(key, url string) error {
	// insert|update Asset where assetID=:key
	return nil
}

// GetAsset returns the token info
func (d *Db) GetAsset(key string) (string, error) {
	// select * from Asset where assetID=:key
	return "", nil
}
