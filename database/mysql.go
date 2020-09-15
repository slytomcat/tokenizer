package database

import (
	"database/sql"
	"fmt"

	// MySQL engine
	_ "github.com/go-sql-driver/mysql"
)

// Db database connection
type Db struct {
	db *sql.DB
}

// ConfigS - database configuration
type ConfigS struct {
	DSN          string
	MaxOpenConns int
}

// NewDBs - makes new database connection
func NewDBs(conf *ConfigS) (Connector, error) {
	db, err := sql.Open("mysql", conf.DSN+"?parseTime=true")
	if err != nil {
		return nil, err
	}

	// set the connection pool size
	db.SetMaxOpenConns(conf.MaxOpenConns)

	DB := &Db{db}
	// Check the connection
	if err = DB.Check(); err != nil {
		return nil, err
	}

	return DB, nil
}

func errorHandler(key string, err error) error {
	if err == sql.ErrNoRows {
		return fmt.Errorf("%s was not found in DB", key)
	}
	return err
}

// Check pings database to check the connection
func (d *Db) Check() error {
	return d.db.Ping()
}

// StoreTokenInfo - stores token info
func (d *Db) StoreTokenInfo(tur string, ti *TokenData) error {
	_, err := d.db.Exec(
		`INSERT INTO token(tur, osys, trid, status, statustimestamp, last4,
			assuranceLevel, cobranded, cobrandName, issuerName, assetURL) VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON DUPLICATE KEY UPDATE
			osys=VALUES(osys), trid=VALUES(trid), status=VALUES(status), statustimestamp=VALUES(statustimestamp),
			last4=VALUES(last4), assuranceLevel=VALUES(assuranceLevel), cobranded=VALUES(cobranded),
			cobrandName=VALUES(cobrandName), issuerName=VALUES(issuerName), assetURL=VALUES(assetURL)`,
		tur, ti.OutSystem, ti.RequestorID, ti.Status, ti.StatusTimestamp, ti.Last4,
		ti.AssuranceLevel, ti.Cobranded, ti.CobrandName, ti.IssuerName, ti.AssetURL)

	return err
}

// GetTokenInfo returns the token info
func (d *Db) GetTokenInfo(tur string) (*TokenData, error) {
	ti := TokenData{}
	row := d.db.QueryRow(`
		SELECT 
		  osys, trid, status, statustimestamp, last4,
		  assuranceLevel, cobranded, cobrandName, issuerName, assetURL 
		FROM token WHERE tur=?`,
		tur,
	)
	err := row.Scan(
		&ti.OutSystem, &ti.RequestorID, &ti.Status, &ti.StatusTimestamp, &ti.Last4,
		&ti.AssuranceLevel, &ti.Cobranded, &ti.CobrandName, &ti.IssuerName, &ti.AssetURL,
	)
	if err != nil {
		return nil, errorHandler(tur, err)
	}
	return &ti, nil
}

// StoreAsset - stores asset info
func (d *Db) StoreAsset(id string, asset *Asset) error {
	_, err := d.db.Exec(
		`INSERT INTO asset(id, url) VALUES(?, ?)
		ON DUPLICATE KEY UPDATE url=VALUES(url)`,
		id, asset.PicURL)

	return err
}

// GetAsset returns the token info
func (d *Db) GetAsset(id string) (*Asset, error) {
	asset := Asset{}
	row := d.db.QueryRow(`
		SELECT url FROM asset WHERE id=?`,
		id,
	)
	err := row.Scan(&asset.PicURL)
	if err != nil {
		return nil, errorHandler(id, err)
	}
	return &asset, nil
}

// StoreOutSysInfo - stores out system info
func (d *Db) StoreOutSysInfo(oSys string, oSysInfo *OutSysInfo) error {

	_, err := d.db.Exec(
		`INSERT INTO osystem(osys,cburl,tridurl) VALUES(?,?,?)
		ON DUPLICATE KEY UPDATE	cburl=VALUES(cburl), tridurl=VALUES(tridurl)`,
		oSys,
		oSysInfo.CBURL,
		oSysInfo.TRIDURL,
	)
	return err
}

// GetOutSysInfo - stores out system info
func (d *Db) GetOutSysInfo(oSys string) (*OutSysInfo, error) {
	oi := OutSysInfo{}
	row := d.db.QueryRow(`
		SELECT cburl, tridurl FROM osystem WHERE osys=?`,
		oSys,
	)
	err := row.Scan(&oi.CBURL, &oi.TRIDURL)
	if err != nil {
		return nil, errorHandler(oSys, err)
	}
	return &oi, nil
}

// StoreTRSecrets - stores out system info
func (d *Db) StoreTRSecrets(trid string, trSecrets *TRSecrets) error {
	_, err := d.db.Exec(
		`INSERT INTO trsecrets(trid, apikey, decyptkey,	encryptkey,	signkey) VALUES(?,?,?,?,?)
		ON DUPLICATE KEY UPDATE apikey=VALUES(apikey), decyptkey=VALUES(decyptkey), encryptkey=VALUES(encryptkey), signkey=VALUES(signkey)`,
		trid, trSecrets.APIKey, trSecrets.DecryptKey, trSecrets.EncryptKey, trSecrets.SingKey)
	return err
}

// GetTRSecrets - stores out system info
func (d *Db) GetTRSecrets(trid string) (*TRSecrets, error) {
	ts := TRSecrets{}
	row := d.db.QueryRow(`
		SELECT apikey, decyptkey, encryptkey, signkey FROM trsecrets WHERE trid=?`,
		trid,
	)
	err := row.Scan(&ts.APIKey, &ts.DecryptKey, &ts.EncryptKey, &ts.SingKey)
	if err != nil {
		return nil, errorHandler(trid, err)
	}
	return &ts, nil
}

// StoreMerchant - stores merchant info
func (d *Db) StoreMerchant(id string, mi *Merchant) error {

	_, err := d.db.Exec(
		`INSERT INTO merchant(id,osys) VALUES(?,?)
		ON DUPLICATE KEY UPDATE	osys=VALUES(osys)`,
		id,
		mi.OutSystem,
	)
	return err
}

// GetMerchant - returns merchant info
func (d *Db) GetMerchant(id string) (*Merchant, error) {
	mi := Merchant{}
	row := d.db.QueryRow(`
		SELECT osys FROM merchant WHERE id=?`,
		id,
	)
	err := row.Scan(&mi.OutSystem)
	if err != nil {
		return nil, errorHandler(id, err)
	}
	return &mi, nil
}
