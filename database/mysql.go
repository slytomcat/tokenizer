package database

// import (
// 	"database/sql"
// 	"errors"

// 	// MySQL engine
// 	_ "github.com/go-sql-driver/mysql"
// )

// // Db database connection
// type Db struct {
// 	db sql.DB
// }

// // ConfigS - database configuration
// type ConfigS struct {
// 	DSN          string
// 	MaxOpenConns int
// }

// // NewDBs - makes new database connection
// func NewDBs(conf *ConfigS) (Connector, error) {
// 	db, err := sql.Open("mysql", conf.DSN)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// set the connection pool size
// 	db.SetMaxOpenConns(conf.MaxOpenConns)

// 	// Check the connection
// 	err = db.Ping()
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &Db{}, nil
// }

// // StoreTokenInfo - stores token info
// func (d *Db) StoreTokenInfo(tur string, ti *TokenData) error {
// 	_, err := d.db.Exec(
// 		`INSERT INTO TokenInfo(
// 						tur,
// 						osys,
// 						trid,
// 						status,
// 						statustimestamp,
// 						last4,
// 						assetURL
// 						)
// 			VALUES(?,?,?,?,?,?,?)
// 		ON DUPLICATE KEY UPDATE
// 			osys=VALUES(osys),
// 		 	trid=VALUES(trid),
// 		 	status=VALUES(status),
// 			statustimestamp=VALUES(statustimestamp),
// 			last4=VALUES(last4),
// 			assetURL=VALUES(assetURL)`,
// 		tur,
// 		ti.OutSystem,
// 		ti.RequestorID,
// 		ti.Status,
// 		ti.StatusTimestamp,
// 		ti.Last4,
// 		ti.AssetURL,
// 	)

// 	return err
// }

// // GetTokenInfo returns the token info
// func (d *Db) GetTokenInfo(tur string) (*TokenData, error) {
// 	ti := TokenData{}
// 	row := d.db.QueryRow(`
// 		SELECT
// 			tur,
// 			osys,
// 			trid,
// 			status,
// 			statustimestamp,
// 			last4,
// 			assetURL
// 		FROM TokenInfo
// 		WHERE tur=?
// 		`,
// 		tur,
// 	)
// 	switch err := row.Scan(&ti.OutSystem, &ti.RequestorID, &ti.Status, &ti.StatusTimestamp, &ti.Last4, &ti.AssetURL); err {
// 	case sql.ErrNoRows:
// 		return nil, errors.New("no rows were returned")
// 	case nil:
// 		return &ti, nil
// 	default:
// 		return nil, err
// 	}
// }

// // StoreAsset - stores asset info
// func (d *Db) StoreAsset(id, url string) error {
// 	_, err := d.db.Exec(
// 		`INSERT INTO asset(id, url)
// 			VALUES(?, ?)
// 		ON DUPLICATE KEY UPDATE
// 		    url=VALUES(url)`,
// 		id, url)

// 	return err
// }

// // GetAsset returns the token info
// func (d *Db) GetAsset(id string) (string, error) {
// 	url := ""
// 	row := d.db.QueryRow(`
// 		SELECT url
// 		FROM asset
// 		WHERE id=?`,
// 		id,
// 	)
// 	switch err := row.Scan(&url); err {
// 	case sql.ErrNoRows:
// 		return "", errors.New("no rows were returned")
// 	case nil:
// 		return url, nil
// 	default:
// 		return "", err
// 	}
// }

// // StoreOutSysInfo - stores out system info
// func (d *Db) StoreOutSysInfo(oSys string, oSysInfo *OutSysInfo) error {
// 	_, err := d.db.Exec(
// 		`INSERT INTO osysyinfo(
// 						osys,
// 						cburl
// 						)
// 			VALUES(?,?)
// 		ON DUPLICATE KEY UPDATE
// 			cburl=VALUES(cburl)`,
// 		oSys,
// 		oSysInfo.CBURL,
// 	)
// 	return err
// }

// // GetOutSysInfo - stores out system info
// func (d *Db) GetOutSysInfo(oSys string) (*OutSysInfo, error) {
// 	oi := OutSysInfo{}
// 	row := d.db.QueryRow(`
// 		SELECT
// 			cburl
// 		FROM osysyinfo
// 		WHERE osys=?`,
// 		oSys,
// 	)
// 	switch err := row.Scan(&oi.CBURL); err {
// 	case sql.ErrNoRows:
// 		return nil, errors.New("no rows were returned")
// 	case nil:
// 		return &oi, nil
// 	default:
// 		return nil, err
// 	}
// }

// // StoreTRSecrets - stores out system info
// func (d *Db) StoreTRSecrets(trid string, trSecrets *TRSecrets) error {
// 	_, err := d.db.Exec(
// 		`INSERT INTO trsecrets(
// 						trid,
// 						apikey,
// 						decyptkey,
// 						encryptkey,
// 						signkey
// 						)
// 			VALUES(?,?,?,?,?)
// 		ON DUPLICATE KEY UPDATE
// 		apikey=VALUES(apikey),
// 		decyptkey=VALUES(decyptkey),
// 		encryptkey=VALUES(encryptkey),
// 		signkey=VALUES(signkey)`,
// 		trid,
// 		trSecrets.APIKey,
// 		trSecrets.DecryptKey,
// 		trSecrets.EncryptKey,
// 		trSecrets.SingKey,
// 	)
// 	return err
// }

// // GetTRSecrets - stores out system info
// func (d *Db) GetTRSecrets(trid string) (*TRSecrets, error) {
// 	ts := TRSecrets{}
// 	row := d.db.QueryRow(`
// 		SELECT
// 			apikey,
// 			decyptkey,
// 			encryptkey,
// 			signkey
// 		FROM trsecrets
// 		WHERE trid=?`,
// 		trid,
// 	)
// 	switch err := row.Scan(&ts.APIKey, &ts.DecryptKey, &ts.EncryptKey, &ts.SingKey); err {
// 	case sql.ErrNoRows:
// 		return nil, errors.New("no rows were returned")
// 	case nil:
// 		return &ts, nil
// 	default:
// 		return nil, err
// 	}
// }
