package database

import (
	"testing"

	"github.com/slytomcat/tokenizer/tools"
	"github.com/stretchr/testify/assert"
)

var (
	db Connector
)

func initDB() {
	if db == nil {
		cfg := struct {
			DB ConfigS
		}{}
		tools.PanicIf(tools.ReadJSON("../config.json", &cfg))

		var err error
		db, err = NewDBs(&cfg.DB)
		tools.PanicIf(err)
	}
}
func TestOutSysData(t *testing.T) {
	initDB()

	err := db.StoreOutSysInfo("A5", &OutSysInfo{
		CBURL:   "urlinit",
		TRIDURL: "tridurl",
	})
	assert.NoError(t, err)
	d, err := db.GetOutSysInfo("A5")
	assert.NoError(t, err)
	if d.CBURL != "urlinit" || d.TRIDURL != "tridurl" {
		t.Fatalf("uncorrect value: %+v", d)
	}
	err = db.StoreOutSysInfo("A5", &OutSysInfo{
		CBURL:   "urlinit1",
		TRIDURL: "tridurl1",
	})
	assert.NoError(t, err)
	d, err = db.GetOutSysInfo("A5")
	assert.NoError(t, err)
	assert.Equal(t, OutSysInfo{
		CBURL:   "urlinit",
		TRIDURL: "tridurl",
	}, d)

}

func TestAssetData(t *testing.T) {
	initDB()

	err := db.StoreAsset("A5", &Asset{"urlinit"})
	assert.NoError(t, err)
	d, err := db.GetAsset("A5")
	assert.NoError(t, err)
	assert.Equal(t, "urlinit", d.PicURL)
	err = db.StoreAsset("A5", &Asset{"urllater"})
	assert.NoError(t, err)
	d, err = db.GetAsset("A5")
	assert.NoError(t, err)
	assert.Equal(t, "urllater", d.PicURL)
}
