package database

import (
	"testing"

	"github.com/slytomcat/tokenizer/tools"
)

var (
	db Connector
)

func initDB() {
	if db == nil {
		cfg := struct {
			DB ConfigS
		}{}
		tools.PanicIf(tools.GetConfig("../config.json", "TOKENIZER_CONF", &cfg))

		var err error
		db, err = NewDBs(&cfg.DB)
		tools.PanicIf(err)
	}
}
func TestOutSysData(t *testing.T) {
	initDB()

	err := db.StoreOutSysInfo("A5", &OutSysInfo{"urlinit"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.GetOutSysInfo("A5")
	if err != nil {
		t.Fatal(err)
	}
	if d.CBURL != "urlinit" {
		t.Fatal("uncorrect value")
	}
	err = db.StoreOutSysInfo("A5", &OutSysInfo{"urllater"})
	if err != nil {
		t.Fatal(err)
	}
	d, err = db.GetOutSysInfo("A5")
	if err != nil {
		t.Fatal(err)
	}
	if d.CBURL != "urllater" {
		t.Fatal("uncorrect value")
	}

}

func TestAssetData(t *testing.T) {
	initDB()

	err := db.StoreAsset("A5", &Asset{"urlinit"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.GetAsset("A5")
	if err != nil {
		t.Fatal(err)
	}
	if d.PicURL != "urlinit" {
		t.Fatal("uncorrect value")
	}
	err = db.StoreAsset("A5", &Asset{"urllater"})
	if err != nil {
		t.Fatal(err)
	}
	d, err = db.GetAsset("A5")
	if err != nil {
		t.Fatal(err)
	}
	if d.PicURL != "urllater" {
		t.Fatal("uncorrect value")
	}

}
