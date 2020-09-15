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
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.GetOutSysInfo("A5")
	if err != nil {
		t.Fatal(err)
	}
	if d.CBURL != "urlinit" || d.TRIDURL != "tridurl" {
		t.Fatalf("uncorrect value: %+v", d)
	}
	err = db.StoreOutSysInfo("A5", &OutSysInfo{
		CBURL:   "urlinit1",
		TRIDURL: "tridurl1",
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err = db.GetOutSysInfo("A5")
	if err != nil {
		t.Fatal(err)
	}
	if d.CBURL != "urlinit1" || d.TRIDURL != "tridurl1" {
		t.Fatalf("uncorrect value: %+v", d)
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
