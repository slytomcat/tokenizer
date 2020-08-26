package cache

import (
	"fmt"
	"testing"

	tools "github.com/slytomcat/tokenizer/tools"
)

func TestCache(t *testing.T) {

	conf := struct{ Cache Config }{}
	err := tools.ReadJSON("../config.json", &conf)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}

	c := NewCache(&conf.Cache)
	payload := []byte("TEST DATA")
	key := "b/test"
	err = c.Put(key, payload)

	if err != nil {
		t.FailNow()
	}

	payloadR, err := c.Get(key)
	if err != nil {
		t.FailNow()
	}

	fmt.Printf("Received payload: %s\n", payloadR)

}
