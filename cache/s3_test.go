package cache

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"testing"

	tools "github.com/slytomcat/tokenizer/tools"
)

func TestCache(t *testing.T) {

	conf := struct{ Cache Config }{}
	err := tools.ReadJSON("../config.json", &conf)
	if err != nil {
		t.Fatal(err)
	}

	c := NewCache(&conf.Cache)

	key := "test2"
	t.Logf("Key: '%s'\n", key)

	url := c.GetURL(key)
	t.Logf("URL: %s", url)

	buf := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Fatalf("random bytes receiving error: %v", err)
	}

	payload := []byte(fmt.Sprintf("BIG TEST DATA: % X", buf))
	t.Logf("Payload to write:   '%s'\n", payload)

	err = c.Put(key, payload)

	if err != nil {
		t.Fatal(err)
	}

	payloadR, err := c.Get(key)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Received payload:   '%s'\n", payloadR)
	if !bytes.Equal(payload, payloadR) {
		t.Fatal("Received payload not equal to written one")
	}

	// err = c.Del(key) // no rights for delete
	// if err != nil {
	// 	t.Fatal(err)
	// }

	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	payloadD, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Downloaded payload: '%s'\n", payloadD)

	if !bytes.Equal(payload, payloadD) {
		t.Fatal("Downloaded payload not equal to written one")
	}

	if err := c.Check(); err != nil {
		t.Fatalf("Errors: %v", err)
	}

}
