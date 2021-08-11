package cache

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"testing"

	tools "github.com/slytomcat/tokenizer/tools"
	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {

	conf := struct{ Cache Config }{}
	err := tools.ReadJSON("../config.json", &conf)
	assert.NoError(t, err)

	c := NewCache(&conf.Cache)

	key := "test2"
	t.Logf("Key: '%s'\n", key)

	url := c.GetURL(key)
	t.Logf("URL: %s", url)

	buf := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, buf)
	assert.NoError(t, err)

	payload := []byte(fmt.Sprintf("BIG TEST DATA: % X", buf))
	t.Logf("Payload to write:   '%s'\n", payload)

	err = c.Put(key, payload)
	assert.NoError(t, err)

	payloadR, err := c.Get(key)
	assert.NoError(t, err)

	t.Logf("Received payload:   '%s'\n", payloadR)
	assert.Equal(t, payload, payloadR)

	// err = c.Del(key) // no rights for delete
	// assert.NoError(t, err)

	resp, err := http.DefaultClient.Get(url)
	assert.NoError(t, err)
	defer resp.Body.Close()

	payloadD, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	t.Logf("Downloaded payload: '%s'\n", payloadD)

	assert.Equal(t, payload, payloadD)

	assert.NoError(t, c.Check())
}
