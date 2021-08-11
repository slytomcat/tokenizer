package cbhandler

import (
	"log"
	"testing"
	"time"

	"github.com/slytomcat/tokenizer/queue"
	"github.com/slytomcat/tokenizer/tools"
	"github.com/stretchr/testify/assert"
)

func Test1(t *testing.T) {
	log.SetFlags(log.Lmicroseconds)
	config := struct {
		QUEUE queue.Config
		CBH   Config
	}{}
	tools.PanicIf(tools.ReadJSON("../config.json", &config))

	// connect to queue
	q, err := queue.NewQueue(&config.QUEUE)
	tools.PanicIf(err)

	// Start call-back handler
	cbExit := New(q, config.CBH.PollingInterval)

	err = q.Send(queue.QData{
		URL:     "http://s-t-c.tk:8080/echo",
		Payload: `{"some":"payload"}`,
	})
	if err != nil {
		t.Fatalf("queue sending error: %v", err)
	}
	t.Log(`sent`)
	time.Sleep(time.Second * 2)

	err = q.Send(queue.QData{
		URL:     "wrong URL",
		Payload: `{"some":"payload"}`,
	})
	assert.NoError(t, err)
	err = q.Send(queue.QData{
		URL:     "http://s-t-c.tk:8080/echo",
		Payload: `{"some":"payload"}`,
	})
	assert.NoError(t, err)
	time.Sleep(time.Second * 2)

	t.Log(`wait finished`)

	cbExit <- true
	time.Sleep(time.Second * 1)

}
