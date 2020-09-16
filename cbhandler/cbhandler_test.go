package cbhandler

import (
	"testing"
	"time"

	"github.com/slytomcat/tokenizer/queue"
	"github.com/slytomcat/tokenizer/tools"
)

func Test1(t *testing.T) {
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
	time.Sleep(time.Second * 4)

	t.Log(`wait finished`)

	cbExit <- true
	time.Sleep(time.Second * 2)
}
