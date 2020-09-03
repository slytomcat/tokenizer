// This is the queue handler that sends the call-backs from queue to the receiver
// WIP: It is just skeleton of code now

package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/slytomcat/tokenizer/queue"
	"github.com/slytomcat/tokenizer/tools"
)

func main() {
	cfg := struct {
		Q queue.Config
	}{}

	tools.PanicIf(tools.GetConfig("config.json", "CBHANDLER_CONFIG", &cfg))

	q, err := queue.NewQueue(&cfg.Q)
	tools.PanicIf(err)

	ch, err := q.Subscribe()
	tools.PanicIf(err)

	// register CTRL-C signal chanel
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt)

	for {
		select {
		case <-exit:
			// q.Disconnect
			return
		case data := <-ch:
			cbData := struct {
				URL     string
				Payload []byte
			}{}
			if err := json.Unmarshal(data, &cbData); err != nil {
				log.Printf("ERROR: can't unmarshal data from queue: %v", err)
				continue
			}

			req, _ := http.NewRequest("POST", cbData.URL, bytes.NewReader(cbData.Payload))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Printf("ERROR: can't send data to receiver: %v", err)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				log.Printf("ERROR: receved unsuccess status code: %s", resp.Status)
				continue

			}
			q.ReportDone()
		}

	}

}
