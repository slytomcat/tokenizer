// This is the queue handler that sends the call-backs from queue to the receiver
// WIP: It is just skeleton of code now

package cbhandler

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/slytomcat/tokenizer/queue"
)

// Config is call-back handler configuration
type Config struct {
	PollingInterval int
}

// New starts call-back handler goroutine that handles q queue with inteval in seconds
func New(q *queue.Queue, interval int) chan bool {

	// register CTRL-C signal chanel
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt)

	// make ticker
	tick := time.NewTicker(time.Second * time.Duration(interval))

	// make quit request chanel
	quit := make(chan bool, 1)

	// start handler
	go func() {
		log.Println("Starting Call-Back handler")
		defer log.Println("Call-Back handler stopped")
		for {
			select {
			case <-exit:
				return
			case <-quit:
				return
			case <-tick.C:
				for {
					// handle all call-backs from queue
					data, receipt, err := q.Receive()
					if err != nil {
						break
					}
					go send(q, data, receipt)
				}
			}
		}
	}()
	return quit
}

func send(q *queue.Queue, d, r string) {

	cbData := queue.QData{}
	if err := json.Unmarshal([]byte(d), &cbData); err != nil {
		log.Printf("ERROR: call-back: can't unmarshal data (%s) from queue: %v", d, err)
		// it's no reason to keep wrong formated data in the queue
		if err = q.Delete(r); err != nil {
			log.Printf("ERROR: call-back: deleting wrong message from queue error: %v", err)
		}
		return
	}

	// make call-back
	req, _ := http.NewRequest("POST", cbData.URL, bytes.NewReader([]byte(cbData.Payload)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("ERROR: call-back: can't send data to: %s error: %v", cbData.URL, err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR: call-back: receved unsuccess status code: %s while sending data to %s", resp.Status, cbData.URL)
		return
	}
	log.Printf("INFO: call-back: successfully send call-back to: %s with: %s", cbData.URL, cbData.Payload)

	// when callback was succesfully sent try to delete message from queue
	if err = q.Delete(r); err != nil {
		log.Printf("ERROR: call-back: deleting sent message from queue error: %v", err)
	}
}
