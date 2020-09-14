// This is the queue handler that sends the call-backs from queue to the receiver
// WIP: It is just skeleton of code now

package cbhandler

import (
	"bytes"
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
	defer tick.Stop()

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

func send(q *queue.Queue, d *queue.QData, r string) {

	// make call-back
	req, _ := http.NewRequest("POST", d.URL, bytes.NewReader([]byte(d.Payload)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("ERROR: call-back: can't send data to: %s error: %v", d.URL, err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR: call-back: receved unsuccess status code: %s while sending data to %s", resp.Status, d.URL)
		return
	}
	log.Printf("INFO: call-back: successfully send call-back to: %s with: %s", d.URL, d.Payload)

	// when callback was succesfully sent try to delete message from queue
	if err = q.Delete(r); err != nil {
		log.Printf("ERROR: call-back: deleting sent message from queue error: %v", err)
	}
}
