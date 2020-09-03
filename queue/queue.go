// package queue is the interface to SQL message queue
// WIP: It is just skeleton of code now

package queue

// Config - SQS connection
type Config struct {
	// SQS connection
}

// Queue - queue connection structure
type Queue struct {
	// something
}

// NewQueue returns new SQS connection
func NewQueue(cnf *Config) (*Queue, error) {
	// make and check SQS connection here
	return &Queue{}, nil
}

// Put puts the data to queue
func (q *Queue) Put(data []byte) error {
	// return q.put()
	return nil
}

// Subscribe subscribe for receiving new data from queue
func (q *Queue) Subscribe() (chan []byte, error) {
	return make(chan []byte, 2), nil
}

// ReportDone ACK responce to queue ??? what is the identifier of the queue item?
func (q *Queue) ReportDone() error {
	return nil
}
