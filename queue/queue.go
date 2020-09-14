// package queue is the interface to SQL message queue
// WIP: It is just skeleton of code now

package queue

import (
	"encoding/json"
	"errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
)

// Config - SQS connection
type Config struct {
	Region     string
	AccesKeyID string
	SecretKey  string
	Endpoint   string
	QueueName  string
}

// Queue - queue connection structure
type Queue struct {
	q         *sqs.SQS
	queueName string
	queueURL  string
}

// QData - queue data structure
type QData struct {
	URL     string
	Payload string
}

// NewQueue returns new SQS connection
func NewQueue(conf *Config) (*Queue, error) {
	mySession := session.Must(session.NewSession())
	q := sqs.New(mySession,
		&aws.Config{
			Region:      aws.String(conf.Region),
			Credentials: credentials.NewStaticCredentials(conf.AccesKeyID, conf.SecretKey, ""),
			Endpoint:    aws.String(conf.Endpoint),
			DisableSSL:  aws.Bool(true),
		})
	// get queue url if queue exists
	res, err := q.GetQueueUrl(&sqs.GetQueueUrlInput{QueueName: aws.String(conf.QueueName)})
	if err != nil {
		// try to create new queue
		res, err := q.CreateQueue(&sqs.CreateQueueInput{
			QueueName: aws.String(conf.QueueName),
			Attributes: map[string]*string{
				"MessageRetentionPeriod": aws.String("345600"), // keep messages for 4 days
				"VisibilityTimeout":      aws.String("30"),
			},
		})
		if err != nil {
			return nil, err
		}
		return &Queue{q, conf.QueueName, *res.QueueUrl}, nil
	}
	return &Queue{q, conf.QueueName, *res.QueueUrl}, nil
}

// Send puts the data to queue
func (q *Queue) Send(data QData) error {
	sdata, _ := json.Marshal(data)
	_, err := q.q.SendMessage(&sqs.SendMessageInput{
		QueueUrl:    aws.String(q.queueURL),
		MessageBody: aws.String(string(sdata)),
	})
	return err
}

// Receive receives 1 message from queue, It returns message body, receipt handle ID, and error
func (q *Queue) Receive() (*QData, string, error) {
	res, err := q.q.ReceiveMessage(&sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(q.queueURL),
		MaxNumberOfMessages: aws.Int64(1),
	})
	if err != nil {
		return nil, "", err
	}
	if len(res.Messages) != 1 {
		return nil, "", errors.New("wrong number of messages received")
	}
	qd := QData{}
	err = json.Unmarshal([]byte(*res.Messages[0].Body), &qd)
	if err != nil {
		// it's no reason to keep the incorrectly formatted message in the queue
		// try to delete it
		q.Delete(*res.Messages[0].ReceiptHandle)
		return nil, "", err
	}
	return &qd, *res.Messages[0].ReceiptHandle, nil
}

// Delete is ACK responce to queue
func (q *Queue) Delete(receiptHandle string) error {
	_, err := q.q.DeleteMessage(&sqs.DeleteMessageInput{
		QueueUrl:      aws.String(q.queueURL),
		ReceiptHandle: aws.String(receiptHandle),
	})
	return err
}

// Check - checks the queue connection and existance
func (q *Queue) Check() error {
	_, err := q.q.GetQueueUrl(&sqs.GetQueueUrlInput{QueueName: aws.String(q.queueName)})

	return err
}
