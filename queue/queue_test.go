package queue

import (
	"log"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/assert"

	"github.com/slytomcat/tokenizer/tools"
)

func TestNew(t *testing.T) {
	log.SetFlags(log.Lmicroseconds)
	conf := struct{ QUEUE Config }{}
	assert.NoError(t, tools.ReadJSON("../config.json", &conf))

	q, err := NewQueue(&conf.QUEUE)
	assert.NoError(t, err)

	// clearance
	req, _ := q.q.PurgeQueueRequest(&sqs.PurgeQueueInput{
		QueueUrl: aws.String(q.queueURL),
	})
	req.Send()

	tdata1 := QData{
		URL:     "some url",
		Payload: "some payload",
	}

	err = q.Send(tdata1)
	assert.NoError(t, err)

	// err = q.Send(tdata2)
	// 	assert.NoError(t, err)

	// _ = q.Send(tdata3)

	data, receipt, err := q.Receive()
	assert.NoError(t, err)
	t.Log(*data)

	err = q.Delete(receipt)
	assert.NoError(t, err)

	err = q.Check()
	assert.NoError(t, err)

	data, receipt, err = q.Receive()
	assert.Error(t, err)
	assert.Nil(t, data)

	// clearance
	req, _ = q.q.PurgeQueueRequest(&sqs.PurgeQueueInput{
		QueueUrl: aws.String(q.queueURL),
	})
	req.Send()

	q.q.DeleteQueue(&sqs.DeleteQueueInput{QueueUrl: aws.String(q.queueURL)})

	data, receipt, err = q.Receive()
	assert.Error(t, err)
	q, err = NewQueue(&conf.QUEUE)
	assert.NoError(t, err)
}
